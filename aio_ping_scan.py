import socket
import ipaddress
import asyncio
import logging
import struct
import time
from concurrent.futures import ProcessPoolExecutor
from utils import split_networks, ip_mask_to_list
from icmp import build
logger = logging.getLogger(__name__)

sender_id = 1
seq = 1

ICMP_MAX_RECV = 1518
ICMP_ECHO_REPLY = 0
ICMP_MAX_SIZE = 1500
ICMP_OFFSET = 20
SRC_IP_OFFSET = 12

ICMP_NETWORK_UNREACH = 3


def mp_ping_network(ip, netmask, timeout, processes=4):
    """

    :param ip:
    :param netmask:
    :param timeout:
    :param processes:
    :return:
    """
    networks = split_networks(ip, netmask, processes)

    loop = asyncio.get_event_loop()
    executor = ProcessPoolExecutor(max_workers=processes)
    tasks = [loop.run_in_executor(executor, ping_network, network[0], network[1], timeout) for network in networks]

    return loop.run_until_complete(asyncio.gather(*tasks))


def ping_network(ip, netmask, timeout):
    """

    :param ip:
    :param netmask:
    :param timeout:
    :return:
    """
    result = []
    loop = asyncio.get_event_loop()
    tasks = [asyncio.ensure_future(ping(addr, timeout)) for addr in ip_mask_to_list(ip, netmask)]
    result = loop.run_until_complete(asyncio.gather(*tasks))
    return list(set([str(addr) for addr in result if addr is not None]))


async def ping(ip, timeout=3):
    """

    :param ip:
    :param timeout:
    :return:
    """
    global seq

    seq = (seq + 1) % 30000
    pkt_seq = seq

    packet = build(pkt_seq, sender_id)

    info = await asyncio.get_event_loop().getaddrinfo(ip, 0)
    sock = socket.socket(family=socket.AF_INET,
                         type=socket.SOCK_RAW,
                         proto=socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    try:
        await async_sender(sock, info, packet)
        result = await receive(sock, pkt_seq, timeout, info[2][4][0])
        if result:
            return ipaddress.IPv4Address(result)
        else:
            return None

    except Exception as e:
        logger.error(f'ping::{str(e)}')
        return None
    finally:
        if sock:
            sock.close()


async def receive(sock, pkt_seq, timeout, ip):
    loop = asyncio.get_event_loop()

    try:
        t1 = time.time()
        while True:
            recv_packet = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout)
            offset = ICMP_OFFSET
            icmp_header = recv_packet[offset:offset + 8]

            type, code, checksum, packet_id, sequence = struct.unpack(
                "bbHHh", icmp_header
            )

            if type == ICMP_ECHO_REPLY:
                resp_ip = recv_packet[SRC_IP_OFFSET:SRC_IP_OFFSET + 4]

                if ipaddress.IPv4Address(resp_ip) == ipaddress.IPv4Address(ip):
                    return ipaddress.IPv4Address(ip)

            t2 = time.time()
            td = int((t2 - t1) * 1000)
            if td > timeout * 1000:
                logger.debug(f'recv timed out')
                return False
    except asyncio.TimeoutError:
        logger.debug(f'recv timed out')
        return False
    except Exception as e:
        logger.error(f'{str(e)}')
        return False


def send(sock, dest, packet):
    try:
        sock.sendto(packet, dest)
    except Exception as e:
        logger.error(f'send:: {str(e)}')


async def async_sender(sock, info, packet):
    try:
        asyncio.get_event_loop().call_soon_threadsafe(send, sock, info[2][4], packet)
    except Exception as e:
        logger.error(f'send_wrap::{str(e)}')
        return False
