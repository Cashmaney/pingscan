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

addresses = {}


class TimeOutError(Exception):
    pass


class aio_pinger(object):
    ICMP_MAX_SIZE = 130

    def __init__(self, timeout=5, loop=asyncio.get_event_loop()):
        self.done_sending = False
        self.loop = loop
        self.timeout = timeout
        self.logger = logging.getLogger(__class__.__name__)
        self.queue = asyncio.Queue()
        self.sequence = 1
        self.message_id = 1
        self.addrs = []
        self.addresses = {}
        self.start_time = None

    def __enter__(self):
        self.rsock = self._create_socket()
        self.ssock = self._create_socket()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()

    def _cleanup(self):
        self.rsock.close()
        self.ssock.close()

    def ping(self, ip, network):
        t1 = time.time()
        self.logger.debug("started to calculate IPs...")
        self._generate_ips(ip, network)
        self.logger.debug(f"done [{int((time.time() - t1) * 1000 * 1000)}us]")
        self.start_time = time.time()

        self.done_sending_time = None

        self.done_receiving = False

        executor = ProcessPoolExecutor(max_workers=4)
        try:
            # tasks = [loop.run_in_executor(executor, ping_network, network[0], network[1], timeout) for network in
            #          networks]
            # result = loop.run_until_complete(asyncio.gather(*tasks))
            #tasks = [loop.run_in_executor(executor, )]
            # self._send_ping_network(ip, network)
            # self._recv()
            # self._process()
            self.loop = asyncio.get_event_loop()
            tasks = [asyncio.ensure_future(self._recv()),
                     asyncio.ensure_future(self._send_ping_network(ip, network)),
                     asyncio.ensure_future(self._process())]
        # tasks = [asyncio.ensure_future(ping(addr, timeout)) for addr in ip_mask_to_list(ip, netmask)]
            result = self.loop.run_until_complete(asyncio.gather(*tasks))
            return [str(addr) for addr in self.addresses]
        #
        except Exception as e:
            self.logger.debug(f'{str(e)}')
            return []
        finally:
            self._cleanup()

    @staticmethod
    def _create_socket():
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setblocking(False)
        return sock

    async def _recv(self):
        try:
            while True:
                # receive a packet or wait till we timeout (will throw an asyncio.TimeoutError after self.timeout)
                try:
                    self.logger.debug("listening...")
                    recv_packet = await asyncio.wait_for(self.loop.sock_recv(self.rsock, ICMP_MAX_SIZE),
                                                         self.timeout / 2)
                except asyncio.TimeoutError:
                    self.logger.debug(f'recv timed out')
                    if self.done_sending:
                        self.logger.debug("Done sending & timeout")
                        self.done_receiving = True
                        raise asyncio.TimeoutError
                    else:
                        self.logger.debug("Timeout but not done sending.. retrying")
                        continue
                self.logger.debug("Got packet, enqueuing")
                # enqueue the received packet (parsing it will be done elsewhere)
                self.queue.put_nowait(recv_packet)

                if self.done_sending:

                    # after handling the packet check if we timed out already
                    td = int((time.time() - self.done_sending_time) * 1000)

                    # timeout is divided by 2 here and in the recv because in the worst case we will be waiting twice
                    if td > self.timeout * 1000 / 2:
                        # self.logger.debug(f'recv timed out')
                        self.done_receiving = True
                        return

        except asyncio.TimeoutError:
            self.logger.debug(f'recv timed out')
            return
        except Exception as e:
            self.logger.error(f'{str(e)}')
            return

    async def _process(self):
        try:
            while True:
                try:
                    packet = await asyncio.wait_for(self.queue.get(), self.timeout / 2)
                except asyncio.TimeoutError:
                    self.logger.debug(f'recv timed out')
                    if self.done_receiving:
                        if self.queue.empty():
                            self.logger.debug("Done with recv & timeout")
                            raise asyncio.TimeoutError
                        continue
                    else:
                        self.logger.debug("Timeout but not done sending.. retrying")
                        continue
                self.logger.debug("Receiver took packet from queue...")
                offset = ICMP_OFFSET
                icmp_header = packet[offset:offset + 8]

                type, code, checksum, packet_id, sequence = struct.unpack(
                    "bbHHh", icmp_header
                )

                if type == ICMP_ECHO_REPLY:
                    resp_ip = packet[SRC_IP_OFFSET:SRC_IP_OFFSET + 4]
                    self.logger.debug(f"packet is icmp reply. adding to list - {resp_ip}")
                    self.addresses.update({ipaddress.ip_address(resp_ip): True})
                    # if ipaddress.ip_address(resp_ip) == ipaddress.ip_address(ip):
                    #     return ipaddress.ip_address(ip)
                # after handling the packet check if we timed out already
                await asyncio.sleep(0)
                # td = int((time.time() - self.start_time) * 1000)

                # timeout is divided by 2 here and in the recv because in the worst case we will be waiting
                # timeout/2 at the recv
                # if td > self.timeout * 1000 / 2:
                #     self.logger.debug(f'recv timed out')
                #     return

        except asyncio.TimeoutError:
            self.logger.debug(f'recv timed out')
            return
        except Exception as e:
            self.logger.error(f'{str(e)}')
            return

    def _send(self, sock, dest, packet):
        try:
            sock.sendto(packet, (dest, 0))
        except Exception as e:
            self.logger.error(f'send:: {str(e)}')
            pass

    async def _send_ping_network(self, ip, network):
        t1 = time.time()
        self.logger.debug(f"starting sending...")
        for addr in self.addrs:
            self.sequence = pkt_seq = (self.sequence + 1) % 30000

            packet = build(pkt_seq, sender_id)

            # info = await asyncio.get_event_loop().getaddrinfo(ip, 0)
            try:
                self.loop.call_soon_threadsafe(self._send, self.ssock, addr, packet)
                await asyncio.sleep(0)
            except Exception as e:
                logger.error(f'send_wrap::{str(e)}')
                return False
        self.logger.debug(f"done sending! [{int((time.time() - t1) * 1000)}ms]")
        self.done_sending = True
        self.done_sending_time = time.time()

    def _generate_ips(self, ip, netmask):
        self.addrs = ip_mask_to_list(ip, netmask)



def mp_ping_network(ip, netmask, timeout, processes=4):
    global addresses
    """

    :param ip:
    :param netmask:
    :param timeout:
    :param processes:
    :return:
    """
    addresses = {}
    networks = split_networks(ip, netmask, processes)

    loop = asyncio.get_event_loop()
    executor = ProcessPoolExecutor(max_workers=processes)
    tasks = [loop.run_in_executor(executor, ping_network, network[0], network[1], timeout) for network in networks]
    result = loop.run_until_complete(asyncio.gather(*tasks))
    return result[0]


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
    return [str(addr) for addr in addresses]
    #return list(set([str(addr) for addr in result if addr is not None]))


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
            # return ipaddress.ip_address(result)
            return True
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
            recv_packet = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout / 2)
            offset = ICMP_OFFSET
            icmp_header = recv_packet[offset:offset + 8]

            type, code, checksum, packet_id, sequence = struct.unpack(
                "bbHHh", icmp_header
            )

            if type == ICMP_ECHO_REPLY:
                resp_ip = recv_packet[SRC_IP_OFFSET:SRC_IP_OFFSET + 4]
                addresses.update({ipaddress.ip_address(resp_ip): True})
                # if ipaddress.ip_address(resp_ip) == ipaddress.ip_address(ip):
                #     return ipaddress.ip_address(ip)

            t2 = time.time()
            td = int((t2 - t1) * 1000)
            if td > timeout * 1000 / 2:
                logger.debug(f'recv timed out')
                return False
    except asyncio.TimeoutError:
        #logger.debug(f'recv timed out')
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
