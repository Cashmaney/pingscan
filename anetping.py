import socket
import os
import ipaddress
import asyncio
import logging
import struct
import fcntl
import icmp

from typing import Optional, Tuple

logger = logging.getLogger(__name__)

packet = icmp.build()


async def ping(ip):
    # get socket
    # set socket non block
    # queue writer
    # queue reader?
    try:
        timeout = 5
        sock = await create_connection()
        #asyncio.StreamWriter.write(packet)
        logger.info("socket created")
        packet = icmp.build()
        await send_wrap(sock, ip, packet)
        delay = await receive(sock, timeout)
        sock.close()

        return delay

    except Exception as e:
        logger.error(f'{str(e)}')
        return False

ICMP_MAX_RECV = 1518
ICMP_ECHO_REPLY = 0x00

import time


async def receive(sock, timeout):
    loop = asyncio.get_event_loop()

    try:
        t1 = time.time()
        while True:

            rec_packet = await loop.sock_recv(sock, 1024)
            # time_received = default_timer()
            # if loop.family == socket.AddressFamily.AF_INET:
            #     offset = 20
            # else:
            #     offset = 0
            icmp_offset = 20
            icmp_header = rec_packet[icmp_offset:icmp_offset + 8]

            type, code, checksum, packet_id, sequence = struct.unpack(
                "bbHHh", icmp_header
            )

            if type != ICMP_ECHO_REPLY:
                t2 = time.time()
                td = int((t2 - t1) * 1000)
                if td > 3000:
                    return False
                await asyncio.sleep(0)
                continue


            # if packet_id == id_:
            # data = rec_packet[offset + 8:offset + 8 + struct.calcsize("d")]
            return rec_packet
    except Exception as e:
        return False

    # self.queue.put_nowait((timeReceived, (dataSize + 8), iphSrcIP, \
    #                         icmpSeqNumber, iphTTL))
    # self.queue = asyncio.Queue(loop=self.loop)


def send(sock, dest, future, packet):
    try:
        sock.sendto(packet, dest)

    except Exception as e:
        logger.error(f'{str(e)}')
    finally:
        asyncio.get_event_loop().remove_writer(sock)
        future.set_result(None)

import functools
async def send_wrap(sock, dest, packet):
    try:
        info = await asyncio.get_event_loop().getaddrinfo(dest, 0)
        future = asyncio.get_event_loop().create_future()
        callback = functools.partial(send, sock, info[2][4], future, packet)
        asyncio.get_event_loop().add_writer(sock, callback)
        await future
    except Exception as e:
        logger.error(f'{str(e)}')
        return False


async def create_connection() -> Optional[socket.socket]:
    sock = None
    loop = asyncio.get_event_loop()
    try:
        sock = socket.socket(family=socket.AF_INET,
                             type=socket.SOCK_RAW,
                             proto=socket.IPPROTO_ICMP)
        sock.setblocking(False)
        #if source_ip is not None:
        #sock.bind((socket.gethostname(), socket.SOCK_RAW))
        # reader, writer = await asyncio.open_connection(loop=asyncio.get_event_loop(), sock=sock)
        # return reader, writer
        loop.add_reader(sock.fileno(), receive)
        return sock
    except OSError as e:
        logger.error(f'error while attempting to bind on interface')

def ip_mask_to_list(ip, netmask):
    """ return list of string ip addresses in ip/netmask (including network names and broadcasts) """
    # todo: turn this into a generator
    net = ipaddress.IPv4Network(f'{ip}/{netmask}')
    return [str(addr) for addr in net]


def netping(ip, netmask):
    addrs=ip_mask_to_list(ip,netmask)
    #[print(addr) for addr in addrs]
