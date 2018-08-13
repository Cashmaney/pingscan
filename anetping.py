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
        (rd, wr) = await create_connection()
        #asyncio.StreamWriter.write(packet)
        await wr.write(packet)
        print("open")
    except Exception as e:
        logger.error(f'{str(e)}')


class PingTestProtocol(asyncio.Protocol):

    def __init__(self, ip):
        self.ip = ip
        self.transport = None
        self.src_mac = None
        self.src_ip = None

    def connection_made(self, transport):
        logger.debug('connection made')
        self.transport = transport
        packet = self.icmp_echo_request(self.ip)
        transport.write(packet)

    def connection_lost(self, exc):
        logger.debug('connection lost')
        # self.loop.stop()

    def pause_writing(self):
        pass

    def resume_writing(self):
        pass

    def data_received(self, data):
        header = icmp.parse(data)
        # skip frame unless ARP
        if header.type == icmp.icmp_reply:
            # We are done: close the transport (it will call connection_lost())
            self.transport.close()

    def eof_received(self):
        return False

    def _get_mac_info(self):
        """Return the MAC address of the interface. The result is cached for
        subsequent access.
        """
        if self.src_mac is not None:
            return self.src_mac
        else:
            sock = self.transport._sock
            interface = pack('256s', sock.getsockname()[0].encode('ascii'))
            info = fcntl.ioctl(sock.fileno(), SIOCSIFHWADDR, interface)
            self.src_mac = macaddress.MACAddress(info[18:24])
            return self.src_mac

    def _get_ip_info(self):
        """Return the IP address of the interface. The result is cached for
        subsequent access.
        """
        if self.src_ip is not None:
            return self.src_ip
        else:
            sock = self.transport._sock
            interface = struct.pack('256s', sock.getsockname()[0].encode('ascii'))
            info = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, interface)
            self.src_ip = ipaddress.IPv4Address(info[20:24])
            return self.src_ip

    def icmp_echo_request(self, ip):
        packet = icmp.build()
        return packet


ICMP_MAX_RECV = 100


def receive(socket):
    recPacket, ancdata, flags, addr = socket.recvmsg(ICMP_MAX_RECV)
    # self.queue.put_nowait((timeReceived, (dataSize + 8), iphSrcIP, \
    #                         icmpSeqNumber, iphTTL))
    # self.queue = asyncio.Queue(loop=self.loop)


def send(socket, dest, packet):
    socket.sendto(packet, (dest, 0))


async def create_connection() -> None:
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
    except OSError as e:
        logger.error(f'error while attempting to bind on interface')
    finally:
        if sock is not None:
            sock.close()


def ip_mask_to_list(ip, netmask):
    """ return list of string ip addresses in ip/netmask (including network names and broadcasts) """
    # todo: turn this into a generator
    net = ipaddress.IPv4Network(f'{ip}/{netmask}')
    return [str(addr) for addr in net]


def netping(ip, netmask):
    addrs=ip_mask_to_list(ip,netmask)
    #[print(addr) for addr in addrs]
