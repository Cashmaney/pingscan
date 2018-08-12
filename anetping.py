import socket
import os
import ipaddress
import asyncio
import logging

import icmp

logger = logging.getLogger(__name__)

def ping(ip):
    pass

class ARPRequestProtocol(asyncio.Protocol):

    def __init__(self, ip):
        self.ip = ip
        self.transport = None
        self.src_mac = None
        self.src_ip = None

    def connection_made(self, transport):
        logger.debug('connection made')
        self.transport = transport
        frame = self.arp_request(self.ip)
        transport.write(frame)

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
            interface = pack('256s', sock.getsockname()[0].encode('ascii'))
            info = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, interface)
            self.src_ip = ipaddress.IPv4Address(info[20:24])
            return self.src_ip

    def arp_request(self, ip):
        packet = ARP(tha='00:00:00:00:00:00', tpa=ip,
                     sha=self._get_mac_info(), spa=self._get_ip_info())
        frame = Ethernet(dst_mac='FF:FF:FF:FF:FF:FF',
                         src_mac=self._get_mac_info(),
                         ethertype='ARP',
                         payload=packet.write())
        log.info(frame.info())
        log.info(packet.info())
        return frame.write()



def create_connection():
    exceptions = []
    sock = None
    try:
        sock = socket.socket(family=socket.AF_INET,
                             type=socket.SOCK_RAW,
                             proto=socket.IPPROTO_ICMP)
        sock.setblocking(False)
        sock.bind(('127.0.0.1', socket.SOCK_RAW))
    except OSError as exc:
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
    [ping(addr) for addr in addrs]
