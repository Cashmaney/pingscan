import ipaddress
import ctypes
import math
import socket
import logging
import asyncio
from typing import Tuple, List, Generator
from contextlib import contextmanager

SOCK_BUFSIZ = 134217728

logger = logging.getLogger(__name__)


def _generate_ips(ip: str, netmask: str) -> Generator[str, str, str]:
    """ convert an ip/subnetmask pair to a list of discrete addresses"""
    return ip_mask_to_list(ip, netmask)


def _create_socket():
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCK_BUFSIZ)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCK_BUFSIZ)
    sock.setblocking(False)
    return sock


def ip_mask_to_list(ip, netmask):
    """ return list of string ip addresses in ip/netmask (including network names and broadcasts)
    :except ValueError: Invalid IP or Netmask"""
    net = ipaddress.IPv4Network(f'{ip}/{netmask}')
    return net.hosts()


def split_networks(ip: str, netmask: str, partitions: int = 4) -> List[Tuple[str, str]]:
    """
    split an IPv4 network into a ip/mask into a number partitions.
    make sure that partitions is a power of 2

    :param ip: ip address in 4 octet string
    :param netmask: subnet mask in 4 octet string
    :param partitions: number of subnetworks to create
    :return: pairs of ip/subnet masks
    """

    # convert ip string to int so we can perform calculations
    ip_int = int(ipaddress.IPv4Address(ip))

    # number of times we need to shift the subnet mask
    shr = int(math.log(partitions, 2))

    # convert subnet mask string to int so we can perform calculations
    int_addr = int(ipaddress.IPv4Address(netmask))

    # shift the inverse of the subnet mask (easier to shift) -
    # we're shifting the mask (use ctypes so we only use 32 bit values)
    mask_add = ctypes.c_uint32(~int_addr).value >> shr

    # convert the shifted value back to a subnet value (1's followed by 0's)
    new_mask = ipaddress.IPv4Address(ctypes.c_uint32(~mask_add).value)

    pairs = []
    for i in range(partitions):
        # create new pairs - follow the maths :)
        pairs.append((str(ipaddress.IPv4Address(ip_int + i * (mask_add + 1))), str(ipaddress.IPv4Address(new_mask))))
    return pairs

@contextmanager
def get_eventloop():
    # Code to acquire resource, e.g.:
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    try:
        yield _loop
    finally:
        # Code to release resource, e.g.:
        _loop.close()


@contextmanager
def get_socket():
    # Code to acquire resource, e.g.:
    _socket = _create_socket()
    try:
        yield _socket
    finally:
        # Code to release resource, e.g.:
        _socket.close()


def _send(sock: socket.socket, dest: str, packet: bytes):
    try:
        sock.sendto(packet, (dest, 0))
    except PermissionError:
        logger.warning("Permission error: Are you root? Are you trying to send a ping to an invalid address?")
    except OSError as e:
        logger.error(f"Error while sending to {dest}, probably some socket error: {packet}, {sock}: {e}")