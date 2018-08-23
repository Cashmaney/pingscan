import os, pwd, grp
import ipaddress
import ctypes
import math
from typing import Tuple, List


def ip_mask_to_list(ip, netmask):
    """ return list of string ip addresses in ip/netmask (including network names and broadcasts) """
    # todo: turn this into a generator
    net = ipaddress.IPv4Network(f'{ip}/{netmask}')
    for addr in net:
        yield str(addr)



def split_networks(ip: str, netmask: str, partitions: int =4) -> List[Tuple[str, str]]:
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
    for i in range(4):
        # create new pairs - follow the maths :)
        pairs.append((str(ipaddress.IPv4Address(ip_int + i * (mask_add + 1))), str(ipaddress.IPv4Address(new_mask))))
    return pairs

