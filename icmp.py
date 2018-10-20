import struct
import collections
from cy_src.c_icmp import build as cbuild

from typing import Union

ICMPHeader = collections.namedtuple('ICMPHeader', 'type code checksum')

ICMP_ECHO_REPLY = 0
ICMP_OFFSET_V4 = 20
SRC_IP_OFFSET_v4 = 12
ICMP_NETWORK_UNREACH = 3
ICMP_MAX_SEQUENCE = 65535
IPv4 = 0
IPv6 = 1

offset = ICMP_OFFSET_V4
offset_src_ip = SRC_IP_OFFSET_v4

def parse(packet: bytes) -> ICMPHeader:
    icmp_header = packet[20:28]
    type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    return ICMPHeader(type, code, checksum)


def build(seq=1, msg_id=1) -> bytes:
    packet = cbuild(seq, msg_id)
    return bytes(packet)


def src_ip_from_packet(packet: memoryview, family: int=IPv4) -> int:
    # if family == IPv4:

    resp_ip = int().from_bytes(packet[offset_src_ip:offset_src_ip + 4], byteorder='little')
    return resp_ip


def is_icmp_reply(packet: memoryview, family: int=IPv4) -> bool:
    # if family == IPv4:

    # icmp type
    if packet[offset] == ICMP_ECHO_REPLY:
        return True
    else:
        return False