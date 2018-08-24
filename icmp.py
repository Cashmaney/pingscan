import struct
import collections
from cy_src.c_icmp import build as cbuild

from typing import Union

ICMPHeader = collections.namedtuple('ICMPHeader', 'type code checksum')

ICMP_ECHO_REPLY = 0
ICMP_OFFSET_V4 = 20
SRC_IP_OFFSET_v4 = 12
ICMP_NETWORK_UNREACH = 3
IPv4 = 0
IPv6 = 1

def parse(packet: bytes) -> ICMPHeader:
    icmp_header = packet[20:28]
    type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    return ICMPHeader(type, code, checksum)


def build(seq=1, msg_id=1) -> bytes:
    packet = cbuild(seq, msg_id)
    return bytes(packet)


def src_ip_from_packet(packet: bytes, family: int=IPv4) -> bytes:
    # if family == IPv4:
    offset = SRC_IP_OFFSET_v4
    resp_ip = packet[offset:offset + 4]
    return resp_ip


def is_icmp_reply(packet: bytes, family: int=IPv4) -> bool:
    # if family == IPv4:
    offset = ICMP_OFFSET_V4
    icmp_header = packet[offset:offset + 8]

    icmp_type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

    if icmp_type == ICMP_ECHO_REPLY:
        return True
    else:
        return False