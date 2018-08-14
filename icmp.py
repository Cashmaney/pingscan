import struct
import collections


ICMPHeader = collections.namedtuple('ICMPHeader', 'type code checksum')

icmp_reply = 0x0

seq = 1


def two_byte_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(buffer):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    :param buffer:
    :return:
    """
    sum = 0
    count_to = (len(buffer) / 2) * 2
    count = 0

    while count < count_to:
        this_val = buffer[count + 1] * 256 + buffer[count]
        sum += this_val
        sum &= 0xffffffff # Necessary?
        count += 2

    if count_to < len(buffer):
        sum += buffer[len(buffer) - 1]
        sum &= 0xffffffff # Necessary?

    sum = (sum >> 16) + (sum & 0xffff)
    sum += sum >> 16
    answer = ~sum
    answer &= 0xffff

    # Swap bytes. Bugger me if I know why.
    # answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def parse(packet: bytes) -> ICMPHeader:
    icmp_header = packet[20:28]
    type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
    return ICMPHeader(type, code, checksum)

def stoi(s):
    return int(s.hex(), 16)

import codecs
def build(seq=1, msg_id=1) -> bytes:
    mtype = 8
    code = 0
    csum = 0
    #msg_id = (msg_id).to_bytes(2, byteorder='little')
    #seq = (seq).to_bytes(2, byteorder='little')
    data = bytes('abcdefghijklmnopqrstuvwabcdefg'.encode())
    msg = struct.pack('BbHHh', mtype, code, csum, msg_id, seq)

    csum = checksum(msg + data)

    header = struct.pack('BbHHh', mtype, code, csum, msg_id, seq)
    packet = header + data
    return packet
