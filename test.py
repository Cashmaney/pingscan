import pytest

from multiping import multi_ping

from utils import *
from aio_ping_scan import *
from icmp import build

import logging

logging.basicConfig(level=logging.DEBUG)


@pytest.fixture(scope='module')
def loop():
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


def test_ip_mask_to_list():
    addrs = ip_mask_to_list('192.168.1.0', '255.255.255.252')
    expected_addrs = ['192.168.1.1', '192.168.1.2']
#    assert addrs == expected_addrs




def test_split_netmask():
    addrs = split_networks('192.168.1.0', '255.255.255.0', 4)
    expected_addrs = [('192.168.1.0','255.255.255.192'),
                      ('192.168.1.64', '255.255.255.192'),
                      ('192.168.1.128', '255.255.255.192'),
                      ('192.168.1.192', '255.255.255.192')]
    assert addrs == expected_addrs


def test_build_icmp():
    result = build(2, 1)
    expected = b'\x08\x00\xf9\xff\x01\x00\x02\x00abcdefghij'
    assert(str(result) == str(expected))


#
# def test_new_ping_single_process(loop):
#     with aio_pinger(3) as p:
#         addrs = p.ping('8.8.8.0', '255.255.255.0')
#         print(f"{len(addrs)} addresses: {addrs}")
#

def test_multiping():
    addrs = ip_mask_to_list('8.8.0.0', '255.255.0.0')
    addrs = list(addrs)[1:-1]
    try:
        result = multi_ping(addrs,
                            timeout=3, retry=0, ignore_lookup_errors=True)
        print(f'{len(result[0])}: {result[0]}')
    except socket.timeout as e:
        print(f'{e}')

def test_new_ping_multi_process(loop):
    addrs = mp_ping('8.8.0.0', '255.255.0.0', 3, 2)
    print(f"{len(addrs)} addresses: {addrs}")