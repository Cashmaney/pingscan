import pytest

import asyncio

from anetping import *
from icmp import build

import logging

logging.basicConfig(level=logging.DEBUG)


def test_ip_mask_to_list():
    addrs = ip_mask_to_list('192.168.1.0', '255.255.255.252')
    expected_addrs = ['192.168.1.1', '192.168.1.2']
    assert addrs == expected_addrs


def test_ping():
    active = netping('192.168.1.0', '255.255.255.0')
    print(active)
    assert active is None


def test_sync_ping():
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    print(ping_network('10.0.0.0', '255.255.255.0', 1))
    loop.close()

async def ping_test(ip):
    return await ping(ip)

    #assert False