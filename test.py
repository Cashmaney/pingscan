import pytest

import asyncio

from anetping import netping, ip_mask_to_list, ping
from icmp import build

import logging

logging.basicConfig(level=logging.DEBUG)


def test_ip_mask_to_list():
    addrs = ip_mask_to_list('192.168.1.0', '255.255.255.252')
    expected_addrs = ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
    assert addrs == expected_addrs


def test_ping():
    active = netping('192.168.1.0', '255.255.255.0')
    print(active)
    assert active is None


def test_sync_ping():
    asyncio.set_event_loop(asyncio.new_event_loop())
    tasks = []
    loop = asyncio.get_event_loop()
    tasks = [asyncio.ensure_future(ping_test(ip)) for ip in ip_mask_to_list('192.168.1.0', '255.255.255.252')]
    result = loop.run_until_complete(asyncio.gather(*tasks))
    loop.close()

async def ping_test(ip):
    res = build()
    return await ping(ip)

    #assert False