import pytest

from anetping import netping, ip_mask_to_list


def test_ip_mask_to_list():
    addrs = ip_mask_to_list('192.168.1.0', '255.255.255.252')
    expected_addrs = ['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
    assert addrs == expected_addrs

def test_ping():
    active = netping('192.168.1.0', '255.255.255.0')
    print(active)
    assert active is not None
