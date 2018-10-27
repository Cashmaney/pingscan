import asyncio
import logging
import time
from utils import split_networks, _generate_ips, _send, get_eventloop, get_socket, host_count
from icmp import build

import multiprocessing
import icmp
from multiprocessing import Value

from typing import Callable, Union

import socket

logger = logging.getLogger(__name__)


ICMP_MAX_SIZE = 150
sender_id = 1
seq = 1


# timeout > 0 just so everything won't timeout immediately
def ping(ip, network='255.255.255.255', *, timeout=0.01, workers=4):
    """ main method for ping scanning """

    with get_eventloop() as loop:
        result = AsyncPinger(loop=loop).ping(ip, network, timeout, workers)

    return result


class AsyncPinger:
    """
    pinger class - we're using a class here because it's the easy to store shared values and duplicate them
    e.g in case we wanted to use multiprocessing
    """

    def __init__(self, loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()) -> None:
        self.done_sending = False
        self.loop = loop
        self.timeout = 0
        self.logger = logging.getLogger(__class__.__name__)
        self.queue = asyncio.Queue()
        self.addresses = {}
        self.num_of_hosts = 0
        self.start_time = None
        self.worker_processes = 1
        self.rsock = None
        self.send_done_count = Value('i', 0)

    def ping(self, ip: str, network: str = '255.255.255.255', timeout: Union[int, float] = 5, workers: int = 4) -> dict:
        self.timeout = timeout
        self.worker_processes = workers

        self.num_of_hosts = host_count(ip, network)

        self.loop.call_soon(self.send, ip, network)

        tasks = list()
        with get_socket() as self.rsock:
            tasks.append(asyncio.ensure_future(self.recv()))
            tasks.append(asyncio.ensure_future(self.process()))

            self.loop.run_until_complete(asyncio.gather(*tasks))

        return self.fetch_result()

    async def process(self):
        """ responsible for removing packets from the queue and processing them. End condition is when the queue is
         empty and timeout has passed """
        while True:
            try:

                packet = await asyncio.wait_for(self.queue.get(), self.timeout / 10)

            except asyncio.TimeoutError:
                # if queue isn't empty yet we're not done
                if self.queue.empty() and self._is_timeout():
                    # queue empty, recv done & queue.get timeout -> processing packets is done
                    return
                continue

            self.process_packet(packet, self._process_callback)

    async def recv(self):
        """
        Async recv function. Will try to receive until the sender method is done, then will receive until timeout is done.
        Note: we're trying to receive from a raw socket, so even if we use multiple listeners they will wake on the
        same packets

        """
        # need to make the buffer big enough to guard against overflow
        bufsiz = self.num_of_hosts * ICMP_MAX_SIZE * 2
        bytebuff = bytearray(bufsiz)
        pos = 0
        while True:
            try:
                memview = memoryview(bytebuff)[pos:pos + ICMP_MAX_SIZE]

                read = await asyncio.wait_for(self.loop.sock_recv_into(self.rsock, memview),
                                               self.timeout / 100)

                pos += read
                pos = pos % bufsiz

            except asyncio.TimeoutError:
                if self._is_timeout():
                    return
                continue

            # self.logger.error(f"Got packet {time.time()-self.start_time}, enqueuing")
            # enqueue the received packet (parsing it will be done elsewhere)
            self.queue.put_nowait(memview)

            if self._is_timeout():
                return
            continue

    def _process_callback(self, ip: str):
        self.addresses.update({ip: True})

    def fetch_result(self) -> dict:
        return self.addresses

    @staticmethod
    def process_packet(packet: memoryview, addr_handle_callback: Callable) -> None:
        """ Checks if a packet is ICMP reply, and records the sender address if it is. We use a callback here
        for handling of ip address even though it is probably a tiny bit more overhead to make it easier to understand
        the flow of the code """
        if icmp.is_icmp_reply(packet):
            resp_ip = icmp.src_ip_from_packet(packet)
            # self.logger.debug(f"packet is icmp reply. adding to list - {resp_ip}")
            addr_handle_callback(resp_ip)

    def _check_done_sending(self) -> bool:
        # self.logger.debug(f"Evaluating end of send: {self.send_done_count} =? {self.worker_processes}")
        return self.send_done_count.value == self.worker_processes

    def _is_timeout(self) -> bool:
        if self._check_done_sending():
            if not self.start_time:
                self.start_time = time.time()

            td = int((time.time() - self.start_time) * 1000)

            # self.logger.debug(f"Evaluating timeout: {td} vs {self.timeout * 1000 * 99 / 100}")
            return td > self.timeout * 1000 * 99 / 100

    def send(self, ip: str, network: str):
        networks = split_networks(ip, network, self.worker_processes)
        for network in networks:
            process = multiprocessing.Process(target=send_multiple,
                                              args=(self.send_done_count, network[0], network[1]))
            process.start()


def send_multiple(send_done_count: multiprocessing.Value, ip: str, network: str = '255.255.255.255'):
    """ ping all addresses stored in self.addrs"""
    t1 = time.time()
    logger.debug("started to calculate IPs...")
    addrs = _generate_ips(ip, network)
    logger.debug(f"done [{int((time.time() - t1) * 1000 * 1000)}us]")

    logger.debug(f"starting sending...")
    counter = 0
    pkt_seq = 0
    with get_socket() as ssock:
        try:
            for addr in addrs:
                pkt_seq = (pkt_seq + 1) % (icmp.ICMP_MAX_SEQUENCE + 1)

                packet = build(pkt_seq, sender_id)
                _send(ssock, str(addr), packet)
                counter = counter + 1
        except ValueError:
            logger.warning("Invalid IP Address/Mask")
        finally:
            logger.debug(f"done sending! [{int((time.time() - t1) * 1000)}ms]")
            send_done_count.value += 1
