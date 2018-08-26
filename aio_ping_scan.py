import socket
import ipaddress
import asyncio
import logging
import struct
import time
from concurrent.futures import ProcessPoolExecutor
from utils import split_networks, ip_mask_to_list
from icmp import build

import multiprocessing
import icmp
from typing import Union, List

logger = logging.getLogger(__name__)

sender_id = 1
seq = 1



addresses = {}

address_queue = multiprocessing.Queue()


class TimeOutError(Exception):
    pass


def mp_ping(ip, network, timeout, processes=4):

    networks = split_networks(ip, network, processes)

    tasks = []
    pingers = []
    for network in networks:
        pingers.append(aio_pinger())
        # (loop.run_in_executor(executor, , ))
        task = multiprocessing.Process(target=pingers[len(pingers) - 1].ping, args=(network[0], network[1], timeout))
        tasks.append(task)
        task.start()

    for task in tasks:
        task.join()

    results = {}
    while not address_queue.empty():
        results.update({address_queue.get():True})
    # result = loop.run_until_complete(asyncio.gather(*tasks))
    return results


class aio_pinger(object):
    """
    pinger class - we're using a class here because it's the easy to store shared values and duplicate them
    e.g in case we wanted to use multiprocessing
    """
    ICMP_MAX_SIZE = 130

    def __init__(self, loop=asyncio.get_event_loop()):
        self.done_sending = False
        self.loop = loop
        self.timeout = 0
        self.logger = logging.getLogger(__class__.__name__)
        self.queue = asyncio.Queue()
        self.sequence = 1
        self.message_id = 1
        self.addrs = []
        self.addresses = {}
        self.start_time = None
        self.rsock = self._create_socket()
        self.ssock = self._create_socket()
        self.done_sending_time = None
        self.done_receiving = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()

    def _cleanup(self):
        self.rsock.close()
        self.ssock.close()

    def ping(self, ip: str, network: str, timeout=5) -> List[str]:
        self.timeout = timeout
        t1 = time.time()
        self.logger.debug("started to calculate IPs...")
        self._generate_ips(ip, network)
        self.logger.debug(f"done [{int((time.time() - t1) * 1000 * 1000)}us]")
        self.start_time = time.time()

        try:
            self.loop = asyncio.get_event_loop()
            tasks = [asyncio.ensure_future(self._recv()),
                     asyncio.ensure_future(self._send_ping_network()),
                     asyncio.ensure_future(self._process())]
            self.loop.run_until_complete(asyncio.gather(*tasks))

            return [address_queue.put(str(addr)) for addr in self.addresses]
        finally:
            self._cleanup()

    @staticmethod
    def _create_socket():
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10485760)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 10485760)
        sock.setblocking(False)
        return sock

    async def _recv(self):
        """
        Async recv function. Will try to receive until the sender method is done, then will receive until timeout is done.
        Note: we're trying to receive from a raw socket, so even if we use multiple listeners they will wake on the
        same packets
        :return:
        """
        try:
            while True:
                try:
                    self.logger.debug("listening...")
                    # receive a packet or wait till we timeout (will throw an asyncio.TimeoutError after self.timeout)
                    recv_packet = await asyncio.wait_for(self.loop.sock_recv(self.rsock, self.ICMP_MAX_SIZE),
                                                         self.timeout / 2)
                except asyncio.TimeoutError:
                    self.logger.debug(f'recv timed out')
                    if self.done_sending:
                        self.logger.debug("Done sending & timeout")
                        self.done_receiving = True
                        raise asyncio.TimeoutError
                    else:
                        self.logger.debug("Timeout but not done sending.. retrying")
                        continue

                self.logger.debug("Got packet, enqueuing")

                # enqueue the received packet (parsing it will be done elsewhere)
                self.queue.put_nowait(recv_packet)

                if self.done_sending:

                    # after handling the packet check if we timed out already
                    td = int((time.time() - self.done_sending_time) * 1000)

                    # timeout is divided by 2 here and in the recv because in the worst case we will be waiting twice
                    if td > self.timeout * 1000 / 2:
                        # self.logger.debug(f'recv timed out')
                        self.done_receiving = True
                        return

        except asyncio.TimeoutError:
            self.logger.debug(f'recv timed out')
            return

    async def _process(self):
        try:
            while True:
                try:
                    packet = await asyncio.wait_for(self.queue.get(), self.timeout / 3)
                except asyncio.TimeoutError:
                    # if recv isn't done yet, just keep trying to get from the queue
                    if self.done_receiving:
                        # if queue isn't empty yet we're not done
                        if self.queue.empty():
                            # queue empty, recv done & queue.get timeout -> processing packets is done
                            self.logger.debug("Done with recv & timeout")
                            return
                        continue
                    else:
                        self.logger.debug("Timeout but not done sending. Retrying")
                        continue
                self.logger.debug("Receiver took packet from queue...")

                if icmp.is_icmp_reply(packet):
                    resp_ip = icmp.src_ip_from_packet(packet)
                    self.logger.debug(f"packet is icmp reply. adding to list - {resp_ip}")
                    self.addresses.update({ipaddress.ip_address(resp_ip): True})

                # after handling the packet pass the execution back to the recv/send
                await asyncio.sleep(0)
        except Exception as e:
            self.logger.error(f'{str(e)}')
            return

    def _send(self, sock, dest, packet):
        try:
            sock.sendto(packet, (dest, 0))
        except PermissionError:
            self.logger.warning("Permission error: Are you root? Are you trying to send a ping to an invalid address?")
            pass

    async def _send_ping_network(self):
        """ ping all addresses stored in self.addrs"""
        t1 = time.time()
        self.logger.debug(f"starting sending...")
        counter = 0
        try:
            for addr in self.addrs:
                self.sequence = pkt_seq = (self.sequence + 1) % (icmp.ICMP_MAX_SEQUENCE + 1)

                packet = build(pkt_seq, sender_id)
                self.loop.call_soon(self._send, self.ssock, addr, packet)
                counter = counter + 1
                # not sure if this does anything, but sure
                if counter % 1024 == 0:
                    await asyncio.sleep(0)
        finally:
            self.logger.debug(f"done sending! [{int((time.time() - t1) * 1000)}ms]")
            self.done_sending = True
            self.done_sending_time = time.time()

    def _generate_ips(self, ip: str, netmask: str) -> None:
        """ convert an ip/subnetmask pair to a list of discrete addresses"""
        self.addrs = ip_mask_to_list(ip, netmask)
