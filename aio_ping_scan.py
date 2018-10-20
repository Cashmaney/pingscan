import ipaddress
import asyncio
import logging
import time
from functools import reduce
from utils import split_networks, ip_mask_to_list, _create_socket, _generate_ips
from icmp import build

import multiprocessing
import icmp
from typing import Union, List, Generator

logger = logging.getLogger(__name__)


ICMP_MAX_SIZE = 130

sender_id = 1
seq = 1

addresses = {}


class TimeOutError(Exception):
    pass


def mp_ping(ip, network='255.255.255.255', *, timeout, workers=4):

    networks = split_networks(ip, network, workers)

    workers = []
    pingers = []
    loops = []

    # toggle for no_recv in ping method
    no_recv = False

    recv_pipe, send_pipe = multiprocessing.Pipe(False)

    for network in networks:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        pingers.append(aio_pinger(loop=asyncio.get_event_loop()))
        # run the ping once for each of the split networks, also call no_recv with False only once
        # - we run the recv/process function once because we don't need 4 of them.
        # this is because listening on multiple receivers isn't effective for raw sockets - they just receive the same
        # data

        worker = multiprocessing.Process(target=pingers[len(pingers) - 1].ping,
                                       args=(send_pipe, network[0], network[1], timeout, no_recv))
        workers.append(worker)
        worker.start()
        no_recv = True

    for worker in workers:
        worker.join()

    # while not address_queue.empty():
    #     results.update({address_queue.get(): True})
    results = recv_pipe.recv()

    for loop in loops:
        loop.close()
    # result = loop.run_until_complete(asyncio.gather(*tasks))
    return results


class aio_pinger:
    """
    pinger class - we're using a class here because it's the easy to store shared values and duplicate them
    e.g in case we wanted to use multiprocessing
    """

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
        self.rsock = _create_socket()
        self.ssock = _create_socket()
        self.done_sending_time = None
        self.done_receiving = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._cleanup()

    def _cleanup(self):
        self.rsock.close()
        self.ssock.close()

    def ping(self, return_pipe, ip: str, network: str = '255.255.255.255', timeout=5, no_recv=False) -> None:
        self.timeout = timeout
        self.start_time = time.time()

        tasks = [asyncio.ensure_future(self.send_multiple(ip, network))]

        if not no_recv:
            tasks.append(asyncio.ensure_future(self._recv()))
            tasks.append(asyncio.ensure_future(self._process()))

        self.loop.run_until_complete(asyncio.gather(*tasks))
        self._cleanup()
        if not no_recv:
            return_pipe.send(len(self.addresses))

    async def _recv(self):
        """
        Async recv function. Will try to receive until the sender method is done, then will receive until timeout is done.
        Note: we're trying to receive from a raw socket, so even if we use multiple listeners they will wake on the
        same packets

        # honestly this is kind of unreliable... Need to rework it

        :return:
        """
        bytebuff = bytearray(65535*130)
        sofar = 0
        try:
            start_time = time.time()
            while True:
                try:
                    # self.logger.debug("listening...")
                    # receive a packet or wait till we timeout (will throw an asyncio.TimeoutError after self.timeout)
                    # recv_packet = await asyncio.wait_for(self.loop.sock_recv(self.rsock, self.ICMP_MAX_SIZE),
                    #                                      self.timeout / 2)
                    memview = memoryview(bytebuff)[sofar:sofar+ICMP_MAX_SIZE]

                    nread = await asyncio.wait_for(self.loop.sock_recv_into(self.rsock, memview),
                                                   self.timeout / 10)

                    sofar += nread

                except asyncio.TimeoutError:

                    td = int((time.time() - start_time) * 1000)

                    self.logger.debug(f"Evaluating timeout: {td} vs {self.timeout * 500}")
                    if td > self.timeout * 1000 * 9 / 10:
                        return

                    self.logger.debug("Timeout but not done sending.. retrying")
                    continue

                self.logger.error(f"Got packet {time.time()-self.start_time}, enqueuing")

                # enqueue the received packet (parsing it will be done elsewhere)
                self.queue.put_nowait(memview)

                # after handling the packet check if we timed out already
                td = int((time.time() - start_time) * 1000)
                # timeout is divided by 2 here and in the recv because in the worst case we will be waiting twice
                if td > self.timeout * 1000:
                    return

        except asyncio.TimeoutError:
            self.logger.debug(f'recv timed out')
            return

        finally:
            self.done_receiving = True

    async def _process(self):
        try:
            start_time = time.time()
            while True:
                try:
                    packet = await asyncio.wait_for(self.queue.get(), self.timeout / 10)
                except asyncio.TimeoutError:
                    # if recv isn't done yet, just keep trying to get from the queue
                    if self.done_receiving:
                        # if queue isn't empty yet we're not done
                        if self.queue.empty():
                            # queue empty, recv done & queue.get timeout -> processing packets is done
                            # self.logger.debug("Done with recv & timeut")
                            return
                        # self.logger.debug("Timeout but not done sending. Retrying")
                    continue
                # self.logger.debug("Receiver took packet from queue...")
                # t1 = time.time()
                if icmp.is_icmp_reply(packet):
                    resp_ip = icmp.src_ip_from_packet(packet)
                    # self.logger.debug(f"packet is icmp reply. adding to list - {resp_ip}")
                    self.addresses.update({resp_ip: True})

        except Exception as e:
            self.logger.error(f'{str(e)}')
            return

    def _send(self, sock, dest, packet):
        try:
            sock.sendto(packet, (dest, 0))
        except PermissionError:
            self.logger.warning("Permission error: Are you root? Are you trying to send a ping to an invalid address?")
        except OSError as e:
            self.logger.error(f"Error while sending to {dest}, probably some socket error: {packet}, {sock}: {e}")

    async def send_multiple(self, ip: str, network: str = '255.255.255.255'):
        """ ping all addresses stored in self.addrs"""
        t1 = time.time()
        self.logger.debug("started to calculate IPs...")
        addrs = _generate_ips(ip, network)
        self.logger.debug(f"done [{int((time.time() - t1) * 1000 * 1000)}us]")

        self.logger.debug(f"starting sending...")
        counter = 0
        try:
            for addr in addrs:
                self.sequence = pkt_seq = (self.sequence + 1) % (icmp.ICMP_MAX_SEQUENCE + 1)

                packet = build(pkt_seq, sender_id)
                self.loop.call_soon(self._send, self.ssock, str(addr), packet)
                counter = counter + 1
                # not sure if this does anything, but sure
                if counter % 1024 == 0:
                    await asyncio.sleep(0)
        except ValueError:
            self.logger.warning("Invalid IP Address/Mask")
        finally:
            self.logger.debug(f"done sending! [{int((time.time() - t1) * 1000)}ms]")
            self.done_sending = True
            self.done_sending_time = time.time()
