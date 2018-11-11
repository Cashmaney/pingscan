Intro
------------

My attempt at making a ping scanner using python.

Basically I needed a good tool to quickly scan large IP ranges, so I rolled my own.

Packet building is in cython, sending the packets is done with multiprocessing, while receiving and processing is done in async.

** Only working on Linux, for IPv4

Usage
------------
*You need root or CAP_NET_RAW to send pings*

``import netscan``

``netscan.scan('192.168.0.0', '255.255.255.0')``

Will return a list of ip addresses that answered the ping - e.g. ['192.168.0.1', '192.168.0.2']


Contributions/Feedback
-----------------------
Feel free to comment, report issues or any feedback or contribute in any way


Performance Tuning
--------------------
Some generic commands in case you run into trouble with linux sockets and the netstack

Increasing socket read and write memory:

``sysctl -w net.core.wmem_max=134217728``
``sysctl -w net.core.rmem_max=134217728``

If you're going for a large local segment with > 256 hosts you may need to configure this (so you ARP table doesn't fill up)
(feel free to play with these values)

``net.ipv4.neigh.default.gc_thresh1 = 4096``
``net.ipv4.neigh.default.gc_thresh2 = 8192``
``net.ipv4.neigh.default.gc_thresh3 = 65535``