Intro
------------

My attempt at making a ping scanner using python.

Basically I needed a good tool to quickly scan large IP ranges, so I rolled my own.

Packet building is in cython, sending the packets is done with multiprocessing, while receiving and processing is done in async.

At the moment only working on Linux, for IPv4.

Code is probably quite rough around the edges, and while I don't expect it to break dramatically, you could encounter
issues. Feel free to report anything.

Usage
------------
*You need root or CAP_NET_RAW to send pings*

You can scan either a combination of ip/netmask, or a list of networks in shortened form (e.g. '192.168.0.0/24')

``import pingscan``

``pingscan.scan('192.168.0.0', '255.255.255.0')``

OR

``pingscan.scan(['192.168.0.0/24', '192.168.1.0/24', '127.0.0.1'])``

Will return a list of ip addresses that answered the ping - e.g. ['192.168.0.1', '192.168.0.2']


Contributions/Feedback
-----------------------
Feel free to comment, report issues, give feedback or contribute in any way

Feature requests are also welcome


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