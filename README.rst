Intro
------------

My attempt at making a ping scanner using python.

Why you ask? (There must be a better language to use!) -- because there didn't seem to be a good tool out there, and I
figured it would be a good learning experience.

Packet building is in cython, scanning is done in multiprocessing using async scans.

** If you're reading this the code is highly unstable, not recommended in production, and not optimized **

** Since I wrote this I found multiping. My version is slightly faster, but less reliable at the moment.

Performance
------------
Currently sucks, but can do a /16 segment (65535 addresses) in about 6 seconds, depending on your internet connection.
Assuming this scales linearly (spoiler: it doesn't), this means scanning a /8 in ~20 minutes, and the entire v4 address
space in about 3 days.

TODO
------------
Planning to add a tcp/udp scanner

RARP function

Others
