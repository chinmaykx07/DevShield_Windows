# Inbound-reply probe: does this machine's answer to a connection someone
# else opened leave?
#
#   reply_probe.py PORT   listen on TCP PORT, write a SYN from 10.9.9.2 to
#                         10.9.9.1:PORT into dstest0 (as if a remote host
#                         connected in), and print "replied" if the
#                         kernel's SYN-ACK comes back out of dstest0 within
#                         about 1 s, else "dropped"
import fcntl
import os
import select
import socket
import struct
import sys

TUNSETIFF, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x0001, 0x1000
port = int(sys.argv[1])


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


ls = socket.socket()
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("0.0.0.0", port))
ls.listen(5)

fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", b"dstest0", IFF_TUN | IFF_NO_PI))
src, dst = socket.inet_aton("10.9.9.2"), socket.inet_aton("10.9.9.1")


def syn(sport):
    tcp = struct.pack("!HHIIBBHHH", sport, port, 1000, 0, 5 << 4, 0x02, 64240, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
    return ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:] + tcp


def is_synack(pkt):
    if len(pkt) < 40 or pkt[9] != 6 or pkt[12:16] != dst:
        return False
    ihl = (pkt[0] & 0x0F) * 4
    sp = struct.unpack("!H", pkt[ihl:ihl + 2])[0]
    return sp == port and pkt[ihl + 13] & 0x12 == 0x12


# A TUN link can lose the first packet right after a process attaches;
# resend (from a new source port each time). An output-hook drop drops
# every SYN-ACK.
result = "dropped"
for attempt in range(5):
    os.write(fd, syn(41000 + attempt))
    ready = select.select([fd], [], [], 0.25)[0]
    while ready:
        if is_synack(os.read(fd, 2048)):
            result = "replied"
            break
        ready = select.select([fd], [], [], 0.05)[0]
    if result == "replied":
        break
print(result)
