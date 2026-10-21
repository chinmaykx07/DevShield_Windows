# Forwarded-traffic probe (stands in for a container or VM).
#
#   forward_probe.py setup   create TUN "fwin" (10.9.7.1/24) and "fwout"
#                            (10.9.6.1/24), enable IPv4 forwarding, and add
#                            198.51.100.1/24 on dstest0 (a "public" net)
#   forward_probe.py probe   write a UDP packet 10.9.7.2 -> 10.9.6.2 into
#                            fwin, as if a container sent it; print
#                            "forwarded" if the kernel routes it out of
#                            fwout within 1 s, else "dropped"
import fcntl
import os
import select
import socket
import struct
import sys

TUNSETIFF, TUNSETPERSIST, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x400454CB, 0x0001, 0x1000


def tun(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    return fd


def addr(name, ip, plen):
    nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    nl.bind((0, 0))
    a = socket.inet_aton(ip)
    rta = lambda k, d: struct.pack("HH", 4 + len(d), k) + d
    p = struct.pack("BBBBI", socket.AF_INET, plen, 0, 0, socket.if_nametoindex(name)) + rta(1, a) + rta(2, a)
    nl.send(struct.pack("IHHII", 16 + len(p), 20, 1 | 4 | 0x400, 1, 0) + p)
    err = struct.unpack("i", nl.recv(4096)[16:20])[0]
    if err:
        raise OSError(-err, os.strerror(-err))


def up(name):
    fcntl.ioctl(socket.socket(), 0x8914, struct.pack("16sH", name.encode(), 0x1 | 0x40))


def checksum(b):
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


if sys.argv[1] == "setup":
    for name, ip in (("fwin", "10.9.7.1"), ("fwout", "10.9.6.1")):
        fd = tun(name)
        fcntl.ioctl(fd, TUNSETPERSIST, 1)
        addr(name, ip, 24)
        up(name)
    addr("dstest0", "198.51.100.1", 24)
    open("/proc/sys/net/ipv4/ip_forward", "w").write("1")
    for f in ("all", "default", "fwin", "fwout"):
        open(f"/proc/sys/net/ipv4/conf/{f}/rp_filter", "w").write("0")
else:
    fin, fout = tun("fwin"), tun("fwout")
    payload = b"forwarded?"
    udp = struct.pack("!HHHH", 40000, 9999, 8 + len(payload), 0) + payload
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                      socket.inet_aton("10.9.7.2"), socket.inet_aton("10.9.6.2"))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    # A TUN link has no carrier until a process attaches, and the first
    # packet right after attaching can be lost; resend a few times. A
    # forward-hook drop still drops every copy.
    result = "dropped"
    for attempt in range(5):
        os.write(fin, hdr + udp)
        ready = select.select([fout], [], [], 0.25)[0]
        while ready:
            if payload in os.read(fout, 2048):
                result = "forwarded"
                break
            ready = select.select([fout], [], [], 0.05)[0]
        if result == "forwarded":
            break
    print(result)
