# Inside a fresh network namespace: bring up loopback and create a
# persistent TUN interface "dstest0" (10.9.9.1/24). Packets sent to
# 10.9.9.2 leave through it, so they pass the OUTPUT hook like real
# traffic; a locally dropped UDP send returns EPERM. Uses raw rtnetlink
# and ioctls because test machines often lack the ip(8) tool.
import fcntl
import os
import socket
import struct

NLM_F_REQUEST, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL = 1, 4, 0x400, 0x200
RTM_NEWADDR = 20
SIOCSIFFLAGS, IFF_UP, IFF_RUNNING = 0x8914, 0x1, 0x40
TUNSETIFF, TUNSETPERSIST, IFF_TUN, IFF_NO_PI = 0x400454CA, 0x400454CB, 0x0001, 0x1000


def rta(kind, data):
    n = 4 + len(data)
    return struct.pack("HH", n, kind) + data + b"\0" * ((4 - n % 4) % 4)


def netlink(sock, kind, flags, payload):
    sock.send(struct.pack("IHHII", 16 + len(payload), kind, flags | NLM_F_REQUEST | NLM_F_ACK, 1, 0) + payload)
    err = struct.unpack("i", sock.recv(4096)[16:20])[0]
    if err:
        raise OSError(-err, os.strerror(-err))


def up(name):
    fcntl.ioctl(socket.socket(), SIOCSIFFLAGS, struct.pack("16sH", name, IFF_UP | IFF_RUNNING))


up(b"lo")
tun = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(tun, TUNSETIFF, struct.pack("16sH", b"dstest0", IFF_TUN | IFF_NO_PI))
fcntl.ioctl(tun, TUNSETPERSIST, 1)
nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
nl.bind((0, 0))
addr = socket.inet_aton("10.9.9.1")
netlink(nl, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL,
        struct.pack("BBBBI", socket.AF_INET, 24, 0, 0, socket.if_nametoindex("dstest0")) + rta(1, addr) + rta(2, addr))
up(b"dstest0")
