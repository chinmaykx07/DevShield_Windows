# Test processes for the live test. One file, several roles:
#
#   fixtures.py server DIR        TCP sink on 127.0.0.1:9000/9001; byte counts in DIR/rx<port>
#   fixtures.py agent DIR         the fake agent: re-execs itself under its agent name
#   fixtures.py probe [UID]       one UDP send out of dstest0: prints ok or EPERM
#   fixtures.py catalog SRC DST   write a catalog with the test agent added
#
# The agent's name is assembled here at run time and never written in any
# file or command line of the harness, so the harness's own shells can
# never look like the agent (that happened once with an ad-hoc test).
import json
import os
import socket
import subprocess
import sys
import threading
import time

AGENT = "-".join(["dsl", "test", "agent"])


def server(d):
    def serve(port):
        ls = socket.socket()
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", port))
        ls.listen(50)
        total, lock = 0, threading.Lock()

        def handle(c):
            nonlocal total
            while True:
                b = c.recv(4096)
                if not b:
                    return
                with lock:
                    total += len(b)
                    with open(f"{d}/rx{port}", "w") as f:
                        f.write(str(total))

        while True:
            c, _ = ls.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    for p in (9000, 9001):
        threading.Thread(target=serve, args=(p,), daemon=True).start()
    threading.Event().wait()


def udp_ok():
    try:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("10.9.9.2", 9999))
        return "udp ok"
    except PermissionError:
        return "udp EPERM"


def worker(d, role, hold):
    """Loop: keep one connection, open new ones, send UDP out of dstest0."""
    log = open(f"{d}/{role}.log", "a", buffering=1)
    held = socket.create_connection(("127.0.0.1", 9000)) if hold else None
    while True:
        if held:
            try:
                held.send(b"held\n")
            except OSError as e:
                log.write(f"held {e}\n")
        try:
            c = socket.create_connection(("127.0.0.1", 9001), timeout=0.5)
            c.send(b"new\n")
            c.close()
            log.write("conn ok\n")
        except OSError as e:
            log.write(f"conn FAIL {e}\n")
        log.write(udp_ok() + "\n")
        time.sleep(0.3)


def main():
    role = sys.argv[1]
    if role == "server":
        server(sys.argv[2])
    elif role == "agent":  # re-exec under the agent name
        os.execv(sys.executable, [sys.executable, __file__, "run", sys.argv[2], AGENT])
    elif role == "run":
        d = sys.argv[2]
        if sys.argv[3] == AGENT:
            # A child that is part of the agent (its name matches) and a
            # neutral helper that Agent Watch does not identify.
            kids = [subprocess.Popen([sys.executable, __file__, "run", d, AGENT + "-child"]),
                    subprocess.Popen([sys.executable, __file__, "helper", d])]
            with open(f"{d}/kids.pid", "w") as f:
                f.write(" ".join(str(k.pid) for k in kids))
            worker(d, "agent", hold=True)
        else:
            worker(d, "child", hold=False)
    elif role == "helper":
        worker(sys.argv[2], "helper", hold=False)
    elif role == "probe":
        if len(sys.argv) > 2:
            os.setgid(65534)
            os.setuid(int(sys.argv[2]))
        print(udp_ok().split()[1])
    elif role == "catalog":
        c = json.load(open(sys.argv[2]))
        c["agents"].append({"name": "Live Test Agent", "vendor": "test", "kind": "cli", "cmdline_patterns": [AGENT]})
        json.dump(c, open(sys.argv[3], "w"))


main()
