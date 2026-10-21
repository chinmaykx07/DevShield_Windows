# Live tests: Linux network controls

`run.sh` tests real-user authorization, the telemetry sinkhole on the real
resolver (a private bind-mounted copy of `/etc/hosts`),
`devshield block/unblock/allow/lockdown/egress-restore` (including forwarded
container/VM traffic, via `forward_probe.py`), `restore-all`
(`restore_all.sh`) and the network monitor (`netwatch.sh`) against
the **real** kernel, nftables and daemon. It runs inside throwaway network
and mount namespaces, so the host's own network is never touched.

```bash
sudo test/linux-live/run.sh                 # builds devshield, runs everything
sudo test/linux-live/run.sh ./devshield     # or test an existing binary
```

It needs root, `nft`, `unshare`, `python3`, `/dev/net/tun` and cgroup v2
support. Every scenario runs twice: once on a freshly mounted cgroup2
hierarchy, and once on the host's own layout (unified, or "hybrid" at
`/sys/fs/cgroup/unified`) if it has one. Each check prints PASS or FAIL. A
failed check also prints diagnostics (group members, agent processes,
recent events), and the script exits non-zero.

Don't run two copies at once: the kernel has one cgroup v2 hierarchy for the
whole machine, so their quarantine groups would collide. That happened once
and produced a false failure.

About 87 checks run per cgroup layout. The work directory is under
`/var/lib`, not `/tmp`: Agent Watch rightly flags scripts that run from
`/tmp`, and the fake agent's script lives in the work directory.

**How it avoids fooling itself.** These are lessons from mistakes made while
building it.
- The fake agent's name is assembled at run time and never appears in any
  file or command line. Otherwise the test's own shells would match the
  agent pattern and be quarantined or allowed along with it. That happened
  once, and the run looked like it passed.
- The first checks assert that Agent Watch detected exactly the fake agent
  and its child, a python process. If that is not true, the run aborts.
- "Caught again" checks look at whether the **current** agent process is
  inside the quarantine group. They do not count audit events: a stale
  event once made a check pass while the agent was still online.
- Every block or allow check has a control: the same probe is run before
  the rule, or by an unrelated process.
- The forward probe resends a few times: a TUN link has no carrier until a
  process attaches to it, and the first packet can be lost. That once made
  the "before lockdown" control flaky. A forward-chain drop still drops
  every copy.

- Replies to inbound connections are probed by injecting a TCP SYN from a
  "remote" address into the test interface (`reply_probe.py`) and watching
  whether the kernel's SYN-ACK comes back out.
- Kernel exec events (the proc connector) exist only in the machine's
  initial network namespace, so they are unavailable in here: the checks
  that a restarted blocked agent is cut off within ~2 s print SKIP, with
  the reason. That path is tested end to end in the host namespace by
  `go test ./internal/daemon -run TestBlockedProgramIsCaughtAtExec` (as
  root).

Not covered here: real WireGuard/Tor tunnels, running under systemd, and
real hardware.
