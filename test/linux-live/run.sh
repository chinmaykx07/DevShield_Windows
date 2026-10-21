#!/bin/sh
# Live test of DevShield's Linux network controls, restore-all and network
# monitor against the real kernel, nftables and daemon — inside throwaway network + mount namespaces, so
# the host's own network is never touched.
#
#   sudo test/linux-live/run.sh [path/to/devshield]
#
# Needs: root, nft, unshare, python3, /dev/net/tun, cgroup v2 support.
# Runs every scenario twice: on a freshly mounted cgroup2 hierarchy, and on
# the host's existing layout (unified or "hybrid") when it has one. Exits
# non-zero if any check fails.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" != "--inner" ]; then
	[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
	# Not under /tmp: Agent Watch rightly flags scripts that run from /tmp,
	# and the fake agent's script lives here. World-traversable, so the
	# unprivileged-user checks can reach the binary and the socket.
	WORK=$(mktemp -d /var/lib/devshield-live.XXXXXX)
	chmod 755 "$WORK"
	if [ -n "${1:-}" ]; then
		cp "$1" "$WORK/devshield" || exit 2
	else
		(cd "$HERE/../.." && go build -o "$WORK/devshield" .) || exit 2
	fi
	chmod 755 "$WORK/devshield"
	BIN=$WORK/devshield
	modes=fresh
	grep -q ' - cgroup2 ' /proc/self/mountinfo && modes="fresh host"
	rc=0
	for mode in $modes; do
		unshare -n -m --propagation private "$0" --inner "$mode" "$BIN" "$WORK" || rc=1
	done
	rm -rf "$WORK"
	[ $rc = 0 ] && echo "ALL PASSED" || echo "SOME CHECKS FAILED"
	exit $rc
fi

# ── inside the namespaces ──
MODE=$2 BIN=$3 WORK=$4
D=$WORK/$MODE
mkdir -p "$D"
SOCK=$D/sock
DS="$BIN --socket $SOCK"
FX="python3 $HERE/fixtures.py"
fails=0

if [ "$MODE" = fresh ]; then
	mount -t cgroup2 none /sys/fs/cgroup || exit 1
	CG=/sys/fs/cgroup
else
	CG=$(awk '$9 == "cgroup2" && $5 ~ "^/sys/fs/cgroup" {print $5; exit}' /proc/self/mountinfo)
fi
echo "== layout: $MODE ($CG)"
python3 "$HERE/netns_setup.py" || exit 1
python3 "$HERE/forward_probe.py" setup || exit 1

check() { # check NAME ACTUAL EXPECTED
	if [ "$2" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1: got '$2', want '$3'"; fails=$((fails + 1)); diag; fi
}
diag() { # state worth seeing when a check fails
	echo "    quarantine: $(cat "$CG/devshield-quarantine/cgroup.procs" 2>/dev/null | tr '\n' ' ')  allowed: $(cat "$CG/devshield-allowed/cgroup.procs" 2>/dev/null | tr '\n' ' ')"
	for p in $AG $(cat "$D/kids.pid" 2>/dev/null); do echo "    pid $p: $(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | cut -c1-60) cgroup $(grep '^0::' /proc/$p/cgroup 2>/dev/null)"; done
	$DS agents --json 2>/dev/null | python3 -c "import json,sys;[print('    agent',a['id'],a['name'],a['processes'],a.get('network_blocked')) for a in json.load(sys.stdin)]"
	$DS events -n 8 2>/dev/null | cut -c1-150 | sed 's/^/    /'
	echo "    ip_forward=$(cat /proc/sys/net/ipv4/ip_forward) links (this namespace): $(python3 -c 'import socket;print(" ".join(n for _, n in socket.if_nameindex()))')"
	nft list ruleset 2>&1 | sed 's/^/    nft: /' | head -40
}
waitfor() { # waitfor SECONDS COMMAND...
	n=$1; shift
	i=0
	while ! "$@" >/dev/null 2>&1; do i=$((i + 1)); [ $i -gt "$n" ] && return 1; sleep 1; done
}
rx() { cat "$D/rx$1" 2>/dev/null || echo 0; }
stopped() { a=$(rx "$1"); sleep 3; [ "$a" = "$(rx "$1")" ] && echo stopped || echo flowing; }
lastudp() { sleep 1.5; grep udp "$D/$1.log" | tail -1 | cut -d' ' -f2; }
event() { $DS events -n 100 | grep -q "$1"; }
probe() { $FX probe "$@"; }
startd() {
	$BIN daemon --state-dir "$D/st" --socket "$SOCK" --catalog "$D/catalog.json" --hosts-list /nonexistent --owner nobody 2>>"$D/daemon.err" &
	DMN=$!
	waitfor 10 $DS status
}
startagent() { rm -f "$D/kids.pid"; $FX agent "$D" & AG=$!; waitfor 10 test -s "$D/kids.pid"; }
stopagent() { kill $AG $(cat "$D/kids.pid") 2>/dev/null; wait $AG 2>/dev/null; sleep 1; }
inq() { grep -qx "$AG" "$CG/devshield-quarantine/cgroup.procs" 2>/dev/null; } # is the CURRENT agent process quarantined?
agentjson() { $DS agents --json | python3 -c "import json,sys;a=[a for a in json.load(sys.stdin) if a['name']=='Live Test Agent'];print(a[0]['$1'] if a else '')"; }
cleanup() {
	kill $DMN $SRV $AG $(cat "$D/kids.pid" 2>/dev/null) 2>/dev/null
	sleep 1
	nft delete table inet devshield 2>/dev/null
	for g in devshield-quarantine devshield-allowed; do rmdir "$CG/$g" 2>/dev/null; done
}
trap cleanup EXIT

python3 -c "import json;print(json.dumps(json.load(open('$HERE/../../internal/agentwatch/catalog.json'))))" >"$D/base.json"
$FX catalog "$D/base.json" "$D/catalog.json"
$FX server "$D" & SRV=$!
startd
startagent
waitfor 30 sh -c "$DS agents | grep -q 'Live Test Agent'"
ID=$(agentjson id)

echo "-- real users: the owner may read, nobody else; only root may change policy"
as() { su "$1" -s /bin/sh -c "$2" 2>&1; }
check "owner (nobody) can read status" "$(as nobody "$DS status >/dev/null && echo ok")" ok
check "another user (daemon) cannot read" "$(as daemon "$DS status" | grep -c 'not authorized')" 1
check "the owner cannot change policy" "$(as nobody "$DS sanction $ID" | grep -c 'requires root')" 1
check "the attempt is logged with the program that tried" "$($DS events -n 20 | grep AGENT_TAMPER_ATTEMPT | grep -c 'sanction')" 1
check "the audit log is root-only" "$(stat -c %a "$D/st/audit.log")" 600
check "kernel exec events in use" "$($DS events -n 50 | grep -c EXEC_EVENTS_UNAVAILABLE)" 0

echo "-- telemetry sinkhole on the real resolver (a private copy of /etc/hosts)"
cp /etc/hosts "$D/hosts.orig"
cp /etc/hosts "$D/hosts.work"
mount --bind "$D/hosts.work" /etc/hosts
check "before: not sinkholed (control)" "$(getent hosts metrics.ubuntu.com | cut -d' ' -f1)" ""
$DS sinkhole on >/dev/null
check "on: the resolver answers 0.0.0.0" "$(getent hosts metrics.ubuntu.com | cut -d' ' -f1)" 0.0.0.0
check "on: the owner's own entries still resolve" "$(getent hosts localhost | cut -d' ' -f1 | head -1 | grep -c -E '127.0.0.1|::1')" 1

echo "-- encrypted DNS (block-doh), which would bypass /etc/hosts"
check "HTTPS to a public DoH resolver before (control)" "$($FX udpsend 1.1.1.1 443)" ok
check "DNS over TLS/QUIC port before (control)" "$($FX udpsend 203.0.113.9 853)" ok
check "a DoH resolver's name before: not sinkholed (control)" "$(getent hosts dns.google | cut -d' ' -f1)" ""
$DS block-doh on >/dev/null
check "on: HTTPS/QUIC to a public DoH resolver dropped" "$($FX udpsend 1.1.1.1 443)" EPERM
check "on: port 853 to any address dropped" "$($FX udpsend 203.0.113.9 853)" EPERM
check "on: other HTTPS/QUIC unaffected" "$($FX udpsend 203.0.113.9 443)" ok
check "on, with the sinkhole on: the resolver's name answers 0.0.0.0" "$(getent hosts dns.google | cut -d' ' -f1)" 0.0.0.0
$DS egress >/dev/null
check "DoH rules match the kernel's listing" "$?" 0
$DS block-doh off >/dev/null
check "off: the resolver is reachable again" "$($FX udpsend 1.1.1.1 443)" ok
check "off: its name is no longer sinkholed" "$(getent hosts dns.google | cut -d' ' -f1)" ""
check "off: the telemetry block is still there" "$(getent hosts metrics.ubuntu.com | cut -d' ' -f1)" 0.0.0.0
$DS sinkhole off >/dev/null
check "off: /etc/hosts byte-identical to before" "$(cmp -s "$D/hosts.orig" /etc/hosts && echo same)" same
umount /etc/hosts

echo "-- detection is the test agent and nothing else"
check "detected exe is python" "$(agentjson exe | grep -c python)" 1
check "agent + its child only (helper and harness not matched)" "$(agentjson processes)" 2
if [ "$(agentjson processes)" != 2 ]; then echo "  ABORT: wrong processes detected; later checks would be meaningless"; exit 1; fi

echo "-- behaviour alone: an uncatalogued program serving on a model port"
$FX listener & LS=$!
unknown() { $DS agents --json | python3 -c "import json,sys;a=[a for a in json.load(sys.stdin) if a['name'].startswith('Unknown AI agent')];print(a[0]['$1'] if a else '')"; }
check "detected with no catalog entry" "$(waitfor 30 sh -c "$DS agents | grep -q 'Unknown AI agent'" && echo yes)" yes
check "its verdict is rogue (undocumented)" "$(unknown verdict)" rogue
check "the reason given is the model port" "$(unknown reasons | grep -c 11434)" 1
kill $LS; wait $LS 2>/dev/null

echo "-- block"
$DS block "$ID" >/dev/null
check "held connection cut" "$(stopped 9000)" stopped
check "new connections refused" "$(stopped 9001)" stopped
check "agent, child and helper quarantined" "$(wc -w <"$CG/devshield-quarantine/cgroup.procs" | tr -d ' ')" 3
check "unrelated process unaffected" "$(python3 -c 'import socket;socket.create_connection(("127.0.0.1",9001),timeout=1);print("ok")')" ok

echo "-- restart is caught again"
stopagent; startagent
check "restart caught within ~2 s (kernel exec events, not the 10 s scan)" "$(waitfor 2 inq && echo yes)" yes
check "re-quarantined after restart" "$(waitfor 30 inq && echo yes)" yes
check "restarted agent cut off" "$(stopped 9001)" stopped

echo "-- unblock"
$DS unblock "$ID" >/dev/null
sleep 2
check "traffic resumes" "$(stopped 9001)" flowing
check "quarantine group removed" "$([ -d "$CG/devshield-quarantine" ] && echo yes || echo no)" no

echo "-- block while not running; rules of closed sockets go away"
stopagent
$DS block "$ID" >/dev/null
startagent
check "caught within ~2 s of starting" "$(waitfor 2 inq && echo yes)" yes
check "caught when it starts" "$(waitfor 30 inq && echo yes)" yes
check "cut off" "$(stopped 9001)" stopped
stopagent
sleep 12
check "socket rules removed after exit" "$($DS egress --json | python3 -c 'import json,sys;print(sum(b["flows_cut"] for b in json.load(sys.stdin).get("blocked",[])))')" 0
$DS unblock "$ID" >/dev/null
startagent

echo "-- lockdown"
check "before lockdown" "$(probe)" ok
check "forwarded (container/VM) traffic before lockdown (control)" "$(python3 "$HERE/forward_probe.py" probe)" forwarded
check "UDP to a public host's port 67 before lockdown (control)" "$($FX udpsend 198.51.100.2 67)" ok
check "a server answers an inbound connection before lockdown (control)" "$(python3 "$HERE/reply_probe.py" 9100)" replied
$DS lockdown on --via wg0 >/dev/null
check "via absent wg0: root blocked" "$(probe)" EPERM
check "via absent wg0: other user blocked" "$(probe 65534)" EPERM
check "loopback still works" "$(python3 -c 'import socket;socket.create_connection(("127.0.0.1",9001),timeout=1);print("ok")')" ok
check "forwarded (container/VM) traffic blocked" "$(python3 "$HERE/forward_probe.py" probe)" dropped
check "DHCP port is no way out: public host, any port" "$($FX udpsend 198.51.100.2 67)" EPERM
check "DHCP port is no way out: public host, from port 68" "$($FX udpsend 198.51.100.2 67 68)" EPERM
check "real DHCP to the local network still works" "$($FX udpsend 10.9.9.2 67 68)" ok
check "SSH (22/tcp) still answers inbound connections" "$(python3 "$HERE/reply_probe.py" 22)" replied
check "a server on another port can't answer whoever connects in" "$(python3 "$HERE/reply_probe.py" 9100)" dropped
$DS lockdown on --via wg0 --inbound 9100/tcp >/dev/null
check "--inbound 9100/tcp: that server answers" "$(python3 "$HERE/reply_probe.py" 9100)" replied
check "--inbound replaces the default: SSH no longer answers" "$(python3 "$HERE/reply_probe.py" 22)" dropped
$DS lockdown on --via wg0 --strict >/dev/null
check "--strict: not even SSH answers" "$(python3 "$HERE/reply_probe.py" 22)" dropped
$DS lockdown on --via wg0 --inbound 22/tcp --inbound 9100/tcp >/dev/null
$DS egress >/dev/null
check "reply rules match the kernel's listing" "$?" 0
$DS lockdown on --via fwout >/dev/null
check "forwarded traffic through the tunnel interface" "$(python3 "$HERE/forward_probe.py" probe)" forwarded
$DS lockdown on --via dstest0 >/dev/null
check "via the tunnel interface" "$(probe)" ok
$DS lockdown on --via wg0 --user nobody >/dev/null
check "allowed user goes out" "$(probe 65534)" ok
check "others still blocked" "$(probe)" EPERM
$DS lockdown on --via wg0 --endpoint 10.9.9.2:9999/udp >/dev/null
check "tunnel endpoint reachable" "$(probe)" ok
$DS block "$ID" >/dev/null
$DS lockdown on --via wg0 --endpoint 10.9.9.2:9999/udp --endpoint '[2001:db8::1]:443' --user nobody --lan >/dev/null
$DS egress >/dev/null
check "full ruleset matches the kernel's listing" "$?" 0
$DS unblock "$ID" >/dev/null

echo "-- tampering"
$DS lockdown on --via wg0 >/dev/null
H=$(nft -a list chain inet devshield egress | grep 'everything else' | sed 's/.*handle //')
nft delete rule inet devshield egress handle "$H"
check "one deleted rule opens the door (control)" "$(probe)" ok
$DS egress >/dev/null
check "egress reports it" "$?" 3
check "rule restored" "$(waitfor 15 sh -c "nft list chain inet devshield egress | grep -q 'everything else'" && probe)" EPERM
nft delete table inet devshield
check "deleted table restored" "$(waitfor 15 nft list table inet devshield && probe)" EPERM

echo "-- dead-man switch"
$DS lockdown off >/dev/null
check "a window shorter than 10 s is refused" "$($DS lockdown on --via wg0 --confirm-within 3s >/dev/null 2>&1 && echo accepted || echo refused)" refused
$DS lockdown on --via wg0 --confirm-within 10s >/dev/null
check "active during window" "$(probe)" EPERM
sleep 12
check "reverted without confirm" "$(probe)" ok
$DS lockdown on --via wg0 --confirm-within 10s >/dev/null
$DS lockdown confirm >/dev/null
sleep 11
check "kept after confirm" "$(probe)" EPERM

echo "-- persistence"
kill $DMN; wait $DMN 2>/dev/null
nft delete table inet devshield
check "no rules with daemon stopped (control)" "$(probe)" ok
$BIN egress-restore --state-dir "$D/st" >/dev/null
check "egress-restore loads lockdown without daemon" "$(probe)" EPERM
nft delete table inet devshield
startd
check "daemon start re-applies lockdown" "$(probe)" EPERM

echo "-- allow (sanctioned agents only)"
waitfor 30 sh -c "$DS agents | grep -q 'Live Test Agent'"
$DS lockdown on --only-allowed >/dev/null
check "unsanctioned agent cannot be allowed" "$($DS allow "$ID" >/dev/null 2>&1 && echo allowed || echo refused)" refused
$DS sanction "$ID" >/dev/null
waitfor 15 sh -c "$DS agents --json | grep -q '\"verdict\": \"sanctioned\"'"
$DS allow "$ID" >/dev/null
check "allowed agent goes out" "$(lastudp agent)" ok
check "its child (part of the agent) goes out" "$(lastudp child)" ok
check "pre-existing helper NOT swept in" "$(lastudp helper)" EPERM
check "other programs blocked" "$(probe)" EPERM
$DS revoke "$ID" >/dev/null
check "revoke withdraws the allowance" "$(waitfor 15 event AGENT_ALLOW_SUSPENDED && lastudp agent)" EPERM
$DS sanction "$ID" >/dev/null
waitfor 15 sh -c "$DS agents --json | grep -q '\"verdict\": \"sanctioned\"'"
$DS allow "$ID" >/dev/null
stopagent; startagent
check "restarted allowed agent allowed again" "$(waitfor 30 sh -c "tail -1 '$D/agent.log' | grep -q 'udp ok'" && echo yes)" yes
$DS block "$ID" >/dev/null
check "block wins over allow" "$(lastudp agent)" EPERM
$DS unblock "$ID" >/dev/null
$DS lockdown off >/dev/null
check "everything open again" "$(lastudp agent)" ok

cleanup
trap - EXIT
check "no DevShield cgroups left" "$(ls -d "$CG"/devshield-* 2>/dev/null | wc -l | tr -d ' ')" 0
check "no DevShield table left" "$(nft list table inet devshield >/dev/null 2>&1 && echo yes || echo no)" no
echo "-- restore-all"
"$HERE/restore_all.sh" "$BIN" "$D" "$CG" || fails=$((fails + 1))
echo "-- network monitor"
"$HERE/netwatch.sh" "$BIN" "$D" || fails=$((fails + 1))

echo "== $MODE: $fails failed"
[ $fails = 0 ]
