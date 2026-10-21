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
	WORK=$(mktemp -d /tmp/devshield-live.XXXXXX)
	BIN=${1:-}
	if [ -z "$BIN" ]; then
		BIN=$WORK/devshield
		(cd "$HERE/../.." && go build -o "$BIN" .) || exit 2
	fi
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

check() { # check NAME ACTUAL EXPECTED
	if [ "$2" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1: got '$2', want '$3'"; fails=$((fails + 1)); diag; fi
}
diag() { # state worth seeing when a check fails
	echo "    quarantine: $(cat "$CG/devshield-quarantine/cgroup.procs" 2>/dev/null | tr '\n' ' ')  allowed: $(cat "$CG/devshield-allowed/cgroup.procs" 2>/dev/null | tr '\n' ' ')"
	for p in $AG $(cat "$D/kids.pid" 2>/dev/null); do echo "    pid $p: $(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null | cut -c1-60) cgroup $(grep '^0::' /proc/$p/cgroup 2>/dev/null)"; done
	$DS agents --json 2>/dev/null | python3 -c "import json,sys;[print('    agent',a['id'],a['name'],a['processes'],a.get('network_blocked')) for a in json.load(sys.stdin)]"
	$DS events -n 8 2>/dev/null | cut -c1-150 | sed 's/^/    /'
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
	$BIN daemon --state-dir "$D/st" --socket "$SOCK" --catalog "$D/catalog.json" --hosts-list /nonexistent 2>>"$D/daemon.err" &
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

echo "-- detection is the test agent and nothing else"
check "detected exe is python" "$(agentjson exe | grep -c python)" 1
check "agent + its child only (helper and harness not matched)" "$(agentjson processes)" 2
if [ "$(agentjson processes)" != 2 ]; then echo "  ABORT: wrong processes detected; later checks would be meaningless"; exit 1; fi

echo "-- block"
$DS block "$ID" >/dev/null
check "held connection cut" "$(stopped 9000)" stopped
check "new connections refused" "$(stopped 9001)" stopped
check "agent, child and helper quarantined" "$(wc -w <"$CG/devshield-quarantine/cgroup.procs" | tr -d ' ')" 3
check "unrelated process unaffected" "$(python3 -c 'import socket;socket.create_connection(("127.0.0.1",9001),timeout=1);print("ok")')" ok

echo "-- restart is caught again"
stopagent; startagent
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
check "caught when it starts" "$(waitfor 30 inq && echo yes)" yes
check "cut off" "$(stopped 9001)" stopped
stopagent
sleep 12
check "socket rules removed after exit" "$($DS egress --json | python3 -c 'import json,sys;print(sum(b["flows_cut"] for b in json.load(sys.stdin).get("blocked",[])))')" 0
$DS unblock "$ID" >/dev/null
startagent

echo "-- lockdown"
check "before lockdown" "$(probe)" ok
$DS lockdown on --via wg0 >/dev/null
check "via absent wg0: root blocked" "$(probe)" EPERM
check "via absent wg0: other user blocked" "$(probe 65534)" EPERM
check "loopback still works" "$(python3 -c 'import socket;socket.create_connection(("127.0.0.1",9001),timeout=1);print("ok")')" ok
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
$DS lockdown on --via wg0 --confirm-within 3s >/dev/null
check "active during window" "$(probe)" EPERM
sleep 5
check "reverted without confirm" "$(probe)" ok
$DS lockdown on --via wg0 --confirm-within 3s >/dev/null
$DS lockdown confirm >/dev/null
sleep 4
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
"$HERE/restore_all.sh" "$BIN" "$D" || fails=$((fails + 1))
echo "-- network monitor"
"$HERE/netwatch.sh" "$BIN" "$D" || fails=$((fails + 1))

echo "== $MODE: $fails failed"
[ $fails = 0 ]
