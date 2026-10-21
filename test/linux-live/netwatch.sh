#!/bin/sh
# Network-monitor live check, called by run.sh inside its namespaces:
#   netwatch.sh BIN WORKDIR
# A real TCP connection to an address that stands in for a telemetry
# domain must be labelled telemetry and logged exactly once; the server
# side of the same connection (inbound) must not be reported.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1 D=$2/netwatch
rm -rf "$D"
mkdir -p "$D"
DS="$BIN --socket $D/sock"
fails=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1: got '$2', want '$3'"; fails=$((fails + 1)); fi; }

# 10.9.9.5 as a local, non-127 address (so it is not "loopback"), named
# like a telemetry host in a private /etc/hosts and in the telemetry list.
python3 - <<'PY'
import socket, struct
nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0); nl.bind((0, 0))
a = socket.inet_aton("10.9.9.5")
rta = lambda k, d: struct.pack("HH", 4 + len(d), k) + d
p = struct.pack("BBBBI", socket.AF_INET, 32, 0, 0, socket.if_nametoindex("lo")) + rta(1, a) + rta(2, a)
nl.send(struct.pack("IHHII", 16 + len(p), 20, 1 | 4 | 0x400, 1, 0) + p)
assert struct.unpack("i", nl.recv(4096)[16:20])[0] == 0
PY
cp /etc/hosts "$D/hosts"
echo "10.9.9.5 telemetry.devshield.test" >>"$D/hosts"
mount --bind "$D/hosts" /etc/hosts
echo '{"version":"test","groups":[{"name":"test","why":"test","domains":["telemetry.devshield.test"]}],"never_block":[]}' >"$D/list.json"

python3 -c 'import socket,time
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("10.9.9.5",8443));s.listen(5)
c,_=s.accept();time.sleep(600)' &
SRV=$!
sleep 0.5
python3 -c 'import socket,time;c=socket.create_connection(("10.9.9.5",8443));time.sleep(600)' &
CLI=$!
$BIN daemon --state-dir "$D/st" --socket "$D/sock" --hosts-list "$D/list.json" 2>"$D/err" &
DMN=$!

i=0
until $DS net --json 2>/dev/null | grep -q '"telemetry"'; do i=$((i + 1)); [ $i -gt 30 ] && break; sleep 1; done
json=$($DS net --json)
check "outbound connection labelled telemetry" "$(echo "$json" | python3 -c "import json,sys;print(sum(1 for e in json.load(sys.stdin) if e['category']=='telemetry' and e['pid']==$CLI and e['host']=='telemetry.devshield.test'))")" 1
check "server side (inbound) not reported" "$(echo "$json" | python3 -c "import json,sys;print(sum(1 for e in json.load(sys.stdin) if e['pid']==$SRV))")" 0
$DS net >/dev/null
check "net exits 3 while telemetry flows" "$?" 3
i=0
until $DS events -n 50 | grep -q NET_TELEMETRY; do i=$((i + 1)); [ $i -gt 40 ] && break; sleep 1; done
sleep 35 # one more monitor pass
check "logged exactly once (deduplicated)" "$($DS events -n 50 | grep -c NET_TELEMETRY)" 1
kill $DMN $SRV $CLI 2>/dev/null
umount /etc/hosts
echo "== netwatch: $fails failed"
[ $fails = 0 ]
