#!/bin/sh
# "restore-all" live check, called by run.sh inside its namespaces:
#   restore_all.sh BIN WORKDIR CGROUP_MOUNT
# Turns on everything DevShield can change (thermal profile, sinkhole, LAN
# privacy, lockdown, encrypted-DNS block, an allowed agent) — the thermal, hosts and LAN-privacy
# parts on a simulated /sys and /etc tree, lockdown and the agent on the
# real kernel inside run.sh's namespaces — runs restore-all, and checks
# every value is back to the original. Then blocks the agent and checks a
# second restore-all releases it. Prints PASS/FAIL lines and exits
# non-zero on any failure.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1 D=$2/restore CG=$3
rm -rf "$D"
mkdir -p "$D"
SOCK=$D/sock DS="$1 --socket $2/restore/sock" R=$D/root
fails=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1: got '$2', want '$3'"; fails=$((fails + 1)); fi; }
waitfor() { i=0; while ! sh -c "$2" >/dev/null 2>&1; do i=$((i + 1)); [ $i -gt "$1" ] && return 1; sleep 1; done; }
lastudp() { sleep 1.5; grep udp "$D/agent.log" | tail -1 | cut -d' ' -f2; }
agcg() { grep '^0::' /proc/$AG/cgroup | cut -d: -f3; }

# Simulated Intel laptop with systemd-resolved and NetworkManager installed.
C=$R/sys/devices/system/cpu
mkdir -p $C/intel_pstate $R/sys/firmware/acpi $R/usr/lib/systemd $R/etc/NetworkManager/conf.d \
	$R/proc/sys/net/ipv6/conf/all $R/proc/sys/net/ipv6/conf/default
echo 0 >$C/intel_pstate/no_turbo
echo balanced >$R/sys/firmware/acpi/platform_profile
echo "low-power balanced performance" >$R/sys/firmware/acpi/platform_profile_choices
for p in policy0 policy1; do
	d=$C/cpufreq/$p
	mkdir -p $d
	echo 400000 >$d/cpuinfo_min_freq
	echo 4800000 >$d/cpuinfo_max_freq
	echo 4800000 >$d/scaling_max_freq
	echo balance_performance >$d/energy_performance_preference
	echo "default performance balance_performance balance_power power" >$d/energy_performance_available_preferences
done
touch $R/usr/lib/systemd/systemd-resolved
echo 0 >$R/proc/sys/net/ipv6/conf/all/use_tempaddr
echo 0 >$R/proc/sys/net/ipv6/conf/default/use_tempaddr
printf '127.0.0.1 localhost\n10.0.0.7 nas.home\n' >$R/etc/hosts

# Values, not bytes: real sysfs/procfs always read back with a newline,
# a simulated tree keeps whatever was written.
snapshot() { (cd $R && for f in $(find . -type f | sort); do printf '%s %s\n' "$f" "$(tr -d '\n' <"$f" | sha256sum | cut -c1-16)"; done) >"$1"; }
snapshot $D/before
cp $R/etc/hosts $D/hosts.orig

$BIN daemon --state-dir $D/st --socket $SOCK --sys-root $R --catalog $2/catalog.json 2>$D/err &
DMN=$!
i=0
until $DS status >/dev/null 2>&1; do i=$((i + 1)); [ $i -gt 10 ] && break; sleep 1; done

# The test agent (see fixtures.py), sanctioned and allowed out of the lockdown.
python3 $HERE/fixtures.py server $D & SRV=$!
python3 $HERE/fixtures.py agent $D & AG=$!
waitfor 10 "test -s $D/kids.pid"
ORIGCG=$(agcg)
waitfor 30 "$DS agents | grep -q 'Live Test Agent'"
ID=$($DS agents --json | python3 -c "import json,sys;print([a for a in json.load(sys.stdin) if a['name']=='Live Test Agent'][0]['id'])")
$DS sanction "$ID" >/dev/null
waitfor 15 "$DS agents --json | grep -q '\"verdict\": \"sanctioned\"'"
$DS allow "$ID" >/dev/null

$DS profile silent >/dev/null
$DS sinkhole on >/dev/null
$DS lan-privacy on >/dev/null
$DS lanprivacy-noop >/dev/null 2>&1 # unknown command: must change nothing
$DS lockdown on --via wg0 >/dev/null
$DS block-doh on >/dev/null
snapshot $D/during
check "everything was switched on (files changed)" "$(diff $D/before $D/during | grep -c '^>' | awk '{print ($1 > 5)}')" 1
check "lockdown active" "$(python3 $HERE/fixtures.py probe)" EPERM
check "DoH blocked" "$(python3 $HERE/fixtures.py udpsend 1.1.1.1 443)" EPERM
check "allowed agent goes out during lockdown" "$(lastudp)" ok
check "allowed agent is in the allowed group" "$(agcg)" /devshield-allowed

$DS restore-all >$D/restore.out
# Exit 3 = done with caveats. Here the only caveats may be the two service
# reloads, which can't work in a namespace without systemd/nmcli.
check "restore-all ran every step (exit 3: caveats only)" "$?" 3
check "no step failed" "$(grep -c '❌' $D/restore.out)" 0
check "the only notes are the two service reloads" "$(grep '^ *⚠' $D/restore.out | grep -vc 'did not reload')" 0
snapshot $D/after
check "every value back to the original" "$(diff $D/before $D/after | wc -l | tr -d ' ')" 0
check "/etc/hosts byte-identical" "$(cmp -s $D/hosts.orig $R/etc/hosts && echo same)" same
check "network open again" "$(python3 $HERE/fixtures.py probe)" ok
check "DoH resolvers reachable again" "$(python3 $HERE/fixtures.py udpsend 1.1.1.1 443)" ok
check "DevShield table removed" "$(nft list table inet devshield >/dev/null 2>&1 && echo present || echo gone)" gone
check "allowed agent back in its own cgroup" "$(agcg)" "$ORIGCG"
check "allowed group removed" "$([ -d "$CG/devshield-allowed" ] && echo present || echo gone)" gone
$DS restore-all >/dev/null
check "second restore-all is a clean no-op" "$?" 0

$DS block "$ID" >/dev/null
check "blocked agent cut off" "$(lastudp)" EPERM
$DS restore-all >/dev/null
check "restore-all with a blocked agent succeeds" "$?" 0
check "blocked agent released to its own cgroup" "$(agcg)" "$ORIGCG"
check "blocked agent goes out again" "$(lastudp)" ok
check "quarantine group removed" "$([ -d "$CG/devshield-quarantine" ] && echo present || echo gone)" gone
check "all three logged" "$($DS events -n 30 | grep -c RESTORE_ALL)" 3
kill $DMN $SRV $AG $(cat $D/kids.pid) 2>/dev/null
echo "== restore-all: $fails failed"
[ $fails = 0 ]
