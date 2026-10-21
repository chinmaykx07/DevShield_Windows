#!/bin/sh
# "restore-all" live check, called by run.sh inside its namespaces:
#   restore_all.sh BIN WORKDIR
# Turns on everything DevShield can change (thermal profile, sinkhole, LAN
# privacy, lockdown) on a simulated system tree, runs restore-all, and
# checks every value is back to the original. Prints PASS/FAIL lines and
# exits non-zero on any failure.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$1 D=$2/restore
rm -rf "$D"
mkdir -p "$D"
SOCK=$D/sock DS="$1 --socket $2/restore/sock" R=$D/root
fails=0
check() { if [ "$2" = "$3" ]; then echo "  PASS  $1"; else echo "  FAIL  $1: got '$2', want '$3'"; fails=$((fails + 1)); fi; }

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

$BIN daemon --state-dir $D/st --socket $SOCK --sys-root $R 2>$D/err &
DMN=$!
i=0
until $DS status >/dev/null 2>&1; do i=$((i + 1)); [ $i -gt 10 ] && break; sleep 1; done

$DS profile silent >/dev/null
$DS sinkhole on >/dev/null
$DS lan-privacy on >/dev/null
$DS lanprivacy-noop >/dev/null 2>&1 # unknown command: must change nothing
$DS lockdown on --via wg0 >/dev/null
snapshot $D/during
check "everything was switched on (files changed)" "$(diff $D/before $D/during | grep -c '^>' | awk '{print ($1 > 5)}')" 1
check "lockdown active" "$(python3 $HERE/fixtures.py probe)" EPERM

$DS restore-all >$D/restore.out
check "restore-all succeeds" "$?" 0
snapshot $D/after
check "every value back to the original" "$(diff $D/before $D/after | wc -l | tr -d ' ')" 0
check "/etc/hosts byte-identical" "$(cmp -s $D/hosts.orig $R/etc/hosts && echo same)" same
check "network open again" "$(python3 $HERE/fixtures.py probe)" ok
check "DevShield table removed" "$(nft list table inet devshield >/dev/null 2>&1 && echo present || echo gone)" gone
$DS restore-all >/dev/null
check "second restore-all is a clean no-op" "$?" 0
check "both logged" "$($DS events -n 5 | grep -c RESTORE_ALL)" 2
kill $DMN
echo "== restore-all: $fails failed"
[ $fails = 0 ]
