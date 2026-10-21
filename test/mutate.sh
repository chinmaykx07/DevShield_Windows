#!/bin/sh
# Mutation check: does a regression test actually catch the bug it guards?
#
#   test/mutate.sh FILE 'OLD' 'NEW' TESTREGEX PKG
#
# Replaces OLD (must occur exactly once in FILE) with NEW, runs the tests
# matching TESTREGEX in PKG, restores FILE, and prints:
#   caught   the test failed: good
#   MISSED   the test still passed: strengthen it
#   INVALID  the mutant didn't compile: choose another mutation
# Example: test/mutate.sh internal/egress/policy.go '	if l.NoReplies {' '	if false {' ReplyServices ./internal/egress/
f=$1 old=$2 new=$3 run=$4 pkg=$5
cd "$(dirname "$0")/.." || exit 2
cp "$f" "$f.mutbak"
python3 -c "
import sys;p,o,n=sys.argv[1:4];s=open(p).read()
if s.count(o)!=1: sys.exit('mutation does not match exactly once: '+o[:60])
open(p,'w').write(s.replace(o,n))" "$f" "$old" "$new" || { mv "$f.mutbak" "$f"; exit 1; }
out=$(go test -count=1 -run "$run" $pkg 2>&1)
mv "$f.mutbak" "$f"
first=$(printf '%s' "$old" | head -1)
if echo "$out" | grep -q "build failed\|setup failed"; then echo "INVALID: $first"; echo "$out" | grep -m3 "\.go:"
elif echo "$out" | grep -q "^FAIL\|--- FAIL"; then echo "caught: $first"
else echo "MISSED: $first"; fi
