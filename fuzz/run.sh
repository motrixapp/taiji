#!/bin/sh
# taiji-fuzz full sweep: $1 seconds per target
# (default 30), uniform -max_len=65536 (the single source of the flags,
# per the README's Running section).
set -e
T="${1:-30}"
cd "$(dirname "$0")/.."
for t in $(ls fuzz_targets | sed 's/\.rs$//'); do
  echo "==== $t (${T}s) ===="
  mkdir -p "fuzz/corpus/$t"
  cargo fuzz run "$t" "fuzz/corpus/$t" "fuzz/seeds/$t" -- \
    -max_total_time="$T" -max_len=65536 || { echo "FUZZ FAIL: $t"; exit 1; }
done
echo "all targets ok"
