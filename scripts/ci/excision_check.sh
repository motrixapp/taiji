#!/usr/bin/env bash
# Excision check (Phase C, protocol/internal split plan): delete the
# aria2 adapter layer from a throwaway copy of this tree and compile
# the kernel ten (store/core/engine/bt/http/media/segment/io/domain/
# metalink) with `cargo check --locked --all-targets` — zero kernel
# source changes allowed.
#
# Why this is not a no-op: cargo only reads manifests (not sources) of
# non-requested members, so "the kernel does not depend on rpc" is
# already true today. This check's value is pinning every Phase C
# migration as *removable*: if the kernel still calls something that
# moved into `crates/taiji-rpc/src/aria2/` (a leftover
# `StatusKind::as_str` consumer, a string field still reading adapter
# tables, a re-export loop), the kernel check below goes red after the
# deletion — that red is exactly the evidence that excision fails.
# It is the source-level completion of guard B (the manifest-face pin
# in crates/taiji-rpc/tests/rpc_boundary_guard.rs).
#
# Premise (registered in rpc_boundary_guard.rs as
# `kernel_dev_dependencies_also_stay_rpc_free_for_excision`):
# `--all-targets` compiles dev-dependency graphs too, so the kernel
# crates must not declare taiji-rpc even as a dev-dependency. Guard B
# deliberately allows dev-deps; this script does not.
#
# The copy is a tar (not a git worktree) so uncommitted state is
# covered; `--locked` keeps the dependency set honest; no cache is
# reused (the copy is a fresh tree) — a cold kernel check is the cost
# of the pin (~5-10 min on CI; local: run when touching the adapter).
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Copy the working tree (excluding target/ and .git), covering both
# committed and uncommitted state.
tar -C "$REPO" --exclude ./target --exclude ./.git -cf - . | tar -C "$TMP" -xf -

# Non-vacuous pin: the adapter must exist in the copy (a renamed or
# deleted directory must not silently turn this script green).
test -d "$TMP/crates/taiji-rpc/src/aria2" || {
  echo 'FATAL: crates/taiji-rpc/src/aria2 is missing from the working tree'
  exit 1
}

# Excise: remove the adapter layer wholesale. taiji-rpc itself may now
# fail to compile (the adapter is a sacrificial skin) — it is not part
# of the check below; neither is the CLI (it depends on rpc).
rm -rf "$TMP/crates/taiji-rpc/src/aria2"

# The kernel ten must check clean with zero modifications.
(cd "$TMP" && cargo check --locked --all-targets \
  -p taiji-store -p taiji-core -p taiji-engine -p taiji-bt -p taiji-http \
  -p taiji-media -p taiji-segment -p taiji-io -p taiji-domain -p taiji-metalink)

echo 'kernel survives aria2 excision (zero kernel changes)'
