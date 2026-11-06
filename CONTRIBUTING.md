# Contributing Guide (CONTRIBUTING)

> This file is the public subset of taiji's engineering discipline; the full
> design spec lives in [docs/SPEC.md](docs/SPEC.md).

## Local gate (all green before every commit)

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test  --workspace --all-targets
```

## Engineering red lines (excerpt of mandatory PR rejections)

- `unsafe` is forbidden repo-wide (workspace lints); platform APIs must go
  through safe wrappers.
- **Verify before hitting disk**: every byte must pass verification before it
  reaches disk (BT: piece/Merkle; including fast-resume semantics).
- **No assuming a global piece index or globally uniform piece lengths**
  (BEP52 v2-first data model).
- `.pad` files (BEP47) are never written to disk and never appear in our own
  requests.
- The infohash is computed only over the raw info byte slice; hashing after a
  decode→re-encode round-trip is forbidden.
- Blocking operations (disk IO, >1MiB parses, hashing, subprocesses) must use
  `spawn_blocking`; blocking `std::fs`/`std::net` calls are forbidden in async
  contexts.
- Unbounded channels are forbidden; `Mutex`/`RwLock` guards must not be held
  across `await`.
- New parsers must ship a `cargo-fuzz` target (`fuzz/`) at the same time;
  protocol behavior changes must come with vector/cross-validation tests
  (reference = upstream aria2 sources, read-only citation).

## Structure and growth discipline

- **New feature = new module file**: appending implementations to existing
  oversized files is forbidden; files are split by domain, own their `use`
  statements, and never rely on facade forwarding.
- **`mod.rs` facades stay thin**: module declarations and re-exports only; no
  business logic.
- **A same-topic module family over threshold (>5 files or >5k lines) =
  crate-extraction candidate**; extraction = relocation, not rewrite, with
  public paths kept at zero drift via re-exports.

## Branches and commits

- Branches: `feat/<slug>` / `fix/<slug>`, cut from the latest main.
- Commits: conventional commits (`feat(bt): ...` / `fix(store): ...`); the
  body explains motivation and behavior changes; documentation changes get
  their own commit.
- Generated artifacts and internal orchestration artifacts are never
  committed.

### Branches and pull requests

- **main** is the default branch: contributions land as pull requests against
  it, one logical change per PR.
- Branch from the latest main (`feat/<slug>` / `fix/<slug>`); keep PRs
  focused — a behavior change and its tests together, unrelated refactors in
  a separate PR.
- A PR is merged only with the full local gate green (above) and the PR
  description listing the behavior changes item by item.

## Definition of Done (DoD)

1. Full gate; 2. the PR description lists the behavior changes item by item;
3. new protocol behavior has tests, new parsers have fuzz targets;
4. `docs/SPEC.md` is updated if affected (SPEC vs code conflict = bug: fix the
code or fix the SPEC); 5. no leftover `todo!()` (or an issue is filed).

## Dependencies

New third-party dependencies must state their purpose and maintenance status;
the license must be compatible with GPL-2.0-or-later (Apache-2.0/MIT/BSD are
fine), and the purpose must be noted next to the workspace dependency in
`Cargo.toml`.

## License

GPL-2.0-or-later. Submitting a contribution means you agree to release it
under the same license.
