#!/usr/bin/env python3
"""taiji: Public Suffix List (PSL) multi-label table generator.

Background: the Set-Cookie `Domain` attribute / Netscape domain-cookie
harvest defenses in `crates/taiji-http/src/cookies.rs` originally relied on
a 704-entry hand-curated static table `MULTI_LABEL_PUBLIC_SUFFIXES`. This
script migrates that table to a "script-generated checked-in table" and
consolidates the PSL wildcard/exception rules (three exact tables):

  1. Download from the official
     https://publicsuffix.org/list/public_suffix_list.dat (or pass an
     already-downloaded .dat file via `--source`, for offline regeneration);
  2. Parse per the PSL syntax (same matching semantics as the runtime
     `binary_search`, isomorphic to libpsl):
       - blank lines and `//` comment lines are ignored;
       - `!foo` exception rules: stored into the exception table after
         stripping the `!` prefix and normalizing — exceptions override
         wildcard hits, and the entry itself is a registrable domain, not
         a public suffix (e.g. `www.ck`/`city.kawasaki.jp`);
       - `*.foo` wildcard rules: stored into the wildcard table in the
         normalized form `*.tail` — `*` matches **exactly one label**:
         `*.kawasaki.jp` ⇒ `foo.kawasaki.jp` is a public suffix, while
         `bar.foo.kawasaki.jp` is a registrable domain; the tail may be a
         single label (`*.ck` ⇒ `foo.ck` rejected / `a.b.ck` allowed) or
         multi-label;
       - single-label rules (`com`): the caller's "no dot" check rejects
         first, so they are not tabled;
       - all remaining multi-label rules are stored into the exact table
         (ICANN section + PRIVATE section — shared hosting domains such as
         github.io belong to the PRIVATE section and are part of the
         harvest surface);
       - non-ASCII (unicode/IDN) entries are converted to punycode one by
         one (same convention for all three tables, matching the actual
         form a `Domain` attribute arrives in); conversion failure is a
         hard error (prevents entries silently going missing);
  3. Append the LEGACY_KEEP historical curation section: entries that were
     hand-curated early on and have since been removed by the official PSL
     (or turned into `*.` wildcard form) — removing them would weaken the
     line relative to the defense, and the false-rejection surface is only
     the pathological usage "a public suffix itself as the Domain", so
     they are frozen and kept (exact forms go into the exact table; their
     official wildcard forms such as `*.sch.uk` naturally enter the
     wildcard table in step 2; the two tables complement each other
     without conflict);
  4. After each of the three tables is sorted and deduplicated, generate
     `crates/taiji-http/src/cookies_psl_generated.rs`
     (three `&[&str]` const tables, with full source/version/sha256/
     provenance comments).

Discipline: standard library only; **this script is NOT run at build time**
(zero build.rs, zero network fetches, offline-deterministic builds); the
table content is checked in with the source, and refreshing requires an
explicit re-run:

    python3 scripts/gen_psl.py            # fetch the official list online and regenerate
    python3 scripts/gen_psl.py --check    # verify the checked-in table is in sync with the official list

Exit codes: 0 success / in sync; 1 failure, or --check found drift.
"""

import argparse
import hashlib
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = REPO_ROOT / "crates" / "taiji-http" / "src" / "cookies_psl_generated.rs"

# Minimum viable table size (sanity lower bound): the official ICANN+PRIVATE
# multi-label rules number about 8.6k entries; falling far below this means
# the source file is abnormal (truncated / wrong URL) — hard error to
# prevent generating a crippled table.
MIN_ENTRIES = 5000

# Normalized-form contract (same convention as the set self-check tests in
# cookies_psl_generated.rs): lowercase ASCII dot-separated, no leading or
# trailing dot, >= 2 labels, each label [a-z0-9-].
ENTRY_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

# Wildcard-table tail normalized-form contract: same as above but allows a
# single-label tail (the `ck` of `*.ck`).
TAIL_RE = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*$")

# Sanity lower bounds for the new tables: the official list has ~311 wildcard
# rules (ICANN geographic/political domains + PRIVATE cloud hosting domains)
# and 8 exception rules (www.ck + 7 Japanese cities), drifting only slowly
# over time; a significant shrinkage means the source file is abnormal
# (truncated / wrong URL) — hard error to prevent a crippled table.
MIN_WILDCARDS = 250
MIN_EXCEPTIONS = 4

# Historical curation retention section: as of the 2026-10-18 migration, the
# full set of entries from the old 704-entry hand-curated table that the
# official PSL no longer contains (removed by list edits, or turned into a
# `*.` wildcard form — under the wildcard form the suffix base name itself
# is no longer a public suffix, but Domain=<base name> can still tail-match
# and harvest the sites under it). Rationale for the frozen retention: see
# step 3 of the script header. Later PSL refreshes will not add to or remove
# from this section; additions/removals require a human review editing this
# spot plus a regeneration.
LEGACY_KEEP = [
    "boi.nz",        # New Zealand banking section (no exact .boi.nz rule in the current PSL)
    "cheju.kr",      # old romanization section of Jeju, South Korea
    "com.is",        # Iceland second-level (removed from the PSL after ISNIC moved to direct second-level registration)
    "com.za",
    "csiro.au",      # Australia's CSIRO agency domain
    "edu.cy",
    "edu.is",
    "gb.com",        # CentralNic commercial suffix family (removed in earlier PSL cleanups)
    "gob.pr",
    "gov.bo",
    "gov.cu",
    "gov.is",
    "gov.mt",
    "gov.pa",
    "hu.com",
    "kr.com",
    "net.is",
    "no.com",
    "or.ir",
    "org.is",
    "per.sg",
    "qc.com",
    "sch.th",
    "sch.uk",        # UK schools section (now the *.sch.uk wildcard form in the PSL)
    "se.com",
    "srl.ro",
    "taxi.hu",
    "uy.com",
    "web.hu",
    "www.pl",
    "xn--kprw13d.tw",  # Taiwan .tw (TWNIC IDN second-level; the PSL now only has the IDN TLD single-label form)
    "xn--kpry57d.tw",  # Taiwan .tw (same as above, traditional-Chinese form)
    "xn--od0agd.cn",    # Shanghai .cn (removed in the CNNIC IDN second-level cleanup)
]


def load_source(source: str) -> bytes:
    """Load the PSL source: https(s) URLs go through urllib, anything else
    is treated as a local file path."""
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={"User-Agent": "taiji-gen-psl/1.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()
    return Path(source).read_bytes()


def to_punycode(rule: str) -> str:
    """Convert unicode rules to punycode one by one (IDNA; ASCII rules pass
    through unchanged).

    Conversion failure (overlong/illegal labels etc.) is a hard error:
    prevents entries silently going missing and weakening the line.
    """
    if rule.isascii():
        return rule
    try:
        return rule.encode("idna").decode("ascii")
    except Exception as exc:  # noqa: BLE001 - per-entry conversion, single unified failure
        raise SystemExit(f"IDNA conversion failed: {rule!r}: {exc}") from exc


def parse_psl(text: str):
    """Parse the .dat text -> (icann multi-label, private multi-label,
    wildcard tails, exceptions, stats dict)."""
    icann, private = [], []
    wild, exc, single = [], [], []
    section = "icann"
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("//"):
            if "===BEGIN PRIVATE DOMAINS===" in line:
                section = "private"
            continue
        if not line:
            continue
        if line.startswith("!"):
            exc.append(line[1:])
        elif line.startswith("*."):
            wild.append(line[2:])
        elif "." not in line:
            single.append(line)
        else:
            (icann if section == "icann" else private).append(line)
    stats = {
        "wildcard": len(wild),
        "exception": len(exc),
        "single_label": len(single),
    }
    return icann, private, wild, exc, stats


def idna_roundtrip_warn(rules):
    """IDNA2003 mapping-divergence check: list entries whose punycode does
    not decode back to the original, as warnings.

    PSL unicode entries should in theory be unaffected by IDNA2003/2008
    mapping differences (no divergent characters such as ß/ς); an
    inconsistency means unusual source-data shapes and needs human review
    (not a failure).
    """
    odd = []
    for r in rules:
        if r.isascii():
            continue
        p = to_punycode(r)
        try:
            back = p.encode("ascii").decode("idna")
        except Exception:  # noqa: BLE001 - collect per-entry, single unified warning
            odd.append((r, p, "<decode failed>"))
            continue
        if back != r:
            odd.append((r, p, back))
    return odd


def build_table(icann, private):
    """Merge + punycode + normalized-form validation + sort/dedupe -> the
    final entry list."""
    merged = [to_punycode(r) for r in icann + private] + list(LEGACY_KEEP)
    for e in merged:
        if not ENTRY_RE.match(e):
            raise SystemExit(f"entry not in normalized form (abnormal source data): {e!r}")
    table = sorted(set(merged))
    if len(table) < MIN_ENTRIES:
        raise SystemExit(f"entry count {len(table)} < sanity lower bound {MIN_ENTRIES}; source file looks abnormal")
    for a, b in zip(table, table[1:]):
        if not a < b:
            raise SystemExit(f"sort invariant violated: {a!r} vs {b!r}")
    return table


def build_wildcard_table(wild):
    """Wildcard rule tails -> normalized `*.tail` form (punycode, sorted
    and deduplicated)."""
    table = sorted({"*." + to_punycode(r) for r in wild})
    for e in table:
        if not e.startswith("*.") or not TAIL_RE.match(e[2:]):
            raise SystemExit(f"wildcard entry not in normalized form (abnormal source data): {e!r}")
    if len(table) < MIN_WILDCARDS:
        raise SystemExit(f"wildcard entry count {len(table)} < sanity lower bound {MIN_WILDCARDS}; source file looks abnormal")
    for a, b in zip(table, table[1:]):
        if not a < b:
            raise SystemExit(f"wildcard table sort invariant violated: {a!r} vs {b!r}")
    return table


def build_exception_table(exc):
    """Exception rules (the `!` prefix already stripped) -> normalized form
    (punycode, sorted and deduplicated)."""
    table = sorted({to_punycode(r) for r in exc})
    for e in table:
        if not ENTRY_RE.match(e):
            raise SystemExit(f"exception entry not in normalized form (abnormal source data): {e!r}")
    if len(table) < MIN_EXCEPTIONS:
        raise SystemExit(f"exception entry count {len(table)} < sanity lower bound {MIN_EXCEPTIONS}; source file looks abnormal")
    for a, b in zip(table, table[1:]):
        if not a < b:
            raise SystemExit(f"exception table sort invariant violated: {a!r} vs {b!r}")
    return table


def render(table, wildcards, exceptions, meta, stats, gen_time_utc: str) -> str:
    """Render the Rust source file text (three exact tables)."""
    n_icann = meta["n_icann"]
    n_priv = meta["n_private"]
    n_legacy = len(LEGACY_KEEP)
    lines = [
        "//! This file is the checked-in table generated by scripts/gen_psl.py —",
        "//! do NOT hand-edit; hand edits are overwritten on the next",
        "//! regeneration;",
        "//! to refresh content or extend the long tail, change the script and",
        "//! re-run: python3 scripts/gen_psl.py.",
        "//! The generator is not run at build time (zero build.rs, zero",
        "//! network fetches, offline-deterministic builds); this file is",
        "//! checked in with the source.",
        "//!",
        f"//! Source: {meta['source_desc']}",
        f"//! Data version: {meta['version']}",
        f"//! Data commit: {meta['commit']}",
        f"//! Source sha256: {meta['sha256']}",
        f"//! Generated (UTC): {gen_time_utc}",
        "//!",
        "//! Rule semantics (three exact tables, same convention as the",
        "//! cookies.rs binary_search matching semantics, isomorphic to",
        "//! libpsl):",
        f"//! - Exact table MULTI_LABEL_PUBLIC_SUFFIXES ({len(table)} entries): ICANN",
        f"//!   section multi-label {n_icann} entries + PRIVATE section multi-label {n_priv} entries",
        "//!   (shared hosting domains such as github.io belong to the PRIVATE",
        "//!   section and are part of the harvest surface) +",
        f"//!   historical curation retention, {n_legacy} entries (hand-curated",
        "//!   early on, since removed by the official PSL or turned into",
        "//!   wildcard form; frozen to prevent weakening — see the",
        "//!   LEGACY_KEEP comment in scripts/gen_psl.py), summed after",
        "//!   sorting and deduplication;",
        f"//! - Wildcard table MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS ({len(wildcards)} entries):",
        "//!   `*.` rules in the normalized `*.tail` form — `*` matches",
        "//!   **exactly one label**; the tail may be a single label (`*.ck`)",
        "//!   or multi-label (`*.kawasaki.jp`);",
        f"//! - Exception table MULTI_LABEL_PUBLIC_SUFFIX_EXCEPTIONS ({len(exceptions)} entries):",
        "//!   `!` rules in normalized form with the `!` prefix stripped —",
        "//!   exceptions override wildcard hits; the entry itself is a",
        "//!   registrable domain (e.g. `www.ck`/`city.kawasaki.jp`);",
        f"//! - {stats['single_label']} single-label rules are not tabled (the caller's",
        "//!   \"no dot\" check rejects first).",
        "//! Data copyright: publicsuffix.org provides the source list under MPL-2.0.",
        "",
        "/// Multi-label public suffix table (normalized form: lowercase",
        "/// dot-separated punycode, leading/trailing dots stripped): a hit",
        "/// after normalizing the domain of a `Set-Cookie` `Domain` attribute /",
        "/// Netscape domain cookie means the **whole cookie is rejected**",
        "/// (semantics unchanged, covering both Set-Cookie and Netscape",
        "/// import) — tail-match would send that cookie to any site under",
        "/// that suffix (evil.me.uk harvesting `Domain=me.uk` -> sent to",
        "/// bank.me.uk). Browsers close this hole with the full PSL; this",
        "/// table is the zero-third-party checked-in table generated by",
        "/// script from the official PSL (for regeneration see the file-header",
        "/// comments).",
        "///",
        "/// Invariants (locked by the set self-check tests): **strict",
        "/// alphabetical order** — the `binary_search` precondition of",
        "/// [`is_multi_label_public_suffix`] (cookies.rs); entries in",
        "/// normalized form, no duplicates.",
        "///",
        "/// False-rejection boundary (same convention as before the migration):",
        "/// over-inclusion only affects the pathological usage \"a public",
        "/// suffix itself as the Domain attribute\" — host-only cookies and",
        "/// the Domain attribute of normal registrable domains (including",
        "/// parent/child domains) are unaffected; the anti-over-blocking",
        "/// anchor is locked by the set self-check tests.",
        "pub(crate) const MULTI_LABEL_PUBLIC_SUFFIXES: &[&str] = &[",
    ]
    lines.extend(f'    "{e}",' for e in table)
    lines.append("];")
    lines.append("")
    lines.extend([
        "/// Multi-label public suffix **wildcard rule** table (PSL `*.` rules",
        "/// in the normalized `*.tail` form: lowercase dot-separated",
        "/// punycode). Matching semantics (isomorphic to libpsl, step 3 of",
        "/// [`is_multi_label_public_suffix`] (cookies.rs)): `*` matches",
        "/// **exactly one label** — candidate = `<label>.tail` means the",
        "/// candidate itself is a public suffix (`foo.kawasaki.jp` rejected);",
        "/// one more label makes it a registrable domain",
        "/// (`bar.foo.kawasaki.jp` allowed); the tail may itself be a single",
        "/// label (`*.ck` ⇒ `foo.ck` rejected / `a.b.ck` allowed — the",
        "/// wildcard eats exactly one label). **Wildcard rules with a",
        "/// single-label tail carry no \"tail must contain another dot\"",
        "/// restriction**: per libpsl `foo.ck` IS a public suffix; adding the",
        "/// restriction would neuter the 7 single-label-tail rules such as",
        "/// `*.ck`/`*.jm` and let `Domain=foo.ck` slip through un-rejected.",
        "///",
        "/// Invariants (locked by the set self-check tests): **strict",
        "/// alphabetical order** (`binary_search` precondition); every entry",
        "/// carries the `*.` prefix, tail in normalized form, no duplicates.",
        "pub(crate) const MULTI_LABEL_PUBLIC_SUFFIX_WILDCARDS: &[&str] = &[",
    ])
    lines.extend(f'    "{e}",' for e in wildcards)
    lines.append("];")
    lines.append("")
    lines.extend([
        "/// Multi-label public suffix **exception rule** table (PSL `!` rules",
        "/// in normalized form with the `!` prefix stripped: lowercase",
        "/// dot-separated punycode). Matching semantics (isomorphic to",
        "/// libpsl, step 1 of [`is_multi_label_public_suffix`] (cookies.rs),",
        "/// taking priority over exact/wildcard): exceptions **override**",
        "/// wildcard hits — the entry itself is not a public suffix but a",
        "/// registrable domain, allowed as a `Domain` attribute / domain-",
        "/// cookie domain (`www.ck` overrides `*.ck`; `city.kawasaki.jp`",
        "/// overrides `*.kawasaki.jp`).",
        "///",
        "/// Invariants (locked by the set self-check tests): **strict",
        "/// alphabetical order**; entries in multi-label normalized form,",
        "/// no duplicates.",
        "pub(crate) const MULTI_LABEL_PUBLIC_SUFFIX_EXCEPTIONS: &[&str] = &[",
    ])
    lines.extend(f'    "{e}",' for e in exceptions)
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def extract_meta(data: bytes, source_desc: str):
    """Extract the VERSION/COMMIT comment lines and the sha256 from the
    .dat bytes (fallback markers when missing)."""
    text = data.decode("utf-8")
    version = next(
        (l.removeprefix("// VERSION: ").strip() for l in text.splitlines() if l.startswith("// VERSION: ")),
        "<no VERSION line in source file>",
    )
    commit = next(
        (l.removeprefix("// COMMIT: ").strip() for l in text.splitlines() if l.startswith("// COMMIT: ")),
        "<no COMMIT line in source file>",
    )
    return {
        "source_desc": source_desc,
        "version": version,
        "commit": commit,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="generate cookies_psl_generated.rs")
    ap.add_argument(
        "--source",
        default=PSL_URL,
        help=f"PSL source (https URL or local .dat path; default {PSL_URL})",
    )
    ap.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUT,
        help=f"output Rust file path (default {DEFAULT_OUT})",
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="write nothing; only compare the checked-in table against the source for sync (exit code 1 on drift)",
    )
    args = ap.parse_args()

    try:
        data = load_source(args.source)
    except Exception as exc:  # noqa: BLE001 - convert uniformly to a readable error
        print(f"error: failed to load the PSL source ({exc}). Offline, first download {PSL_URL}\n"
              "then re-run with --source <local path>.", file=sys.stderr)
        return 1

    text = data.decode("utf-8")
    icann, private, wild, exc, stats = parse_psl(text)
    odd = idna_roundtrip_warn(icann + private + wild + exc)
    table = build_table(icann, private)
    wildcards = build_wildcard_table(wild)
    exceptions = build_exception_table(exc)
    meta = extract_meta(data, args.source)
    meta["n_icann"] = len(icann)
    meta["n_private"] = len(private)
    gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    content = render(table, wildcards, exceptions, meta, stats, gen_time)

    print(
        f"ICANN multi-label {len(icann)} + PRIVATE multi-label {len(private)} + "
        f"legacy retention {len(LEGACY_KEEP)} -> {len(table)} entries in the exact table after dedupe+sort; "
        f"wildcard table {len(wildcards)} / exception table {len(exceptions)} entries; "
        f"not tabled: {stats['single_label']} single-label; data version {meta['version']}"
    )
    if odd:
        print("IDNA round-trip inconsistency warnings (human review; not a failure):", odd)

    if args.check:
        # The generated-time line moves with the wall clock; exclude it when
        # comparing; everything else must match to count as in sync.
        key = lambda l: l.startswith("//! Generated (UTC)")  # noqa: E731
        old = args.output.read_text(encoding="utf-8").splitlines()
        new = content.splitlines()
        if [l for l in old if not key(l)] == [l for l in new if not key(l)]:
            print(f"in sync: {args.output} matches the source")
            return 0
        print(f"drift: {args.output} does not match the source; re-run the generator", file=sys.stderr)
        return 1

    args.output.write_text(content, encoding="utf-8")
    print(f"wrote {args.output} ({len(table)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
