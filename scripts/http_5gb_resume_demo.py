#!/usr/bin/env python3
"""`taiji http` >=5GiB end-to-end demo: mock origin + throttle + kill -9 +
resume + final checksum verdict (B0 delivery criterion: CLI multi-connection
download >=5GB, kill -9 resume).

Flow (fully reproducible, zero external network dependencies):
  1. cargo build --bin taiji (debug; pass --release to speed up);
  2. in-process mock origin (HTTP/1.1 206 Range in all forms + per-chunk
     throttling), content = deterministic periodic pattern (zero-material
     slicing at any offset);
  3. stream-compute the pattern's ground-truth sha-256 (expected checksum;
     no 5GiB buffer materialized);
  4. first run: start `taiji http --checksum <expected>` in the background
     -> poll the session-store bitmap snapshot (>= --min-blocks completed
     blocks, after the 2s debounce and before completion settles) ->
     **kill -9** the pinned pid;
  5. assert the `.part` half-built state survived and no final file exists;
  6. second run: restart with the same args -> bootstrap rebuild + bitmap
     resume (mock records corroborate that block 0 is not refetched) ->
     the final checksum verdict closes out at completion;
  7. independent verdict: streaming sha-256(final file) == expected
     (cross-confirms the engine's own verdict);
  8. print a run summary (kill point / bytes per run / hashes / timing).

Usage (repo root):
  python3 scripts/http_5gb_resume_demo.py [--release] [--keep]
      [--size-gib 5] [--rate-mib-s 32] [--min-blocks 8] [--inject-fail]

Disk budget: the work dir transiently holds ~5GiB (.part prealloc) + 5GiB
(final file) side by side; confirm enough free space (self-checked at
startup).

Failure-path discipline: all assertions funnel through try/finally —
whether success, assertion failure, or injected failure, the finally block
kills live child processes, stops the mock, and cleans the work dir
(.part/db/final file all removed, no >=4GiB residue); only the phase logs
are copied out to /tmp for forensic retention. --inject-fail = deliberate
failure injection (fails right after the phase-1 start; negative control
for the failure-cleanup path; exempt from the >=5GiB criterion assertion —
not a verdict run, may be small).
"""

from __future__ import annotations

import argparse
import hashlib
import os
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CHUNK_SERVE = 256 * 1024          # mock per-chunk send granularity
PATTERN_BLOCK = 64 * 1024         # deterministic content pattern period (offset-independent periodic block)
DB_POLL_INTERVAL = 0.1


def log(msg: str) -> None:
    print(f"[demo] {msg}", flush=True)


# ---------------------------------------------------------------- content

def pattern_block() -> bytes:
    return bytes((i * 31 + 7) % 256 for i in range(PATTERN_BLOCK))


def pattern_sha256(total: int) -> str:
    """Ground-truth sha-256 of the pattern content (streamed; no
    full-length buffer materialized)."""
    block = pattern_block()
    h = hashlib.sha256()
    done = 0
    while done < total:
        n = min(len(block), total - done)
        h.update(block[:n])
        done += n
    return h.hexdigest()


def file_sha256(path: Path, bufsize: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(bufsize)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- mock origin

class RangeServer:
    """HTTP/1.1 Range full-form mock origin (206/200 + per-chunk throttling).

    `phases[phase]` = [(start, end_incl), ...]: data Range samples taken
    (probe bytes=0-0 not counted). The script flips phase around the kill —
    the evidence surface for resume "does not refetch block 0".
    """

    def __init__(self, total: int, rate_mib_s: float):
        self.total = total
        self.delay = (CHUNK_SERVE / (rate_mib_s * 1024 * 1024)) if rate_mib_s > 0 else 0.0
        self.phases: dict[int, list[tuple[int, int]]] = {0: [], 1: []}
        self.phase = 0
        self.lock = threading.Lock()
        self._block = pattern_block()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence the default access log
                pass

            def handle(self):
                # after kill -9, in-flight connection resets are the expected
                # path; keep the log unpolluted.
                try:
                    super().handle()
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):
                rng = self.headers.get("Range")
                if rng is None:
                    self._serve_200()
                    return
                # Range: bytes=s-e (probe 0-0 or the data plane).
                spec = rng.strip().lower().removeprefix("bytes=")
                s, _, e = spec.partition("-")
                try:
                    start, end = int(s), int(e)
                except ValueError:
                    self._serve_200()
                    return
                if start == 0 and end == 0:
                    # probe: 1-byte body.
                    body = outer._block[:1]
                    self.send_response(206)
                    self.send_header("Content-Range", f"bytes 0-0/{outer.total}")
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Content-Length", "1")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                with outer.lock:
                    outer.phases[outer.phase].append((start, end))
                end = min(end, outer.total - 1)
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{end}/{outer.total}")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(end - start + 1))
                self.end_headers()
                off = start
                try:
                    while off <= end:
                        n = min(CHUNK_SERVE, end - off + 1)
                        self.wfile.write(outer._slice(off, n))
                        off += n
                        if outer.delay:
                            time.sleep(outer.delay)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # in-flight response cut by kill -9; normal path.

            def _serve_200(self):
                self.send_response(200)
                self.send_header("Content-Length", str(outer.total))
                self.send_header("Accept-Ranges", "bytes")
                self.end_headers()
                try:
                    for off in range(0, outer.total, CHUNK_SERVE):
                        n = min(CHUNK_SERVE, outer.total - off)
                        self.wfile.write(outer._slice(off, n))
                        if outer.delay:
                            time.sleep(outer.delay)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()

    def _slice(self, off: int, n: int) -> bytes:
        # periodic-block slicing (zero-material generation on the send side).
        block = self._block
        base = off % len(block)
        out = bytearray()
        while len(out) < n:
            take = min(len(block) - base, n - len(out))
            out += block[base : base + take]
            base = 0
        return bytes(out)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/demo-5g.bin"

    def served_bytes(self, phase: int) -> int:
        return sum(e - s + 1 for s, e in self.phases[phase])


# ---------------------------------------------------------------- helpers

def bitmap_done_blocks(db: Path) -> int | None:
    """http_task bitmap completed-block count (read-only WAL polling; None
    when there is no bitmap row)."""
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
    except sqlite3.Error:
        return None
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        rows = conn.execute(
            "SELECT block_bitmap FROM http_task WHERE block_bitmap IS NOT NULL"
        ).fetchall()
    except sqlite3.Error:
        return None
    finally:
        conn.close()
    if not rows:
        return None
    return max(sum(bin(b).count("1") for b in row[0]) for row in rows)


def wait_bitmap(db: Path, min_blocks: int, timeout_s: float) -> tuple[int, float]:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout_s:
        n = bitmap_done_blocks(db)
        if n is not None and n >= min_blocks:
            return n, time.monotonic() - t0
        time.sleep(DB_POLL_INTERVAL)
    raise SystemExit(
        f"FAIL: bitmap snapshot with >= {min_blocks} blocks not reached in {timeout_s:.0f}s"
    )


def run_child(cmd: list[str], log_path: Path) -> subprocess.Popen:
    log_f = open(log_path, "w")
    return subprocess.Popen(cmd, stdout=log_f, stderr=subprocess.STDOUT)


def fail(msg: str):
    """Single assertion-failure exit: SystemExit pierces the finally-block
    cleanup."""
    raise SystemExit(f"FAIL: {msg}")


def preserve_logs(work: Path) -> Path | None:
    """Failure forensics: copy the phase logs to a persistent location
    before cleanup destroys the artifacts."""
    logs = sorted(work.glob("*.log"))
    if not logs:
        return None
    dest = Path(tempfile.mkdtemp(prefix="tj-5gb-demo-logs-"))
    for p in logs:
        shutil.copy2(p, dest / p.name)
    return dest


# ---------------------------------------------------------------- demo

def main() -> int:
    ap = argparse.ArgumentParser(description="taiji http >=5GiB kill -9 resume demo")
    ap.add_argument("--release", action="store_true", help="cargo build --release")
    ap.add_argument("--size-gib", type=float, default=5.0, help="content size (GiB, default 5)")
    ap.add_argument("--rate-mib-s", type=float, default=32.0, help="mock throttle (MiB/s)")
    ap.add_argument("--min-blocks", type=int, default=8, help="minimum completed bitmap blocks before the kill")
    ap.add_argument("--keep", action="store_true", help="keep the work dir (forensics)")
    ap.add_argument(
        "--smoke", action="store_true",
        help="mechanism smoke test (64MiB, no >=5GiB criterion enforced; not acceptance evidence)",
    )
    ap.add_argument(
        "--inject-fail", action="store_true",
        help="negative injection: deliberately fail once after phase 1 starts, "
             "exercising the failure-cleanup path (.part/db purged, logs kept for "
             "forensics, no large-file residue); "
             "not a verdict run — exempt from the >=5GiB assertion, may be small",
    )
    args = ap.parse_args()

    if args.smoke:
        total = 64 * 1024 * 1024
        # smoke shape: lower the rate/threshold so the kill lands mid-download
        # (at full speed 64MiB would finish before the 2s-debounce snapshot).
        rate = min(args.rate_mib_s, 8.0)
        min_blocks = min(args.min_blocks, 2)
    else:
        total = int(args.size_gib * 1024**3)
        rate = args.rate_mib_s
        min_blocks = args.min_blocks
        if not args.inject_fail:
            assert total >= 5 * 1024**3, "demo criterion requires >=5GiB"

    repo = Path(__file__).resolve().parent.parent
    build = ["cargo", "build"] + (["--release"] if args.release else []) + ["--bin", "taiji"]
    log(f"building: {' '.join(build)}")
    subprocess.run(build, cwd=repo, check=True)
    taiji = repo / "target" / ("release" if args.release else "debug") / "taiji"

    work = Path(tempfile.mkdtemp(prefix="tj-5gb-demo-"))
    dl = work / "dl"
    dl.mkdir()
    db = work / "taiji.sqlite3"
    final_file = dl / "demo-5g.bin"
    part_file = dl / "demo-5g.bin.part"

    free = shutil.disk_usage(work).free
    need = int(total * 2.1)
    if free < need:
        raise SystemExit(
            f"FAIL: insufficient disk for demo: free {free/2**30:.1f}GiB < need {need/2**30:.1f}GiB"
        )

    log(f"work dir: {work}")
    log(f"content: {total} bytes ({total/2**30:.2f} GiB), deterministic pattern")
    t0 = time.monotonic()
    expected = pattern_sha256(total)
    log(f"expected sha-256: {expected} (computed in {time.monotonic()-t0:.1f}s)")

    server = RangeServer(total, rate)
    server.start()
    log(f"mock origin: {server.url} (throttle {rate} MiB/s)")

    cmd = [
        str(taiji), "http", server.url,
        "-d", str(dl),
        "-o", "demo-5g.bin",
        "--checksum", f"sha-256={expected}",
        "--sqlite3-db-path", str(db),
    ]

    # success / assertion failure / injected failure all funnel through the
    # same finally — kill live children, stop the mock, clean the work dir
    # (.part/db/final file, no >=4GiB residue); only logs kept for forensics.
    ok = False
    p1 = None
    p2 = None
    try:
        if args.inject_fail:
            log("phase 1: INJECT-FAIL — aborting mid-download on purpose "
                "(negative control for the failure-cleanup path)")
            p1 = run_child(cmd, work / "phase1.log")
            time.sleep(3.0)  # let .part prealloc / the startup surface settle
            fail("injected failure (negative control for the failure-cleanup path)")

        # ---- run 1: pinned kill -9 interrupt ----
        log(f"phase 1: start download, kill after >= {min_blocks} bitmap blocks")
        p1 = run_child(cmd, work / "phase1.log")
        blocks, waited = wait_bitmap(db, min_blocks, timeout_s=120)
        log(f"phase 1: bitmap snapshot reached {blocks} blocks (waited {waited:.1f}s) -> kill -9 {p1.pid}")
        os.kill(p1.pid, signal.SIGKILL)
        rc1 = p1.wait()
        server.phase = 1
        log(f"phase 1: killed (wait rc={rc1})")
        time.sleep(0.5)  # settle window for kernel reclamation (flock/handle release).

        if not part_file.exists():
            fail(".part must survive the kill -9")
        if final_file.exists():
            fail("no final file may exist after the kill -9")
        part_len = part_file.stat().st_size
        log(f"phase 1: .part preserved (prealloc {part_len} bytes), no final file")

        # ---- run 2: same-args restart -> bootstrap resume to completion ----
        log("phase 2: restart same args -> bootstrap rebuild + bitmap resume + checksum verdict")
        t2 = time.monotonic()
        p2 = run_child(cmd, work / "phase2.log")
        rc2 = p2.wait()
        phase2_wall = time.monotonic() - t2
        out2 = (work / "phase2.log").read_text(errors="replace")
        if rc2 != 0:
            fail(f"resume run exit {rc2}\n{out2[-2000:]}")
        if "resuming in-flight" not in out2:
            fail(f"resume must attach in-flight task\n{out2[-2000:]}")
        if part_file.exists():
            fail(".part must be renamed after completion")
        if not final_file.exists():
            fail("final file missing")
        log(f"phase 2: exit 0 in {phase2_wall:.1f}s (attached + resumed + checksum verified)")

        # ---- independent verdict ----
        log("verdict: independent streaming sha-256 of final file")
        t3 = time.monotonic()
        got = file_sha256(final_file)
        if got != expected:
            fail(f"sha mismatch\ngot      {got}\nexpected {expected}")
        log(f"verdict: sha-256 MATCH ({got}) in {time.monotonic()-t3:.1f}s")

        # ---- resume evidence (mock sampling surface) ----
        p1_ranges = server.phases[0]
        p2_ranges = server.phases[1]
        if not p1_ranges or p1_ranges[0][0] != 0:
            fail("phase1 must fetch from offset 0")
        if not p2_ranges:
            fail("phase2 must actually fetch the remaining data")
        if any(s <= 0 for s, _ in p2_ranges):
            fail("phase2 must not refetch block 0 (bitmap-resume evidence)")

        print("\n==== DEMO SUMMARY ====")
        mode = ("SMOKE (not a verdict run)" if args.smoke else
                "VERDICT (>=5GiB)")
        print(f"mode           : {mode}")
        print(f"content        : {total} bytes ({total/2**30:.2f} GiB), sha-256 {expected}")
        print(f"throttle       : {rate} MiB/s (single connection)")
        print(f"kill -9 at     : bitmap {blocks} blocks done (~{blocks*4} MiB), phase1 log {work/'phase1.log'}")
        print(f"phase1 served  : {server.served_bytes(0)} bytes in {len(p1_ranges)} data ranges")
        print(f"phase2 served  : {server.served_bytes(1)} bytes in {len(p2_ranges)} data ranges "
              f"(min offset {min(s for s, _ in p2_ranges)} > 0: resume without refetch)")
        print(f"phase2 wall    : {phase2_wall:.1f}s to green")
        print(f"final file     : {final_file} ({final_file.stat().st_size} bytes), sha-256 verified")
        print(f"engine verdict : --checksum sha-256 accepted (exit 0), .part renamed")
        print("======================\n")
        ok = True
    finally:
        for p in (p1, p2):
            if p is not None and p.poll() is None:
                try:
                    p.send_signal(signal.SIGKILL)
                except OSError:
                    pass
                p.wait()
        server.stop()
        if args.keep:
            log(f"work dir kept: {work}")
        else:
            forensic = preserve_logs(work) if not ok else None
            shutil.rmtree(work, ignore_errors=True)
            if ok:
                log("work dir cleaned")
            else:
                log(f"failure path: .part/db/final purged (no large-file residue), "
                    f"logs preserved for forensics: {forensic}")
        if not args.keep and work.exists():
            log(f"WARNING: residue detected — work dir not fully removed: {work}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
