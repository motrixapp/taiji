#!/usr/bin/env python3
"""Offline report for the taiji session-metrics JSONL capture.

Input: the file written by the engine when ``BH_METRICS_TRACE=<path>``
is set — one JSON object per 1s session tick, keys = the
``MetricsSnapshot`` field names (see ``crates/taiji-engine/src/
metrics_trace.rs``; the same snapshot the rpc ``/metrics`` face
renders). Output: a Markdown report with time-series sections for the
most diagnostic families:

1. Throughput (bytes/s) — per-tick deltas of the cumulative byte
   counters (``bytes_down_tcp_total`` / ``bytes_down_utp_total`` are
   the production-fed downlink split; the aggregate ``*_total``
   counters are plotted too and are flat when unfed).
2. Peer supply by class — ``peers_by_class_{local,tcp,utp}`` gauges
   plus ``peer_inflight_active`` and the connection counts.
3. DHT — routing-table node gauges (``dht_nodes_v4/v6``) and
   per-second rates of the query-kind / inbound counters.
4. Storage pipeline — queue/in-flight watermarks and the verified
   block rate.

Rendering: PNG line charts via matplotlib when it is importable
(no hard dependency — the report degrades to sampled Markdown
tables), so the tool runs anywhere python3 does.

Usage:
    python3 scripts/metrics_report.py --input trace.jsonl
    python3 scripts/metrics_report.py --input trace.jsonl --output report.md
    python3 scripts/metrics_report.py --self-test

Self-test (CI-friendly): synthesizes a small capture, renders it, and
asserts the report contains every section — exercising the whole
pipeline without matplotlib being present.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import tempfile
from pathlib import Path

# Sections are declared as (heading, [(series key, legend label), ...])
# against whatever the capture lines actually contain; a missing key
# simply drops that series (captures from older/newer engines stay
# renderable).

SECTIONS = [
    (
        "Throughput (bytes/s)",
        [
            ("__down_rate", "down total (tcp+utp) B/s"),
            ("bytes_down_tcp_total_rate", "down tcp B/s"),
            ("bytes_down_utp_total_rate", "down utp B/s"),
            ("__up_rate", "up total B/s"),
        ],
    ),
    (
        "Peer supply by class",
        [
            ("peers_by_class_local", "local"),
            ("peers_by_class_tcp", "tcp"),
            ("peers_by_class_utp", "utp"),
            ("peer_inflight_active", "inflight-active"),
            ("conn_tcp_in", "conn tcp in"),
            ("conn_tcp_out", "conn tcp out"),
            ("conn_utp_in", "conn utp in"),
            ("conn_utp_out", "conn utp out"),
        ],
    ),
    (
        "DHT nodes and queries",
        [
            ("dht_nodes_v4", "nodes v4"),
            ("dht_nodes_v6", "nodes v6"),
            ("dht_queries_ping_total_rate", "q ping /s"),
            ("dht_queries_find_node_total_rate", "q find_node /s"),
            ("dht_queries_get_peers_total_rate", "q get_peers /s"),
            ("dht_queries_announce_peer_total_rate", "q announce /s"),
            ("dht_inbound_packets_total_rate", "in packets /s"),
            ("dht_inbound_queries_total_rate", "in queries /s"),
        ],
    ),
    (
        "Storage pipeline",
        [
            ("hashpool_queue_depth", "hash queue depth"),
            ("block_inflight", "block inflight"),
            ("blocks_verified_total_rate", "blocks verified /s"),
            ("wrcache_evict_total_rate", "wrcache evicts /s"),
        ],
    ),
]

MIB = 1024.0 * 1024.0


def fmt_bytes(v: float) -> str:
    if v >= MIB:
        return f"{v / MIB:.2f} MiB"
    if v >= 1024.0:
        return f"{v / 1024.0:.1f} KiB"
    return f"{v:.0f} B"


def fmt_count(v: float) -> str:
    if v >= 1_000_000:
        return f"{v / 1_000_000:.2f}M"
    if v >= 10_000:
        return f"{v / 1_000:.1f}k"
    return f"{v:.0f}"


def load_capture(path: Path) -> tuple[list[dict], int]:
    """Parse the JSONL capture; returns (rows, malformed-line count).

    Malformed lines (a torn tail line after a crash, stray text) are
    skipped and counted, never fatal — a diagnostic tool must render
    whatever survived.
    """
    rows: list[dict] = []
    bad = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows, bad


def ts_ms(row: dict) -> float:
    """Tick timestamp in seconds (ts_ms preferred; uptime fallback)."""
    ts = row.get("ts_ms")
    if isinstance(ts, (int, float)):
        return float(ts) / 1000.0
    return float(row.get("uptime_seconds", 0))


def derive_rate_series(rows: list[dict], key: str) -> tuple[list[float], list[float]]:
    """Per-tick rate (value/s) of a cumulative counter.

    Negative deltas (counter reset — a capture that wrapped at its size
    cap, or a restarted session appended to one file) are dropped.
    """
    xs: list[float] = []
    ys: list[float] = []
    prev_t: float | None = None
    prev_v: float | None = None
    for row in rows:
        v = row.get(key)
        if not isinstance(v, (int, float)):
            continue
        t = ts_ms(row)
        if prev_t is not None and prev_v is not None:
            dt = t - prev_t
            dv = float(v) - float(prev_v)
            if dt > 0 and dv >= 0:
                xs.append(t)
                ys.append(dv / dt)
        prev_t, prev_v = t, float(v)
    return xs, ys


def derive_gauge_series(rows: list[dict], key: str) -> tuple[list[float], list[float]]:
    xs: list[float] = []
    ys: list[float] = []
    for row in rows:
        v = row.get(key)
        if isinstance(v, (int, float)):
            xs.append(ts_ms(row))
            ys.append(float(v))
    return xs, ys


def series_for(rows: list[dict], key: str) -> tuple[list[float], list[float]]:
    """Resolve a section series key to (x seconds, y values).

    Keys ending in ``_rate`` are computed per-tick deltas of the named
    counter; ``__down_rate`` / ``__up_rate`` are the summed/fed byte
    families (down = tcp + utp split, the production-fed bridge; up =
    the aggregate upload counter).
    """
    if key == "__down_rate":
        tcp_x, tcp_y = derive_rate_series(rows, "bytes_down_tcp_total")
        utp_x, utp_y = derive_rate_series(rows, "bytes_down_utp_total")
        if not tcp_x:
            return derive_rate_series(rows, "bytes_down_total")
        ys = [a + b for a, b in zip(tcp_y, utp_y + [0.0] * (len(tcp_y) - len(utp_y)))]
        return tcp_x, ys
    if key == "__up_rate":
        return derive_rate_series(rows, "bytes_up_total")
    if key.endswith("_rate"):
        return derive_rate_series(rows, key[: -len("_rate")])
    return derive_gauge_series(rows, key)


def stats(values: list[float]) -> str:
    if not values:
        return "no samples"
    peak = max(values)
    mean = sum(values) / len(values)
    peak_unit = fmt_bytes(peak) if peak > 4096 else fmt_count(peak)
    mean_unit = fmt_bytes(mean) if mean > 4096 else fmt_count(mean)
    return f"peak {peak_unit}, mean {mean_unit}, n={len(values)}"


def render_table(
    title: str,
    series: list[tuple[str, list[float], list[float]]],
    max_rows: int,
) -> str:
    """Markdown-table fallback (sampled to max_rows lines)."""
    out: list[str] = [f"### {title}", ""]
    live = [(label, xs, ys) for label, xs, ys in series if xs]
    if not live:
        out.append("_no samples for this section_")
        out.append("")
        return "\n".join(out)
    for label, xs, ys in live:
        out.append(f"- {label}: {stats(ys)}")
    out.append("")
    step = max(1, math.ceil(len(live[0][1]) / max_rows))
    header = "| t (s) | " + " | ".join(label for label, _, _ in live) + " |"
    out.append(header)
    out.append("|---" * (len(live) + 1) + "|")
    for i in range(0, len(live[0][1]), step):
        cells = []
        for _, xs, ys in live:
            j = min(i, len(ys) - 1)
            v = ys[j]
            cells.append(fmt_bytes(v) if v > 4096 else fmt_count(v))
        t = live[0][1][i] - live[0][1][0]
        out.append(f"| {t:.0f} | " + " | ".join(cells) + " |")
    out.append("")
    return "\n".join(out)


def render_chart(
    title: str,
    series: list[tuple[str, list[float], list[float]]],
    assets_dir: Path,
    stem: str,
    mpl_pyplot,
) -> str:
    fig, ax = mpl_pyplot.subplots(figsize=(10, 4))
    plotted = False
    for label, xs, ys in series:
        if not xs:
            continue
        base = xs[0]
        ax.plot([x - base for x in xs], ys, label=label)
        plotted = True
    if not plotted:
        mpl_pyplot.close(fig)
        return f"### {title}\n\n_no samples for this section_\n\n"
    ax.set_xlabel("t (s)")
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=8, loc="best")
    fig.tight_layout()
    asset = assets_dir / f"{stem}.png"
    fig.savefig(asset, dpi=110)
    mpl_pyplot.close(fig)
    summary = "; ".join(f"{label}: {stats(ys)}" for label, xs, ys in series if xs)
    return (
        f"### {title}\n\n"
        f"![{title}]({asset.name})\n\n"
        f"{summary}\n\n"
    )


def generate_report(
    rows: list[dict],
    malformed: int,
    output: Path,
    assets_dir: Path,
    max_table_rows: int,
) -> Path:
    """Render the Markdown report; returns the output path."""
    try:
        # Headless by default: this is a batch tool, never interactive.
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as mpl_pyplot
    except ImportError:
        mpl_pyplot = None

    lines: list[str] = []
    lines.append("# taiji session metrics report")
    lines.append("")
    lines.append(
        f"- capture rows: {len(rows)} (malformed lines skipped: {malformed})"
    )
    if rows:
        t0, t1 = ts_ms(rows[0]), ts_ms(rows[-1])
        lines.append(f"- window: {t1 - t0:.0f}s (uptime {rows[0].get('uptime_seconds', '?')}s"
                     f" -> {rows[-1].get('uptime_seconds', '?')}s)")
        down = rows[-1].get("bytes_down_tcp_total", 0) + rows[-1].get(
            "bytes_down_utp_total", 0
        )
        lines.append(
            f"- cumulative: down (tcp+utp) {fmt_bytes(float(down))},"
            f" up {fmt_bytes(float(rows[-1].get('bytes_up_total', 0)))},"
            f" completed tasks {rows[-1].get('torrent_completed_total', 0)}"
        )
    lines.append(
        f"- renderer: {'matplotlib charts' if mpl_pyplot else 'markdown tables (matplotlib absent)'}"
    )
    lines.append("")

    assets_dir.mkdir(parents=True, exist_ok=True)
    for i, (title, keys) in enumerate(SECTIONS):
        series = []
        for key, label in keys:
            xs, ys = series_for(rows, key)
            series.append((label, xs, ys))
        if mpl_pyplot is not None:
            lines.append(render_chart(title, series, assets_dir, f"section_{i}", mpl_pyplot))
        else:
            lines.append(render_table(title, series, max_table_rows))

    output.write_text("\n".join(lines), encoding="utf-8")
    return output


def synthetic_capture(path: Path, ticks: int = 60) -> None:
    """Deterministic synthetic capture (the self-test input): a
    download ramp (30s up, 15s plateau, 15s drain) with peer supply
    following the ramp, a DHT table filling, and a busy pipeline."""
    down_tcp = 0
    down_utp = 0
    up = 0
    queries = {"ping": 0, "find_node": 0, "get_peers": 0, "announce_peer": 0}
    inbound = {"packets": 0, "queries": 0}
    verified = 0
    with path.open("w", encoding="utf-8") as fh:
        for i in range(ticks):
            if i < 30:
                rate = 2 * MIB * (i + 1) / 30.0
                peers = 1 + i // 4
                nodes = min(200, i * 7)
            elif i < 45:
                rate = 2 * MIB
                peers = 8
                nodes = min(200, 210 + i)
            else:
                rate = 2 * MIB * (ticks - i) / 15.0
                peers = max(1, (ticks - i) // 4)
                nodes = 200
            down_tcp += rate * 0.75
            down_utp += rate * 0.25
            up += rate * 0.1
            queries["ping"] += 2 + i % 3
            queries["find_node"] += 1
            queries["get_peers"] += 4
            queries["announce_peer"] += i % 2
            inbound["packets"] += 6
            inbound["queries"] += 3
            verified += int(rate / (16 * 1024))
            row = {
                "ts_ms": 1_700_000_000_000 + i * 1000,
                "uptime_seconds": i,
                "bytes_down_tcp_total": int(down_tcp),
                "bytes_down_utp_total": int(down_utp),
                "bytes_down_total": int(down_tcp + down_utp),
                "bytes_up_total": int(up),
                "peers_by_class_local": peers // 2,
                "peers_by_class_tcp": peers,
                "peers_by_class_utp": max(0, peers - 4),
                "peer_inflight_active": max(1, peers - 1),
                "conn_tcp_in": peers // 3,
                "conn_tcp_out": peers - peers // 3,
                "conn_utp_in": 0,
                "conn_utp_out": max(0, peers - 5),
                "dht_nodes_v4": nodes,
                "dht_nodes_v6": nodes // 10,
                "dht_queries_ping_total": queries["ping"],
                "dht_queries_find_node_total": queries["find_node"],
                "dht_queries_get_peers_total": queries["get_peers"],
                "dht_queries_announce_peer_total": queries["announce_peer"],
                "dht_inbound_packets_total": inbound["packets"],
                "dht_inbound_queries_total": inbound["queries"],
                "hashpool_queue_depth": (i * 7) % 64,
                "block_inflight": (i * 13) % 256,
                "blocks_verified_total": verified,
                "wrcache_evict_total": i // 10,
                "torrent_completed_total": 1 if i > 50 else 0,
            }
            fh.write(json.dumps(row) + "\n")


def self_test() -> int:
    """End-to-end self-test: synthetic capture -> report -> assert the
    sections exist. Exercises the exact code path a real capture takes
    (no matplotlib required)."""
    with tempfile.TemporaryDirectory(prefix="taiji-metrics-selftest-") as tmp:
        tmp_path = Path(tmp)
        capture = tmp_path / "trace.jsonl"
        synthetic_capture(capture)
        rows, bad = load_capture(capture)
        assert bad == 0 and len(rows) == 60, f"parse failed: {len(rows)} rows, {bad} bad"
        report = generate_report(
            rows, bad, tmp_path / "report.md", tmp_path / "assets", max_table_rows=30
        )
        text = report.read_text(encoding="utf-8")
        for title, _keys in SECTIONS:
            assert title in text, f"report is missing section: {title}"
        # The renderer must have produced one of the two arms, and the
        # summary must reflect real data (nonzero down bytes).
        assert "markdown tables" in text or "matplotlib charts" in text
        assert "MiB" in text, "throughput summary missing byte-scale numbers"
        try:
            import matplotlib  # noqa: F401

            pngs = list((tmp_path / "assets").glob("section_*.png"))
            assert pngs, "matplotlib present but no chart assets were written"
        except ImportError:
            assert text.count("| t (s) |") >= len(SECTIONS), "table fallback missing"
    print("metrics_report self-test passed")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render a taiji session-metrics JSONL capture to a Markdown report."
    )
    parser.add_argument("--input", type=Path, help="capture file (BH_METRICS_TRACE output)")
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="report path (default: <input>.md)",
    )
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=None,
        help="chart output directory (default: <output>_assets)",
    )
    parser.add_argument(
        "--max-table-rows",
        type=int,
        default=40,
        help="table-fallback sampling cap per section (default 40)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="synthesize a capture, render, assert sections; exit nonzero on failure",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.input is None or not args.input.exists():
        parser.error("--input is required (or pass --self-test); file not found")
    output = args.output or args.input.with_suffix(".md")
    assets = args.assets_dir or output.with_name(output.stem + "_assets")
    rows, bad = load_capture(args.input)
    if not rows:
        print(f"no parseable rows in {args.input}", file=sys.stderr)
        return 1
    generate_report(rows, bad, output, assets, args.max_table_rows)
    print(f"wrote {output} ({len(rows)} rows; assets in {assets})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
