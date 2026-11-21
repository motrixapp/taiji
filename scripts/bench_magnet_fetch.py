#!/usr/bin/env python3
"""Compare native magnet fetching using the engine's infoValidatedUs clock.

Requires the same optional Python dependencies as bench_magnet_ws.py.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import random
import statistics
import time
from pathlib import Path

import libtorrent as lt
from websockets.asyncio.client import connect

from bench_magnet import Daemon, Fixture
from bench_magnet_ws import WebSocketRpc, check_info, wait_ready


SCENARIOS = (
    "healthy", "rtt-single", "rtt-staggered", "rtt-mixed", "metadata-stall",
    "dead-peers", "dead-trackers", "slow-blocks", "v2-32k", "v2-513",
    "v2-file-tree", "dial-contention",
)


async def fetch(rpc, fixture, gid, directory, timeout):
    rpc.ready[gid] = asyncio.Event()
    deadline = time.monotonic() + timeout
    before = fixture.counters.copy()
    trace_start = len(fixture.trace)
    row = {"outcome": "error", "elapsed_ms": None}
    try:
        returned = await rpc.call("taiji.addUri", [[fixture.magnet], {
            "gid": gid, "motrix-await-selection": "true",
            "bt-save-metadata": "false", "dir": str(directory),
        }], timeout)
        if returned != gid:
            raise RuntimeError("engine changed reserved identity")
        await wait_ready(rpc, gid, deadline, "notify", 0.02)
        result = await rpc.call("taiji.getTorrentManifest", [gid], max(.001, deadline-time.monotonic()))
        if not result["awaitingSelection"]:
            raise RuntimeError("native selection barrier missing")
        expected = check_info(lt.torrent_info(base64.b64decode(result["data"])), fixture)
        if result["manifest"]["infoHash"] != str(expected.v1 if expected.has_v1() else expected.v2):
            raise RuntimeError("manifest identity mismatch")
        if len(result["manifest"]["files"]) != fixture.file_count:
            raise RuntimeError("manifest file count mismatch")
        if fixture.counters.get("payload_requests", 0):
            raise RuntimeError("unexpected payload request")
        row["outcome"] = "success"
    except TimeoutError as error:
        row.update(outcome="timeout", error=str(error))
    except Exception as error:
        row["error"] = str(error)
    try:
        resolution = await rpc.call("taiji.getMagnetResolution", [gid])
        row["resolution"] = resolution
        us = resolution.get("infoValidatedUs")
        if row["outcome"] == "success":
            if not isinstance(us, int) or us < 0:
                raise RuntimeError("engine has no infoValidatedUs measurement")
            if us > timeout * 1_000_000:
                row.update(outcome="timeout", error="engine validation exceeded deadline")
            else:
                row["elapsed_ms"] = us / 1000
    except Exception as error:
        if row["outcome"] == "success":
            row.update(outcome="error", error=str(error))
    row["counters"] = {key: value-before.get(key, 0) for key, value in fixture.counters.items()}
    row["peer_trace"] = fixture.trace[trace_start:]
    return row


async def reset_fixture(fixture):
    handlers = list(fixture.handlers)
    for task in handlers:
        task.cancel()
    await asyncio.gather(*handlers, return_exceptions=True)
    fixture.counters = dict.fromkeys(fixture.counters, 0)
    fixture.trace.clear()
    fixture.responded_pieces.clear()
    fixture.started = time.monotonic()


async def run_case(binary, fixtures, directory, args):
    daemon = Daemon("taiji", binary, directory, peer_connection_type="tcp")
    rpc = None
    try:
        await daemon.start()
        url = daemon.rpc.url.replace("http://", "ws://", 1)
        socket = await connect(url, proxy=None, max_size=32*1024*1024,
                               ping_interval=None, close_timeout=1)
        rpc = WebSocketRpc(socket)
        if args.prepare_ms:
            await rpc.call("taiji.prepareBitTorrent", [])
            await asyncio.sleep(args.prepare_ms / 1000)
        primed = []
        if args.cache == "memory":
            primed = await asyncio.gather(*(
                fetch(rpc, fixture, f"{index+1:016x}", directory/"initial", args.timeout)
                for index, fixture in enumerate(fixtures)
            ))
            for index, row in enumerate(primed):
                if row["outcome"] != "success":
                    raise RuntimeError(f"cache setup failed: {row}")
                gid = f"{index+1:016x}"
                await rpc.call("taiji.forceRemove", [gid])
            for fixture in fixtures:
                await reset_fixture(fixture)
                # The next resolution may only use the cache. Leave the same
                # tracker list in the URI to detect unexpected network work.
        rows = await asyncio.gather(*(
            fetch(rpc, fixture, f"{index+101:016x}", directory/"preview", args.timeout)
            for index, fixture in enumerate(fixtures)
        ))
        for index, row in enumerate(rows):
            if primed:
                row["cache_prime"] = primed[index]
            if row["outcome"] != "success":
                continue
            cache = row["resolution"]["cache"]
            if args.cache == "memory" and (cache != "memory" or any(row["counters"].values())):
                row.update(outcome="error", elapsed_ms=None, error="expected memory cache with no network work")
            elif args.cache == "cold" and cache is not None:
                row.update(outcome="error", elapsed_ms=None, error=f"unexpected {cache} cache hit")
        return rows
    except Exception as error:
        return [{"outcome": "error", "elapsed_ms": None, "error": str(error),
                 "counters": fixture.counters.copy()} for fixture in fixtures]
    finally:
        if rpc:
            await rpc.close()
        await daemon.close()
        for fixture in fixtures:
            await reset_fixture(fixture)


def summarize(rows):
    summary = {}
    counters = ("announces", "silent_tracker_accepts", "silent_peer_accepts", "connections",
                "metadata_request_frames", "metadata_bytes", "duplicate_metadata_bytes")
    for key in sorted({f"{r['scenario']}/{r['client']}" for r in rows}):
        group = [r for r in rows if f"{r['scenario']}/{r['client']}" == key]
        timings = sorted(r["elapsed_ms"] for r in group if r["outcome"] == "success")
        summary[key] = {
            "runs": len(group), "successes": len(timings),
            "timeouts": sum(r["outcome"] == "timeout" for r in group),
            "errors": sum(r["outcome"] == "error" for r in group),
            "p50_ms": statistics.median(timings) if timings else None,
            "p95_ms": timings[(95*len(timings)+99)//100-1] if timings else None,
            "counter_totals": {name: sum(r["counters"].get(name, 0) for r in group) for name in counters},
        }
    return summary


async def main(args):
    args.output.mkdir(parents=True, exist_ok=False)
    clients = {"baseline": args.baseline.resolve()}
    if args.candidate:
        clients["candidate"] = args.candidate.resolve()
    config = {
        "baseline": str(args.baseline.resolve()), "candidate": str(args.candidate.resolve()) if args.candidate else None,
        "binary_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in clients.items()},
        "samples_per_scenario": args.samples, "seed": args.seed, "cache": args.cache,
        "scenarios": args.scenarios, "timeout_s": args.timeout, "prepare_ms": args.prepare_ms,
        "peer_connection_type": "tcp", "dht": False, "peer_profiles": Fixture.PEER_PROFILES,
        "clock": "taiji.getMagnetResolution.infoValidatedUs", "reference_decoder": lt.version,
    }
    (args.output/"config.json").write_text(json.dumps(config, indent=2)+"\n")
    rng = random.Random(args.seed)
    rows = []
    with (args.output/"runs.jsonl").open("w", buffering=1) as raw:
        for iteration in range(args.samples):
            scenarios = args.scenarios.split(",")
            rng.shuffle(scenarios)
            for scenario in scenarios:
                fixtures = []
                try:
                    parallel = 6 if scenario == "dial-contention" else 1
                    for index in range(parallel):
                        fixture = Fixture(scenario, iteration*parallel+index, "127.0.0.1")
                        fixtures.append(fixture)
                        await fixture.start()
                        rng.shuffle(fixture.peers)
                    order = list(clients)
                    rng.shuffle(order)
                    for name in order:
                        directory = args.output / f"{iteration}-{scenario}-{name}"
                        results = await run_case(clients[name], fixtures, directory, args)
                        for index, (fixture, row) in enumerate(zip(fixtures, results, strict=True)):
                            row.update(client=name, scenario=scenario, iteration=iteration,
                                       task=index, order=order, info_bytes=len(fixture.info),
                                       file_count=fixture.file_count,
                                       healthy_peer_positions=[fixture.peers.index(p)+1 for p in fixture.healthy_peers])
                            print(json.dumps(row), file=raw)
                            rows.append(row)
                finally:
                    for fixture in fixtures:
                        await fixture.close()
    summary = summarize(rows)
    (args.output/"results.json").write_text(json.dumps({
        "config": config, "summary": summary, "runs": rows,
    }, indent=2)+"\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS))
    parser.add_argument("--seed", type=int, default=44)
    parser.add_argument("--timeout", type=float, default=7)
    parser.add_argument("--prepare-ms", type=float, default=50)
    parser.add_argument("--cache", choices=["cold", "memory"], default="cold")
    args = parser.parse_args()
    if set(args.scenarios.split(",")) - set(SCENARIOS):
        parser.error("unknown scenario")
    asyncio.run(main(args))
