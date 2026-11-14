#!/usr/bin/env python3
"""Compare magnet file-list latency using isolated synthetic tracker/peer fixtures.

Requires the optional libtorrent Python wheel, plus transmission-daemon for that
reference. No public swarm, user profile, or system service is touched.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import random
import shutil
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import libtorrent as lt


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Fixture:
    def __init__(self, scenario, iteration, peer_host):
        self.peer_host = peer_host
        info = {
            b"name": f"magnet-bench-{scenario}-{iteration}.bin".encode(),
            b"length": 32768,
            b"piece length": 16384,
            b"pieces": hashlib.sha1(bytes(16384)).digest() * 2,
        }
        if scenario == "slow-blocks":
            info[b"x-benchmark-padding"] = bytes(128 * 1024)
        self.v2 = scenario in {"v2-32k", "v2-513"}
        if self.v2:
            piece_length, pieces = (32768, 2) if scenario == "v2-32k" else (16384, 513)
            blocks = piece_length // 16384 * pieces
            nodes = [hashlib.sha256(bytes(16384)).digest()] * blocks
            nodes += [bytes(32)] * ((1 << (len(nodes) - 1).bit_length()) - len(nodes))
            while len(nodes) > 1:
                nodes = [hashlib.sha256(nodes[i] + nodes[i + 1]).digest()
                         for i in range(0, len(nodes), 2)]
            info = {b"name": f"{scenario}-{iteration}.bin".encode(), b"meta version": 2,
                    b"piece length": piece_length,
                    b"file tree": {b"payload.bin": {b"": {
                        b"length": piece_length * pieces, b"pieces root": nodes[0]}}}}
        self.info = lt.bencode(info)
        self.identity = (hashlib.sha256 if self.v2 else hashlib.sha1)(self.info).digest()
        self.hash = self.identity[:20]
        self.scenario = scenario
        self.public = False
        self.file_count = 1
        self.servers = []
        self.handlers = set()
        self.counters = {"announces": 0, "connections": 0, "metadata_requests": 0,
                         "metadata_bytes": 0}
        self.trackers = []
        self.peers = []
        self.healthy_peers = []
        self.responded_pieces = set()

    async def server(self, callback, peer=False):
        async def track(reader, writer):
            task = asyncio.current_task()
            self.handlers.add(task)
            try:
                await callback(reader, writer)
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                pass
            finally:
                self.handlers.discard(task)
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
        server = await asyncio.start_server(track, self.peer_host if peer else "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def start(self):
        async def blackhole(reader, _writer):
            await reader.read()
        for _ in range(64 if self.scenario == "dead-peers" else 0):
            self.peers.append(await self.server(blackhole, peer=True))
        for index in range(4 if self.scenario == "slow-blocks" else 1):
            async def peer(reader, writer, index=index):
                return await self.peer(reader, writer, index)
            self.peers.append(await self.server(peer, peer=True))
            self.healthy_peers.append(self.peers[-1])
        for _ in range(24 if self.scenario == "dead-trackers" else 0):
            port = await self.server(blackhole)
            self.trackers.append(f"http://127.0.0.1:{port}/announce")
        port = await self.server(self.tracker)
        self.trackers.append(f"http://127.0.0.1:{port}/announce")
        return self

    @property
    def magnet(self):
        return "magnet:?xt=urn:" + ("btmh:1220" if self.v2 else "btih:") + self.identity.hex() + "".join(
            "&tr=" + urllib.parse.quote(url, safe="") for url in self.trackers)

    async def tracker(self, reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        self.counters["announces"] += 1
        peers = b"".join(socket.inet_aton(self.peer_host) + struct.pack(">H", port)
                         for port in self.peers)
        body = lt.bencode({b"interval": 3600, b"peers": peers})
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()

    async def peer(self, reader, writer, index):
        self.counters.setdefault("accepted", 0)
        self.counters["accepted"] += 1
        handshake = await reader.readexactly(68)
        if handshake[28:48] != self.hash:
            self.counters.setdefault("non_plain_handshakes", 0)
            self.counters["non_plain_handshakes"] += 1
            return
        self.counters["connections"] += 1
        reserved = bytearray(8)
        reserved[5] = 0x10
        if self.v2:
            reserved[7] = 0x10
        peer_id = b"-BM0001-" + f"{index:012d}".encode()
        writer.write(b"\x13BitTorrent protocol" + reserved + self.hash + peer_id)
        def send(extension, data):
            writer.write(struct.pack(">IBB", len(data) + 2, 20, extension) + data)
        send(0, lt.bencode({b"m": {b"ut_metadata": 7}, b"metadata_size": len(self.info)}))
        await writer.drain()
        remote_id = 2
        while True:
            length = struct.unpack(">I", await reader.readexactly(4))[0]
            if length > 1024 * 1024:
                return
            message = await reader.readexactly(length)
            if message and message[0] == 6:
                self.counters["payload_requests"] = self.counters.get("payload_requests", 0) + 1
            if len(message) < 2 or message[0] != 20:
                continue
            value = lt.bdecode(message[2:])
            if message[1] == 0:
                remote_id = value.get(b"m", {}).get(b"ut_metadata", 2)
            elif message[1] == 7 and value.get(b"msg_type") == 0:
                piece = int(value[b"piece"])
                block = self.info[piece * 16384:(piece + 1) * 16384]
                if not block:
                    send(remote_id, lt.bencode({b"msg_type": 2, b"piece": piece}))
                else:
                    if self.scenario == "slow-blocks":
                        await asyncio.sleep(0.05)
                    self.counters["metadata_requests"] += 1
                    self.counters["metadata_bytes"] += len(block)
                    if piece in self.responded_pieces:
                        self.counters["duplicate_metadata_bytes"] = self.counters.get("duplicate_metadata_bytes", 0) + len(block)
                    self.responded_pieces.add(piece)
                    send(remote_id, lt.bencode({b"msg_type": 1, b"piece": piece,
                                              b"total_size": len(self.info)}) + block)
                await writer.drain()

    async def close(self):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(s.wait_closed() for s in self.servers))
        tasks = list(self.handlers)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class PublicTorrent:
    """Explicit opt-in: derive a magnet without supplying metainfo to any client."""
    def __init__(self, path, scenario):
        info = lt.torrent_info(str(path))
        self.info = info.info_section()
        self.file_count = info.num_files()
        self.public = True
        self.peer_host = "0.0.0.0"
        self.counters = {}
        query = urllib.parse.parse_qsl(lt.make_magnet_uri(info).split("?", 1)[1])
        allowed = {"xt", "dn"} if scenario == "public-dht" else {"xt", "dn", "tr"}
        self.magnet = "magnet:?" + urllib.parse.urlencode([(k,v) for k,v in query if k in allowed], safe=":")

    async def start(self):
        return self

    async def close(self):
        return None


class HttpRpc:
    def __init__(self, url, transmission=False):
        self.url = url
        self.transmission = transmission
        self.session_id = ""
        self.sequence = 0

    def request(self, method, params):
        self.sequence += 1
        payload = ({"method": method, "arguments": params} if self.transmission
                   else {"jsonrpc": "2.0", "id": self.sequence, "method": method,
                         "params": ["token:benchmark-secret", *params]})
        data = json.dumps(payload).encode()
        for _ in range(2):
            request = urllib.request.Request(self.url, data, {
                "Content-Type": "application/json",
                "X-Transmission-Session-Id": self.session_id,
            })
            try:
                # Loopback fixture calls must never inherit an environment proxy.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(request, timeout=5) as response:
                    result = json.load(response)
                if self.transmission:
                    if result.get("result") != "success":
                        raise RuntimeError(result)
                    return result["arguments"]
                if result.get("error"):
                    raise RuntimeError(result["error"])
                return result["result"]
            except urllib.error.HTTPError as error:
                if self.transmission and error.code == 409:
                    self.session_id = error.headers["X-Transmission-Session-Id"]
                else:
                    raise
        raise RuntimeError("Transmission session negotiation failed")

    async def call(self, method, params):
        return await asyncio.to_thread(self.request, method, params)


class Daemon:
    def __init__(self, kind, binary, directory, public=False):
        self.kind, self.binary, self.directory = kind, binary, directory
        self.public = public
        self.process = None
        self.log = None
        self.version = None

    async def start(self):
        self.directory.mkdir(parents=True)
        downloads = self.directory / "downloads"
        downloads.mkdir()
        port = free_port()
        if self.kind == "transmission":
            settings = {
                "rpc_enabled": True, "rpc_authentication_required": False,
                "rpc_bind_address": "127.0.0.1",
                "rpc_whitelist_enabled": False, "rpc_host_whitelist_enabled": False,
                "dht_enabled": self.public, "lpd_enabled": False, "pex_enabled": self.public,
                "port_forwarding_enabled": False, "utp_enabled": self.public,
                "encryption": 1 if self.public else 0,
                "preallocation": 0,
                "peer_limit_global": 500, "peer_limit_per_torrent": 128,
            }
            (self.directory / "settings.json").write_text(json.dumps(settings))
            args = [self.binary, "--foreground", "--config-dir", str(self.directory),
                    "--port", str(port), "--no-auth", "--dht" if self.public else "--no-dht", "--no-lpd",
                    "--no-portmap", "--peerport", str(free_port()),
                    "--download-dir", str(downloads), "--log-level=error"]
            self.rpc = HttpRpc(f"http://127.0.0.1:{port}/transmission/rpc", True)
            method, params = "session-get", {}
        else:
            args = [self.binary, "--enable-rpc=true", "--rpc-secret=benchmark-secret",
                    f"--rpc-listen-port={port}", "--rpc-listen-all=false",
                    "--rpc-aria2-compat=false", f"--enable-dht={str(self.public).lower()}", f"--enable-dht6={str(self.public).lower()}",
                    "--bt-enable-lpd=false", "--bt-enable-upnp=false",
                    "--bt-enable-nat-pmp=false", "--listen-port=0", "--bt-max-peers=128",
                    "--bt-save-metadata=false", f"--dir={downloads}",
                    f"--sqlite3-db-path={self.directory / 'state.sqlite3'}"]
            self.rpc = HttpRpc(f"http://127.0.0.1:{port}/jsonrpc")
            method, params = "taiji.getVersion", []
        self.log = (self.directory / "daemon.log").open("w")
        self.process = await asyncio.create_subprocess_exec(
            *args, stdout=self.log, stderr=self.log, cwd=self.directory,
            env={**os.environ, **({"RUST_LOG": "warn,taiji::core::magnet=debug,taiji::bt::dht=debug,taiji::bt::tracker=debug"} if self.public else {})})
        for _ in range(150):
            if self.process.returncode is not None:
                raise RuntimeError((self.directory / "daemon.log").read_text()[-2000:])
            try:
                version = await self.rpc.call(method, params)
                self.version = version.get("version", version.get("rpc_version", "unknown"))
                return self
            except (OSError, RuntimeError, urllib.error.URLError):
                await asyncio.sleep(0.05)
        raise RuntimeError("daemon did not become ready")

    async def resolve(self, magnet, timeout, file_count=1):
        started = time.monotonic()
        if self.kind == "transmission":
            result = await self.rpc.call("torrent-add", {"filename": magnet, "paused": False, "files-unwanted": list(range(file_count))})
            added = result.get("torrent-added", result.get("torrent-duplicate"))
            task_id = added["id"]
        else:
            task_id = await self.rpc.call("taiji.addUri", [[magnet], {
                "motrix-await-selection": "true", "bt-save-metadata": "false",
                "dir": str(self.directory / "metadata"),
            }])
        while time.monotonic() - started < timeout:
            if self.kind == "transmission":
                result = await self.rpc.call("torrent-get", {
                    "ids": [task_id], "fields": ["id", "metadataPercentComplete", "errorString", "downloadedEver", "fileStats", "hashString"]})
                torrent = result["torrents"][0]
                ready = torrent["metadataPercentComplete"] == 1
                if ready and torrent["downloadedEver"] != 0:
                    raise RuntimeError("unexpected reference payload")
            else:
                result = await self.rpc.call("taiji.tellStatus", [task_id, ["status", "errorMessage", "completedLength"]])
                if result["status"] == "error":
                    raise RuntimeError(result.get("errorMessage", "task error"))
                ready = result["status"] == "paused"
                if ready and int(result["completedLength"]) != 0:
                    raise RuntimeError("unexpected payload before file selection")
            if ready:
                expected = lt.parse_magnet_uri(magnet).info_hashes
                if self.kind == "transmission":
                    expected_hash = str(expected.v1 if expected.has_v1() else expected.v2)
                    if torrent["hashString"] != expected_hash:
                        raise RuntimeError("reference metadata identity mismatch")
                else:
                    metadata = await self.rpc.call("taiji.getTorrentMetadata", [task_id])
                    received = lt.torrent_info(base64.b64decode(metadata["data"])).info_hashes()
                    if (expected.has_v1() and received.v1 != expected.v1) or (expected.has_v2() and received.v2 != expected.v2):
                        raise RuntimeError("native metadata identity mismatch")
                elapsed = (time.monotonic() - started) * 1000
                diagnostics = None
                if self.kind == "taiji":
                    diagnostics = await self.rpc.call("taiji.getMagnetResolution", [task_id])
                return elapsed, diagnostics
            await asyncio.sleep(0.01)
        diagnostic = await self.rpc.call("taiji.getMagnetResolution", [task_id]) if self.kind == "taiji" else None
        return None, diagnostic

    async def close(self):
        if self.process is not None and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self.log:
            self.log.close()


async def libtorrent_resolve(fixture, directory, timeout, warmup=0):
    directory.mkdir(parents=True)
    session = lt.session({
        "listen_interfaces": "0.0.0.0:0,[::]:0" if fixture.public else fixture.peer_host + ":0", "enable_dht": fixture.public, "enable_lsd": False,
        "enable_upnp": False, "enable_natpmp": False,
        "enable_outgoing_utp": fixture.public, "enable_incoming_utp": fixture.public,
        # v2.1.1 reverses these names in its enum/name table. Magnets assign
        # each tr a separate tier, so enabling both preserves the intended
        # one-per-tier fan-out regardless of that mapping. Wire preflight
        # below validates behavior, not just a symmetric settings readback.
        "announce_to_all_tiers": True, "announce_to_all_trackers": True,
        "connection_speed": 30, "connections_limit": 500,
        # All test peers are loopback endpoints, not a production recommendation.
        "allow_multiple_connections_per_ip": True,
    })
    if warmup:
        await asyncio.sleep(warmup)
    params = lt.parse_magnet_uri(fixture.magnet)
    params.save_path = str(directory)
    params.flags &= ~(lt.torrent_flags.paused | lt.torrent_flags.auto_managed)
    params.flags |= lt.torrent_flags.upload_mode
    params.max_connections = 128
    started = time.monotonic()
    handle = session.add_torrent(params)
    try:
        while time.monotonic() - started < timeout:
            status = handle.status()
            if status.has_metadata:
                if status.total_payload_download != 0:
                    raise RuntimeError("unexpected libtorrent payload in upload mode")
                files = handle.torrent_file().files()
                if files.num_files() != fixture.file_count:
                    raise RuntimeError("reference file manifest mismatch")
                return (time.monotonic() - started) * 1000, None
            await asyncio.sleep(0.01)
        return None, None
    finally:
        session.remove_torrent(handle)
        session.pause()


def summarize(rows):
    result = {}
    for row in rows:
        key = f"{row['scenario']}/{row['client']}"
        result.setdefault(key, []).append(row)
    for key, group in result.items():
        timings = sorted(r["elapsed_ms"] for r in group if r["outcome"] == "success")
        result[key] = {
            "runs": len(group), "successes": len(timings),
            "p50_ms": timings[len(timings)//2] if timings else None,
            "p95_ms": timings[max(0, math.ceil(len(timings)*0.95)-1)] if timings else None,
            "timeouts": sum(r["outcome"] == "timeout" for r in group),
            "errors": sum(r["outcome"] == "error" for r in group),
        }
    return result


async def check_libtorrent_discovery(output, peer_host):
    fixture = await Fixture("dead-trackers", -1, peer_host).start()
    try:
        params = lt.parse_magnet_uri(fixture.magnet)
        if len(set(params.tracker_tiers)) != len(fixture.trackers):
            raise RuntimeError("reference magnet tiers are not independent")
        elapsed, _ = await libtorrent_resolve(fixture, output / "reference-preflight", 3)
        evidence = {"version": lt.version, "elapsed_ms": elapsed,
                    "tracker_count": len(fixture.trackers), "counters": fixture.counters.copy()}
        (output / "reference-preflight.json").write_text(json.dumps(evidence, indent=2))
        if elapsed is None or not fixture.counters["announces"]:
            raise RuntimeError("libtorrent did not reach the valid tracker behind 24 stalled tiers; refusing a misconfigured comparison")
    finally:
        await fixture.close()


async def main(args):
    output = args.output.resolve()
    if (output / "results.json").exists():
        raise SystemExit("Choose a new output directory; existing benchmark evidence is preserved")
    output.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    clients = {"taiji": str(args.taiji.resolve()), "libtorrent": None}
    if args.transmission:
        clients["transmission"] = args.transmission
    if args.baseline:
        clients["baseline"] = str(args.baseline.resolve())
    if args.clients:
        selected = set(args.clients.split(","))
        clients = {name: binary for name, binary in clients.items() if name in selected}
        if not clients:
            raise SystemExit("No requested reference client is available")
    if args.torrent and "transmission" in clients:
        if args.clients:
            raise SystemExit("Transmission cannot enforce metadata-only mode before magnet resolution; use --clients taiji,libtorrent for public runs")
        del clients["transmission"]
    binary_hashes = {name: hashlib.sha256(Path(binary).read_bytes()).hexdigest()
                     for name, binary in clients.items() if binary is not None}
    if "libtorrent" in clients:
        await check_libtorrent_discovery(output, args.peer_host)
    rows = []
    for iteration in range(args.samples):
        for scenario in args.scenarios.split(","):
            order = list(clients)
            rng.shuffle(order)
            for name in order:
                fixture = await (PublicTorrent(args.torrent, scenario) if args.torrent else Fixture(scenario, iteration, args.peer_host)).start()
                if not fixture.public and scenario == "dead-peers":
                    if args.peer_order == "seeded":
                        random.Random(args.seed * 1009 + iteration).shuffle(fixture.peers)
                    elif args.peer_order in {"first", "middle"}:
                        healthy = fixture.peers.pop()
                        fixture.peers.insert(0 if args.peer_order == "first" else len(fixture.peers)//2, healthy)
                directory = output / f"{iteration}-{scenario}-{name}"
                daemon = None
                row = {"client": name, "scenario": scenario, "iteration": iteration,
                       "info_bytes": len(fixture.info), "timeout_s": args.timeout, "warmup_s": args.warmup}
                if not fixture.public:
                    row["healthy_peer_positions"] = [fixture.peers.index(p) + 1 for p in fixture.healthy_peers]
                try:
                    if name == "libtorrent":
                        row["version"] = lt.version
                        elapsed, diagnostic = await libtorrent_resolve(fixture, directory, args.timeout, args.warmup)
                    else:
                        daemon = Daemon(name, clients[name], directory, fixture.public)
                        await daemon.start()
                        row["version"] = daemon.version
                        if args.warmup:
                            if daemon.kind == "taiji":
                                await daemon.rpc.call("taiji.prepareBitTorrent", [])
                            await asyncio.sleep(args.warmup)
                        elapsed, diagnostic = await daemon.resolve(fixture.magnet, args.timeout, fixture.file_count)
                    row.update(elapsed_ms=elapsed, outcome="success" if elapsed is not None else "timeout",
                               diagnostics=diagnostic, counters=fixture.counters.copy())
                except Exception as error:
                    row.update(outcome="error", elapsed_ms=None, error=str(error),
                               counters=fixture.counters.copy())
                finally:
                    if daemon:
                        await daemon.close()
                    await fixture.close()
                rows.append(row)
                print(json.dumps(row), flush=True)
                (output / "results.json").write_text(json.dumps({
                    "config": {"samples": args.samples, "seed": args.seed, "peer_order": args.peer_order, "clients": list(clients), "binary_sha256": binary_hashes, "peer_host": args.peer_host, "public_torrent": str(args.torrent) if args.torrent else None, "warmup_s": args.warmup,
                               "scenario_order": args.scenarios, "timeout_s": args.timeout},
                    "runs": rows, "summary": summarize(rows),
                }, indent=2))
    print(json.dumps({"summary": summarize(rows)}, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--taiji", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--transmission", default=shutil.which("transmission-daemon"))
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--scenarios", default="healthy,dead-peers,dead-trackers,slow-blocks")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--peer-order", choices=["seeded", "first", "middle", "last"], default="seeded", help="Healthy candidate placement; seeded order avoids a fixed last-candidate bias")
    parser.add_argument("--clients", help="Optional comma-separated subset of taiji,baseline,libtorrent,transmission")
    parser.add_argument("--peer-host", default="127.0.0.1", help="Local IPv4 interface; Transmission rejects loopback tracker peers, so use a LAN address for that reference")
    parser.add_argument("--torrent", type=Path, help="Opt into metadata-only public tests using a known torrent descriptor; no metainfo is submitted to clients")
    parser.add_argument("--warmup", type=float, default=0, help="Idle preparation time excluded from resolution latency")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    allowed = {"public-trackers", "public-dht"} if args.torrent else {"healthy", "dead-peers", "dead-trackers", "slow-blocks"}
    if not set(args.scenarios.split(",")).issubset(allowed) or args.samples < 1 or args.timeout <= 0 or args.warmup < 0:
        parser.error("invalid scenarios, sample count or time budgets")
    asyncio.run(main(args))
