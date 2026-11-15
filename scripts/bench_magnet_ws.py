#!/usr/bin/env python3
"""Event-driven magnet comparison: native WebSocket RPC and libtorrent alerts.

Optional benchmark dependencies: libtorrent and websockets==15.0.1.
Only synthetic, metadata-only fixtures are accepted. No public swarm is used.
"""
import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import random
import socket
import time
from pathlib import Path

import libtorrent as lt
from websockets.asyncio.client import connect

import bench_magnet as fixture_lib


class WebSocketRpc:
    def __init__(self, socket):
        self.socket = socket
        self.pending = {}
        self.ready = {}
        self.sequence = 0
        self.calls = []
        self.reader = asyncio.create_task(self.read())

    async def read(self):
        try:
            async for message in self.socket:
                value = json.loads(message)
                if 'id' in value:
                    future = self.pending.pop(value['id'], None)
                    if future is not None and not future.done():
                        if 'error' in value:
                            future.set_exception(RuntimeError(str(value['error'])))
                        else:
                            future.set_result(value.get('result'))
                elif value.get('method') in {
                    'taiji.onTorrentMetadataReady', 'taiji.onDownloadPause'
                }:
                    for event in value.get('params', []):
                        ready = self.ready.get(event.get('gid'))
                        if ready is not None:
                            ready.set()
        except Exception as error:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(error)
        finally:
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(RuntimeError('WebSocket closed'))
            self.pending.clear()

    async def call(self, method, params, timeout=5):
        self.sequence += 1
        request_id = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[request_id] = future
        self.calls.append(method)
        try:
            await self.socket.send(json.dumps({
                'jsonrpc': '2.0', 'id': request_id, 'method': method,
                'params': ['token:benchmark-secret', *params],
            }))
            return await asyncio.wait_for(future, timeout)
        finally:
            self.pending.pop(request_id, None)

    async def close(self):
        await self.socket.close()
        await self.reader


async def wait_ready(rpc, gid, deadline, mode, interval):
    async def poll():
        while True:
            state = await rpc.call('taiji.tellStatus', [gid, ['status', 'errorMessage', 'completedLength']], max(.001, deadline-time.monotonic()))
            if state['status'] == 'error':
                raise RuntimeError(state.get('errorMessage', 'metadata error'))
            if state['status'] == 'paused':
                if int(state['completedLength']) != 0:
                    raise RuntimeError('unexpected payload before selection')
                return 'status'
            await asyncio.sleep(interval)
    if mode == 'poll':
        return await asyncio.wait_for(poll(), max(.001, deadline-time.monotonic()))
    if rpc.ready[gid].is_set():
        return 'notification'
    notified = asyncio.create_task(rpc.ready[gid].wait())
    polling = asyncio.create_task(poll())
    try:
        done, _ = await asyncio.wait([notified, polling], timeout=max(.001, deadline-time.monotonic()), return_when=asyncio.FIRST_COMPLETED)
        if notified in done:
            return 'notification'
        if polling in done:
            return polling.result()
        raise TimeoutError('metadata readiness timed out')
    finally:
        for task in [notified, polling]:
            task.cancel()
        await asyncio.gather(notified, polling, return_exceptions=True)


def check_info(info, fixture):
    expected = lt.parse_magnet_uri(fixture.magnet).info_hashes
    received = info.info_hashes()
    if ((expected.has_v1() and received.v1 != expected.v1)
            or (expected.has_v2() and received.v2 != expected.v2)):
        raise RuntimeError('metadata identity mismatch')
    if info.num_files() != fixture.file_count:
        raise RuntimeError('file count mismatch')
    return expected


async def resolve_native(daemon, fixture, timeout, mode, interval, prepare_ms):
    url = daemon.rpc.url.replace('http://', 'ws://', 1)
    socket = await connect(url, proxy=None, max_size=32*1024*1024, ping_interval=None, close_timeout=1)
    rpc = WebSocketRpc(socket)
    try:
        await rpc.call('taiji.getVersion', [])
        await rpc.call('taiji.prepareBitTorrent', [])
        await asyncio.sleep(prepare_ms/1000)
        rpc.calls.clear()
        gid = os.urandom(8).hex()
        rpc.ready[gid] = asyncio.Event()
        started = time.monotonic()
        deadline = started + timeout
        returned = await rpc.call('taiji.addUri', [[fixture.magnet], {
            'gid': gid, 'motrix-await-selection': 'true', 'bt-save-metadata': 'false',
            'dir': str(daemon.directory/'metadata'),
        }], timeout)
        if returned != gid:
            raise RuntimeError('engine changed reserved identity')
        try:
            via = await wait_ready(rpc, gid, deadline, mode, interval)
            result = await rpc.call('taiji.getTorrentManifest', [gid], max(.001, deadline-time.monotonic()))
            if not result['awaitingSelection']:
                raise RuntimeError('native selection barrier missing')
            expected = check_info(lt.torrent_info(base64.b64decode(result['data'])), fixture)
            if result['manifest']['infoHash'] != str(expected.v1 if expected.has_v1() else expected.v2):
                raise RuntimeError('native manifest identity mismatch')
            if len(result['manifest']['files']) != fixture.file_count:
                raise RuntimeError('native manifest count mismatch')
            if fixture.counters.get('payload_requests', 0):
                raise RuntimeError('unexpected native payload request')
            elapsed = (time.monotonic()-started)*1000
            if elapsed > timeout*1000:
                return None, {'ready_via': via, 'rpc_calls': rpc.calls.copy()}
            calls = rpc.calls.copy()
            snapshot = await rpc.call('taiji.getMagnetResolution', [gid])
            return elapsed, {'ready_via': via, 'rpc_calls': calls, 'resolution': snapshot}
        except TimeoutError:
            return None, {'rpc_calls': rpc.calls.copy()}
    finally:
        await rpc.close()


async def resolve_libtorrent(fixture, directory, timeout, prepare_ms=50):
    directory.mkdir(parents=True)
    session = lt.session({
        'listen_interfaces': fixture.peer_host+':0',
        'enable_dht': False, 'enable_lsd': False,
        'enable_upnp': False, 'enable_natpmp': False,
        'enable_outgoing_utp': False, 'enable_incoming_utp': False,
        'announce_to_all_tiers': True, 'announce_to_all_trackers': True,
        'connection_speed': 30, 'connections_limit': 500,
        'allow_multiple_connections_per_ip': True,
        'alert_mask': lt.alert.category_t.status_notification | lt.alert.category_t.error_notification,
    })
    # Python must use a nonblocking FD, not a callback which would acquire the GIL.
    # https://www.libtorrent.org/python_binding.html#set-alert-notify
    reader, writer = socket.socketpair()
    reader.setblocking(False)
    writer.setblocking(False)
    wake = asyncio.Event()
    loop = asyncio.get_running_loop()
    def drain():
        try:
            while reader.recv(4096):
                pass
        except BlockingIOError:
            pass
        wake.set()
    loop.add_reader(reader.fileno(), drain)
    session.set_alert_fd(writer.fileno())
    await asyncio.sleep(prepare_ms/1000)
    params = lt.parse_magnet_uri(fixture.magnet)
    params.save_path = str(directory)
    params.flags &= ~(lt.torrent_flags.paused | lt.torrent_flags.auto_managed)
    params.flags |= lt.torrent_flags.upload_mode
    params.max_connections = 128
    started = time.monotonic()
    handle = session.add_torrent(params)
    try:
        while time.monotonic()-started < timeout:
            wake.clear()
            for alert in session.pop_alerts():
                if isinstance(alert, lt.metadata_received_alert):
                    if handle.status().total_payload_download != 0:
                        raise RuntimeError('unexpected libtorrent payload')
                    check_info(handle.torrent_file(), fixture)
                    if fixture.counters.get('payload_requests', 0):
                        raise RuntimeError('unexpected reference payload request')
                    elapsed = (time.monotonic()-started)*1000
                    return elapsed if elapsed <= timeout*1000 else None, {'ready_via': 'metadata_received_alert'}
                if isinstance(alert, lt.torrent_error_alert):
                    raise RuntimeError(alert.message())
            try:
                await asyncio.wait_for(wake.wait(), max(.001, timeout-(time.monotonic()-started)))
            except TimeoutError:
                return None, None
        return None, None
    finally:
        # Cleanup is outside the measured interval. These trackers are owned
        # fixtures; do not block their Python event loop waiting for stop ACKs.
        session.apply_settings({'stop_tracker_timeout': 0})
        session.set_alert_fd(-1)
        session.remove_torrent(handle)
        session.pause()
        loop.remove_reader(reader.fileno())
        reader.close()
        writer.close()


async def main(args):
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    clients = {'taiji': str(args.taiji.resolve()), 'libtorrent': None}
    if args.baseline:
        clients['baseline'] = str(args.baseline.resolve())
    if args.clients:
        selected = args.clients.split(',')
        if set(selected)-clients.keys():
            raise SystemExit('Unavailable requested client')
        clients = {name: clients[name] for name in selected}
    if 'libtorrent' in clients:
        fixture = await fixture_lib.Fixture('dead-trackers', -1, args.peer_host).start()
        try:
            elapsed, _ = await resolve_libtorrent(fixture, output/'preflight', 3, args.prepare_ms)
            preflight = {'version': lt.version, 'elapsed_ms': elapsed, 'counters': fixture.counters, 'trackers': len(fixture.trackers)}
            (output/'reference-preflight.json').write_text(json.dumps(preflight, indent=2))
            if elapsed is None or not fixture.counters['announces']:
                raise RuntimeError('libtorrent discovery preflight failed')
        finally:
            await fixture.close()
    hashes = {name: hashlib.sha256(Path(binary).read_bytes()).hexdigest() for name, binary in clients.items() if binary}
    config = {'mode': args.mode, 'fallback_poll_ms': args.poll_ms, 'samples': args.samples,
              'seed': args.seed, 'peer_host': args.peer_host, 'timeout_s': args.timeout, 'prepare_ms': args.prepare_ms,
              'clients': list(clients), 'binary_sha256': hashes, 'libtorrent': lt.version,
              'scenarios': args.scenarios, 'reference_readiness': 'metadata_received_alert'}
    rows=[]
    rng = random.Random(args.seed)
    for iteration in range(args.samples):
        for scenario in args.scenarios.split(','):
            order = list(clients)
            rng.shuffle(order)
            for name in order:
                fixture = await fixture_lib.Fixture(scenario, iteration, args.peer_host).start()
                if scenario == 'dead-peers':
                    random.Random(args.seed*1009+iteration).shuffle(fixture.peers)
                row={'client': name, 'scenario': scenario, 'iteration': iteration,
                     'info_bytes': len(fixture.info), 'timeout_s': args.timeout,
                     'healthy_peer_positions': [fixture.peers.index(p)+1 for p in fixture.healthy_peers]}
                daemon=None
                try:
                    directory=output/f'{iteration}-{scenario}-{name}'
                    if name == 'libtorrent':
                        elapsed, diagnostic = await resolve_libtorrent(fixture, directory, args.timeout, args.prepare_ms)
                        row['version']=lt.version
                    else:
                        daemon=fixture_lib.Daemon(name, clients[name], directory)
                        await daemon.start()
                        elapsed, diagnostic = await resolve_native(daemon, fixture, args.timeout, args.mode, args.poll_ms/1000, args.prepare_ms)
                        row['version']=daemon.version
                    row.update(elapsed_ms=elapsed, outcome='success' if elapsed is not None else 'timeout', diagnostics=diagnostic, counters=fixture.counters.copy())
                except Exception as error:
                    row.update(elapsed_ms=None, outcome='error', error=str(error), counters=fixture.counters.copy())
                finally:
                    if daemon:
                        await daemon.close()
                    await fixture.close()
                rows.append(row)
                (output/'results.json').write_text(json.dumps({'config': config, 'runs': rows, 'summary': fixture_lib.summarize(rows)}, indent=2))
                print(json.dumps(row), flush=True)
    print(json.dumps(fixture_lib.summarize(rows), indent=2))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--taiji', type=Path, required=True)
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--clients')
    parser.add_argument('--samples', type=int, default=10)
    parser.add_argument('--scenarios', default='healthy,dead-peers,dead-trackers,slow-blocks,v2-32k,v2-513')
    parser.add_argument('--timeout', type=float, default=5)
    parser.add_argument('--poll-ms', type=float, default=10)
    parser.add_argument('--prepare-ms', type=float, default=50, help='Idle preparation before starting the clock; native clients call prepareBitTorrent first')
    parser.add_argument('--mode', choices=['notify','poll'], default='notify')
    parser.add_argument('--seed', type=int, default=43)
    parser.add_argument('--peer-host', default='127.0.0.1')
    parser.add_argument('--output', type=Path, required=True)
    args=parser.parse_args()
    allowed={'healthy','dead-peers','dead-trackers','slow-blocks','v2-32k','v2-513'}
    if (not set(args.scenarios.split(',')).issubset(allowed) or args.samples < 1
            or args.timeout <= 0 or args.poll_ms <= 0 or args.prepare_ms < 0):
        parser.error('invalid scenarios or measurement bounds')
    asyncio.run(main(args))
