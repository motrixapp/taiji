# aria2 v1 wire surface (frozen profile)

This inventory freezes the v1 wire surface: every method, error code, event, and option name listed below is part of the frozen aria2-compatibility profile. New capabilities default to the `taiji.*` v2 surface and never widen v1 implicitly; anything that must enter v1 is first registered in [`docs/compat/aria2-v1-deviations.yaml`](aria2-v1-deviations.yaml) — no registration, no entry.

**Total: 354 entries — methods 59, error codes 119, events 11, options 165.**

## Methods

The registry is the single source of truth: `RPC_METHODS` in `taiji-domain/src/methods.rs` (the name table, methods.rs:24-148) and `RPC_METHOD_INFO` (names + the read-only bit + dispatch-category descriptors, methods.rs:220-565; the two tables are kept bidirectionally identical by a governance test, taiji-core/src/session/command.rs:783-810). RPC-layer dispatch lives in `taiji-rpc/src/dispatch.rs`: alias normalization `canonical_method` (dispatch.rs:168-185), unknown methods authenticate first and then error (dispatch.rs:319-331), the write gate (dispatch.rs:260-275, 364-366), and the dedicated `system.*` arm (dispatch.rs:333-352). The execution arms live in `taiji-rpc/src/dispatch/methods.rs` (the query family is table-driven via `QUERY_METHODS`, methods.rs:275-406; per-method arms methods.rs:478-1046), `dispatch/params.rs` (decoding helpers), `dispatch/multicall.rs` (`system.multicall` expansion), and the metalink seam `taiji-rpc/src/metalink.rs:423`.

Naming-surface rules (one surface at a time, `--rpc-aria2-compat`, dispatch.rs:119-127):

- The bare-name family is registered as bare strings and presented/invoked with a prefix: canonical face `taiji.<bare>` (the prefixed form is always accepted), compat face `aria2.<bare>` (accepted only while compat is on; when off it falls to "No such method: aria2.X", dispatch.rs:172-178).
- Dotted literal names (`system.*`, the `taiji.*` extensions) carry no prefix aliases of any kind (dispatch.rs:181-183) and share the same shape on both faces; the `system.listMethods` output is the registry's face projection (dispatch.rs:196-208).
- Authentication: the aria2 `token:<secret>` first-parameter convention applies to every method that goes through execute (stripped before parameter decoding, dispatch.rs:285-307); `system.listMethods`/`system.listNotifications` are exempt (the reference implementation overrides execute, dispatch.rs:346-352); multicall authentication sinks into the sub-calls (multicall.rs:76-87).
- Write gate: with `--rpc-secret` unset, every method with `read_only=false` is refused (`STR_UNAUTH_WRITE`, dispatch.rs:364-366); the read-only exemptions number 21 (rows whose Notes column below is marked 只读).
- Numeric parameter conventions: numbers or numeric strings, both forms accepted (uint_value, params.rs:110-126); the options dictionary accepts string values only (gatherOption rules, params.rs:38-50); string lists drop non-string elements (params.rs:152-160).

### aria2-compatible family (bare names + `system.*`, registry order)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `addUri` | (uris: string[], options?: dict, position?: uint≥0) | aria2.addUri 同名 | 写;空 uris → "URI is not provided."(methods.rs:530-543) |
| `addTorrent` | (torrent: base64 串, webseedURIs[]?, options?, position?) | aria2.addTorrent 同名 | 写;参数位 1(webseed URI)显式丢弃、已声明(methods.rs:551-556);base64 非法 → 显式错(methods.rs:548-549) |
| `tellStatus` | (gid, keys?: string[]) | aria2.tellStatus 同名 | 只读;GidKeys 形状(methods.rs:276-288) |
| `getFiles` | (gid) | aria2.getFiles 同名 | 只读;QueryStatus |
| `getPeers` | (gid) | aria2.getPeers 同名 | 只读 |
| `getServers` | (gid) | aria2.getServers 同名 | 只读;外层保持 `{index, servers}` 嵌套(methods.rs:323-326) |
| `getUris` | (gid) | aria2.getUris 同名 | 只读 |
| `pause` | (gid) | aria2.pause 同名 | 写 |
| `forcePause` | (gid) | aria2.forcePause 同名 | 写 |
| `unpause` | (gid) | aria2.unpause 同名 | 写 |
| `forceRecheck` | (gid) | 无——taiji 能力扩展(aria2 1.37.0 无 recheck RPC;taiji-domain methods.rs:35-40) | 写;裸名注册,前缀归一后 `taiji.forceRecheck`/`aria2.forceRecheck`(compat)双名可达 |
| `pauseAll` | () | aria2.pauseAll 同名 | 写 |
| `forcePauseAll` | () | aria2.forcePauseAll 同名 | 写(methods.rs:620-625) |
| `unpauseAll` | () | aria2.unpauseAll 同名 | 写 |
| `remove` | (gid) | aria2.remove 同名 | 写 |
| `forceRemove` | (gid) | aria2.forceRemove 同名 | 写 |
| `purgeDownloadResult` | () | aria2.purgeDownloadResult 同名 | 写 |
| `removeDownloadResult` | (gid) | aria2.removeDownloadResult 同名 | 写 |
| `changeUri` | (gid, fileIndex: int≥1, delUris: string[], addUris: string[], pos?) | aria2.changeUri 同名 | 写;fileIndex ≥1 校验,措辞照 RpcMethodImpl.cc(methods.rs:628-657) |
| `changePosition` | (gid, pos: int, how: "POS_SET"\|"POS_CUR"\|"POS_END") | aria2.changePosition 同名 | 写;Special 臂;非法 how → "Illegal argument.";gid 与 how 同坏时措辞优先级与上游相反(已声明差异,methods.rs:715-739) |
| `changeOption` | (gid, options) | aria2.changeOption 同名 | 写 |
| `getOption` | (gid) | aria2.getOption 同名 | 只读;QueryStatus |
| `changeGlobalOption` | (options) | aria2.changeGlobalOption 同名 | 写 |
| `getGlobalOption` | () | aria2.getGlobalOption 同名 | 只读 |
| `getGlobalStat` | () | aria2.getGlobalStat 同名 | 只读 |
| `getVersion` | () | aria2.getVersion 同名 | 只读 |
| `getSessionInfo` | () | aria2.getSessionInfo 同名 | 只读 |
| `tellActive` | (keys?: string[]) | aria2.tellActive 同名 | 只读;KeysOnly |
| `tellWaiting` | (offset: int, num: int≥0, keys?) | aria2.tellWaiting 同名 | 只读;PagedKeys,负 offset 渲染期反转,num<0 → 显式错(params.rs:139-148) |
| `tellStopped` | (offset, num, keys?) | aria2.tellStopped 同名 | 只读;同上 |
| `saveSession` | () | aria2.saveSession 同名 | 写(持久化副作用) |
| `shutdown` | () | aria2.shutdown 同名 | 写;成功回 `"OK"` 并取消 shutdown token(methods.rs:479-504) |
| `forceShutdown` | () | aria2.forceShutdown 同名 | 写;同上 |
| `system.listMethods` | () | 同名 | 免鉴权;返回呈现面投影(裸名加前缀,带点名透传;dispatch.rs:348) |
| `system.multicall` | (specs: [{methodName: string, params?: array}]) | 同名 | 免外层鉴权(下沉子调用,子调用 id=null);成功包一层 `[payload]`、错误原位内联(multicall.rs:88-94);递归禁令先于鉴权(dispatch.rs:333-343);spec 上限 1000(multicall.rs:51-53,payload.rs:35);batch 内 multicall 总子调用预算 10,000(payload.rs:45、103-117);spec 非对象/缺 methodName → 内联错(multicall.rs:57-64) |
| `system.listNotifications` | () | 同名 | 免鉴权;六事件名,规范面 `taiji.onXxx`/compat 面 `aria2.onXxx`(dispatch.rs:73-104) |
| `addMetalink` | (metalink: base64 串, options?, position?) | aria2.addMetalink 同名 | 写;**feature 门控 `metalink`**(taiji-rpc/Cargo.toml:63 默认开、:68 `metalink = ["dep:taiji-metalink", "taiji-core/metalink"]`;关 = 未注册 → "No such method",同 aria2 关 ENABLE_METALINK 之形);执行于 RPC 接缝:解析 → 逐任务 addUri 展开,回 GID 数组;600s 解析预算(metalink.rs:47、381-423) |

### taiji.* extension family (dotted literal names, no aliases, same shape on both faces)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `taiji.moveStorage` | (gid, dir: string) | 无上游对应 | 写;注册但 actor 恒答 NotSupported(显式 not_supported 面,methods.rs:756-762) |
| `taiji.renameFile` | (gid, oldPath, newPath) | 无上游对应 | 写;同上 |
| `taiji.banAddr` | (target: string, minutes?: 数字/数字串) | taiji 扩展 | 写;target=单 IP/CIDR;minutes 缺省=永久(methods.rs:788-818) |
| `taiji.unbanAddr` | (target) | taiji 扩展 | 写 |
| `taiji.listBans` | () | taiji 扩展 | 只读 |
| `taiji.setSchedulerPolicy` | (gid, policy: 名称串或 {"policy": 名称串}) | taiji 扩展 | 写;未知名显式报错(methods.rs:819-848) |
| `taiji.getSchedulerPolicy` | (gid) | taiji 扩展 | 只读 |
| `taiji.setFilePriority` | (gid, pairs: [{index≥1, priority∈-1..=7}]) | taiji 扩展(对齐 libtorrent prioritize_files) | 写;空数组/非对象条目/缺键/越域显式错(methods.rs:888-950) |
| `taiji.setStreamingPlayhead` | (gid, file: uint, position: uint, bytesPerSec?: uint>0) | taiji 扩展 | 写;bps 显式 0 拒绝(methods.rs:849-887) |
| `taiji.getDiskTier` | (gid) | taiji 扩展 | 只读 |
| `taiji.setDiskTier` | (gid, tier: "throughput"\|"ssd-protect"\|"hdd-sequential") | taiji 扩展 | 写;大小写不敏感,未知名显式错(methods.rs:951-978) |
| `taiji.getCapabilities` | () | taiji 扩展 | 只读;结构化能力发现,schema_version=1(methods.rs:1038-1044) |
| `taiji.addTracker` | (gid, urls: string\|string[], options?: {position}) | taiji 扩展(fork 无此二法) | 写;position 0 基、越界钳尾(methods.rs:666-714) |
| `taiji.removeTracker` | (gid, urls) | taiji 扩展 | 写 |
| `taiji.addUriWithCookies` | (uris: string[], cookies[], options?, position?) | Motrix aria2 fork 有同名 `aria2.*` 方法;taiji 不做 compat 投影,`aria2.addUriWithCookies` 恒 "No such method"(taiji-domain methods.rs:113-121) | 写;http/https 方案门由 actor 防线背书(methods.rs:565-587) |
| `taiji.setTaskCookies` | (gid, cookies[]) | 同上(fork 有 `aria2.setTaskCookies`) | 写(methods.rs:588-595) |
| `taiji.createTorrent` | (files: string[]≥1, outputDir, options?: {pieceLength, format: v1\|v2\|hybrid, private, comment, announce, creationDate}) | taiji 扩展(aria2 无) | 写;绕过 SessionActor 直调 `taiji_core::create`(spawn_blocking + 600s 上限)(methods.rs:47-204) |
| `taiji.addMedia` | (url: string, options?, position?) | taiji 扩展 | 写;options 携 dir/out/selector/subtitles/template/no-meta/media-* 族/probe-token/cookies(methods.rs:979-1013) |
| `taiji.probeMedia` | (url) | taiji 扩展 | 写(动作面:外发请求+快照缓存,无 secret 同样 fail-closed)(methods.rs:1014-1025) |
| `taiji.getMediaFormats` | (gid) | taiji 扩展 | 只读 |
| `taiji.stopRecording` | (gid) | taiji 扩展 | 写;LIVE 执行语义声明落在 0.4(methods.rs:1029-1031) |
| `taiji.clearMediaArchive` | () | taiji 扩展 | 写;全表破坏性清空,CLI 对应 `--media-archive-clear`(methods.rs:1032-1037) |

共 59 条(metalink feature 开=默认;关时 58 条,`addMetalink` 整条不存在)。

## Error codes

The single source of truth for the RPC error surface is `taiji-rpc/src/error.rs` (the repository-level mapping table; no other crate may define its own mapping, error.rs:1-8); JSON-RPC protocol errors live in `taiji-rpc/src/jsonrpc.rs`, with construction points spread across dispatch/payload/methods/multicall/metalink/server/view/params/rpc_cookies. The error object's wire shape is frozen as `{code,message}` (error.rs:49-52; encoded in jsonrpc.rs:51-58, response key order id→jsonrpc→result|error, jsonrpc.rs:62-69). The numeric codes (aria2 namespace) appear only in the task-terminal `errorCode` (view.rs:303-311), never in JSON-RPC `error.code`; the `taiji.*` string codes appear only as message prefixes (error.rs:196-199). The aria2 reference side was checked value by value against `aria2/src/error_code.h:44-78`, `rpc_helper.cc:84-101`, `RpcMethod.cc:87`, `RpcMethodImpl.cc:1522`, and `RpcMethodImpl.h:67-72`.

### A. JSON-RPC / generic execution error codes (error.rs:35-47)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `CODE_GENERIC` | code=1,message 任意 | 对齐(`RpcMethod.cc` createErrorResponse→`Integer::g(1)`) | 一切方法执行失败、未知方法、鉴权失败的落点(error.rs:32-35) |
| `CODE_PARSE_ERROR` | code=-32700,`"Parse error."`,id=null | 对齐(HttpServerBodyCommand.cc:280 / WebSocketSession.cc:172) | 构造点 jsonrpc.rs:142-151 |
| `CODE_INVALID_REQUEST` | code=-32600,`"Invalid Request."` | 对齐(rpc_helper.cc:84/88) | 非对象/缺 id/非字符串 method;构造点 jsonrpc.rs:116-127 |
| `CODE_INVALID_PARAMS` | code=-32602,`"Invalid params."` | 对齐(rpc_helper.cc:101) | params 非数组(含显式 null/dict);构造点 jsonrpc.rs:129-138 |
| `CODE_METHOD_NOT_FOUND` | code=-32601(常量) | 对齐(仅 HTTP 映射分支存在) | **从不产生**:未知方法走 code=1(NoSuchMethodRpcMethod 语义,error.rs:41-47);常量仅为 http_status 表对齐保留 |

### B. aria2 numeric error-code constants (error.rs:200-213; read-only reference error_code.h)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `NUM_UNKNOWN_ERROR` | 1 | error_code.h UNKNOWN_ERROR=1 | 兜底行(RequestGroup 回退规则,error.rs:300-304) |
| `NUM_TIME_OUT` | 2 | TIME_OUT=2 | 仅 transport+TransportTimeout 直达 |
| `NUM_RESOURCE_NOT_FOUND` | 3 | RESOURCE_NOT_FOUND=3 | unexpected_response 404 |
| `NUM_NETWORK_PROBLEM` | 6 | NETWORK_PROBLEM=6 | transport Bare(含 DNS 文本) |
| `NUM_CANNOT_RESUME` | 8 | CANNOT_RESUME=8 | bad_range/range_ignored |
| `NUM_FILE_ALREADY_EXISTS` | 13 | FILE_ALREADY_EXISTS=13 | path_conflict |
| `NUM_FILE_IO_ERROR` | 17 | FILE_IO_ERROR=17 | disk 家族单行(15/16 不可达,error.rs:281-284) |
| `NUM_FTP_PROTOCOL_ERROR` | 21 | FTP_PROTOCOL_ERROR=21 | ftp/ftp_resume_unsupported |
| `NUM_HTTP_PROTOCOL_ERROR` | 22 | HTTP_PROTOCOL_ERROR=22 | unexpected_response 兜底/insecure_redirect |
| `NUM_HTTP_TOO_MANY_REDIRECTS` | 23 | HTTP_TOO_MANY_REDIRECTS=23 | redirect_limit/redirect_loop |
| `NUM_HTTP_AUTH_FAILED` | 24 | HTTP_AUTH_FAILED=24 | unexpected_response 401 / taiji.auth.failed |
| `NUM_OPTION_ERROR` | 28 | OPTION_ERROR=28 | taiji.option.invalid |
| `NUM_HTTP_SERVICE_UNAVAILABLE` | 29 | HTTP_SERVICE_UNAVAILABLE=29 | unexpected_response 502..=504 |
| `NUM_CHECKSUM_ERROR` | 32 | CHECKSUM_ERROR=32 | checksum_mismatch |

Note: aria2's 19/15/16 (NAME_RESOLVE/FILE_OPEN/FILE_CREATE) have no production-reachable rows and are left unnamed (error.rs:193-199); 31 (REMOVED) and 0 (FINISHED) do not pass through this table — the core merged face passes the number straight through into `errorCode` (view.rs:303-311).

### C. `HttpFailureKind` sub-dimensions (error.rs:224-236; core-side mirror taiji-core/src/session/view.rs:304-314, hand-off point view.rs:454-463)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `Bare` | 无子维度 | 对齐(单值码/fallback 行语义) | transport 链文本与 disk 载荷恒为 Bare(error.rs:215-223) |
| `Status(u16)` | 原始 HTTP 状态码 | 对齐(HttpSkipResponseCommand.cc 状态开关) | 仅 unexpected_response 家族携带 |
| `TransportTimeout` | 读空闲超时(`--timeout` 零字节增长) | 对齐(EX_TIME_OUT 槽位) | 任务级 stall 闭包构造(error.rs:230-235) |

### D. HTTP failure → aria2 numeric-code mapping table (`try_http_numeric_code`/`http_numeric_code`, error.rs:244-304; key domain = taiji-segment/src/error.rs:347-373 `HttpError::code()`)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `taiji.http.bad_range` | →8 | 对齐(HttpResponse.cc isRangeSatisfied→CANNOT_RESUME) | PreconditionFailed 变体(412 If-Match)复用同码(taiji-segment error.rs:263-269,356) |
| `taiji.http.range_ignored` | →8 | 对齐(同 bad_range 家族) | 声明差异:aria2 重启从零,taiji 显式终态失败(error.rs:246-251) |
| `taiji.http.unexpected_response` | Status(404)→3 / Status(401)→24 / Status(502..=504)→29 / 其他(含 403、Bare)→22 | 对齐(HttpSkipResponseCommand.cc:仅 401/404/502/503/504 有专臂) | 403 归 22 非 24 有专项 pin(error.rs:397-417);RetryAfter 变体(429/503+Retry-After)复用同码(taiji-segment error.rs:75-84,354) |
| `taiji.http.transport` | TransportTimeout→2 / Bare→6 | 对齐(EX_TIME_OUT / NETWORK_PROBLEM) | DNS 永久失败 DnsPermanent 变体共享 6(19 不可达,声明差异;error.rs:260-268,468-491) |
| `taiji.http.redirect_limit` | →23 | 对齐(MAX_REDIRECT 耗尽) | |
| `taiji.http.redirect_loop` | →23 | 对齐(同一码) | taiji visited-set 更早拒绝,线码相同(error.rs:270-272) |
| `taiji.http.insecure_redirect` | →22 | 无对应(https→http 降级拒绝为 taiji 增强) | declared difference |
| `taiji.http.mirror_mismatch` | →1 | 无对应(跨镜像长度比对) | taiji 增强 |
| `taiji.http.no_source` | →1 | 对齐(全部 URI 失败落通用码) | |
| `taiji.http.total_length_exceeded` | →1 | 无对应(权威总长上限) | taiji 增强 |
| `taiji.http.coordinator_stopped` | →1 | 无对应 | taiji 增强 |
| `taiji.http.cookie_file_too_large` | →1 | 无对应(aria2 读 cookie 失败仅记日志) | taiji 升级为任务失败(收紧,declared difference) |
| `taiji.http.cookie_file` | →1 | 同上 | 同上 |
| `taiji.http.path_conflict` | →13 | 对齐(--allow-overwrite=false 语义) | |
| `taiji.http.disk` | Bare→17 | 对齐(AbstractDiskWriter.cc FILE_IO_ERROR) | 单行;aria2 更细的 15/16 不可达(error.rs:285-288) |
| `taiji.option.invalid` | →28 | 对应(OPTION_ERROR) | 字符串码属 taiji 命名空间、数字值对齐 aria2 |
| `taiji.auth.failed` | →24 | 对齐(HTTP_AUTH_FAILED) | 已声明偏差:FTP 登录 530 在 aria2 落 21,taiji 统一 24(rpc.md declared differences) |
| `taiji.http.ftp` | →21 | 对齐(FtpNegotiationCommand.cc 全 FTP 控制面) | FtpDns 变体共享(21,error.rs:291-294,486-491) |
| `taiji.http.ftp_resume_unsupported` | →21 | 对齐(REST 拒绝=FTP 命令失败) | |
| `taiji.http.checksum_mismatch` | →32 | 对齐(ChecksumCheckIntegrityEntry.cc) | 字符串码在此命名并由 core 经视图携至渲染层 |
| `taiji.http.redirect_to_restricted_ip` | 无表行→兜底 1 | 无对应(SSRF 防护) | 码在 code() 表(taiji-segment error.rs:360)但映射表无显式行(见 Survey caveats) |
| (兜底)任意 off-table 码 | None→`http_numeric_code` 回落 1 | 对齐(RequestGroup UNKNOWN_ERROR 回退) | error.rs:300-304;测试 638-648 |

### E. Media error-code numeric face (`media_numeric_code`, error.rs:314-340; row list = the media error-code wire)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `taiji.media.ffmpeg_missing` | →1 | 无对应 | 全家族无 aria2 对应行;错误 message 原样携带字符串码(error.rs:306-313) |
| `taiji.media.not_media` | →1 | 无对应 | |
| `taiji.media.manifest_too_large` | →1 | 无对应 | |
| `taiji.media.live_unsupported` | →1 | 无对应 | |
| `taiji.media.sample_aes_unsupported` | →1 | 无对应 | |
| `taiji.media.session_key_unsupported` | →1 | 无对应 | |
| `taiji.media.iframes_unsupported` | →1 | 无对应 | |
| `taiji.media.manifest_parse` | →1 | 无对应 | |
| `taiji.media.variant_policy` | →1 | 无对应 | |
| `taiji.media.cross_volume` | →1 | 无对应 | |
| `taiji.media.staging_quota_exceeded` | →1 | 无对应 | |
| `taiji.media.segment_decrypt_failed` | →1 | 无对应 | |
| `taiji.media.ssrf_blocked` | →1 | 无对应 | 2026-10-28 注释行 |
| `taiji.media.key_invalid` | →1 | 无对应 | 同上 |
| `taiji.media.staging` | →1 | 无对应 | 同上 |
| `taiji.media.remux_verify_failed` | →1 | 无对应 | 继承的 verify 失败码 |
| `taiji.media.template_unsafe` | →1 | 无对应 | 首批接线 |
| `taiji.media.probe_expired` | →1 | 无对应 | 首批接线 |
| (兜底)任意 media 形状/off-table | →1 | 对齐(同 http 面回退规则) | 测试另断言 `drm_unsupported`/`sidx_unsupported`(error.rs:607-608,走兜底,见 Survey caveats) |

### F. `taiji.*` string-code constants (error.rs:49-82; wire shape = error.message prefix, code=1)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `STR_NOT_SUPPORTED` | `taiji.method.not_supported: {method}` | 无对应 | 承诺未实现/永久不支持方法的标准面(system.* 占位、moveStorage/renameFile 能力面;error.rs:114-124) |
| `STR_SESSION_CLOSED` | `taiji.session.closed` | 无对应 | map_session_error 落点(error.rs:131-135) |
| `STR_REQUEST_TOO_LARGE` | `taiji.request.too_large: see --rpc-max-request-size` | 无对应(aria2 直接断连,HttpServerCommand.cc) | 显式化差异:HTTP 413 + JSON body(server.rs:640-652) |
| `STR_TOO_MANY_ITEMS` | `taiji.request.too_many_items: batch/multicall capped at 1000 calls` / `…: batch subcall budget exceeded ({n} > 10000)` | 无对应(aria2 无 cap) | 构造点 payload.rs:68-75、105-111;cap=MAX_BATCH_ITEMS 1000(payload.rs:35)/MAX_REQUEST_SUBCALLS 10_000(payload.rs:45) |
| `STR_CREATE_TORRENT_FAILED` | `taiji.create_torrent.failed: {err}` | 无对应 | 构造点 map_create_torrent_error(error.rs:149-162),调用 methods.rs:202 |
| `STR_CREATE_TORRENT_TIMEOUT` | `taiji.create_torrent.timeout: {err}` | 无对应 | 600s 同步预算兜底(禁无超时上限的同步 RPC) |
| `STR_METALINK_PARSE_FAILED` | `taiji.metalink.parse_failed: {err}` | 形状对齐(METALINK_PARSE_ERROR→DL_ABORT_EX→code 1) | DocumentTooLarge/TooManyFiles/TooManyUrls 归此行(error.rs:164-184) |
| `STR_METALINK_UNSUPPORTED_VERSION` | `taiji.metalink.unsupported_version: {err}` | 无对应(v3/未知版本显式降级=声明差异) | |
| `STR_METALINK_TIMEOUT` | `taiji.metalink.timeout: metalink parse exceeded the {600s} budget` | 无对应 | 构造点 metalink.rs:462-470 |
| `STR_UNAUTH_WRITE` | `unauthenticated write requires --rpc-secret` | 无对应(aria2 无 --rpc-secret 时写方法不拒绝) | 安全修复冻结文本,非 taiji.* 前缀但属外部可见兼容面(error.rs:77-82;构造点 dispatch.rs:273-275,闸门 dispatch.rs:364-366) |

### G. Error construction points (external message shapes; unless noted, code=1, unauthorized=false)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| unauthorized(dispatch.rs:325,357) | `Unauthorized`,unauthorized=true(HTTP 层延迟 1s 再发) | 对齐(RpcMethod.cc:87 DL_ABORT_EX;DelayedCommand) | error.rs:104-113 |
| no-such-method(dispatch.rs:327-330) | `No such method: {raw_method}` | 对齐(RpcMethodImpl.cc:1522) | 授权先行、顺序对齐 |
| recursive-multicall(dispatch.rs:338-341) | `Recursive system.multicall forbidden.` | 对齐(RpcMethodImpl.cc) | 递归检查先于鉴权 |
| param missing(params.rs:20-26) | `The parameter at {index} is required but missing.` | 对齐(RpcMethodImpl.h:72) | multicall 手写同文(multicall.rs:35,42) |
| param wrong type(params.rs:20-26) | `The parameter at {index} has wrong type.` | 对齐(RpcMethodImpl.h:67) | |
| pagination 负值(params.rs:139-148) | `The integer parameter at {index} has invalid value: the value must be greater than or equal to 0.` | 对齐(checkRequiredInteger+IntegerGE(0)) | |
| createTorrent 空文件集(methods.rs:97) | `file paths are not provided.` | 对齐(addUri 空集文本同形) | |
| unknown torrent format(methods.rs:129-136) | `unknown torrent format: {other} (expected one of v1\|v2\|hybrid)` | 无对应 | taiji 命名空间方法参数 |
| unexpected shutdown reply(methods.rs:500) | `unexpected shutdown reply: {other:?}` | 无对应 | 内部防御面 |
| URI 缺失(methods.rs:534,576) | `URI is not provided.` | 对齐 | addUri/addTorrent |
| torrent base64 无效(methods.rs:549) | `torrent data is not valid base64.` | 对齐(DECODE_FAILURE 语义) | |
| changeUri fileIndex(methods.rs:638-642) | `Integer value must be greater than or equal to 1.` | 对齐(checkRequiredInteger+IntegerGE(1)) | |
| addTracker 空集(methods.rs:696) | `tracker URLs are not provided.` | 对齐 | |
| 非法参数(methods.rs:734) | `Illegal argument.` | 对齐(aria2 文本) | |
| unknown scheduler policy(methods.rs:843-846) | `unknown scheduler policy: {shown}` | 无对应 | taiji 扩展选项 |
| setStreamingPlayhead 速率(methods.rs:869-875) | `The integer parameter at 3 has invalid value: bytes_per_sec must be greater than 0 (omit the parameter for the default rate).` | 无对应 | taiji 扩展方法 |
| setFilePriority 空对(methods.rs:907-909) | `The parameter at 1 has invalid value: pairs must not be empty.` | 无对应 | 文本模板对齐 aria2 风格 |
| setFilePriority 非对象项(methods.rs:915-917) | `The parameter at 1 has invalid value: entry {n} is not an object.` | 无对应 | |
| setFilePriority 缺 index(methods.rs:922-924) | `The parameter at 1 has invalid value: entry {n} misses index.` | 无对应 | |
| setFilePriority 优先域(methods.rs:941-944) | `The parameter at 1 has invalid value: entry {n} priority must be an integer in -1..=7.` | 无对应 | |
| unknown disk tier(methods.rs:970-974) | `unknown disk tier: {name} (expected one of […])` | 无对应 | taiji 扩展选项 |
| addMedia/probeMedia URL 缺失(methods.rs:993,1022) | `URL is not provided.` | 对齐(文本同形) | |
| metalink auto-discover 值域(metalink.rs:367-372) | `taiji.option.invalid: --metalink-enable-auto-discover {v:?} (want true\|false)` | 无对应 | 注意:字符串码与 28 行同名,但此构造点 JSON error.code=1(非 errorCode 数字面) |
| metalink base64 无效(metalink.rs:450-455) | `metalink data is not valid base64.` | 对齐(DECODE_FAILURE) | |
| metalink join 失败(metalink.rs:456-461) | `metalink parse join failed: {e}` | 无对应 | spawn_blocking join 防御面 |
| addMetalink 部分失败(metalink.rs:515-522) | code 1 + 原始 message + ` (created gids: …)` | 形状对齐({code,message} 不变),gid 附注为 taiji 扩展 | 已建任务保留 |
| unexpected addMetalink reply(metalink.rs:496-499) | `unexpected addMetalink reply: {other:?}` | 无对应 | 内部防御面 |
| multicall inline 错误槽(multicall.rs:103-105) | `{"code":1,"message":…}` 子项内嵌 | 对齐(RpcMethod.cc createErrorResponse 形状) | |
| task cookie 上限(rpc_cookies.rs:38) | `Too many task cookies.` | 无对应 | task cookies 为 taiji 扩展面;DL_ABORT_EX 文本风格经 generic(rpc_cookies.rs:8) |
| task cookie 非对象(rpc_cookies.rs:44) | `Task cookie must be an object.` | 无对应 | |
| 未知 cookie 字段(rpc_cookies.rs:60) | `Unknown task cookie field.` | 无对应 | |
| cookie 语法(rpc_cookies.rs:82) | `Invalid task cookie syntax.` | 无对应 | |
| cookie 域(rpc_cookies.rs:108) | `Invalid task cookie domain.` | 无对应 | |
| cookie 过期(rpc_cookies.rs:140) | `Task cookie expiry must be nonnegative Unix milliseconds.` | 无对应 | |
| cookie 字符串字段(rpc_cookies.rs:145) | `Invalid task cookie string field.` | 无对应 | |
| cookie 布尔字段(rpc_cookies.rs:173) | `Invalid task cookie boolean field.` | 无对应 | |
| unexpected reply(view.rs:243) | `unexpected {method} reply: {other:?}` | 无对应 | 内部防御面 |

### H. HTTP status face (numeric code → status, error.rs:342-356; against the HttpServerBodyCommand.cc switch)

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| code 0 | →200 | 对齐 | |
| code 1 | →400 | 对齐 | |
| code -32600 | →400 | 对齐 | |
| code -32601 | →404 | 对齐 | 分支保留、错误面从不产生 |
| 其他(含 -32700/-32602) | →500 | 对齐(上游即如此,忠实复制) | error.rs:344-347 注释 |
| batch 响应 | 恒 200 | 对齐(sendJsonRpcBatchResponse 不选状态码) | error.rs:346-347 |
| 请求体超限(server.rs:643-652) | 413 + JSON-RPC body(code 1 + taiji.request.too_large) | 无对应(aria2 断连) | 显式化差异 |
| Basic 未授权(server.rs:664-676) | 401 + `WWW-Authenticate: Basic realm="aria2"` + Connection: close,空 body | 对齐(HttpServerCommand.cc) | |
| Bearer 未授权 /metrics 门(server.rs:743-752) | 401 + `Bearer realm="taiji"` + Connection: close | 无对应(/metrics 为 taiji 扩展面) | |

Supplement (not table entries, but on the error-code surface's periphery): `taiji.sftp.deferred: SFTP transport is deferred in this build …` rejects sftp:// at addUri task creation (code 1, no numeric row; produced at taiji-core/src/session/actor/tasks.rs:2470-2477, documented as the "SFTP deferral" line in [docs/design/rpc.md](../design/rpc.md)); the WS close is `Close(None)` with no error code (server.rs:1137 et al.).

共 119 条

## Events

The name source of the event surface is `taiji-core/src/session/events.rs` (`EventKind`, six events + three extension families); WS notification payload serialization is at `taiji-rpc/src/server.rs:983-1078`; the `system.listNotifications` table is at `taiji-rpc/src/dispatch.rs:68-104`. All notifications travel on WS text frames only (HTTP has no notification channel, `server.rs:1100` ws_loop); the envelope is uniformly `{jsonrpc:"2.0", method, params:[...]}` with no `id`. The six named events swap faces: `--rpc-aria2-compat` (default off) = the single `taiji.onXxx` face; enabled = the `aria2.onXxx` face (`server.rs:90-95`, `dispatch.rs:119-127`) — only one face is pushed at a time. Extension events (`taiji.recovery*` / `taiji.media.*` / `taiji.task.*`) never swap faces. The event bus capacity is 256 (`events.rs:12`); a slow subscriber that goes Lagged is disconnected (`server.rs:1147-1157`).

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| `taiji.onDownloadStart` / `aria2.onDownloadStart` | WS 通知 `params:[{gid}]`,gid=hex16 小写(`taiji-domain/src/gid.rs:40` `{:016x}`) | aria2 `EVENT_ON_DOWNLOAD_START` → WS method `aria2.onDownloadStart`(WebSocketSessionMan.cc) | `EventKind::Start`(`events.rs:20`);组激活;名字双面 `events.rs:59/76` |
| `taiji.onDownloadPause` / `aria2.onDownloadPause` | 同上 `params:[{gid}]` | `EVENT_ON_DOWNLOAD_PAUSE` | `EventKind::Pause`;暂停回队首;重启分支不发布(`events.rs:22-24`) |
| `taiji.onDownloadStop` / `aria2.onDownloadStop` | 同上 | `EVENT_ON_DOWNLOAD_STOP` | `EventKind::Stop`;IN_PROGRESS/REMOVED 拆除(移除/关机中断,`events.rs:25-27`) |
| `taiji.onDownloadComplete` / `aria2.onDownloadComplete` | 同上 | `EVENT_ON_DOWNLOAD_COMPLETE` | `EventKind::Complete`;终态 FINISHED(`events.rs:28-29`) |
| `taiji.onDownloadError` / `aria2.onDownloadError` | 同上 | `EVENT_ON_DOWNLOAD_ERROR` | `EventKind::Error`;错误拆除(`events.rs:30-31`) |
| `taiji.onBtDownloadComplete` / `aria2.onBtDownloadComplete` | 同上 | `EVENT_ON_BT_DOWNLOAD_COMPLETE` | `EventKind::BtComplete`;BT 转做种,与 Complete 在同一存储点双发(`events.rs:32-35`) |
| `taiji.recoveryStarted` | `params[0]: {gid, files:["1",…]}`;files=1-based 客户端文件序,**数字字符串化**(`server.rs:1013-1019`) | 无(taiji 扩展) | `RecoveryEventKind::Started`(`taiji-domain/src/recovery.rs:38,63`);缺层任务激活即恢复拉取;兼容模式不换名 |
| `taiji.recoveryCompleted` | `params[0]: {gid, files:[…], status:"ready"}`(status 仅 Completed 有,`server.rs:1020-1022`) | 无(taiji 扩展) | `RecoveryEventKind::Completed`;无失败终态事件——status 是未来终态预留槽(`taiji-domain/src/recovery.rs:41-48`) |
| `taiji.media.phaseChanged` | `params[0]: {gid, phase, phaseDetail?, warning?{code,message}}`(`server.rs:1040-1059`);phase 十态字符串 queued/resolving/downloading/recording/processing/verifying/finalizing/paused/error/done(`taiji-media/src/phase.rs:56-68`);phaseDetail 仅 Paused 带(相位记忆);warning=告警面 | 无(taiji 扩展,旁路) | 名字常量 `events.rs:124`;warning.code 实际发布集:`taiji.media.template_unsafe`(`session/media.rs:1358`)、`taiji.media.metadata_degraded`(`media.rs:1437`)、`taiji.media.staging`(sidecar 降级+合成告警,`media.rs:1663/1864`)、`taiji.media.archive_duplicate`(`media.rs:2249`);告警非 §14 错误码 |
| `taiji.task.cookiesClearedOnError` | `params[0]: {gid, taskKind:"http"\|"media", count:number}`(`server.rs:1067-1078`) | 无(taiji 扩展,旁路) | 名字常量 `events.rs:172`;错误终态清 cookie 的告警;载荷永不携带 cookie 值/名/域(脱敏纪律,`events.rs:174-188`) |
| `system.listNotifications`(方法) | 返回六事件名数组(双面:默认 taiji 六名/兼容 aria2 六名,`dispatch.rs:349-352` + `dispatch.rs:73-104`) | aria2 `system.listNotifications`(RpcMethodFactory.cc 同名方法/同表) | 免鉴权(override authorize,`dispatch.rs:345-347`);扩展事件不入此表,改由 `taiji.getCapabilities` 的 `notifications` 字段声明恰好 4 项(recovery×2 + media + task-cookie,`session/actor/commands.rs:816-831`) |

Verification: the name-freeze and dual-table consistency tests were run and passed during the survey session — `cargo test -p taiji-core --lib session::events::tests` (10 passed), `cargo test -p taiji-rpc --lib notification` (6 passed, including `notifications_match_core_event_kinds` and the dual-face e2e), and `cargo test -p taiji-rpc --lib capabilities_declare` (1 passed).

共 11 条

## Options

The option surface = the declaration tables in `taiji-core/src/session/options.rs` (task table `TASK_OPTION_TABLE` options.rs:1815, global table `GLOBAL_PATCH_TABLE` options.rs:2053, cited-name table `ARIA2_OPTION_NAMES` options.rs:938, extension whitelist `DECLARED_OPTION_DIFFS` options.rs:1134, non-accepted table options.rs:1461, unwired table options.rs:1587) + taiji-rpc's `changeGlobalOption`/`changeOption` (dispatch/methods.rs:740, 658; options parameter shape dispatch/params.rs:38-50, non-string values dropped) + the actor consumption face (session/actor/commands.rs:533-646, 2319-2784). Value conventions: bool = "true"/"false", size = bare bytes or a K/M/G suffix (1024-based, parse_size options.rs:2837), seed-time unit = minutes; unknown keys are always ignored (the aria2 RpcMethod.cc rule, options.rs:9-11); invalid values of known keys are explicitly rejected on the HTTP/addMedia/changeOption faces with error code `taiji.option.invalid` (numeric 28, error.rs:211, 289).

Method face (not counted in the entry totals):

| Method | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| changeGlobalOption | (options:dict)→"OK" | 同名 | 表外键忽略;methods.rs:740-746 |
| getGlobalOption | ()→dict<string,string> | 同名 | 回显=接受域∪启动期键;rpc-secret/rpc-passwd 永不回显(options.rs:677-820、3612-3651) |
| getOption | (gid)→dict | 同名 | 三域查找(active∪reserved∪result);未接受键不伪造;commands.rs:2876-2993 |
| changeOption | (gid,options)→"OK" | 同名 | 活动任务=重启语义;select-file/bt-sequential-download 活动态显式拒绝;commands.rs:2319 |

**A. `changeGlobalOption` accepted face — global hot-reload (52 table rows options.rs:2053-2578 + 2 actor arms commands.rs:559/565)**

| Name | Shape / default | aria2 counterpart | Notes |
|---|---|---|---|
| media-variant-policy | highest\|resolution=<H>\|bandwidth=<B>;默认 highest | taiji 扩展 | 无效值忽略(lenient);对后续 addMedia 生效 |
| media-audio-lang | RFC5646 前缀;默认未设 | taiji 扩展 | 同上 |
| media-subtitles | sidecar\|none;默认 sidecar | taiji 扩展 | |
| media-segment-concurrency | 1..=64;默认 8 | taiji 扩展 | 网络段并发 |
| media-staging-quota-gib | 默认 50 | taiji 扩展 | |
| media-staging-dir | 路径;默认 <dir>/.taiji-b | taiji 扩展 | |
| media-allow-private-key-url | bool;默认 false | taiji 扩展 | SSRF 私网放行(双面) |
| media-ffmpeg-path | auto\|<dir>\|path:<dir>;默认 auto | taiji 扩展 | |
| media-archive | bool;默认 false | taiji 扩展 | 下载档案开关 |
| media-info-json | bool;默认 false | taiji 扩展 | info.json 白名单导出 |
| max-concurrent-downloads | 数 clamp [1,64];默认 5 | 同名 | |
| max-concurrent-seeds | 0..=4096,0=无限;默认 16(两态) | taiji 扩展 | 种子池预算 |
| max-concurrent-checks | 1..=16;默认 2 | taiji 扩展 | 校验池预算 |
| media-synthesis-concurrency | 1..=16;默认 2 | taiji 扩展 | 合成池预算 |
| max-overall-download-limit | size,0=无限;默认 0 | 同名 | 热改共享令牌桶 |
| max-overall-upload-limit | size,0=无限;默认 0 | 同名 | 同上 |
| enable-dht | bool;默认 true | 同名(但热改为扩展) | aria2 无 setChangeGlobalOption 位;翻转热推运行引擎 |
| enable-dht6 | bool;默认 false | 同名 | 无独立 v6 门(跟随 enable-dht),声明分歧 |
| enable-peer-exchange | bool;默认 true | 同名 | 对后续激活任务生效 |
| bt-lsd | bool;默认 false | 重命名(aria2 --bt-enable-lpd) | 与 bt-enable-lpd 同槽别名 |
| client-ban-prefixes | 逗号列表;默认空 | taiji 扩展 | 整表替换;热推+kv 持久化 |
| bt-metadata-web-sources | URL 模板逗号列表;默认空=关 | taiji 扩展 | 磁链 web 镜像源 |
| bt-enable-hook-after-hash-check | bool;默认 true | 同名 | |
| load-cookies | Netscape 文件路径;空串=清除 | 同名 | 后续任务加载,失败即拒 |
| bt-tracker-interval | 秒;默认 0=不覆盖 | 同名 | |
| bt-tracker-timeout | 秒 1..=600;默认 60 | 同名 | |
| bt-tracker-connect-timeout | 秒 1..=600;默认 60 | 同名 | |
| bt-stop-timeout | 秒;默认 0=无看门狗 | 同名 | 做种停滞看门狗 |
| dir | 路径;默认 "." | 同名 | 空串忽略;后续任务默认目录 |
| seed-ratio | f64≥0;默认 1.0 | 同名 | |
| bt-max-peers | 数;默认 55 | 同名 | wired=false:引擎上限是常量缝,仅值面/回显 |
| bt-enable-lpd | bool;默认 false | 同名 | bt-lsd 的 aria2 原名别名行 |
| bt-tracker | 逗号列表 | 同名 | actor 臂(commands.rs:559);并集累积导入+持久化+热推(语义扩展) |
| bt-tracker-file | 路径 | taiji 扩展 | actor 臂(commands.rs:565);trackerslist 文件导入(≤1MiB) |
| split | 字符串(no-op) | 同名 | no-op 值面(DEPRECATED;值存 unwired_option_values,回显原值) |
| min-split-size | 字符串(no-op) | 同名 | 同上 |
| max-connection-per-server | 字符串(no-op) | 同名 | 同上(任务面才有效) |
| user-agent | 字符串(no-op) | 同名 | 同上 |
| connect-timeout | 字符串(no-op) | 同名 | 同上 |
| timeout | 字符串(no-op) | 同名 | 同上 |
| max-tries | 字符串(no-op) | 同名 | 同上 |
| retry-wait | 字符串(no-op) | 同名 | 同上 |
| remote-time | 字符串(no-op) | 同名 | 同上 |
| async-dns | 字符串(no-op) | 同名 | 解析器行为固定,无接线缝 |
| continue | 字符串(no-op) | 同名 | 恒续传语义(倒置声明) |
| pause | 字符串(no-op) | 同名 | aria2 本无 changeGlobal 位;Motrix 守卫会发 |
| bt-exclude-tracker | 字符串(no-op) | 同名 | 无排除面;Motrix 占位空串 |
| all-proxy | 字符串(no-op) | 同名 | 全局代理默认无消费缝 |
| max-download-result | 字符串(no-op) | 同名 | 无结果保留缝 |
| max-file-not-found | 字符串(no-op) | 同名 | 无 404 换源计数缝 |
| max-resume-failure-tries | 字符串(no-op) | 同名 | 无回零缝 |
| max-mmap-limit | 字符串(no-op) | 同名 | 无 mmap 路径 |
| enable-async-dns6 | 字符串(no-op) | 同名 | aria2 侧本就是 Deprecated 包装 |
| https-proxy | 字符串(no-op) | 同名 | 任务面才有效 |

**B. Global startup/config face — echoed or hidden by getGlobalOption only (not accepted by changeGlobalOption)**

| Name | Shape / default | aria2 counterpart | Notes |
|---|---|---|---|
| bt-detach-seed-only | bool;默认 false | 同名 | 仅回显(options.rs:680) |
| listen-port | u16;默认 6881 | 同名 | 启动期;含 6881-6999 回退 |
| bt-require-crypto | bool;默认 false | 同名 | 启动期 |
| bt-min-crypto-level | plain\|arc4;默认 plain | 同名 | 启动期 |
| bt-peer-connection-type | tcp\|utp\|prefer-utp\|prefer-tcp;默认 prefer-tcp | taiji 扩展(fork 旧名) | 启动期 |
| bt-enable-upnp | bool;默认 false | taiji 扩展 | 启动期(aria2 无 UPnP) |
| bt-enable-nat-pmp | bool;默认 false | taiji 扩展 | 启动期 |
| peer-id-prefix | 默认 -TJ0001- | 同名 | 启动期;超长截 20B 不拒 |
| summary-interval | 秒 0..=INT32_MAX;默认 60,0=关 | 同名 | 启动期(options.rs:411-424) |
| dht-entry-point | HOST:PORT;无默认 | 同名 | 启动期 |
| dht-message-timeout | 秒 1..=60;默认 10 | 同名 | 启动期 |
| save-session | 路径;默认空 | 同名 | 回显;saveSession 文本导出目标 |
| save-session-interval | 秒;默认 0=关 | 同名 | 仅 CLI/conf 面,不回显不接受(options.rs:299-314) |
| rpc-user | 字符串;默认空 | 同名 | 设置时回显(options.rs:806-808) |
| rpc-secret | 字符串 | 同名 | 秘密级:永不回显(options.rs:279-282) |
| rpc-passwd | 字符串 | 同名 | 秘密级:永不回显(比 aria2 收紧,options.rs:287-291) |

**C. Task options — `TASK_OPTION_TABLE` (parsing shared by changeOption and the addUri/addTorrent options, options.rs:1815-1976)**

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| dir | 路径 | 同名 | 任务目录;仅未激活任务可改 |
| pause | bool | 同名 | 入队即暂停 |
| seed-ratio | f64≥0 | 同名 | |
| seed-time | 分钟 [0,2^40] | 同名 | 上界为防 Duration 换算 panic(options.rs:21-47) |
| bt-max-peers | 数 | 同名 | |
| max-connection | 数 | taiji 扩展 | Motrix UX 别名→bt-max-peers 槽 |
| max-connection-per-server | 数 | 同名 | BT 面上映射到 bt-max-peers 槽 |
| max-download-limit | size,0=无限 | 同名 | 活动任务热改共享桶 |
| max-upload-limit | size,0=无限 | 同名 | 同上 |
| bt-save-metadata | bool | 同名 | 磁链族 |
| bt-metadata-only | bool | 同名 | 磁链族 |
| follow-torrent | bool | 同名 | 磁链族 |
| pause-metadata | bool | 同名 | 磁链族 |
| bt-load-saved-metadata | bool | 同名 | 磁链族 |
| bt-tracker | 逗号列表 | 同名 | 解析接受但 wired=false 无消费臂(options.rs:1905-1919);原生面=taiji.addTracker/removeTracker |
| select-file | "1-3,5"(1 基闭区间,域 1..=1048576) | 同名 | 三收紧:非法值显式拒/活动任务拒/与 so= 冲突拒(options.rs:3027-3088) |
| bt-disable-dht | bool | taiji 扩展 | 每任务 DHT 门(libtorrent 对齐);活动任务热推 |
| enable-http-seeding | bool;默认 true | taiji 扩展 | BEP19 webseed 开关 |
| bt-enable-hook-after-hash-check | bool;默认 true | 同名 | |
| bt-sequential-download | bool | 同名(投影) | 权威面=taiji.setSchedulerPolicy;活动/做种任务拒 |
| bt-stop-timeout | 秒;默认回退全局 | 同名 | 每任务覆盖 |
| on-download-start | 命令字符串 | 同名 | 手动臂六连(HookEvent::ALL,taiji-domain/hook.rs:88-100);空串=blank=unset |
| on-download-pause | 命令字符串 | 同名 | 同上 |
| on-download-stop | 命令字符串 | 同名 | 同上 |
| on-download-complete | 命令字符串 | 同名 | 同上 |
| on-download-error | 命令字符串 | 同名 | 同上 |
| on-bt-download-complete | 命令字符串 | 同名 | 同上 |

**D. Keys read directly by addUri (options.rs:2731-2735) — task**

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| http-max-per-host | 1..=u32;默认 64 | taiji 扩展(options.rs:227-241) | 每主机连接帽;运行期 last-set-wins;getGlobalOption 回显被 actor 用有效帽覆盖(commands.rs:633-645) |
| out | 文件名 | 同名 | Windows 保留名/尾点尾空格显式拒(windows_unsafe_basename) |
| load-cookies | 路径 | 同名 | 失败即拒(缺文件/不可读/>1MiB) |

**E. HTTP task persistence face (persisted with the task row; `HTTP_PERSIST_OPTION_NAMES` options.rs:2666-2667; table actor/mod.rs:589-631) — task**

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| http-incomplete-suffix | 后缀字符串 | taiji 扩展 | aria2 恒 .aria2 命名 |
| checksum | <scheme>=<hex> | 同名 | 完成时校验裁决 |
| remote-time | bool | 同名 | |

**F. HTTP task runtime face (`HTTP_TASK_OPTION_TABLE` actor/mod.rs:589-1081; invalid value = `taiji.option.invalid` rejection) — task**

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| timeout | 秒≥1 | 同名 | |
| connect-timeout | 秒≥1 | 同名 | |
| max-tries | ≥0,0=无限 | 同名 | |
| retry-wait | 秒≥0 | 同名 | |
| user-agent | 字符串 | 同名 | |
| header | "Name: value" 多行\n 连接 | 同名 | 累积键(fold) |
| http-user | 字符串 | 同名 | 手动臂成对凭据(Basic/Digest 单槽) |
| http-passwd | 字符串 | 同名 | 同上 |
| all-proxy | http(s) URL;socks 拒 | 同名 | socks 拒=声明限制 |
| https-proxy | http(s) URL | 同名 | 域2:HTTPS 专用槽,优先于 all-proxy |
| referer | 字符串 | 同名 | 域2:每跳携带(比 aria2 宽) |
| http-accept-gzip | bool | 同名 | 域2:透明解压 |
| check-certificate | bool;默认 true | 同名 | false 优先于 ca-certificate |
| ca-certificate | PEM 路径 | 同名 | 替换平台信任库;解析期路径/PEM 校验拒 |
| split | 1..=MAX_SPLIT | 同名(语义重定义) | 动态调度下仅种子化初始 extent |
| min-split-size | size | 同名(语义重定义) | 同上 |
| max-connection-per-server | 1..=16 | 同名(语义重定义) | AIMD 环增长帽 |
| http-stall-window | 秒≥3 | taiji 扩展 | 停滞窃取检测窗 |
| http-scheduler | dynamic\|static;默认 dynamic | taiji 扩展 | |
| http-block-size | 2 的幂 256KiB..16MiB;默认 4MiB | taiji 扩展 | 任务内不可变(changeOption 显式拒) |
| http-max-chunk | size≥block-size;默认 32MiB | taiji 扩展 | 引导 extent 帽;跨键校验 |
| http-protocol | auto\|h1\|h2;默认 auto | taiji 扩展(实验窗) | h2=h2c 先验知识 |
| http2-adaptive-window | bool;默认 false | taiji 扩展(实验窗) | |
| http2-stream-window | 字节 65535..=2^31-1;默认 8MiB | taiji 扩展(实验窗) | |
| http2-connection-window | 同域;默认 16MiB | taiji 扩展(实验窗) | |
| http2-max-connections | 1..=8;默认 1 | taiji 扩展(实验窗) | 计入 http-max-per-host |
| http2-keep-alive-interval | 秒 0..=3600;默认 0=关 | taiji 扩展(实验窗) | 超时=2×间隔 |
| http-batch-budget | 2..=64;默认 16 | taiji 扩展 | 同主机组聚合预算 |
| ftp-user | 字符串 | 同名 | FTP 专用凭据槽(手动臂) |
| ftp-passwd | 字符串 | 同名 | 同上 |
| ftp-ssl | none\|auth\|implicit;默认 auth(实现默认 none 由 parse 定) | taiji 扩展 | aria2 无 FTPS |
| ftp-pasv | 仅 true 接受 | 同名(收紧) | false=主动模式显式拒 |
| ftp-reuse-connection | bool;默认 true | 同名 | |
| ftp-pasv-address-check | peer\|strict\|off;默认 peer | taiji 扩展 | PASV/EPSV 地址裁决 |

**G. `taiji.addMedia` option key set (`MEDIA_OPTION_KEYS` media_task.rs:47-68; unknown key = explicit `taiji.option.invalid` rejection) — task**

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| dir | 路径 | 同名 | |
| out | 文件名 | 同名 | |
| pause | bool | 同名 | |
| media-selector | 选择表达式(如 res<=720) | taiji 扩展 | 与 media-variant-policy 互斥 |
| media-variant-policy | highest\|resolution=\|bandwidth= | taiji 扩展 | 投影进 selector 三层 |
| media-audio-lang | RFC5646 前缀 | taiji 扩展 | |
| sub-lang | RFC5646 前缀 | taiji 扩展 | 字幕语言 |
| media-subtitles | sidecar\|none | taiji 扩展 | |
| media-template | 模板字符串 | taiji 扩展 | changeOption 面可再武装 |
| no-meta | bool | taiji 扩展 | 关合成内嵌 |
| media-archive | bool | taiji 扩展 | |
| media-info-json | bool | taiji 扩展 | |
| media-segment-concurrency | 1..=64 | taiji 扩展 | |
| media-staging-quota-gib | 数 | taiji 扩展 | |
| media-staging-dir | 路径 | taiji 扩展 | |
| media-allow-private-key-url | bool | taiji 扩展 | |
| media-ffmpeg-path | auto\|<dir>\|path:<dir> | taiji 扩展 | |
| media-muxer | auto\|… | taiji 扩展 | 仅本面 |
| media-output-format | 默认 mp4 | taiji 扩展 | 仅本面 |
| probe-token | 字符串 | taiji 扩展 | 探测令牌(仅本面) |

**H. addMetalink seam-accepted keys (`METALINK_ACCEPTED_SEAM_OPTION_NAMES` options.rs:2745-2755; taiji-rpc/metalink.rs:58-72) — task (addMetalink)**

| Name | Shape | aria2 counterpart | Notes |
|---|---|---|---|
| metalink-file | 路径 | 同名 | CLI `--metalink-file` 同源 |
| metalink-language | 字符串 | 同名 | 忽略+警告 |
| metalink-location | 字符串 | 同名 | 忽略+警告 |
| metalink-os | 字符串 | 同名 | 忽略+警告 |
| metalink-version | 字符串 | 同名 | 忽略+警告 |
| metalink-preferred-protocol | 字符串 | 同名 | 忽略+警告 |
| metalink-enable-unique-protocol | 字符串 | 同名 | 忽略+警告 |
| metalink-force-protocol | 字符串 | 历史名(不在 1.37.0) | 忽略+警告 |
| metalink-enable-auto-discover | bool;true=按无效处理 | 不在 1.37.0 | true 忽略+警告(不做嗅探转换) |

**I. Declared non-accepted aria2 names (`DECLARED_NON_ACCEPTED_OPTION_NAMES` options.rs:1461-1581; mutual exclusion with the accepted faces is pinned by tests)**

| Name | aria2 counterpart | Notes |
|---|---|---|
| http-proxy | 同名 | 仅 all-proxy 单槽 |
| no-proxy | 同名 | 无按主机豁免面 |
| http-proxy-user | 同名 | 凭据走 URL userinfo |
| http-proxy-passwd | 同名 | 同上 |
| https-proxy-user | 同名 | 同上 |
| https-proxy-passwd | 同名 | 同上 |
| all-proxy-user | 同名 | 同上 |
| all-proxy-passwd | 同名 | 同上 |
| proxy-method | 同名 | 请求形式固定 GET 隧道 |
| save-cookies | 同名 | sqlite 唯一持久源 |
| http-auth-challenge | 同名 | 认证行为固定 |
| http-no-cache | 同名 | 缓存指令面固定 |
| use-head | 同名 | 不用 HEAD 探测 |
| enable-http-keep-alive | 同名 | 恒开 |
| enable-http-pipelining | 同名 | 无管线化 |
| max-http-pipelining | 同名 | 同上 |
| allow-overwrite | 同名 | 恒 false 语义(冲突→taiji.http.path_conflict 13) |
| auto-file-renaming | 同名 | 恒自动改名(false 语义不可达) |
| lowest-speed-limit | 同名 | 0.2 未接线(AIMD 无低速断开源) |
| follow-metalink | 同名 | 不做响应转 metalink |
| metalink-base-uri | 同名 | 无相对 URI 基消费者 |
| dht-listen-port | 同名 | DHT/BT 共口(属 --listen-port) |
| dht-file-path | 同名 | DHT 持久化=sqlite dht_state 表 |
| ftp-type | 同名 | 恒 TYPE I |
| ftp-proxy | 同名 | P2 项 |
| ftp-proxy-user | 同名 | 同上 |
| ftp-proxy-passwd | 同名 | 同上 |

**J. Unwired taiji names and CLI-only accepted names**

| Name | Affiliation | aria2 counterpart | Notes |
|---|---|---|---|
| http-min-chunk | 未接线声明(options.rs:1587-1592) | taiji 扩展 | 按未知键忽略(有效值恒=block 粒度) |
| metalink-servers | CLI-only | taiji 扩展(历史 -C 名) | 每条目镜像数截断(options.rs:4357-4358) |
| stop | CLI-only | 同名(单位差异:aria2 秒/此处分) | 进程限时关停 |
| hash-check-only | CLI-only | 语义锚 TEXT_HASH_CHECK_ONLY | 只校验不下载 |
| peer-agent | CLI-only | 同名 | 接受+警告+无效(UA 钉死构建常量) |

共 165 条(A-H/J 共 198 行按面计,跨面重名去重后 165 个唯一选项名;30 个名字跨面重复,共 33 次额外出现)。

## Survey caveats (non-normative)

The following open review items were recorded by the read-only survey that produced this inventory; they do not change the frozen tables above.

**Count corrections (applied at review).** The survey's declared counts were recomputed from this document's own tables during review: error codes 119 (A5+B14+C3+D22+E19+F10+G37+H9, the two `(兜底)` fallback rows of tables D/E included), not the declared 120; options 165 unique names (198 rows across tables A–H/J with the method-face table excluded; 30 names repeat across faces, 33 extra occurrences), not the declared 162 — no counting convention reproduces 162. The header total follows the recomputed counts (59+119+11+165 = 354).

### Methods

1. The header comment at taiji-rpc/src/dispatch/methods.rs:6 says "the 35 aria2 methods", which does not match the registry decomposition (33 upstream same-name bare names + addMetalink = 34 bare names, plus forceRecheck as an extension and 3 `system.*` entries) — likely a stale comment; needs a human pass (does not affect the table itself).
2. addTorrent parameter slot 1 (webseed URIs) is currently dropped explicitly (dispatch/methods.rs:551-556); the code comment declares the merge as pending engine-side wiring. The difference from upstream aria2 (which merges them into the webseed set) is declared in code; the external documentation stance needs human confirmation.
3. taiji.moveStorage / taiji.renameFile are registered but always answer NotSupported; whether any frontend actually calls them was not checked (the motrix-app frontend code was not read).
4. The survey was read-only; cargo test was not run (a build writes target/ artifacts). The governance test asserting the two registry tables are identical lives at taiji-core/src/session/command.rs:783-810; its pass status is unverified.
5. "Same name" in the aria2-counterpart column follows the inline comments in taiji-domain/src/methods.rs (several cross-checked against RpcMethodFactory.cc / RpcMethodImpl.cc) and the public aria2 1.37.0 method set; the aria2 sources were not re-checked row by row.

### Error codes

1. `media_numeric_code` (error.rs:314) has no production call site in the repository (grep hits only its own definition and the tests in error.rs); the media-task terminal errorCode actually goes through the `http_numeric_code` off-table fallback to 1 at view.rs:306. The doc comment's "threaded through the numeric mapping" wiring point was not found — needs human review (planned-but-unwired, or wired elsewhere such as e2e assertions).
2. `taiji.media.drm_unsupported` / `sidx_unsupported` are asserted only in a test list (error.rs:607-608); the match table has no explicit row and they fall to the 1 fallback (behavior consistent, but the table and the test row list are out of sync).
3. `taiji.http.redirect_to_restricted_ip` (taiji-segment/src/error.rs:360) has no mapping-table row → fallback 1; the error.rs:664 variant-sweep test claims to cover "every taiji-http variant" but its list lacks RedirectToRestrictedIp and RetryAfter — the coverage claim has a seam.
4. The reference doc's row "empty-file probe Done→0 (FINISHED)" (docs/design/rpc.md:443-446) has no row in `try_http_numeric_code` (the success path is not an error); errorCode=31 (REMOVED) has no constant and is passed through numerically by the core (view.rs:309) — the numeric face has both a core pass-through and a mapping-table source; this inventory lists the mapping table.
5. aria2 alignment was checked textually against the read-only aria2 reference sources in the enclosing motrix-app workspace (`aria2/`, `aria2-1.37.0/` — outside the taiji repository; error_code.h, rpc_helper.cc, RpcMethod.cc, RpcMethodImpl.cc/.h, HttpServerBodyCommand.cc, WebSocketSession.cc) and in-code citation comments; aria2 C++ behavior was not re-executed row by row.

### Events

1. The aria2 counterparts (EVENT_ON_* constants, WebSocketSessionMan.cc, RpcMethodFactory.cc, DefaultPieceStorage.cc) are all taken from reference citations in this repository's source comments; the read-only aria2 reference trees live in the enclosing motrix-app workspace (`aria2/`, `aria2-1.37.0/` — outside the taiji repository) and were not re-checked verbatim for this table.
2. MediaWarning's code set is the string literal at each publish point rather than a centralized frozen table: the semantic categories listed in the events.rs:126-142 comment (sidecar degradation / dual-audio failure / splice failure) all collapse to code `taiji.media.staging` at the actual publish points (media.rs:1663, 1864); a new publish point could introduce a new code — a human should confirm whether a centralized enum is needed.
3. This table focuses on names / payloads / dual-face switching; the engine-side publish points of the six events (the hook/actor trigger matrix) were not mapped one by one.
4. payload.rs was verified during the survey to be the request entry (single/batch), not the notification-payload file; notification serialization is at server.rs:983-1078, and this document states that as verified.

### Options

1. Same-name / accepted-or-not determinations all follow in-repo declarations (ARIA2_OPTION_NAMES / DECLARED_* tables and row comments citing prefs.cc / OptionHandlerFactory.cc); aria2 1.37.0 sources were not re-checked — whether metalink-force-protocol / metalink-enable-auto-discover / metalink-servers are truly absent from 1.37.0 prefs.cc deserves a manual spot check.
2. The 4 CLI-only keys (metalink-servers / stop / hash-check-only / peer-agent) come from the CLI_ONLY_ACCEPTED test registration at options.rs:4357-4358; the taiji crate's conf.rs / CLI definitions were not opened one by one to verify spelling and face.
3. save-session-interval, rpc-secret, rpc-passwd are not registered in ARIA2_OPTION_NAMES (the governance test requires registered names to have accept/echo references); their aria2 same-name identity comes from field comments (options.rs:279-291, 299-314) and they are classified as the startup/CLI config face — the classification needs human confirmation.
4. max-concurrent-seeds default 16 is a "two-state default" per comment (to return to 0=unlimited once the connection budget lands, options.rs:84-89, 511-514); the final state needs human confirmation.
5. bt-tracker (task face, options.rs:1905-1919) and bt-max-peers (global face, options.rs:2456-2472) are wired=false accepted faces (parsed and accepted, no consumer / never reach the engine); this inventory counts them as accepted faces — whether to flag them separately as "fake accepts" is a policy call.
6. getOption echoing is an "echo only when a real value exists" projection (e.g. bt-disable-dht / enable-http-seeding appear only when explicitly overridden, commands.rs:3267-3277); this inventory counts accepted faces and does not list echo-only keys separately; the six hook keys are likewise echoed in getOption only when set.
7. Table F's http-block-size is an explicit rejection arm on the changeOption incremental face (mod.rs:1437-1446; settable at creation); the table Notes say so, but the accept/reject split for this key depends on the entry point — a human may refine.
