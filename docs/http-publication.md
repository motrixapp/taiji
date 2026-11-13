# HTTP file publication

[简体中文](http-publication.zh-CN.md)

As of 0.3.0, taiji owns normal HTTP/FTP file publication. With
`http-incomplete-suffix=.motrix`, a download writes `name.ext.motrix` and
publishes `name.ext` once. All transfer modes, including non-Range and
unknown-length responses, verify any requested checksum before publication,
sync the file and close its handles.

## Completion and retries

The durable `http_task` state is `finalizing` while publication is pending.
The record in `config_json.publication` contains the actual source, selected
target, expected length, reservation nonce, phase
and last error. Closed outputs do not consume download concurrency, including
when the configured payload budget is zero. Temporary file locks and unavailable
volumes are retried without probing or fetching the source again. A task is
`done`, and emits `taiji.onDownloadComplete`, only after publication succeeds.

The normal operation is a no-replace rename. A late name collision selects a
numbered filename and persists that path before trying it. An existing target
of the same size is never adopted while the source still exists. When native
no-replace rename is unsupported, taiji tries a hard link and then an exclusive,
journaled target reservation in the same parent directory. The reservation
fallback assumes an application-managed namespace; it is not an exclusion
mechanism against an unrestricted external writer replacing that reservation.

Normal completion and replay require no filesystem file ID, volume UUID,
sidecar process or second full-file hash. Unsupported directory sync degrades
with a logged durability note, including Windows directory-access rejection.
File sync failures and real disk/transport failures remain pending or errors.
The final artifact takes priority over cleanup of a redundant hard-link source.

## Fixed embedding API

Set `http-host-finalize=true` for a task whose host runs pre-publication hooks.
The native driver persists `ready` and emits `taiji.onHttpOutputReady` after
closing its handles. The host must query the actual paths, not reconstruct them
from the original name. `tellStatus.http.hostControlled` lets a host retain its
logical Finalizing state until its database transaction commits.

- `taiji.getHttpOutput(gid)` returns string-valued fields: `state`
  (`downloading|ready|publishing|published`), `hostControlled`, `paused`, and,
  when available, `sourcePath`, `finalPath`, `length`, `error`.
- `taiji.finalizeHttp(gid, {action, path?})` accepts `publish`, `external` or
  `hold`. Paths must be absolute. `publish` durably accepts native publication;
  repeated acceptance keeps the original accepted intent. Filesystem work runs
  in the driver, outside the session command loop. `external` acknowledges an
  exceptional host-owned replacement/move after the host has committed its
  filesystem and database transaction. `hold` cancels and drains publication
  while retaining the receipt, so removal can query the actual owned path.
- The host commits its actual final path, file references and completion outbox
  in one logical transaction, then calls `removeDownloadResult`. Published
  receipts survive until removal. Notification loss is handled by querying
  receipts on startup, reconnect and while a logical task remains Finalizing.

Pause preserves the publication intent. Force-remove cancels and drains an
in-flight publication operation before acknowledging removal. A filesystem
operation that has already begun cannot be undone by cancelling its future.

## Recovery

The driver resumes the exact publication record before constructing any HTTP
client. The startup hold protects admission until the host restores task
ownership. A ready task waits for host acceptance; an accepted publication
retries its saved target, and a published receipt waits for the host database
commit. No filename inference or additional transfer is involved.

| Interruption | Recovery |
| --- | --- |
| Before closed-data intent | Normal transfer checkpoint recovery |
| Ready, before host acceptance | Replay ready; run eligible host hooks |
| Accepted, before rename | Retry persisted publication; do not rerun hooks |
| Rename succeeded, journal not cleared | Confirm source absence and the recorded target length; retry directory sync |
| Native publication succeeded, host DB commit failed | Retry only the logical host transaction |
| Host DB committed, result not removed | Retire the native receipt on retry/startup |

Motrix uses the ordinary path for empty hook contributions and same-parent
renames. Actual plugin metadata/replacements and moves to another parent keep
the existing durable host transaction. This makes plugin changes during a
running download effective without duplicating the common file lifecycle.
