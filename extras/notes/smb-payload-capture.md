# SMB Payload Capture Notes

Context from investigation of SMB bots attempting remote execution through `SVCCTL`.

## Current Findings

- We now handle `SVCCTL` `ROpenServiceW` (`opnum 16`) in [`honeypots/smb_honeypot.py`](/root/knock-knock/honeypots/smb_honeypot.py).
- That got at least one bot as far as `OPEN_SERVICE`, but not yet to `CreateServiceW` / `StartServiceW`.
- The strongest current theory is:
  - bots try to stage a payload on the decoy writable share (currently `PUBLIC`)
  - they then verify whether the payload exists
  - if the file still appears absent, they do not proceed to service creation

Observed pattern:

1. `TREE_CONNECT IPC$`
2. `SRVSVC` bind and share enumeration
3. `TREE_CONNECT PUBLIC`
4. attempted payload create paths such as:
   - `olCpUbct.exe`
   - `temp/svchost.exe`
5. repeated `FSCTL_PIPE_TRANSCEIVE`
6. `SVCCTL`:
   - `OpenSCManager`
   - `OpenService`
7. follow-up create/open checks like:
   - `olCpUbct.exe` -> `not_found`
   - `temp/tmp.vbs` -> `not_found`
8. no `CreateServiceW`

Interpretation:

- `OpenService` is not execution.
- The bot may continue into SCM probing even after an earlier failed create.
- But once follow-up checks show the payload is not present, the bot appears not to advance to `CreateServiceW`.

## Current Logging Changes

- SMB `CREATE` knocks now emit for all SMB1/SMB2 decoy-share create attempts, not just some outcomes.
- `ROpenServiceW` DCERPC request parsing was tightened to be more spec-driven, with additional trace fields:
  - `stub_preview`
  - `has_object_uuid`
  - `auth_length`
  - `auth_pad_length`

## This Session's Changes

Changes made during this debugging session that may affect whether the bot proceeds farther:

- Added handling for `SVCCTL` `ROpenServiceW` so the honeypot now reaches `OPEN_SERVICE` instead of faulting immediately.
- Tightened DCERPC REQUEST parsing for `ROpenServiceW` to handle:
  - optional object UUID
  - optional auth verifier trailer
  - auth padding
- Added bounded request-stub tracing so future `ROpenServiceW` failures can be diagnosed from logs without guessing:
  - `stub_preview`
  - `has_object_uuid`
  - `auth_length`
  - `auth_pad_length`
- Changed SMB1/SMB2 decoy-share `CREATE` handling to emit knocks for all create attempts, including:
  - successful opens
  - `write_denied`
  - `not_found`

These changes may improve observability enough to show the next blocker more clearly, but they may not by themselves be sufficient to drive the bot into `CreateServiceW`.

## What To Watch For Next

On the next run from a similar bot, watch specifically for:

- whether `svcctl_open_service` now logs a real `service_name`
- whether the bot proceeds to:
  - `svcctl_create_service`
  - `svcctl_start_service`
- whether the follow-up `PUBLIC` create/open checks still show:
  - payload path `not_found`
  - or repeated write/create failures

If `OPEN_SERVICE` decodes cleanly but the bot still does not reach `CreateServiceW`, that would strengthen the current theory that fake file staging success is the next required step.

## Proposed Next Step

Implement a fake writable in-memory overlay for decoy shares, most importantly `PUBLIC`.

### Goal

Make bots believe payload staging succeeded so they continue into:

- `CreateServiceW`
- `StartServiceW`

and possibly allow capture of the actual dropped payload bytes.

### Suggested Design

Add per-session overlay state in the SMB session handler, alongside existing maps like:

- `decoy_trees`
- `open_files`
- `pipe_fids`
- `svc_handles`

Recommended new state:

- `overlay_files = {(share, path): bytes}`
- optionally `overlay_dirs = {(share, path)}`

`open_files` entries for writable/create handles should point to the overlay path so later:

- `CREATE` can create/open the file
- `WRITE` can store bytes in memory
- `CLOSE` can finalize state
- later `CREATE` / open / existence checks see the file as present
- optional `READ` / `QUERY_INFO` can return coherent size/content

### Why Store Actual Bytes

Storing only an existence record is weaker than storing the full in-memory content.

Keeping actual bytes enables:

- believable file size / read behavior
- payload capture for later analysis
- hashing or preview extraction if desired

Likely data shape:

- `('PUBLIC', 'olCpUbct.exe') -> b'...'`
- `('PUBLIC', 'temp/svchost.exe') -> b'...'`
- `('PUBLIC', 'temp/tmp.vbs') -> b'...'`

### Minimum Viable Behavior

To drive bots farther, the likely minimum useful implementation is:

1. payload `CREATE` succeeds for new files
2. `WRITE` succeeds and stores bytes
3. `CLOSE` succeeds
4. later existence checks reopen the same path successfully

That may be enough to trigger `CreateServiceW`.

### Optional Later Enhancements

- emit a dedicated knock or trace when a payload is closed after writes
- compute hash / size of dropped payload
- optionally persist full payloads to disk for offline inspection
- add `smb_result` or richer create outcome fields later if needed

## Caveat

Before implementing broad fake write success, keep scope narrow:

- decoy shares only
- in-memory only
- no real filesystem writes

This should be enough to study the execution chain without changing the external deployment model.
