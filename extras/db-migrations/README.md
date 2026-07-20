# DB Migrations

One-off scripts for repairing or migrating the SQLite database when the data format changes.

Current scripts:

- `updatedb.py`
  - Updates an existing `knock_knock.db` to the current schema
  - Creates a timestamped backup in the database directory by default
  - Also updates `visitors.db` if it exists and needs the current visitor schema
  - Runs the one-time v3 SMTP body migration automatically. This is the **complete**
    upgrade path for a **single-server** honeypot (skip with `--no-smtp-backfill`). A
    **multi-server aggregator** running SMTP needs one additional step — see
    [Upgrading a multi-server aggregator](#upgrading-a-multi-server-aggregator)
  - Moves the historical schema transformations out of `monitor.py`

- `migrate_mail_to_smtp.py`
  - Merges legacy `MAIL` per-protocol intel rows into `SMTP`
  - Preserves `country`, `asn`, and `lat`/`lng`
  - Intended to be run before deploying the code that removes `MAIL`

- `fix_mail_migration.py`
  - Repairs databases that were already migrated with the older buggy `migrate_mail_to_smtp.py`
  - Backfills:
    - `country_intel_proto.country` from `country_intel`
    - `isp_intel_proto.asn` from `isp_intel`
    - `ip_intel_proto.lat` / `lng` from `ip_intel`

- `migrate_visitors_v2.py`
  - Migrates `visitors.db` from one row per visit to one row per IP per day
  - Legacy helper; `updatedb.py` now handles the current visitor schema

- `rename_source_id.py`
  - Renames or merges a `SOURCE_ID` across SQLite and Redis

- `prune_dial_intel_suffix_artifacts.py`
  - Dry-run-first maintenance script for removing likely low-hit SIP
    `dial_intel` parser artifacts when a much stronger shorter suffix target
    exists
  - Only touches `dial_intel`; historical `knocks_sip` rows are preserved

- `fix_cryptic_tnet.py`
  - Dry-run-first cleanup of the Telnet `<cryptic binary>` credential noise that
    topped the password leaderboard (non-Telnet protocol probes on port 23,
    decoded into bogus creds). The honeypot now gates these at capture; this
    removes the already-accumulated rows.
  - Surgical: removes only the Telnet (`proto=TNET`) contribution, subtracting it
    from the ALL aggregates and dropping the Telnet `_proto` rows. The same
    placeholder for SMTP (real bots) and RDP (binary NLA usernames) is preserved.
  - Restart the honeypot with the Telnet gate live first (freezes the count).
    `--apply` to write; `--purge-knocks` also clears matching `knocks_tnet` rows.

- `fix_tollfree_labels.py`
  - Dry-run-first backfill of NANP toll-free `dial_intel` rows from the old generic
    `International Network` label to `North American Toll-Free` (the honeypot now
    labels them that way, but existing rows — and the dial cache they seed at startup —
    kept the old label, so already-seen numbers never updated on their own).
  - Parser-validated: recomputes each candidate via `sip_honeypot.parse_dial_country()`
    and relabels only true NANP toll-free; genuine `+800`/malformed rows are left alone.
  - After `--apply`, restart the honeypot so the dial cache re-seeds.

- `smtp_body_backfill.py`
  - Dry-run-first backfill for the v3 SMTP change: moves each inline `knocks_smtp.body`
    into the deduped `smtp_body_intel` table (one row per distinct body, keyed by
    `sha256`), links the knock via `body_id`, self-redacts the stored body (your own
    IP/host/domain → `<target-*>`, including inside base64/quoted-printable content), and
    clears the original inline body.
  - `updatedb.py` calls this automatically for a single-server honeypot, so you normally
    don't run it by hand. It's used directly only on a **multi-server aggregator** — see
    [Upgrading a multi-server aggregator](#upgrading-a-multi-server-aggregator).
  - `--print-identity` prints this server's resolved identifiers (env `REDACT_SELF_*` plus
    runtime discovery) as `--fleet` file lines; `--fleet FILE` supplies the other servers'
    identifiers on an aggregator. Idempotent; once all rows are backfilled it drops the
    now-empty `knocks_smtp.body` column by default (`--keep-body-column` to keep it).

Examples:

```bash
python extras/db-migrations/updatedb.py
python extras/db-migrations/updatedb.py data/knock_knock.db --backup before-upgrade.db
python extras/db-migrations/updatedb.py data/knock_knock.db --no-backup
python extras/db-migrations/migrate_mail_to_smtp.py data/knock_knock.db
python extras/db-migrations/fix_mail_migration.py data/knock_knock.db
python extras/db-migrations/migrate_visitors_v2.py
python extras/db-migrations/rename_source_id.py --from ams2 --to AMS2 --dry-run
python extras/db-migrations/prune_dial_intel_suffix_artifacts.py --db data/knock_knock.db
python extras/db-migrations/prune_dial_intel_suffix_artifacts.py --db data/knock_knock.db --max-suspect-hits 50 --with-knock-samples
python extras/db-migrations/prune_dial_intel_suffix_artifacts.py --db data/knock_knock.db --mode nanp-alias --with-knock-samples
python extras/db-migrations/prune_dial_intel_suffix_artifacts.py --db data/knock_knock.db --apply
python extras/db-migrations/smtp_body_backfill.py --print-identity
python extras/db-migrations/smtp_body_backfill.py --db data/knock_knock.db --fleet fleet.txt --apply
```

These scripts are intended to be safe to run multiple times.

## Upgrading a multi-server aggregator

This step is **only** for a multi-server setup where feeder honeypots forward their
knocks to a central aggregator dashboard **and** SMTP is enabled. A single-server
honeypot needs nothing here — `updatedb.py` already did everything.

v3 stores each SMTP message body once, in a deduped `smtp_body_intel` table, with your
own IP/host/domain redacted out. `updatedb.py` does this
automatically — but **only for the mail this server captured itself**, because it redacts
using *this machine's* identity (its IPs, hostnames, domains, discovered at runtime).

On an aggregator, most SMTP was captured by the **feeders**, and those bodies contain the
*feeders'* addresses — which the aggregator can't discover on its own. So `updatedb.py`
**skips** them and prints how many it left. Until you run the step below, those bodies stay
stored un-redacted on the aggregator.

To finish, give the migration each feeder's identity:

1. On **each feeder**, print its identity as ready-to-use lines:
   ```bash
   python extras/db-migrations/smtp_body_backfill.py --print-identity
   ```
2. Paste every feeder's output into one file, e.g. `fleet.txt` (comment lines are ignored):
   ```
   # feeder ny3
   source=ny3
   ip=203.0.113.9
   host=mail.ny3.example.net
   domain=example.net
   # feeder lon1
   source=lon1
   ip=198.51.100.7
   ```
3. On the **aggregator**, run it — dry-run first, then `--apply`:
   ```bash
   python extras/db-migrations/smtp_body_backfill.py --db data/knock_knock.db --fleet fleet.txt
   python extras/db-migrations/smtp_body_backfill.py --db data/knock_knock.db --fleet fleet.txt --apply
   ```

Listing an address that never appears in a body does nothing, so the combined `fleet.txt`
is safe to run over everything. It's idempotent — safe to re-run. Once **every** body is
migrated (global count of un-backfilled rows hits zero — i.e. after this fleet pass on an
aggregator), the run **drops the now-empty `knocks_smtp.body` column** automatically (pass
`--keep-body-column` to keep it; on SQLite < 3.35 it just stays). Going forward, each feeder
redacts its own mail before forwarding, so this is a one-time catch-up for history captured
before the upgrade.
