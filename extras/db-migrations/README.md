# DB Migrations

One-off scripts for repairing or migrating the SQLite database when the data format changes.

Current scripts:

- `updatedb.py`
  - Updates an existing `knock_knock.db` to the current schema
  - Creates a timestamped backup in the database directory by default
  - Also updates `visitors.db` if it exists and needs the current visitor schema
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
```

These scripts are intended to be safe to run multiple times.
