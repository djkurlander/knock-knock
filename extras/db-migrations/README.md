# DB Migrations

One-off scripts for repairing or migrating the SQLite database when the data format changes.

Current scripts:

- `updatedb.py`
  - Updates an existing `knock_knock.db` to the current schema
  - Creates a timestamped backup in the database directory by default
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

Examples:

```bash
python extras/db-migrations/updatedb.py
python extras/db-migrations/updatedb.py data/knock_knock.db --backup before-upgrade.db
python extras/db-migrations/updatedb.py data/knock_knock.db --no-backup
python extras/db-migrations/migrate_mail_to_smtp.py data/knock_knock.db
python extras/db-migrations/fix_mail_migration.py data/knock_knock.db
```

These scripts are intended to be safe to run multiple times.
