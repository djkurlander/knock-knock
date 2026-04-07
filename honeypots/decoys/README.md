# SMB Honeypot Decoy Shares

This directory defines the fake SMB shares served by the SMB honeypot. It contains
**no real credentials or sensitive data** — everything here is bait.

## How it works

Each subdirectory becomes an SMB share name (e.g. `PUBLIC/` → `\\server\PUBLIC`).
Files inside are loaded into memory at startup and served verbatim to anyone who
connects and reads them. Zero filesystem access happens after boot.

```
decoys/
  PUBLIC/          ← share name (uppercased)
    passwords.txt  ← bait file served to attackers on READ
  FINANCE/         ← add more shares by adding more subdirectories
    accounts.csv
    vpn_creds.txt
```

## The files are fake

`passwords.txt` contains invented credentials that don't work anywhere. The goal is
to look convincing enough that an automated scanner reads the file and possibly tries
the credentials — which generates additional knock events we can observe.

## This README is never served

Files in the root of this directory are ignored by `_load_decoys()`. Only files
inside share subdirectories are loaded. Safe to document here freely.

## Customizing

- Add/rename subdirectories to change share names
- Add/edit files to change what attackers see when they read the share
- Set `SMB_DECOY_DIR` env var to point at a different directory entirely
- If this directory is missing or empty, the honeypot falls back to a hardcoded
  `PUBLIC/passwords.txt` so it always has something to serve
