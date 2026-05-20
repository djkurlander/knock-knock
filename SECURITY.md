# Security Policy

## Decoy Credentials in `honeypots/decoys/`

The files under `honeypots/decoys/` contain **intentional fake credentials** used as SMB honeypot lures. These are served to attackers who access the decoy file shares, making the honeypot look like a real server with sensitive data.

These files will trigger automated secret scanners (gitleaks, truffleHog, etc.). They are not real credentials:

- `AKIAIOSFODNN7EXAMPLE` — Amazon's own documented example AWS key ID, universally recognised as fake
- All passwords, connection strings, and keys in this directory are fictional

A `.gitleaks.toml` allowlist is included to suppress false positives for operators running gitleaks in their own pipelines. GitHub's built-in secret scanning already recognises the Amazon example key and will not alert on it.
