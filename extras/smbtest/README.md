# SMB Test Utilities

These scripts exercise the SMB honeypot against the local decoy surface.

- `smbtest_v1.py`: SMB1-only client using `impacket`
- `smbtest_v2.py`: SMB2/3 client using `smbprotocol`

Usage:

```bash
python extras/smbtest/smbtest_v1.py [target_ip] [port]
python extras/smbtest/smbtest_v2.py [target_ip]
```

Defaults:

- target host: `127.0.0.1`
- username: `testuser`
- password: `testpass`

Purpose:

- enumerate shares
- traverse decoy directories
- read decoy file content
- catch protocol compatibility regressions in the honeypot
