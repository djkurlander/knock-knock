# SIP Honeypot — Asterisk Media Integration

## Background

The SIP honeypot (`honeypots/sip_honeypot.py`) handles full SIP signaling — REGISTER,
INVITE, auth challenges, knock emission, dedup, throttling — but returns a fake SDP
with `port=0` in its 200 OK responses. This means the call appears to complete from
the attacker's perspective, but no actual RTP audio is exchanged.

Adding Asterisk as a media backend allows the honeypot to:
- Accept real RTP audio from the attacker
- Play a pre-recorded greeting (e.g. a convincing embassy automated attendant)
- Record what the attacker sends — potentially revealing whether calls are automated
  probes, IVR-navigation bots, or humans expecting to reach a specific destination
- Gather evidence bearing on *why* specific numbers (e.g. foreign embassy switchboards
  in Washington D.C.) appear on toll fraud target lists

## Architecture Overview

```
Attacker ──SIP signaling──▶ sip_honeypot.py (port 5060)
                                │  emits knock JSON to stdout
                                │  (credentials, dial number, geo, etc.)
                                │
                                │  [NEW] if FORWARD_TO_ASTERISK matches:
                                │    1. call whitelist API on Asterisk VPS
                                │    2. return real SDP pointing to Asterisk
                                │
Attacker ──RTP audio──────────▶ Asterisk VPS
                                   plays greeting, records response
                                   saves .wav files locally
```

Everything in `monitor.py`, Redis, and the dashboard is unchanged — the Asterisk
integration lives entirely inside `sip_honeypot.py` and the Asterisk server.

---

## Option 1 — Swap SDP to Real RTP Endpoint (Initial Implementation)

`sip_honeypot.py` continues to handle all SIP signaling. When it sends a 200 OK for
an INVITE that matches `FORWARD_TO_ASTERISK`, it substitutes a real IP:port in the
SDP instead of `port=0`. The attacker's RTP stream goes directly to Asterisk. The
SIP signaling never touches Asterisk.

### Advantages
- ~20–50 lines of code change in `sip_honeypot.py`
- No changes to `monitor.py`, Redis, or dashboard
- Low risk — gated entirely behind `FORWARD_TO_ASTERISK` env var; default behavior
  is identical to today
- One Asterisk install serves all honeypot servers

### Disadvantages
- Asterisk's IP address is visible to the attacker in the SDP
- Asterisk must be on a dedicated VPS with no other sensitive services
- Asterisk does not receive SIP signaling — no caller ID or dial string in its dialplan
  (mitigated by the whitelist API passing metadata if needed)

### Deployment

**Single remote Asterisk VPS** — set `ASTERISK_RTP_HOST` on each honeypot server.
All honeypot servers share one Asterisk instance. No per-server Asterisk install.

---

## Option 2 — B2BUA / SIP Forwarding (Future, If IP Privacy Required)

`sip_honeypot.py` acts as a Back-to-Back User Agent (B2BUA): it terminates the
attacker's INVITE on one leg and re-originates a fresh INVITE to Asterisk on a second
leg. The attacker only ever sees the honeypot server's IP. Asterisk's IP is never
exposed.

### Advantages
- Asterisk IP stays completely hidden
- Asterisk receives a full SIP INVITE — caller ID, dial string, headers all available
  in the Asterisk dialplan
- Can run Asterisk on any private/internal network

### Disadvantages
- ~200+ lines of new B2BUA logic in `sip_honeypot.py`
- Higher complexity, more failure modes
- Higher risk of affecting existing INVITE handling

### When to choose Option 2
If the Asterisk VPS IP exposure from Option 1 becomes a problem (e.g. the VPS starts
receiving significant direct attack traffic that the dynamic firewall cannot manage),
migrate to Option 2.

---

## Dynamic Firewall Whitelist

Because any IP:port published in an SDP will eventually be scanned directly, the
Asterisk VPS should not have its RTP ports permanently open. Instead, `sip_honeypot.py`
calls a small API on the Asterisk VPS immediately before sending the 200 OK, opening
a temporary firewall rule for the specific attacker IP.

### Flow

1. INVITE arrives from `attacker-ip`
2. `sip_honeypot.py` calls `POST https://asterisk-vps/allow` with `{ip, duration_seconds}`
3. Asterisk VPS adds a temporary `iptables`/`ufw` rule: allow UDP from `attacker-ip`
   to RTP port range (e.g. 10000–20000) for `duration_seconds` (suggested: 600)
4. `sip_honeypot.py` sends 200 OK with real SDP
5. Rule expires automatically after the window

### Asterisk VPS firewall default policy
- Block all inbound UDP to RTP port range by default
- Block port 5060 entirely (Asterisk does not need to receive SIP from attackers)
- Permanently allow inbound from each honeypot server's IP (for the whitelist API)
- Authenticated whitelist API (shared secret in `Authorization` header)

### Whitelist API (small Flask app on Asterisk VPS)

```python
# ~30 lines — receives POST /allow {ip, duration_seconds}
# validates shared secret
# runs: iptables -A INPUT -s {ip} -p udp --dport 10000:20000 -j ACCEPT
# schedules removal after duration via threading.Timer or at
```

---

## New Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `FORWARD_TO_ASTERISK` | unset | Forwarding policy (see below) |
| `ASTERISK_ALLOW_IPS` | unset | Comma-separated source IPs to forward; unset = no IP filter |
| `ASTERISK_RTP_HOST` | unset | IP of the Asterisk VPS |
| `ASTERISK_RTP_PORT_START` | `10000` | Start of Asterisk RTP port range |
| `ASTERISK_WHITELIST_URL` | unset | URL of the whitelist API on the Asterisk VPS |
| `ASTERISK_WHITELIST_SECRET` | unset | Shared secret for whitelist API auth |
| `ASTERISK_WHITELIST_WINDOW` | `600` | Seconds to hold the firewall rule open |

### `FORWARD_TO_ASTERISK` values

| Value | Behaviour |
|-------|-----------|
| unset or `none` | Current behaviour — fake SDP, no media forwarding |
| `all` | Forward all answered INVITEs to Asterisk |
| `+12022234942,+12029446000` | Forward only calls to these specific E.164 numbers |
| `+1202` | Forward calls matching this prefix (all DC area code numbers) |
| `US` | Forward calls where `sip_dial_country` matches this ISO code |

Matching is checked in order: exact E.164 → prefix → country code. If the dial
number does not match, the current fake SDP behaviour is used as fallback.

---

## Changes to `sip_honeypot.py`

All changes are confined to `_send_invite_sequence()` and a new helper
`_maybe_forward_to_asterisk()`.

### `_maybe_forward_to_asterisk(dial_number, client_ip)`

1. Check `FORWARD_TO_ASTERISK` env var — return `None` if unset/none or no match
2. Call whitelist API: `POST ASTERISK_WHITELIST_URL/allow {ip: client_ip, duration: ASTERISK_WHITELIST_WINDOW}`
3. On API success, return `(asterisk_host, asterisk_rtp_port)` tuple
4. On API failure (timeout, auth error), log and return `None` — falls back to fake SDP

### `_send_invite_sequence()` modification

```python
# Existing: always uses fake SDP with port=0
# New: check for Asterisk forwarding first

asterisk = _maybe_forward_to_asterisk(dial_number, client_ip)
if asterisk:
    host, port = asterisk
    sdp = _build_real_sdp(host, port, session_id)
else:
    sdp = _build_fake_sdp(session_id)   # current behaviour unchanged
```

### SDP construction

Real SDP differs from fake SDP only in:
- `c=IN IP4 <asterisk_host>` instead of honeypot IP
- `m=audio <asterisk_rtp_port> RTP/AVP 0 8` with real port instead of `0`

---

## Asterisk Dialplan (Sketch)

```
[honeypot-inbound]
exten => _X.,1,Answer()
exten => _X.,n,Wait(1)
exten => _X.,n,Playback(embassy-greeting)   ; pre-recorded mp3 converted to .wav
exten => _X.,n,Record(/var/spool/asterisk/honeypot/${CALLERID(num)}-${EPOCH}.wav)
exten => _X.,n,Hangup()
```

Recordings saved to `/var/spool/asterisk/honeypot/` with caller IP and timestamp in
filename. A cron job or inotify watcher can ship new recordings to a central store.

---

## Note on Symmetric RTP

Some SIP clients use symmetric RTP — they send RTP from the same IP:port they expect
to receive it on. This is a NAT traversal technique and is completely normal. It does
not affect whether you receive their audio stream. It only affects whether they can
hear your playback, which requires Asterisk to send return audio to their source
IP:port. Asterisk handles this correctly by default.

In practice: automated bots may not receive or act on your playback at all. Human
operators on the other end are more likely to have properly configured SIP clients
that receive your audio — and are the most interesting capture target.

---

## What to Expect in Recordings

| Caller type | Likely audio content |
|-------------|---------------------|
| Pure capability probe | Silence — RTP port opens, few packets, hangup |
| IVR-navigation bot | DTMF tones — bot navigating what it thinks is a menu |
| Toll fraud infrastructure test | Silence or brief audio burst, then hangup |
| Human operator | Voice — possibly confused, possibly conducting scripted business |
| Pre-recorded fraud audio | Audio in any language, possibly embassy-context content |

The recording is valuable regardless of content. Even silence confirms the call
connected and the bot did not send audio — which is itself a data point about intent.
