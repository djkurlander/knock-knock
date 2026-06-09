# SIP Honeypot - Asterisk B2BUA Integration

## Background

The SIP honeypot (`honeypots/sip_honeypot.py`) handles SIP signaling today:
REGISTER, INVITE, auth challenges, knock emission, dedup, throttling, and dial
number enrichment. For INVITEs it currently returns fake SDP with `port=0`, so the
call appears to progress but no real RTP audio is exchanged.

Adding Asterisk as a media backend should let the honeypot:
- play a convincing pre-recorded greeting;
- record inbound caller audio and DTMF;
- preserve existing knock telemetry for dial strings, credentials, source IPs, and
  destination geocoding;
- investigate why specific numbers appear on toll-fraud target lists.

## Decision

Use a Back-to-Back User Agent (B2BUA) design implemented in a separate module:

```text
honeypots/sip_honeypot.py  - existing SIP parser, classifier, logger, fallback fake SDP
honeypots/sip_b2bua.py     - optional Asterisk bridge, SIP leg mapping, RTP relay
```

Do not continue with the earlier "swap SDP to Asterisk RTP" approach as the main
implementation. That design exposes the Asterisk IP to attackers and does not give
Asterisk a normal SIP call leg. Bidirectional audio then requires ARI External Media
and a sidecar process, which moves complexity out of the repository and into the
Asterisk host.

With B2BUA, the attacker only sees the honeypot. Asterisk receives a normal SIP call
from the honeypot and can use an ordinary dialplan.

## Architecture

```text
Attacker
  SIP/RTP
    |
    v
sip_honeypot.py :5060
  - parses and logs attacker INVITE
  - emits existing SIP knock JSON to monitor.py
  - asks sip_b2bua.py whether this INVITE should be bridged
    |
    v
sip_b2bua.py
  - creates outbound SIP leg to Asterisk
  - rewrites SDP as needed
  - relays RTP between attacker and Asterisk
  - maps ACK/BYE/CANCEL between both legs
    |
    v
Asterisk
  - receives normal SIP INVITE from honeypot
  - runs standard dialplan: Answer, Playback, Record, Hangup
```

`monitor.py`, Redis publishing, and dashboard rendering remain unchanged. The
honeypot still emits the knock before or while bridging the call. Bridging is an
optional side effect of selected SIP INVITEs, not a replacement for telemetry.

## Security Model

The Asterisk server should not be exposed to attackers.

- Asterisk SIP port accepts traffic only from honeypot server IPs.
- Asterisk RTP range accepts traffic only from honeypot server IPs.
- The attacker never sees the Asterisk IP in SIP headers or SDP.
- No attacker-IP whitelist API is needed for the B2BUA path.
- Asterisk can run on a private network or a firewall-restricted VPS.

The honeypot remains the public SIP endpoint. If the B2BUA setup fails, the honeypot
falls back to the current fake SDP behavior.

## Configuration

Unset `PBX_HOST` means B2BUA bridging is disabled.

| Variable | Default | Purpose |
|----------|---------|---------|
| `PBX_HOST` | unset | PBX/Asterisk SIP host; setting this enables bridging |
| `PBX_PORT` | `5060` | PBX/Asterisk SIP UDP port |
| `PBX_DIAL_POLICY` | `all` | Dial policy for calls eligible for PBX bridging |
| `SIP_PUBLIC_IP` | auto-detect | Honeypot IP advertised to attackers in SDP |
| `PBX_RTP_PORT_START` | `30000` | First local RTP relay port on the honeypot |
| `PBX_RTP_PORT_END` | `30100` | Last local RTP relay port on the honeypot |
| `PBX_CALL_TIMEOUT` | `120` | Maximum bridge lifetime before cleanup |
| `PBX_TRACE` | `false` | Emit bridge debug traces to stdout/stderr |

### `PBX_DIAL_POLICY` values

| Value | Behavior |
|-------|----------|
| `all` | Bridge all ring/answer INVITEs with a valid dial target |
| `none` or empty | Do not bridge; use existing fake SDP behavior |
| `+12022234942,+12029446000` | Bridge only these E.164 numbers |
| `+1202` | Bridge calls matching this E.164 prefix |
| `US` | Bridge calls whose parsed destination country is this ISO code |

Matching should use the already parsed `sip_dial_number` and `sip_dial_country`
values from `sip_honeypot.py`. Setting `PBX_HOST` enables the B2BUA feature; set
`PBX_DIAL_POLICY=none` if the upstream host should remain configured
but no calls should be bridged.

## Module Boundary

`sip_honeypot.py` should stay small. It should continue to own:
- parsing inbound SIP;
- extracting dial metadata;
- emitting knocks;
- current fake/ring/answer fallback behavior;
- TCP/UDP listener lifecycle.

`sip_b2bua.py` should own:
- whether B2BUA is enabled;
- dial-target policy checks;
- outbound INVITE construction;
- Call-ID, CSeq, tag, Contact, Via, and branch mapping;
- SDP generation and rewriting;
- local RTP relay allocation;
- ACK, BYE, and CANCEL handling for active bridged calls;
- bridge cleanup and timeout handling.

The integration point should be narrow. Conceptually:

```python
bridge = sip_b2bua.maybe_start_bridge(
    req=req,
    client_ip=client_ip,
    dial_number=common.get("sip_dial_number"),
    dial_country=common.get("sip_dial_country"),
    send_to_attacker=send_fn,
)
if bridge:
    common["sip_asterisk_forwarded"] = 1
    return "INVITE_B2BUA", req, bridge
```

The exact API may differ, but `sip_honeypot.py` should not need to know B2BUA
internal state.

## First Implementation Scope

Keep the first version deliberately narrow:

- UDP SIP only for bridged calls.
- INVITE, provisional/final responses, ACK, BYE, and CANCEL.
- PCMU/PCMA only.
- One configured Asterisk upstream.
- No SIP authentication to Asterisk unless required later.
- One RTP relay pair per active call.
- Conservative timeouts and cleanup.
- Fallback to fake SDP on setup failure.

TCP parity, multiple upstreams, SIP auth, codec expansion, and richer call-state
inspection can come later.

## SIP Flow

1. Attacker sends INVITE to `sip_honeypot.py`.
2. `sip_honeypot.py` parses the request and emits the normal SIP knock.
3. If `PBX_HOST` is unset or `PBX_DIAL_POLICY` does not match, existing
   fake SDP behavior continues.
4. If B2BUA matches, `sip_b2bua.py` allocates RTP relay resources and sends an
   outbound INVITE to Asterisk.
5. Asterisk replies with provisional/final responses.
6. `sip_b2bua.py` maps responses back to the attacker.
7. RTP flows attacker <-> honeypot relay <-> Asterisk.
8. ACK/BYE/CANCEL and timeout cleanup tear down both legs and release relay ports.

## RTP Relay

To keep Asterisk hidden, the attacker-facing SDP must advertise the honeypot's IP
and a local RTP relay port. The Asterisk-facing SDP must advertise a separate local
relay port reachable by Asterisk.

The relay should avoid media processing. It only forwards UDP packets between the
attacker endpoint and the Asterisk endpoint after each side is learned or configured.
Do not decode, transcode, inspect, or buffer audio in Python.

Expected added latency should be small for low-volume honeypot calls. The main risks
are blocking code, excessive buffering, or codec transcoding. Keep both legs on PCMU
or PCMA and let Asterisk handle prompts and recording.

## Asterisk Setup

With B2BUA, Asterisk receives a normal call from the honeypot. The dialplan can be
ordinary:

```asterisk
[honeypot-inbound]
exten => _X.,1,Answer()
exten => _X.,n,Wait(1)
exten => _X.,n,Playback(embassy-greeting)
exten => _X.,n,Record(/var/spool/asterisk/honeypot/${CALLERID(num)}-${EPOCH}.wav)
exten => _X.,n,Hangup()
```

Recordings should be saved locally on the Asterisk host and shipped out-of-band if
needed. The filename should include enough call metadata to correlate back to the SIP
knock, such as caller source IP or generated bridge ID.

## Telemetry

`sip_asterisk_forwarded` remains useful, but its meaning should be precise:

- `1`: the INVITE was selected for B2BUA bridging and bridge setup was attempted.
- `0`: the INVITE used existing fallback behavior.

It does not confirm that audio was recorded. A future field such as
`sip_asterisk_recorded` can be set by an Asterisk callback or recording shipper if
confirmed media receipt matters.

`protocols/sip.py` should declare:

```python
Column("sip_asterisk_forwarded", "INTEGER"),
```

`monitor.py` already persists declared protocol columns when SIP knock saving is
enabled and passes through `sip_` fields to Redis/WebSocket packages.

## Rejected Option: SDP-Only RTP Forwarding

The earlier plan was to replace fake SDP with Asterisk's RTP IP and port while
keeping all SIP signaling inside `sip_honeypot.py`.

That approach is not the main path because:
- it exposes the Asterisk IP in SDP;
- Asterisk receives no SIP INVITE, so the normal dialplan does not run;
- bidirectional audio requires parsing attacker SDP and coordinating ARI External
  Media or a separate RTP sidecar;
- port allocation and concurrent call handling become Asterisk-side state problems;
- the implementation is harder to operate and debug than a normal SIP call leg.

It remains acceptable as a future passive-recording experiment, but not for the
primary bidirectional audio design.

## Open Questions

- Should the first version bridge only one call per source IP at a time?
- Should the Asterisk dialed extension be the original destination number or a fixed
  honeypot extension with metadata in headers?
- How should recordings be correlated back to `knocks_sip` rows: Call-ID, generated
  bridge ID, or filename convention?
