# SIP embassy beacons — bots dialing DC foreign embassies as route-reachability tests

**Date:** 2026-06-14 (updated 2026-06-20)
**Status:** Observed / ongoing

## Summary

Multiple **independent** SIP-scanning toolkits dial four Washington-DC foreign-embassy
numbers through the honeypot. They are used as **answer-supervision "reachability
beacons"**: a number guaranteed to answer 24/7, dialed to confirm that a scanned route
can place a call to the US and get a real answer. The bots take the `200` and abandon
(no `ACK`, no media). Embassies are a *common* beacon choice across **unrelated**
campaigns — not one botnet.

## The four numbers (all embassies in Washington, DC)

| Number | Embassy | hits | last seen |
|---|---|---|---|
| `+12022234942` | Albania | 3426 | 2026-05-25 |
| `+12029446000` | France | 1542 | 2026-06-13 |
| `+12023423800` | Saudi Arabia | 726 | 2026-05-31 |
| `+12025886500` | Britain | 162 | 2026-06-14 |

(All geocode to the same DC centroid — `~38.895, -77.036` — because the geocoder only
resolves to city level.)

## Why an embassy?

Answer supervision only yields signal if the destination actually answers. An embassy's
24/7 line is a near-perfect "always-`200`" beacon: a returned `200` cleanly means "this
route reaches the US and completes." So bots use embassies to **validate routes** — the
same idea as an operator-controlled beacon, but using a *public* always-on number, so no
infrastructure of their own is needed.

## Campaigns / toolkits (several, independent)

| toolkit / origin | embassies | signature |
|---|---|---|
| **ReliableSite.Net (ASN 23470)** — dominant | Albania, France, Saudi | hex/num-triplet Call-IDs (`999206533-729379986-…`, `fdd18-13a4421-…`); IPs `209.222.101.54`, `104.243.45.20`, `185.150.191.148`, `104.194.10.189`. **`185.150.191.148` dials both Albania *and* France** → coordinated multi-embassy probing from shared infra (~5k calls) |
| **caller `"101"` / `@TUVTT`** | Britain | caller `101`, Call-IDs ending `@TUVTT` (`24.123.196.28` Charter, `119.8.x` Huawei Cloud) and the `e5f4a…e4f7a` variant (`92.204.168.45` velia.net) |
| **ab00day-adjacent** | Britain | `172.110.223.133` — same `/24` + "Husam A. H. Hijazi" ASN (47154) as the ab00day bot `172.110.223.203` |
| **PALTEL (ASN 12975)** | Albania, France | small volume (`213.244.114.185`, `212.14.249.117` caller `1000`) |

## Behaviour (deep profile: `92.204.168.45` → Britain, 2026-06-14)

Representative of the answer-supervision pattern:
- **Single target** — only ever dials `+12025886500` (British embassy); 14 calls / 3 days,
  low-and-slow, *not* a flood.
- Origin **velia.net (German VPS, ASN 29066)**, geo Strasbourg FR; caller `"101"`;
  Call-ID `e5f4a<6 digits>e4f7a`.
- **Silent-abandon:** INVITE → `200` (Asterisk retransmits ~10× for want of an ACK) →
  no ACK, no media (no RTP dump), no CANCEL/BYE → B2BUA `attacker_no_ack` at ~45s. It
  never completes and never passes audio. (Other dialers not yet deep-profiled, but the
  single-target, low-rate, answer-supervision shape is consistent.)

## Would an embassy ever actually receive a call?

- **Through this honeypot: no, never.** LA1 answers the call itself (fake `200` / silence,
  or bridges to *our* Asterisk) and never dials outbound to the real number. The bot
  believes it found an answering route; the embassy gets nothing from us. We are a
  dead-end.
- **Through a *real* vulnerable PBX (what the bot hunts for): yes — it rings.** Answer
  supervision *requires* the call to reach a number that answers, so a genuine route
  really dials the embassy: it rings (maybe briefly answers), then — because the bot
  abandons after the `200`, never ACKing — the call drops. Each successful probe ≈ one
  ring / brief-answer-then-hangup at the embassy.
- **Exception — False Answer Supervision (FAS):** if a fraudulent intermediary *fakes*
  the `200` without completing, the embassy is not rung. So real route → embassy rings;
  FAS route → it doesn't. Either way, **the honeypot never causes an embassy call.**

## 2026-06-20 — deep profile of the dominant ReliableSite actor (`209.222.101.54` → Albania)

Three findings on the most active embassy beacon, now backed by per-bridge B2BUA
media instrumentation rather than inference.

### Phase shift: From-extension enumeration × dial-prefix probing

The From-user is no longer static (earlier phases used a fixed caller — `check_123`,
`101`, `1000`). It now rotates a candidate-extension list in a tight **2-call cycle
per extension**, same target both times:

1. `From: <ext>` → dial string `12022234942` (**bare** E.164)
2. `From: <ext>` → dial string `912022234942` (**`9` +** E.164)

…then it advances to a new `<ext>` and repeats. Verified over 120 consecutive calls:
an exact **60/60** bare-vs-`9+` split and **exactly 2 calls per From-user**. The From
values are non-sequential, mixed 3–4 digit (`8548, 419, 9300, 396, 2500, 112, 9004,
496, 4501, 4447, 5004, 330, 6106, …`) — a plausible-extension wordlist (PBX ranges
`1xx`/`2xx`/`4xxx`/`9xxx`). Cadence ≈ one extension every ~2 min (two ~37 s calls
~45–50 s apart). The earlier `00…`/`011…` international-prefix forms are **absent** in
this phase — just bare + `9`. Read: this is **dial-plan / class-of-service mapping** —
"originating as extension N, can I reach this number directly, and via a `9`
trunk-access code?" — a recon step *beyond* bare answer-supervision.

### Not a listener — now measured, not assumed

New B2BUA traces (`stage=sdp_media`, `stage=rtp_unreachable`; analyze with
`extras/sip-b2bua-trace/b2bua_trace.py --listeners`) show **every** one of these calls
advertises a fixed **RFC1918 media endpoint `192.168.1.83:25282`** (`cls=private`,
`sig_match=False` vs the signaling source `209.222.101.54`) — identical IP *and* port
across calls, i.e. boilerplate SDP, not a negotiated media port. Combined with: never
`ACK`s, sends **no inbound RTP** (so symmetric-RTP latching has nothing to latch onto),
and no DTMF. Listener verdict: **`not-listener`** — the call-tree bait audio cannot
reach it and is **for naught for this actor**. (A lone stray-RTP bridge of ~0.5 KB and
a single `rtp_unreachable` appear in the roll-up; the dominant verdict is unambiguous —
`L1/P0/N…`.) This is the first *measured* confirmation of the "answer-supervision,
doesn't consume media" model this note asserted. See the `sdp_media` / `rtp_unreachable`
/ listener-verdict additions in `honeypots/sip_b2bua.py` and `extras/sip-b2bua-trace/`.

### Why the bait audio plays for only ~32 s anyway

These calls tear down deterministically at **~37 s (5 s ring + ~32 s)** — by **SIP
Timer H** (64×T1), *not* by our call cap. The B2BUA self-`ACK`s the Asterisk leg only
for *live-permit* bridges; for these non-live playback calls it relays the attacker's
`ACK`, and a silent-abandon bot never sends one — so Asterisk's un-`ACK`ed `200`
Timer-H's out at 32 s and BYEs (`reason='pbx_bye'`). This **preempts** both
`PBX_ABANDON_SECONDS` (60) and `PBX_CALL_TIMEOUT` (1200): the no-`ACK` shape self-caps
at ~32 s of post-answer audio. (The older velia.net profile above logged
`attacker_no_ack` at ~45 s under earlier settings; under the current path Timer H at
32 s dominates.) Note this is *faithful* — a real embassy line called by a no-`ACK` bot
behaves identically; extending it would require self-`ACK`ing the non-live leg, which
would itself be an unrealistic tell.

## Prior mention

`docs/SIP_HONEYPOT_ASTERISK_SUPPORT.md` used two of these numbers
(`+12022234942,+12029446000`) as a `PBX_DIAL_POLICY` example and an `embassy-greeting`
Playback in a sample dialplan — so the embassy traffic was *noticed* early but never
investigated until this note.

## Next / open

- Deep-profile the other dialers to confirm answer-supervision across the board
  (`92.204.168.45`/Britain and now `209.222.101.54`/Albania-ReliableSite detailed; the
  latter measured as `not-listener` via the `--listeners` instrumentation).
- Watch for a `cls=global` embassy beacon: an actor advertising a *real public* media
  endpoint would flip the question from "can't reach it" to a live `rtp_unreachable` /
  `possible`-listener test. None seen on the embassy DIDs yet (all `cls=private`).
- Pivot the Call-ID fingerprints (hex/num-triplet, `@TUVTT`, `e5f4a…e4f7a`) and origins
  (ASN 23470 ReliableSite especially) across the other honeypots — the ReliableSite
  multi-embassy campaign is the strongest single actor.
