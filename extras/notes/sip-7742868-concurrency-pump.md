# SIP `77.42.86.8` concurrency pump — settled targets, cap-riding holds

**Date:** 2026-06-18 (updated 2026-06-26)  
**Status:** Open — recurring; ban-reprieved again ~06-25 → resumed hard, target set re-expanded

## Summary

`77.42.86.8` (Hetzner Online GmbH, AS24940; DB geolocation: Finland) produced the
cleanest LA1 example so far of a **settled concurrency pump**: a small set of
destinations, two stable dial-out forms per number, high parallelism, `ACK`, no
voluntary `BYE`, and every confirmed call riding the B2BUA cap.

This is not shaped like ordinary phone-route discovery. Discovery usually spreads
across many dial strings, many prefixes, and often abandons after answer
supervision. This run optimized for completed call duration and concurrency.

## Update — 2026-06-21 (banned → ban-reprieved → resumed, retargeted)

This answers the "watch for recurrence" follow-up — but the gap was **our ban, not the
actor pausing.** `77.42.86.8` had been auto-banned (lifetime `ban_count=4`); a manual
`sip_ban_reprieve` (~2026-06-20, to gather more data) re-permitted it, and on resumption
**2026-06-21** (250 INVITEs on LA1) it ran the same signature — `ACK` + hold to the 1200 s
cap — against a **retargeted** destination set:

| Destination | Held-to-cap bridges | Note |
|---|---:|---|
| `+97233751353` | 74 | **continuing** the Israel `+9723375135x` block (after `…349/351`) |
| `+254208780226` | 107 | Kenya (`+254`) — new |
| `+12098941013` | 36 | US — new |
| `+3545395213` | 33 | Iceland (`+354`) — new |

So it **kept the Israel `+9723375135x` allocation** and **swapped the UK `+44208089019x`
pair for Kenya/US/Iceland** — same monetization-shaped concurrency, fresh targets. Re-banned
2026-06-21 (`ban_until` 2026-07-21). The reprieve was a deliberate data-gathering move; the
payoff is the retargeting intel (the actor's target list rotates while its *behaviour*
— `ACK`+hold-to-cap, controlled/allocated-looking endpoints — stays constant).

## Update — 2026-06-26 (ban-reprieved again → resumed, target set re-expanded)

A second manual `sip_ban_reprieve` (~06-25, data-gathering) re-permitted it, and it resumed
**immediately and hard**: in the 06-25 17:19 → 06-26 15:26 window, **227 INVITEs across 6
destinations**, same `ACK` + hold-to-1200 s-cap signature (53 held-to-cap bridges in the window,
most of them this actor):

| Destination | Held bridges | Carrier / rate | Note |
|---|---:|---|---|
| `+97233751353` | 16 | Hallo 015, `$0.0292` | Israel `+9723375135x` block |
| `+254208780226` | 9 | Iristel Kenya, **`$0.243`** | the priciest hold this window |
| `+97233751349` | 8 | Hallo 015, `$0.0292` | Israel block |
| `+3545395213` | (held) | Tismi BV, `$0.009` | Iceland |
| `+19197508327` | 9 | Peerless NC, `$0.005` | US (shifted from `…336` to `…327`) |
| `+442080890189` | 9 | DIDWW, `$0.0042` | **re-expanded** onto the original UK pair |

So vs 06-21 it **re-expanded** — kept Israel/Kenya/Iceland/US *and* came back onto the original
UK `+44208089018x` it had dropped. Notable this run: **heavy dial-string prefix enumeration**
(e.g. **45 distinct dial-string forms** for `+97233751353` alone) — sweeping trunk/intl prefixes
against each target (consistent with the 06-25 LA1 dialplan restriction now `404`-ing the
non-standard forms; the standard-prefix holds still complete). Behaviour constant, target list
breathes.

## Window and scope

- Server: LA1 (`SOURCE_ID=LA1`, SQLite `source=0`)
- Window reviewed: since the daily diary mtime, `2026-06-17 22:13:33 UTC`
- Primary data:
  - `data/knock_knock.db`, table `knocks_sip`
  - `data/b2bua_trace.log`

## Dialing pattern

LA1 DB rows for `77.42.86.8`:

| Metric | Count |
|---|---:|
| SIP rows | 102 |
| Normalized destinations | 4 |
| Raw dial strings | 8 |
| Rows marked bridged | 102 |

Breakdown:

| Destination | Raw dial string | Bridged rows |
|---|---|---:|
| `+97233751351` | `0097233751351` | 30 |
| `+97233751351` | `90097233751351` | 16 |
| `+442080890190` | `00442080890190` | 28 |
| `+442080890190` | `900442080890190` | 16 |
| `+442080890189` | `00442080890189` | 3 |
| `+442080890189` | `900442080890189` | 3 |
| `+97233751349` | `0097233751349` | 3 |
| `+97233751349` | `90097233751349` | 3 |

The UK targets are adjacent (`+442080890189`, `+442080890190`) and the Israel
targets are near-adjacent (`+97233751349`, `+97233751351`). That looks more like
owned / allocated endpoints than random victims. Random victims are a poor fit
for a sustainable campaign: a pump wants endpoints that answer predictably, hold
predictably, and avoid human complaints or unpredictable call behavior.

## B2BUA lifecycle

Trace-confirmed bridges from `77.42.86.8`:

| Metric | Count |
|---|---:|
| Confirmed B2BUA bridges | 50 |
| `attacker_ack` | 50 |
| `attacker_bye` | 0 |
| `attacker_no_ack` | 0 |
| `b2bua_timeout` | 50 |
| Peak confirmed concurrency | 50 |
| Cap | 1200 seconds |

Every trace-confirmed call sent `ACK`, never sent `BYE`, and ended only when the
B2BUA hit the `1200s` cap. That is the critical distinction from
answer-supervision probes: these calls committed the dialog and held it as long
as allowed.

## Rate / destination economics

The four destinations are **not high-cost according to `rates.csv`** under the
default / non-surcharged matches:

| Destination | Default rate |
|---|---:|
| `+442080890190` | `$0.0042/min` |
| `+442080890189` | `$0.0042/min` |
| `+97233751351` | `$0.0292/min` |
| `+97233751349` | `$0.0292/min` |

That does not make the behavior benign. The economics may be based on settlement
asymmetry, revenue-share endpoints, controlled destination allocation, or
downstream accounting not visible in our sheet. Low per-minute value also scales
with concurrency: many simultaneous long calls can still be useful.

## Interpretation

Best current label: **monetization-shaped concurrency pump against controlled or
semi-controlled endpoints**.

Possible readings:

- It was a direct monetization pass: the calls themselves were the pump.
- It was a concurrency qualification run before larger-scale monetization.
- Both are true: the campaign both earns and measures capacity in the same pass.

What it does **not** look like: broad route discovery. The run used few targets,
few dial strings, high `ACK` rate, high concurrency, no `BYE`, and cap-riding
duration.

## Follow-up

- Watch whether `77.42.86.8` returns after the cap or no-ACK window changes.
- Add a per-source active bridge cap before long-term exposure to this behavior.
- Temporarily set `PBX_ABANDON_SECONDS=60` for one day to detect late `ACK`s in
  no-ACK populations; this will not change the `77.42.86.8` holder behavior, but
  it helps distinguish answer-supervision probes from slow committers.
- On the Asterisk server, record split receive/transmit legs (`rx` / `tx`) for
  bridged calls and run automated silence / energy checks on the far-end audio
  leg. Goal: determine whether the recipient endpoints send non-silence audio
  during these cap-riding holds. Prefer automated analysis over manual listening,
  and compress retained files after call close if storage becomes a problem.
