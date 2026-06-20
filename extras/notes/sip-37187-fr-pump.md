# SIP `37.187.144.149` — single-IP French monetization pump on `+33972307742`

**Date:** 2026-06-20
**Status:** Open / ongoing

## Summary

`37.187.144.149` (OVH, AS16276) has pumped a single French non-geographic number
`+33972307742` since 2026-06-15 — ~2,000 INVITEs over 5 days from one IP to one target.
On 2026-06-20 it ran as a sustained monetization hold pump: in an ~11 h window it ACKed
and held **233 calls to the full 1200 s B2BUA cap** (≈78 h of held time → high
concurrency). Behaviourally a settled IRSF-style hold pump — single IP, single target,
`ACK`+hold-to-cap, From-user extension enumeration. Whether the destination is a
high-rate revenue-share number is **unconfirmed** (not in the IPRN harvest; `+33 9` is
French *non-geographic*, not the classic premium `+33 89x` range).

## Actor & target

| field | value |
|---|---|
| Source IP | `37.187.144.149` |
| ISP / ASN | OVH SAS / **AS16276** (France) |
| Target | `+33972307742` (FR, `+33 9` non-geographic / VoIP) |
| First seen | 2026-06-15 11:36 UTC |
| Last seen | 2026-06-20 11:52 UTC |
| INVITEs (all-time) | ~2,000 (`dial_intel`: 1,995 hits) |
| IPRN harvest match | none (`iprn_harvested_targets.csv`); no `+3397230xxxx` block |

## Behaviour (2026-06-20 05:42–16:46 UTC window)

- **233 bridges ACK + held to the 1200 s cap.** Lifecycle: `200` →
  `attacker_ack age≈5 s` → hold → `timeout cap=1200` → `pbx_teardown via=ACK+BYE` →
  `closed reason=b2bua_timeout`. Same shape as the other monetization pumps
  (`107.189` French mobile, the Palestine-mobile burst).
- ≈233 × 20 min ≈ **78 h of held call time in ~11 h wall** → peak concurrency ~7+.
- **From-user (caller ID) enumerates extensions:** `101, 111, 11, 1011, 2000, 4001,
  300, 500, …` — same recon flavour as the embassy beacon's From-extension cycle.
- **SDP `c_ip=0.0.0.0` (`cls=unspecified`)** → listener verdict **`not-listener`**;
  **102 `rtp_unreachable`** on relayed audio. It advertises no real media address.
- 7 calls rejected `488 Not Acceptable Here` (codec/media), during the Asterisk-stress
  window ~11:49–12:08 UTC (see the 2026-06-20 diary entry).

## Method / how we know

- B2BUA trace (`data/b2bua_trace.log`): outcomes via
  `extras/sip-b2bua-trace/b2bua_trace.py --completions / --listeners`; held bridges
  mapped to `srcip → dest` via the `rtp_dump_armed` filenames (`id → srcip → destnum`).
- `knocks_sip` (`source=0`) for volume, first/last seen, and `sip_from_user`.
- IPRN cross-ref: `grep -F 33972307742 data/iprn_harvested_targets.csv` → no match.

## Verdict / open questions

- **Classification:** monetization-shaped hold pump (`ACK`+hold-to-cap, single target) —
  behaviourally indistinguishable from verification/monetization, like `107.189`, but it
  holds a French *non-geographic* number rather than a mobile.
- **Open — is `+33972307742` actually high-rate / revenue-share?** Needs a Telnyx / A-Z
  rate sheet. `+33 9` is non-geographic VoIP, not classic premium, so payout is uncertain;
  the *behaviour* is monetization regardless of the rate.
- **Open — relationship to the other OVH/FR pumps** (`107.189` Transatel mobile,
  `172.110.223.197` Argentina): same ASN family, same hold-to-cap signature.

## Links

- [sip-107189-cli-counter.md](sip-107189-cli-counter.md) — sibling single-target FR pump (mobile, CLI counter).
- [sip-intl-clusters-cost.md](sip-intl-clusters-cost.md) — cost-vs-volume classification of dial targets.
- [sip-7742868-concurrency-pump.md](sip-7742868-concurrency-pump.md) — another settled concurrency pump.
- Diary: [sip_daily_observations.md](sip_daily_observations.md) — 2026-06-20 (second entry).
