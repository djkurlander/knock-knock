# SIP international dial clusters (UK / Israel-Palestine / Italy) — type, cost, and probe-vs-pump

**Date:** 2026-06-17
**Status:** Resolved (Phases 1–3 + source attribution); call lifecycle open
**Tooling:** [../sip-number-exploration/](../sip-number-exploration/) (`classify_intl_targets.py`, `analyze_intl_targets.py`)

## Summary

The three big non-NANP dial clusters (+44, +972/+970, +39) total ~210 destination
numbers and ~314k INVITEs — nearly 3× the NANP volume. sipstack is US/Canada-only,
so these are classified with **python-phonenumbers** (type/carrier/geo) and priced
against a **Telnyx voice rate sheet** (per-minute outbound cost — the IRSF metric,
since here the value is the *cost to call* the destination, not terminating access).

Three findings:

1. **Cost inverts the volume ranking.** By hits the leader is a London landline
   (`+442038072087`, 23k hits, **$0.0042/min**). By cost it's an Israeli
   Jawwal mobile (`+972592295853`, 6,848 hits, **$0.2422/min** — Telnyx's
   "Mobile Palestine Region" rate, ~60× the UK fixed rate). The money is in the
   **Israel/Palestine mobile** ranges, not the high-volume UK/Italy landlines.
2. **Raw INVITEs are mostly dial-plan recon, not call attempts.** Each destination
   is dialed in *hundreds* of dial-out prefix variants (`011…`, `00…`, `9…`,
   `9011…`). The right inventory unit is **distinct destinations (~210)**, not
   INVITEs (~314k). The INVITE-based "cost-weight" is an upper bound on *attempts*,
   not realized money.
3. **Probing vs pumping tracks cost.** The expensive cluster (IL/PS mobile) is the
   most *pump-shaped*; the cheap clusters (UK/IT/Tel-Aviv fixed) are near-pure
   *enumeration*. The bots probe everything but **repeat the destinations that
   would actually pay** — so the Palestine-region mobiles read as the payout
   target and the cheap fixed blocks as reachability / route-discovery anchors.

## Type mix and cost (per cluster)

`classify_intl_targets.py --prefixes +44,+972,+39,+970` → `analyze_intl_targets.py --by-country`.

| Cluster | Numbers | Type mix | Telnyx $/min | Cost-weight¹ |
|---|---:|---|---|---:|
| GB | 123 | 98% fixed | fixed $0.0042; mobile $0.02–0.29 | 1,056 |
| IL | 45 | 69% mobile | **mobile (Palestine region) $0.2422**; fixed $0.0085–0.029 | 8,190 |
| IT | 24 | 96% fixed | fixed $0.0115 | 357 |
| PS | 17 | 100% mobile | **$0.2400** (West Bank mobile) | 1,620 |

¹ Cost-weight = Σ(hits × $/min) — **a labelled upper bound on attempts** assuming
every INVITE completed for 1 minute. See the reframe below; it is *not* realized $.

Top legs by cost-weight are all Jawwal/Ooredoo +9725x ("Mobile Palestine Region")
and +970 West Bank mobile, despite far fewer hits than the UK landlines. UK is
overwhelmingly cheap fixed; Italy likewise.

## Why the INVITE count is the wrong unit (probe vs pump)

From `knocks_sip` (534k INVITE rows; `sip_dial_string` = the raw dialed form,
`sip_dial_number` = canonical E.164):

| Cluster | INVITEs | **Distinct destinations** | Distinct forms | forms/dest | knocks/form |
|---|---:|---:|---:|---:|---:|
| UK | 219,003 | **125** | 34,914 | 279 | 6.3 |
| IL/PS mobile ($0.24) | 37,450 | **48** | 5,064 | 105 | 7.4 |
| IT | 31,060 | **25** | 11,965 | 478 | 2.6 |
| IL fixed (Tel Aviv) | 27,049 | **14** | 8,630 | 616 | 3.1 |

`forms/dest` (hundreds) is dial-plan brute-forcing — testing which outbound prefix
the PBX needs — against each target. The 219k UK INVITEs collapse to **125 real
destinations**. Example: `+442038072087` alone was dialed in **6,929 distinct
forms** (~3 each) — almost pure enumeration.

**Implication for the estimate (the two biases do not cancel):**
- Probing INVITEs (the bulk) carry ~zero monetization intent → counting them at
  1 min each **overstates**.
- Pumping INVITEs (the minority, once a route is found) would hold far longer than
  a minute → 1 min **understates** those.
- They apply to different subsets, so the net is not a wash. The honest unit is
  **distinct destination × P(working route found) × realistic hold (5–20+ min) ×
  rate**. A single completed 15-min Palestine-mobile call ≈ $3.60; realized
  exposure is however many complete and repeat across the ~48-number target set —
  which the honeypot cannot observe (it never truly completes). Compare the
  monetization-shaped holds in [sip-107189-cli-counter.md](sip-107189-cli-counter.md).

Notably IL/PS mobile has the **lowest** forms/dest (105) and **highest** knocks/form
(7.4): the expensive cluster is the most repeated, i.e. most pump-shaped. The cheap
fixed clusters (478–616 forms/dest, ~3 knocks/form) are route-discovery anchors —
cf. [sip-embassy-beacons.md](sip-embassy-beacons.md).

## Structure: sequential DID blocks (owned inventory)

Large consecutive ranges, strongest in the cheap UK/IT fixed clusters:
Liverpool `+441519470xxx` (×18, 28.1k hits), London `+442038076xxx` (×14, 23.9k)
& `+442038077xxx` (×9, 10.3k), Manchester `+441613940xxx` (×8, 17.3k), Tel Aviv
`+97233751xxx` (×12, 25.4k), Milan `+390237902xxx` / `+390242101xxx`. Same
block-ownership pattern as the NANP `919-750`/`615-549` ranges
([sip-nanp-line-types-whois.md](sip-nanp-line-types-whois.md)).

**+970/+972 twin-dialing:** several subscribers are dialed under both country codes
(`+970595595888`/`+972595595888`, `+970567004550`/`+972567004550`,
`+970592698190`/`+972592698190`) — a route-discovery probe over which form the PBX
will complete.

## Source attribution

The high-value IL/PS-mobile cluster is **distributed, not one actor**: 63 source
IPs, the top ones geolocating to **OVH France/Germany hosting** (`5.196.63.60`
4,000 hits/1 number, `87.98.242.75`, `5.135.70.138`, `51.178.122.178`,
`51.68.3.62`). UK is the most diffuse (194 IPs).

## Lifecycle — open (data limitation)

`knocks_sip` records only INVITEs, and the B2BUA live-permit path engaged for ~0 of
these clusters (3 UK calls), so **complete-and-hold vs answer-and-abandon cannot be
reconstructed** from stored data. The hold-time evidence used elsewhere lives in the
B2BUA SIPTRACE / `sip_live_permit` logs. To get it: mine retained SIPTRACE if
available, or prospectively route a sample of the ~48 Palestine-mobile destinations
through `sip_live_permit` and log hold-times — i.e. the
[sip-phase2-bait-experiment.md](sip-phase2-bait-experiment.md).

## Update — 2026-06-23: authoritative carrier / line-type (Telnyx LRN lookup)

The original classification used `phonenumbers` (sipstack is US/Canada-only). A full
authoritative pass via **Telnyx number-lookup** (`../sip-number-exploration/telnyx_number_lookup_cache.py`,
538 numbers cached) sharpens it:

- **The UK cluster is sourced through DIDWW.** `DIDWW Ireland` is the **#1 carrier across
  the entire target set** — 143/527 valid, **all fixed-line**, **123 GB + 19 SE**. DIDWW is
  a specialized wholesale-DID provider (not a universal substrate), so this is a real
  *sourcing fingerprint* for the UK pool — see
  [sip-operator-attribution.md](sip-operator-attribution.md).
- **Held-to-cap targets resolve to controlled small/niche carriers — the "allocated
  endpoint" pattern, not random victims:**

  | target | country | line type | carrier |
  |---|---|---|---|
  | `+34902561521` | ES | **shared cost** | PEOPLETEL — *explicit revenue-share* (`902`) |
  | `+97233751349/351/353` | IL | fixed | **Hallo 015** (the `77.42.86.8` block — one carrier) |
  | `+970567209720` | PS | mobile | Wataniya/Ooredoo |
  | `+33756758573` | FR | mobile | **Transatel** (confirms [sip-107189-cli-counter.md](sip-107189-cli-counter.md)) |
  | `+254208780226` | KE | fixed | Iristel Kenya |
  | `+3545395213` | IS | fixed | Tismi BV |
  | `+541139876436` | AR | fixed | NSS S.A. |

  The Spanish `+34902561521` being a **`902` "shared cost"** number is the first *explicit*
  revenue-share line-type in the dataset — a smoking-gun IRSF payout type, not inference.
- **Mobile networks resolve to exact MCC/MNC:** Jawwal (425-05, 34) + Ooredoo Palestine
  (425-06, 14) = 48 Palestine-mobile targets (the high-cost core); plus Vodafone/Orange
  Egypt and Orange Tunisie — **Egypt/Tunisia mobile** is a target geography not previously
  flagged.
- **Caveats:** Telnyx `type=carrier` returns blank `ported_status` and null `fraud`, so
  neither is testable here; 11 `dial_intel` numbers are invalid (`is_possible` artifacts).

## Caveats

- Cost-weight assumes completion; the honeypot never completes — these are
  *intended* exposure. Worst-case rate used per prefix (for +9725x that is the
  legitimate Palestine-region mobile rate, not noise).
- `phonenumbers` fills carrier only for mobiles; the fixed blocks show geo but no
  carrier — the gap that an Ofcom National Numbering Scheme lookup would close for
  the UK ranges (Phase 4, not yet done).

## Method / reproduce

```bash
source .venv/bin/activate
python extras/sip-number-exploration/classify_intl_targets.py \
    --prefixes +44,+972,+39,+970 --rates /tmp/rates.csv --out /tmp/intl.tsv
python extras/sip-number-exploration/analyze_intl_targets.py /tmp/intl.tsv --by-country
```

The Telnyx rate sheet is vendor data (~25 MB, gitignored under
`extras/sip-number-exploration/rates.csv`); drop your own export in to reproduce.

## Next / open

- **Phase 4 (Ofcom):** map the Liverpool/London/Manchester blocks to allocated UK
  communications providers — confirm wholesale-VoIP, as for NANP.
- **Phase 5 (lifecycle):** per above — backfill from SIPTRACE or route a bait sample.
- Pivot on the OVH source IPs and the +970/+972 twin-dialers as actor fingerprints.
