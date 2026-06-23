# SIP NANP dial targets — line type, carrier, and the rural-VoIP monetization signature

**Date:** 2026-06-16
**Status:** Resolved (one-shot analysis; reproducible via tooling)
**Tooling:** [../sip-number-exploration/](../sip-number-exploration/)

## Summary

Of the 134 NANP (`+1`) numbers the SIP honeypot has been asked to call, **73%
are VoIP** (83% of the 118 that resolve to a geographic line), almost entirely
from **wholesale CLEC DID providers** (Bandwidth, ONVOY/Inteliquent, Peerless,
Level 3, Telnyx…). A random-NANP control sample puts the population base rate at
only **~32% VoIP / ~20% wholesale-VoIP** — so the attacker list is **2.6×
enriched in VoIP and ~3.9× enriched in wholesale-VoIP**. The list also skews
hard toward DIDs homed in **rural rate centers**, which is the classic
access-stimulation economic signature. Verdict on "real monetization targets vs
route testing": **both, and separable** — a small set of heavily-pumped,
clustered, rural-wholesale-VoIP numbers carry the monetization signature, while
a long one-off tail (toll-free, round, malformed numbers) is honeypot/dialplan
probing.

## Line-type mix (honeypot NANP targets)

134 numbers, 112,624 hits. Line type via SIPSTACK WHOIS (`technical.type`).

| Line type | Numbers | % | Hits | % of volume |
|---|---:|---:|---:|---:|
| **VoIP** | 98 | 73% | 99,725 | 89% |
| Wireline (landline) | 14 | 10% | 6,103 | 5% |
| Wireless | 6 | 4% | 2,925 | 3% |
| Unresolved¹ | 16 | 12% | 3,871 | 3% |

¹ Toll-free (800/888) + malformed/spoofed (`+10000219777`, `+11144199199`, …)
with no line record. Among the 118 that resolve to a real line: **83% VoIP / 12%
landline / 5% wireless.** Wholesale-CLEC VoIP is **90 numbers = 76% of resolved**
(92% of the VoIP).

## Base rate (random-NANP control)

300 random valid-format US numbers (`baseline_sample.py --n 300 --seed 1`), same
lookup and same analyzer. 257 resolved (86%); 43 unallocated.

| Line type (random) | Share of resolved |
|---|---:|
| Wireline | 34.6% |
| Wireless | 33.9% |
| **VoIP** | **31.5%** |

Of those VoIP, ~63% are wholesale CLECs → **wholesale-VoIP ≈ 19.8% of resolved
numbers (~1 in 5).**

**Enrichment vs population** (same tool/regex on both sides):

| | Random | Honeypot | × |
|---|---:|---:|---:|
| VoIP share of resolved | 31.5% | 83.1% | 2.6× |
| Wholesale-VoIP share of resolved | 19.8% | 76.3% | 3.9× |

In the wild wholesale-VoIP is ~1 in 5; in the target list it's ~3 in 4. That
inversion is the signal — this is a list of *monetizable termination points*,
not "phone numbers."

## Carrier / telco

Almost entirely bulk-DID wholesalers, not legacy phone companies:
Bandwidth.com CLEC (~25), ONVOY/Inteliquent (~20), Peerless Network (~15, heavily
NC), Level 3, Comcast IP Phone, Telnyx, O1, ISP Telecom; Canada via Iristel,
Fibernetics, ISP Telecom, Bell. True legacy ILECs are rare (Pacific Bell,
Michigan Bell, BellSouth, Qwest, + two rural independents below).

## Urban vs rural, and why rural pays

By rate center (heuristic): **53 rural/small-town vs 65 urban/suburban** numbers,
but rural carries **more** volume (60,810 vs 47,943 hits) — driven by the #1
target overall, `+12092977081` (24,600 hits), a Bandwidth/ONVOY VoIP DID in
**Angels Camp, CA (pop. ~3,800)**.

**Why rural:** the scheme runs on **intercarrier compensation** — the
originating carrier pays the terminating carrier per minute; whoever owns the
destination number collects. The FCC historically let **small rural carriers
charge much higher terminating access rates**, so a minute terminating in rural
Iowa was worth multiples of one terminating in Chicago. That created
**traffic-pumping / access stimulation**: home a high-volume number in a rural
rate center, pump minutes, collect a revenue share. The modern twist: fraudsters
no longer need rural copper — they buy a **VoIP DID from a wholesale CLEC
numbered into a rural rate center**, capturing the economics with zero
infrastructure. (Caveats: FCC 2011/2019–2020 access-stimulation reforms thinned
the margin; cheap bulk DID availability in low-demand rural rate centers is a
complementary reason. Both point the same way.)

### Genuine rural landlines (the IRSF-classic case)

Only two true rural independent-ILEC landlines appear, both low-volume:

| Number | Hits | Rate center | Carrier |
|---|---:|---|---|
| `+18033779837` | 54 | Chester, SC | Chester Tel. Co. (independent ILEC) |
| `+12185890165` | 1 | Dalton, MN | Park Region Mutual Tel. Co. (rural co-op) |

The other landlines are urban — notably four Washington DC Verizon numbers
(`+1202…`, ~5,900 hits combined). So the rural angle shows up overwhelmingly via
**VoIP DIDs in rural rate centers**, not actual rural landlines.

## Monetization targets vs route testing

The hit distribution is bimodal, and the split is the tell:

**Monetization-shaped (the volume):**
- **Concentration** — top 10 numbers = 65,605 / 112,624 hits = **58% of all
  volume**; 27 numbers (20%) dialed ≥1,000× each. You don't need 24,600 calls to
  test reachability.
- **Sequential DID blocks** — Goldsboro NC has **7 numbers in one NXX**
  (919-750-8193/8320/8327/8328/8329/8336/8341, all Peerless); Lebanon TN has 3
  consecutive lines (615-549-1942/1943/1950). Owning a *block* = revenue-share
  inventory.
- The rural-wholesale-VoIP skew (above).

**Probing-shaped (the breadth):**
- 46 numbers (34%) dialed ≤5×; 22 (16%) exactly once — scattershot.
- Famous toll-free (`+18005551111`, `+18005555111`, `+18007458696`) and
  malformed/round numbers = dialplan-qualification / honeypot negative controls
  (see [sip-negative-control-probes.md](sip-negative-control-probes.md)): "will
  this PBX route out, and to where?" *before* burning the money numbers.

## Update — 2026-06-23: authoritative line-type (Telnyx) confirms the VoIP signature

The original ~83% VoIP figure came from **sipstack WHOIS**, which we later found can be
**stale** — it mislabeled a *current-Bandwidth VoIP* number as "USA Mobility Wireless" (a
recycled-paging block owner); see [sip-operator-attribution.md](sip-operator-attribution.md).
A full authoritative re-pass via **Telnyx number-lookup** (LRN-current;
`../sip-number-exploration/telnyx_number_lookup_cache.py`) **confirms** the finding:
**US-only line type = 76% VoIP + 6% toll-free** (94+7 of 124 valid US numbers). The small
gap vs sipstack's ~83% is Telnyx correctly splitting out toll-free — the rural-VoIP
access-stim conclusion **survives the better data**. Method note: prefer the **Telnyx LRN
dip** over static line-type sites for carrier/line-type ground truth; carrier-of-record
sites lag porting/reassignment (and the carrier *name* is itself low-signal when it's a
universal wholesaler like Bandwidth — which underlies Google Voice, Twilio, etc.).

## Caveats

- **Topology:** the honeypot *is* the would-be victim PBX and never completes a
  call to these destinations, so we observe the attacker's *intended* termination
  inventory, not realized settlements. Monetization is inferred from structure,
  not seen.
- **Test and monetize overlap:** a number hit 24,600× may be simultaneously a
  revenue-share DID **and** the bot's media-path confirmation endpoint — cf. the
  `ab00day` beacon ([sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md),
  [sip-media-presence-probes.md](sip-media-presence-probes.md)) and the
  monetization-shaped holds in [sip-107189-cli-counter.md](sip-107189-cli-counter.md).
  For the top numbers I treat the two readings as overlapping, not competing.
- Line type is **carrier-of-record** (LERG/ported), not "in service"; urban/rural
  is a hand-curated rate-center heuristic.

## Method / reproduce

```bash
source .venv/bin/activate
# classify NANP dial targets from dial_intel
python extras/sip-number-exploration/classify_dial_targets.py --out /tmp/nanp.tsv
python extras/sip-number-exploration/analyze_dial_targets.py /tmp/nanp.tsv
# population base rate
python extras/sip-number-exploration/baseline_sample.py --n 300 --seed 1 --out /tmp/baseline.tsv
python extras/sip-number-exploration/analyze_dial_targets.py /tmp/baseline.tsv
```

Data via the SIPSTACK WHOIS API (`api-whois.sipstack.com/v1/whois/lookup/`); see
[../sip-number-exploration/README.md](../sip-number-exploration/README.md).

## Next / open

- Run the same classification on the non-NANP destinations (the UK / Israel /
  Italy clusters that dominate total volume) — the sequential ranges there
  (`+44161394…` Manchester, `+9723375…` Tel Aviv) look like the same
  block-ownership pattern.
- Cross-reference the high-hit wholesale-VoIP rate centers against known
  access-stimulation LATAs.
