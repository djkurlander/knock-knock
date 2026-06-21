# SIP bot → operator attribution — signals & caveats

**Date:** 2026-06-21
**Status:** Reference / living

How to reason about whether two streams of SIP bot traffic are run by the **same
operator**. No single signal proves it; attribution is a probabilistic case built from
*converging, independent* clues — and the first discipline is asking what each clue
actually attributes to.

## The core trap: target vs toolset vs infrastructure vs operator

Most "they look the same" signals don't point at the *operator* at all. Before weighting
any clue, classify it:

- **Target** — the dialed number / destination. Widely **shared** (especially route-test
  anchors). Tells you about a *number pool / provider*, not who's dialing.
- **Toolset** — the dialer software: dial-form set, From wordlist, SIP-stack fingerprint,
  RTP signature. **Forkable / leaked / commercial** — the *same tool* shows up across
  *different* operators. Tells you about the *tool*, not the actor.
- **Infrastructure** — ASN, IP ranges, hosting. **Rented**; one operator spans many,
  many operators share popular (bulletproof) hosts. Tells you about the *host*.
- **Operator** — the actual actor. Best inferred from **coordination** (things that
  require one hand on the wheel) and **bespoke** elements (things not shared), not from
  shared tools/targets/hosts.

The canonical cautionary tale is the **666.7 Hz beacon**: a *byte-identical* G.711 frame
(`md5 980b7e2c90`) seen from two **different ASNs** (`172.110.223.203`/AS47154 and
`51.38.52.76`/OVH). Identical artifact, different networks ⇒ we called it **shared
*tooling*, not one operator** ([sip-media-presence-probes.md](sip-media-presence-probes.md),
[sip-ab00day-audio-beacon.md](sip-ab00day-audio-beacon.md)). Same lesson as the embassy
beacons: multiple independent toolkits converge on the same always-answer targets
([sip-embassy-beacons.md](sip-embassy-beacons.md)).

## Signal catalog

| Signal | Attributes to | Strength for *operator* | Caveats |
|---|---|---|---|
| **Same dialed number(s)** | Target | **Weak** | Route-test/reachability numbers are shared across unrelated crews (a provider's test pool). Only meaningful if it's a *bespoke* number not on the public/known list. |
| **Same destination number *block*** (sequential/leased DIDs — e.g. `…911031` & `…911049`, or the `44203807xxxx` London set) | Target / number-provider | **Weak for operator; strong for provider** | Different numbers in one contiguous block share a *provider allocation* → clusters the *number pool*, not the caller. Operator-meaningful only if the block is **bespoke** (privately allocated to one crew, not a known shared pool). Sequential-block rural/wholesale VoIP is the pumping signature ([sip-nanp-line-types-whois.md](sip-nanp-line-types-whois.md)). |
| **Same VM / terminating endpoint** on the called number | Target/destination provider | **N/A for callers** | Clusters *numbers/providers*, not bots. Orthogonal to who's dialing. |
| **Same ASN / hosting** | Infrastructure | **Weak** | Rented; shared across operators on popular hosts. |
| **Source IP-block adjacency / intra-block rotation** | Infrastructure (→ deployment) | **Moderate** | One actor often controls a contiguous range and *rotates source IPs within it* (to dodge per-IP block/dedup) — so several IPs in one `/24` (or adjacent `/24`s) with the *same behaviour* is one deployment (`91.236.55.133/.140/.184`; `185.213.155.237/.241`; ab00day's `172.110.223.x`). A block can also be a host's shared tenant range, so **strong only with a tooling/behaviour match**; bare co-location is weak. |
| **Same dial-prefix rotation** (dial-form fuzz set) | Toolset | **Weak–moderate** | Same tool, possibly forked. Strong only if the pattern is *rare/bespoke* (e.g. ab00day's `#*~/%`-laced 946-form set vs a generic numeric sweep). |
| **Same From rotation** (extension wordlist/algorithm) | Toolset | **Weak–moderate** | Same as dial-prefix — part of the dialer. |
| **Same SIP-stack fingerprint** (User-Agent, header order, Call-ID/branch/tag token format, SDP quirks) | Toolset | **Moderate** *for tool* | A precise stack fingerprint is a strong *tool* match; a *rare* one narrows the actor set but doesn't isolate it. |
| **Same RTP signature** (e.g. a byte-identical frame) | Toolset | **Weak for operator** | See 666.7 Hz — identical frame crossed ASNs ⇒ shared tool. |
| **Call cadence / pacing** (inter-call gap, burst shape, concurrency) | Toolset (mostly) | **Weak–moderate** | Pacing is largely the tool's. |
| **Parallel / lockstep probing across targets** (same dial-form or From value hitting *multiple* of our honeypot sources from one IP/ASN at the *same instant*) | Toolset architecture **+** coordination | **Moderate–strong** | The scanner iterates *value-major*: holds one prefix/extension constant and fans it across its whole target list at once. The **iteration order itself** (value-outer/target-inner vs target-major — exhaust one server before moving on) is a tool fingerprint, and the *synchronization* across our independent vantage points is a single-orchestrator signal. **Strongest** when *different* IPs/ASNs run lockstep with *each other* (one C2 driving many IPs → operator link). Only visible because we aggregate multiple honeypots. |
| **Coordinated onset/cessation across distinct infra** | **Operator** | **Strong-ish** | Synchronized start/stop or interleaved waves across *otherwise-independent* IPs/ASNs implies one C2 / one hand. Hard to fake incidentally. |
| **Temporal separation** (months apart) | — | weak *against* same campaign | Different campaigns; doesn't rule out the same operator over time. |
| **Bespoke shared target** (a private number, not a known test anchor) | **Operator** | **Strong** | If two streams both hit a target *not* on the shared list, that's a real link. |
| **Registration / hosting reseller / abuse-contact / payment overlap** | Infra → Operator | **Strong** when found | Rarely visible from honeypot data alone; needs external pivots. |

## Combining signals (the actual method)

1. **Classify first, weight second.** A pile of *toolset* matches (same dial-forms + same
   From wordlist + same RTP frame) is evidence of the **same tool** — which may be used by
   many operators. Don't let three toolset signals masquerade as operator attribution.
2. **Prefer hard-to-share signals.** Coordination (synchronized cross-infra timing) and
   bespoke elements (private targets, unique tool+infra+target *combinations*) are the
   signals that actually point at an operator, because they can't be incidentally shared.
3. **Look for convergence of *independent* axes.** Same operator is plausible when
   *unrelated* dimensions line up at once — e.g. same rare stack fingerprint **and**
   coordinated timing **and** a bespoke target — not when one shared dimension repeats.
4. **State the alternative explicitly.** For every "same operator" claim, name the
   competing read ("same forked tool," "same popular host," "shared test number") and say
   what would distinguish them.
5. **Different toolset ≠ different operator.** One operator can run several tool
   versions/campaigns; absence of a tool match doesn't split them, and presence doesn't
   merge them.
6. **Map source-block × destination-block, not just point matches.** A *contiguous source
   range* consistently dialing a *contiguous destination block* is a coherent
   operation-level mapping (one infra → one number pool) — more telling than a single
   shared IP or a single shared number. Build the relation "which source `/24`s hit which
   destination blocks"; convergence there — especially onto a **bespoke** destination
   block — is a real operator/operation link, where a single shared *test* number is not.
7. **Exploit the multi-vantage.** Because we aggregate several honeypots, one bot hits
   *several* of our sources — so we can read its **parallelization**, which a single sensor
   can't. The same value landing across sources at the same instant reveals *value-major*
   iteration + a single orchestrator; the iteration *order* fingerprints the tool; and
   *different* IPs in cross-source lockstep with each other points at one C2. Treat the
   cross-source timing correlation as a first-class clue, not an afterthought.

## Worked example — the rural Bandwidth cluster (2026-06-21)

Two rural Bandwidth.com-CLEC VoIP numbers (`+14793451932` Natural Dam AR, `+17018902767`
Valley City ND) with the **same default British-accent voicemail**, dialed across NY/AMS/
TYO/LON sources (not LA1) by **four ASNs**:

| ASN | Org | dial-form fingerprint |
|---|---|---|
| 47154 | Husam / ab00day | 946 forms, special chars (`#*~/%`), sequential sweeps |
| 39351 | 31173 Services AB | clean 63-form `+/0/00/9` set; From `1001–1008/2000–2002` |
| 42201 | PVDataNet | minimal 8 forms |
| 50599 | Dataspace | 69 forms, odd extras |

Reading it through the framework:
- **Same numbers + same VM** → a shared **target/provider** signal (the numbers are a
  provider's *test/reachability* pool — *not* attributed payout numbers, since a shared
  number can't be attributed per-customer). **Weak** for operator.
- **Different dial-form fingerprints** → different **toolsets**. *Suggestive* of different
  actors, but **one actor can run several tools** — not dispositive.
- **Different ASNs + months apart** (47154 May, 39351 June) → no coordinated wave observed
  → leans different actors/campaigns, still unproven.
- **Within AS39351**, `.237`/`.241` are byte-identical tooling in one `/24` → one
  deployment.
- **Verdict:** probably different actors *or* at least different campaigns; **unresolved**
  from current data. The shared numbers are a link between *targets/provider*, not a link
  between *operators*. To strengthen either way we'd need a hard-to-share signal —
  coordinated cross-ASN timing, a bespoke shared target, or hosting/registration overlap.

## Practical pivots (from honeypot data)

- Dial-form set per IP: `knocks_sip` `sip_dial_string` grouped by `ip_address`.
- From wordlist/rotation: `sip_from_user` per IP (sequential? same vocabulary?).
- Stack fingerprint / RTP signature: B2BUA trace + `sip_rtp_triage.py --fingerprint`.
- Cadence & coordination: `started` timestamps per IP/ASN — look for synchronized
  onset/cessation across *different* ASNs (the operator signal), not just similar pacing.
- Target overlap: same `sip_dial_number` across IPs — then ask "is this a known shared
  test anchor or a bespoke number?" before weighting it.
- Source-block rotation: group `ip_address` by `/24` (and adjacent `/24`s) per actor —
  multiple IPs in a range with the same behaviour over time = one deployment rotating IPs.
- Destination block: group `sip_dial_number` by leading digits (strip the last 2–4) to
  surface sequential DID blocks; then map **which source ranges hit which destination
  blocks** — the cross-product is the operation-level signal, not the point matches.
- Parallel probing: for one IP, find a `sip_dial_string`/`sip_from_user` value that lands
  across ≥2 `source`s within a few seconds — value-major lockstep fan-out (reads the tool's
  iteration order). If *different* IPs are synchronized with each other on the same value
  at the same instant, that's a C2/operator link, not just a shared tool.
