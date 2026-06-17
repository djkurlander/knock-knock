# SIP dial-target number exploration

Tools for classifying the numbers the SIP honeypot was asked to call by **line
type** (VoIP / landline / wireless), **carrier**, and **rate-center geography**,
using the public SIPSTACK WHOIS API, and for measuring how that profile compares
to the random NANP population.

Built for the investigation in
[../notes/sip-nanp-line-types-whois.md](../notes/sip-nanp-line-types-whois.md):
the headline finding is that the honeypot's NANP dial targets are ~83% VoIP vs
~32% for random numbers — a 2.6× enrichment (3.9× for wholesale-CLEC VoIP
specifically), with a heavy skew toward DIDs homed in rural rate centers
(access-stimulation economics).

## Data source

All tools call the same unauthenticated JSON endpoint that `whois.sipstack.com`
uses for anonymous visitors:

    GET https://api-whois.sipstack.com/v1/whois/lookup/<11-digit-number>

It returns `technical.type` (VoIP/Wireline/Wireless), `technical.carrier`,
`technical.rateCenter`, `regional.city/region`, and a community spam `score`,
from LERG / ported-number data. Stdlib only — no third-party deps.

## Tools

| File | Role |
|------|------|
| `sipstack_whois.py` | Shared client: `lookup(number) -> dict`, plus a CLI for ad-hoc lookups. |
| `classify_dial_targets.py` | Pull dial targets from the `dial_intel` table (default `+1` / NANP) and classify each → TSV. |
| `analyze_dial_targets.py` | Read that TSV → line-type mix, VoIP / wholesale-VoIP ratio, carriers, urban/rural split, concentration, sequential-block clustering. |
| `baseline_sample.py` | Random-NANP control sample → same TSV schema → feed to the analyzer to get the population base rate. |
| `classify_intl_targets.py` | Non-NANP clusters (+44/+972/+39/+970…): classify by type/carrier/geo via `phonenumbers` + per-minute outbound cost via a Telnyx rate CSV → TSV. (sipstack is US/Canada only.) |
| `analyze_intl_targets.py` | Read that TSV → type mix, cost-weighted ranking (hits × $/min), concentration, sequential blocks; `--by-country`. |

## Usage

```bash
source .venv/bin/activate

# 1. One-off lookup
python extras/sip-number-exploration/sipstack_whois.py +12092977081

# 2. Classify all NANP dial targets from the DB
python extras/sip-number-exploration/classify_dial_targets.py --out /tmp/nanp.tsv

# 3. Categorize them
python extras/sip-number-exploration/analyze_dial_targets.py /tmp/nanp.tsv

# 4. Measure the random-population base rate to compare against
python extras/sip-number-exploration/baseline_sample.py --n 300 --seed 1 --out /tmp/baseline.tsv
python extras/sip-number-exploration/analyze_dial_targets.py /tmp/baseline.tsv

# 5. International clusters (phonenumbers + Telnyx rate sheet, no API)
python extras/sip-number-exploration/classify_intl_targets.py \
    --prefixes +44,+972,+39,+970 --rates /tmp/rates.csv --out /tmp/intl.tsv
python extras/sip-number-exploration/analyze_intl_targets.py /tmp/intl.tsv --by-country
```

`classify_dial_targets.py` can also take `--prefix +44` (or any country prefix),
`--min-hits`, or `--numbers-file nums.txt` instead of the DB.

## Notes / caveats

- **Attacker data is untrusted.** Dial strings are looked up as evidence, never
  dialed or executed.
- **Line type is carrier-of-record**, from LERG/ported data — not "in service."
  Validity ≠ allocation (see ../notes/sip-negative-control-probes.md).
- **Urban/rural is a heuristic** keyed on a hand-curated rate-center set in
  `analyze_dial_targets.py` (`RURAL_RATE_CENTERS`); the API has no urban/rural
  flag. Extend the set for other regions.
- **Be polite to the API**: lookups are serial with a default sleep. `baseline_sample.py`
  sends random, non-personal numbers — a statistical measurement, not targeting;
  keep `--n` modest.
