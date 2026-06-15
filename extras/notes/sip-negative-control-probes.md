# SIP negative-control probes — bots dialing known-bad numbers to detect honeypots

**Date:** 2026-06-14
**Status:** Observed; defensive idea proposed

## Summary

Some route-discovery bots dial a number that **must not legitimately complete** — a
structurally-valid but unallocated/fake number — as a **negative control**. A genuine
carrier rejects it (`404`/`484`/error); a route that answers *everything* (a honeypot,
or a False-Answer-Supervision fraud route) returns `200 OK` to it anyway. So the bot
uses the route's response to the fake number to decide **whether the route is honest**:
if it `200`s the garbage, it's a liar → discard its "this number works" signals.

**We currently flunk this test** — `SIP_OK_DIALPLAN=all` (and the default form-set)
answer the fake number, marking LA1 as a honeypot/FAS to any control-probing bot.

## Evidence

`213.244.94.129` dialed `+18005555111` (dial string `18005555111`, a US toll-free
`555` test number) **3× interspersed with a diverse set of real targets** (Apr–May 2026):

| number | country | note |
|---|---|---|
| `+18005555111` | US toll-free | **the negative control** |
| `+18094514565` | Dominican Republic | classic **IRSF / premium** destination |
| `+970599953142` | Palestine | real |
| `+17072440012` / `+917072440012` | US / India | same suffix, two country guesses |
| `+13158958024`, `+17753688989`, `+16469150146` | US | real |
| `+913198276800`, `+912465382550` | India | real |

Genuine toll/premium probing **plus** a number that should fail on an honest route =
the control-test signature. (Caveats: Apr–May data, not currently active; and it could
in principle be a tool-default placeholder — but "dialed among live targets" leans
deliberate.)

## Why `phonenumbers` doesn't catch it

`+18005555111` is `is_valid_number=True` (US, `TOLL_FREE`). libphonenumber's NANP
validation is structural — valid area code + correct length — not "in service." So
obvious junk (`555` lines, `+18004444444`, etc.) all read as *valid*. **Validity ≠
allocated**, so it can't gate negative-control numbers.

## Defensive idea: reject bogus numbers like a real carrier (realism / better bait)

To **pass** the honesty check (and look like a real PBX to the sophisticated bots — the
ones worth baiting), reject exactly what a real carrier rejects. This is a **number-level**
gate, distinct from `SIP_OK_DIALPLAN` (which gates dial *form* / prefixes): even though
the number resolves to a valid E.164, return `404` if it matches a known-bogus pattern.

Conservative denylist (obvious cases only, to avoid 404-ing real numbers):
- NANP toll-free with `555` prefix (`8XX-555-XXXX`).
- Geographic `555-01XX` (reserved fictional range).
- Obvious test/sequential/repeated patterns (e.g. `+18004444444`, `1234567890`) —
  keep tight; these *can* be real.
- N11 service codes / known-unallocated ranges.
- (Weak signal) `is_possible_number` true but `is_valid_number` false.

Effect: a control-probe **passes** — we error on the `555`, answer the real targets — so
the bot **trusts the route**. That directly improves the
[phase-2 bait](sip-phase2-bait-experiment.md): the bots most worth completing/holding are
the ones that *test* for honeypots first.

Trade-off: we have no real allocation database, so this only catches the *obvious* fakes;
a determined prober with an unusual unallocated number we don't recognize still detects
us. Catch the common controls; accept the long tail.

## Next / open

- Scan the data for other negative-control patterns (repeated/sequential digits, `555`,
  N11, known invalid ranges) and quantify how many distinct bots run control probes.
- If implemented, log when a bogus-reject fires (which bot, which number) — that itself
  fingerprints the *sophisticated* (honeypot-aware) actors.
