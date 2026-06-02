#!/usr/bin/env python3
"""
Regression test for the HTTP exploit classifier.

Covers both classification sources:
  - Named entries in http_exploits.json (207 cases)
  - Heuristic _RE_* patterns in http_honeypot.py (15 cases)

Golden set: extras/tests/http/http_classifier_golden.json
  Each case: {type, source, method, path, ua, body, expected_purpose, expected_name}

Exit 0 on full pass, 1 on any failure.
"""
import json
import sys
import os

# honeypots/ is two levels up from extras/tests/http/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', 'honeypots'))
from http_honeypot import _classify_purpose  # noqa: E402

GOLDEN_PATH = os.path.join(os.path.dirname(__file__), 'http_classifier_golden.json')


def run():
    with open(GOLDEN_PATH) as f:
        cases = json.load(f)

    failures = []
    named_ok = heuristic_ok = 0

    for c in cases:
        got_purpose, got_name, _ = _classify_purpose(
            c['method'], c['path'], c['ua'], c['body']
        )

        if got_name == c['expected_name'] and got_purpose == c['expected_purpose']:
            if c['type'] == 'named':
                named_ok += 1
            else:
                heuristic_ok += 1
        else:
            failures.append({'case': c, 'got_purpose': got_purpose, 'got_name': got_name})

    total = len(cases)
    passed = named_ok + heuristic_ok
    print(f"HTTP classifier regression: {passed}/{total} passed "
          f"(named={named_ok}, heuristic={heuristic_ok})")

    if failures:
        print(f"\n{len(failures)} FAILURE(S):")
        for fail in failures:
            c = fail['case']
            label = c['expected_name'] or c['expected_purpose']
            print(f"  [{c['type']}] {label!r}")
            print(f"    input:    {c['method']} {c['path']!r}  ua={c['ua']!r}  body={c['body'][:60]!r}")
            print(f"    expected: name={c['expected_name']!r}  purpose={c['expected_purpose']!r}")
            print(f"    got:      name={fail['got_name']!r}  purpose={fail['got_purpose']!r}")
        sys.exit(1)


if __name__ == '__main__':
    run()
