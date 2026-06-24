"""Telnyx rate-sheet lookup helpers backed by a local SQLite index."""

import csv
import os
import sqlite3
import tempfile


HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RATES_PATH = os.path.join(HERE, "rates.csv")
DEFAULT_INDEX_PATH = os.path.join(HERE, "rates.sqlite")


def row_record(row):
    dest = (row.get("Destination Prefixes") or "").strip()
    if not dest:
        return None
    rate_text = (row.get("Rate") or "").strip()
    try:
        rate = float(rate_text) if rate_text else None
    except ValueError:
        rate = None
    price_per_call_text = (row.get("Price Per Call") or "").strip()
    try:
        price_per_call = float(price_per_call_text) if price_per_call_text else 0.0
    except ValueError:
        price_per_call = 0.0
    return {
        "rate": rate,
        "country": (row.get("Country") or "").strip(),
        "iso": (row.get("ISO") or "").strip(),
        "description": (row.get("Description") or "").strip(),
        "origination": (row.get("Origination Prefixes") or "").strip(),
        "interval_1": (row.get("Interval 1") or "").strip(),
        "interval_n": (row.get("Interval N") or "").strip(),
        "price_per_call": price_per_call,
        "exact_match": (row.get("Exact Match") or "").strip(),
        "prefix": dest,
    }


def choose(existing, candidate):
    if existing is None:
        return candidate
    existing_generic = not existing["origination"]
    candidate_generic = not candidate["origination"]
    if candidate_generic != existing_generic:
        return candidate if candidate_generic else existing
    existing_rate = existing["rate"]
    candidate_rate = candidate["rate"]
    if existing_rate is None:
        return candidate
    if candidate_rate is None:
        return existing
    return candidate if candidate_rate > existing_rate else existing


def selected_rates(path):
    selected = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rec = row_record(row)
            if not rec:
                continue
            kind = "exact" if rec["exact_match"] else "prefix"
            key = (kind, rec["prefix"])
            selected[key] = choose(selected.get(key), rec)
    return selected


def build_index(csv_path=DEFAULT_RATES_PATH, index_path=DEFAULT_INDEX_PATH):
    fd, tmp_path = tempfile.mkstemp(prefix="rates.", suffix=".sqlite", dir=HERE)
    os.close(fd)
    try:
        con = sqlite3.connect(tmp_path)
        con.execute("""
            CREATE TABLE rates (
                kind TEXT NOT NULL,
                prefix TEXT NOT NULL,
                prefix_len INTEGER NOT NULL,
                rate REAL,
                iso TEXT NOT NULL,
                country TEXT NOT NULL,
                description TEXT NOT NULL,
                origination TEXT NOT NULL,
                interval_1 TEXT NOT NULL,
                interval_n TEXT NOT NULL,
                price_per_call REAL NOT NULL,
                PRIMARY KEY (kind, prefix)
            )
        """)
        rows = []
        for (kind, prefix), rec in selected_rates(csv_path).items():
            rows.append((
                kind, prefix, len(prefix), rec["rate"],
                rec["iso"], rec["country"], rec["description"], rec["origination"],
                rec["interval_1"], rec["interval_n"], rec["price_per_call"],
            ))
        con.executemany("""
            INSERT INTO rates (
                kind, prefix, prefix_len, rate, iso, country,
                description, origination, interval_1, interval_n, price_per_call
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, rows)
        con.execute("CREATE INDEX rates_prefix_lookup ON rates(kind, prefix_len DESC, prefix)")
        con.execute("""
            CREATE TABLE meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        con.executemany("INSERT INTO meta VALUES (?, ?)", [
            ("csv_path", os.path.abspath(csv_path)),
            ("csv_mtime_ns", str(os.stat(csv_path).st_mtime_ns)),
            ("rows", str(len(rows))),
        ])
        con.commit()
        con.close()
        os.replace(tmp_path, index_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def index_current(csv_path=DEFAULT_RATES_PATH, index_path=DEFAULT_INDEX_PATH):
    if not os.path.exists(index_path):
        return False
    try:
        con = sqlite3.connect(index_path)
        row = con.execute("SELECT value FROM meta WHERE key='csv_mtime_ns'").fetchone()
        con.close()
        return row is not None and row[0] == str(os.stat(csv_path).st_mtime_ns)
    except sqlite3.Error:
        return False


def ensure_index(csv_path=DEFAULT_RATES_PATH, index_path=DEFAULT_INDEX_PATH):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"rates.csv not found: {csv_path}")
    if not index_current(csv_path, index_path):
        build_index(csv_path, index_path)


def connect(csv_path=DEFAULT_RATES_PATH, index_path=DEFAULT_INDEX_PATH):
    ensure_index(csv_path, index_path)
    return sqlite3.connect(index_path)


def row_to_match(row):
    if row is None:
        return None
    keys = [
        "kind", "matched_prefix", "prefix_len", "rate_per_minute", "iso", "country",
        "description", "origination_prefixes", "interval_1", "interval_n",
        "price_per_call",
    ]
    rec = dict(zip(keys, row))
    rec["match_type"] = "exact" if rec["kind"] == "exact" else "prefix"
    rec["matched"] = True
    rec.pop("kind", None)
    rec.pop("prefix_len", None)
    return rec


def lookup(number, con=None, csv_path=DEFAULT_RATES_PATH, index_path=DEFAULT_INDEX_PATH):
    close = False
    if con is None:
        con = connect(csv_path, index_path)
        close = True
    try:
        digits = number[1:] if number.startswith("+") else number
        row = con.execute("SELECT * FROM rates WHERE kind='exact' AND prefix=?", (digits,)).fetchone()
        if row:
            rec = row_to_match(row)
            rec["number"] = number
            return rec
        candidates = [digits[:length] for length in range(len(digits), 0, -1)]
        placeholders = ",".join("?" for _ in candidates)
        row = con.execute(
            f"SELECT * FROM rates WHERE kind='prefix' AND prefix IN ({placeholders}) "
            "ORDER BY prefix_len DESC LIMIT 1",
            candidates,
        ).fetchone()
        rec = row_to_match(row)
        if rec:
            rec["number"] = number
            return rec
        return {"number": number, "rate_per_minute": None, "matched": False}
    finally:
        if close:
            con.close()


def lookup_many(numbers, csv_path=DEFAULT_RATES_PATH, index_path=DEFAULT_INDEX_PATH):
    con = connect(csv_path, index_path)
    try:
        return [lookup(number, con=con) for number in numbers]
    finally:
        con.close()
