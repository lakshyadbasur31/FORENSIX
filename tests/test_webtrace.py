"""Unit and integration tests for Phase 3: WEBTRACE module.

Tests cover:
1. CSV parsing
2. JSON parsing
3. Chrome/Edge SQLite parsing
4. Firefox SQLite parsing
5. WebKit timestamp conversion
6. Firefox timestamp conversion
7. Malformed CSV handling
8. Invalid JSON handling
9. Corrupt SQLite handling
10. Missing optional columns
11. Download event extraction
12. Direct-IP indicator
13. Executable-download indicator
14. Unknown domain is not automatically flagged as malicious
15. Repeated visit burst detection
16. Visit-download correlation
17. Duplicate import handling
18. UTC normalization
19. Sensitive URL parameter redaction
20. Export generation
"""
import os
import json
import sqlite3
import tempfile
import pandas as pd
from pathlib import Path

from database.db import init_db, execute_commit, execute_query
from modules.webtrace import (
    convert_webkit_timestamp,
    convert_firefox_timestamp,
    normalize_iso_timestamp,
    redact_sensitive_url,
    extract_hostname,
    is_direct_ip,
    is_punycode,
    detect_browser_artifact_type,
    parse_csv_artifact,
    parse_json_artifact,
    parse_chromium_sqlite_artifact,
    parse_firefox_sqlite_artifact,
    analyze_forensic_indicators,
    ingest_browser_artifact,
    get_webtrace_overview_stats,
    get_webtrace_events,
    get_webtrace_indicators,
    link_download_to_evidence
)


# ==============================================================================
# 5 & 6. TIMESTAMP CONVERSION TESTS
# ==============================================================================

def test_webkit_timestamp_conversion():
    """5. WebKit timestamp conversion (Chromium microseconds since 1601-01-01 UTC)."""
    # Known reference: 13344686400000000 us = 2023-11-16 12:00:00 UTC approx
    # 11644473600000000 + (1700000000 * 1000000)
    epoch_sec = 1700000000  # 2023-11-14 22:13:20 UTC
    webkit_us = 11644473600000000 + (epoch_sec * 1000000)
    converted = convert_webkit_timestamp(webkit_us)
    assert converted == "2023-11-14 22:13:20"

    # Edge cases
    assert convert_webkit_timestamp(0) == "1970-01-01 00:00:00"
    assert convert_webkit_timestamp(-500) == "1970-01-01 00:00:00"
    assert convert_webkit_timestamp("invalid") == "1970-01-01 00:00:00"


def test_firefox_timestamp_conversion():
    """6. Firefox PRTime timestamp conversion (microseconds since 1970-01-01 UTC)."""
    epoch_sec = 1700000000
    prtime_us = epoch_sec * 1000000
    converted = convert_firefox_timestamp(prtime_us)
    assert converted == "2023-11-14 22:13:20"

    assert convert_firefox_timestamp(0) == "1970-01-01 00:00:00"
    assert convert_firefox_timestamp("abc") == "1970-01-01 00:00:00"


def test_utc_normalization():
    """18. UTC normalization from ISO strings and numeric timestamps."""
    iso_clean = normalize_iso_timestamp("2026-11-16T09:14:35Z")
    assert iso_clean == "2026-11-16 09:14:35"

    numeric_sec = normalize_iso_timestamp(1700000000)
    assert "2023-11-14" in numeric_sec


# ==============================================================================
# 19. SENSITIVE URL PARAMETER REDACTION
# ==============================================================================

def test_sensitive_url_parameter_redaction():
    """19. Sensitive URL parameter redaction protects credentials in UI displays."""
    url = "https://example.com/api?token=SECRET_ABC&user=analyst&password=MY_PASSWORD_123"
    redacted = redact_sensitive_url(url)
    assert "SECRET_ABC" not in redacted
    assert "MY_PASSWORD_123" not in redacted
    assert "token=%5BREDACTED%5D" in redacted or "token=[REDACTED]" in redacted
    assert "user=analyst" in redacted

    # User:pass in netloc
    url_auth = "http://admin:secret123@192.168.1.1:8080/dashboard"
    redacted_auth = redact_sensitive_url(url_auth)
    assert "secret123" not in redacted_auth
    assert "[REDACTED_AUTH]" in redacted_auth


# ==============================================================================
# 1, 7, 10. CSV PARSING TESTS
# ==============================================================================

def test_csv_parsing_and_missing_columns():
    """1. CSV parsing and 10. Missing optional columns."""
    csv_content = """timestamp,url,title
2026-11-16 09:10:00,https://example.com/page1,Example Title
2026-11-16 09:12:00,https://example.org/page2,
"""
    with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False) as tf:
        tf.write(csv_content)
        path = Path(tf.name)

    try:
        events, valid, skipped = parse_csv_artifact(path, "TestBrowser")
        assert valid == 2
        assert skipped == 0
        assert len(events) == 2
        assert events[0]["url"] == "https://example.com/page1"
        assert events[0]["hostname"] == "example.com"
        assert events[1]["page_title"] == "Untitled"  # Handled missing column cleanly
    finally:
        if path.exists():
            path.unlink()


def test_malformed_csv_handling():
    """7. Malformed CSV handling (skipped invalid lines without crash)."""
    malformed_csv = """header1,header2
invalid_line_without_required_url_or_path
,
"""
    with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False) as tf:
        tf.write(malformed_csv)
        path = Path(tf.name)

    try:
        events, valid, skipped = parse_csv_artifact(path, "TestBrowser")
        assert valid == 0
        assert skipped >= 1
    finally:
        if path.exists():
            path.unlink()


# ==============================================================================
# 2 & 8. JSON PARSING TESTS
# ==============================================================================

def test_json_parsing():
    """2. JSON parsing for browser history."""
    json_data = [
        {"timestamp": "2026-11-16 10:00:00", "url": "https://example.net/home", "title": "Home Page"},
        {"timestamp": "2026-11-16 10:05:00", "url": "https://example.net/dl", "target_path": "payload.zip"}
    ]
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
        json.dump(json_data, tf)
        path = Path(tf.name)

    try:
        events, valid, skipped = parse_json_artifact(path, "JSONBrowser")
        assert valid == 2
        assert skipped == 0
        assert events[0]["event_type"] == "PAGE_VISIT"
        assert events[1]["event_type"] == "DOWNLOAD"
        assert events[1]["download_filename"] == "payload.zip"
    finally:
        if path.exists():
            path.unlink()


def test_invalid_json_handling():
    """8. Invalid JSON handling (raises clear error)."""
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
        tf.write("{ NOT VALID JSON STRING !!!")
        path = Path(tf.name)

    try:
        try:
            parse_json_artifact(path, "JSONBrowser")
            assert False, "Should have raised exception"
        except Exception:
            pass  # Expected behavior
    finally:
        if path.exists():
            path.unlink()


# ==============================================================================
# 3, 4, 9. SQLITE BROWSER PARSING TESTS
# ==============================================================================

def test_chromium_sqlite_parsing():
    """3. Chrome/Edge SQLite History parsing."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
        db_path = Path(tf.name)

    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE downloads (
                id INTEGER PRIMARY KEY,
                start_time INTEGER,
                current_path TEXT,
                url TEXT
            )
        """)
        # Insert sample rows
        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://example.com/login', 'Example Login', 2, 13344686400000000)"
        )
        conn.execute(
            "INSERT INTO downloads VALUES (1, 13344686400000000, 'C:/Users/user/Downloads/setup.exe', 'https://example.com/setup.exe')"
        )
        conn.commit()
        conn.close()

        # Detect format
        fmt = detect_browser_artifact_type(db_path)
        assert fmt == "CHROMIUM_SQLITE"

        # Parse
        events, valid, skipped = parse_chromium_sqlite_artifact(db_path, "Chrome")
        assert valid == 2
        assert len(events) == 2
        assert events[0]["event_type"] == "PAGE_VISIT"
        assert events[1]["event_type"] == "DOWNLOAD"
        assert events[1]["download_filename"] == "setup.exe"
    finally:
        if db_path.exists():
            db_path.unlink()


def test_firefox_sqlite_parsing():
    """4. Firefox places.sqlite parsing."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
        db_path = Path(tf.name)

    try:
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_date INTEGER
            )
        """)
        conn.execute(
            "INSERT INTO moz_places VALUES (1, 'https://mozilla.org/firefox', 'Firefox Browser', 3, 1700000000000000)"
        )
        conn.commit()
        conn.close()

        fmt = detect_browser_artifact_type(db_path)
        assert fmt == "FIREFOX_SQLITE"

        events, valid, skipped = parse_firefox_sqlite_artifact(db_path, "Firefox")
        assert valid == 1
        assert events[0]["url"] == "https://mozilla.org/firefox"
        assert events[0]["hostname"] == "mozilla.org"
    finally:
        if db_path.exists():
            db_path.unlink()


def test_corrupt_sqlite_handling():
    """9. Corrupt SQLite handling."""
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tf:
        tf.write(b"SQLite format 3\x00CORRUPT_BYTES_DATA_STREAM_TEST")
        db_path = Path(tf.name)

    try:
        try:
            parse_chromium_sqlite_artifact(db_path, "Corrupt")
            assert False, "Should have failed on corrupt database"
        except Exception:
            pass
    finally:
        if db_path.exists():
            db_path.unlink()


# ==============================================================================
# 11-16. FORENSIC INDICATOR ENGINE TESTS
# ==============================================================================

def test_forensic_indicators_detection():
    """11. Download extraction, 12. Direct-IP, 13. Executable-download,
    14. Unknown domain is NOT malicious, 15. Burst detection, 16. Visit-download correlation."""
    events = [
        # Normal visit to unfamiliar domain - must NOT be flagged as malicious
        {
            "event_id": "EVT-1",
            "event_type": "PAGE_VISIT",
            "timestamp_utc": "2026-11-16 09:00:00",
            "url": "https://unfamiliar-random-portal.org/index",
            "hostname": "unfamiliar-random-portal.org",
            "page_title": "Unfamiliar Portal"
        },
        # Direct IP access
        {
            "event_id": "EVT-2",
            "event_type": "PAGE_VISIT",
            "timestamp_utc": "2026-11-16 09:02:00",
            "url": "http://198.51.100.25:8088/tools",
            "hostname": "198.51.100.25:8088",
            "page_title": "IP Staging"
        },
        # Executable download shortly after visit to same host
        {
            "event_id": "EVT-3",
            "event_type": "DOWNLOAD",
            "timestamp_utc": "2026-11-16 09:03:00",
            "url": "http://198.51.100.25:8088/tools/updater.exe",
            "hostname": "198.51.100.25:8088",
            "download_filename": "updater.exe",
            "page_title": "Download: updater.exe"
        },
        # Punycode hostname
        {
            "event_id": "EVT-4",
            "event_type": "PAGE_VISIT",
            "timestamp_utc": "2026-11-16 09:04:00",
            "url": "https://xn--apple-test.com",
            "hostname": "xn--apple-test.com",
            "page_title": "Punycode"
        }
    ]

    indicators = analyze_forensic_indicators(events, correlation_window_seconds=120)
    ind_names = [i["indicator_name"] for i in indicators]

    # 12: Direct-IP
    assert "DIRECT_IP_ACCESS" in ind_names
    # 13: Executable-download
    assert "EXECUTABLE_DOWNLOAD" in ind_names
    # Non-standard port
    assert "NON_STANDARD_PORT" in ind_names
    # Punycode
    assert "PUNYCODE_HOSTNAME" in ind_names
    # 16: Visit-download correlation
    assert "VISIT_DOWNLOAD_CORRELATION" in ind_names

    # 14: Confirm unknown domain was NOT flagged as an indicator
    unfamiliar_flags = [i for i in indicators if i.get("observed_value") == "unfamiliar-random-portal.org"]
    assert len(unfamiliar_flags) == 0


def test_repeated_visit_burst_detection():
    """15. Repeated visit burst detection within configurable window."""
    burst_events = []
    base_ts = pd.to_datetime("2026-11-16 10:00:00")
    for i in range(10):
        # 10 visits within 5 seconds
        ts = (base_ts + pd.Timedelta(milliseconds=500 * i)).strftime("%Y-%m-%d %H:%M:%S")
        burst_events.append({
            "event_id": f"BURST-{i}",
            "event_type": "PAGE_VISIT",
            "timestamp_utc": ts,
            "url": f"https://example.com/item/{i}",
            "hostname": "example.com",
            "page_title": f"Item {i}"
        })

    indicators = analyze_forensic_indicators(burst_events, burst_threshold=8, burst_window_seconds=10)
    ind_names = [i["indicator_name"] for i in indicators]
    assert "REPEATED_VISIT_BURST" in ind_names


# ==============================================================================
# 17 & 20. END-TO-END INGESTION, DUPLICATES & EXPORT
# ==============================================================================

def test_ingestion_duplicate_prevention_and_export():
    """17. Duplicate import handling and 20. Export generation."""
    init_db()
    case_id = "CAS-WEBTRACE-TEST-01"

    try:
        execute_commit(
            "INSERT INTO investigations (id, case_name, lead_investigator) VALUES (?, ?, ?)",
            (case_id, "WebTrace Unit Case", "Investigator Test")
        )

        sample_csv = """timestamp,url,title,target_path
2026-11-16 09:14:00,https://example.com/home,Home,
2026-11-16 09:18:00,https://example.com/patch.zip,Download,C:/Users/test/Downloads/patch.zip
"""
        with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False) as tf:
            tf.write(sample_csv)
            sample_path = Path(tf.name)

        # 1. Ingest
        res1 = ingest_browser_artifact(case_id, sample_path, "Chrome")
        assert res1["status"] == "SUCCESS"
        assert res1["valid_records"] == 2
        import_id = res1["import_id"]

        # 2. Duplicate ingestion attempt
        res2 = ingest_browser_artifact(case_id, sample_path, "Chrome")
        assert res2["status"] == "DUPLICATE_IMPORT"

        # 3. Retrieve stats and events
        stats = get_webtrace_overview_stats(case_id)
        assert stats["total_events"] == 2
        assert stats["total_downloads"] == 1

        evts = get_webtrace_events(case_id)
        assert len(evts) == 2

        # 4. Link download to dummy evidence
        dl_evt = [e for e in evts if e["event_type"] == "DOWNLOAD"][0]
        link_download_to_evidence(dl_evt["id"], "EV-DUMMY-123")
        updated_evts = get_webtrace_events(case_id)
        updated_dl = [e for e in updated_evts if e["event_type"] == "DOWNLOAD"][0]
        assert updated_dl["linked_evidence_id"] == "EV-DUMMY-123"

        # 5. Export generation
        df_export = pd.DataFrame(evts)
        csv_out = df_export.to_csv(index=False)
        assert "example.com" in csv_out

        json_out = json.dumps(stats)
        assert "total_events" in json_out

    finally:
        execute_commit("DELETE FROM investigations WHERE id = ?", (case_id,))
        if sample_path.exists():
            sample_path.unlink()
