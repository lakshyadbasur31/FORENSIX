"""WEBTRACE — Browser History Analysis & Web Activity Reconstruction Module.

Features:
- Multi-format ingestion: CSV, JSON, Chromium SQLite History, Firefox places.sqlite
- WebKit & PRTime timestamp conversion to UTC
- URL credential & token sanitization / redaction
- Common normalized event model
- Web activity analysis (browsing, downloads, domains)
- Rule-based explainable forensic indicator engine
"""
import os
import re
import csv
import json
import uuid
import sqlite3
import tempfile
import ipaddress
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Any, Optional, Tuple, Union

import pandas as pd
from database.db import execute_query, execute_commit, execute_many
from modules.hash_verification import compute_file_hashes

# Sensible list of risky download extensions for rule-based flagging
EXECUTABLE_EXTENSIONS = {".exe", ".msi", ".scr", ".com", ".pif", ".application", ".gadget"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta"}
SUSPICIOUS_ARCHIVE_EXTENSIONS = {".iso", ".img", ".vhd", ".vhdx"}

# Standard web ports
STANDARD_WEB_PORTS = {80, 443, 8080, 8443}

# Sensitive query parameter keys to redact from URLs
SENSITIVE_PARAM_NAMES = {
    "token", "access_token", "auth_token", "api_key", "apikey", "key",
    "password", "pass", "pwd", "secret", "session", "session_id", "sessionid",
    "bearer", "auth", "credential", "signature", "sig"
}


# ==============================================================================
# 1. TIMESTAMP CONVERSIONS
# ==============================================================================

def convert_webkit_timestamp(webkit_microsec: Union[int, float, str]) -> str:
    """Converts Chromium WebKit epoch (microseconds since 1601-01-01 UTC) to UTC ISO string.
    
    Returns '1970-01-01 00:00:00' if input is zero or invalid.
    """
    try:
        us = int(webkit_microsec)
        if us <= 0:
            return "1970-01-01 00:00:00"
        
        # Microseconds between 1601-01-01 and 1970-01-01 UTC = 11,644,473,600,000,000
        unix_seconds = (us - 11644473600000000) / 1000000.0
        if unix_seconds < 0:
            return "1970-01-01 00:00:00"
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "1970-01-01 00:00:00"


def convert_firefox_timestamp(prtime_microsec: Union[int, float, str]) -> str:
    """Converts Mozilla Firefox PRTime (microseconds since 1970-01-01 UTC) to UTC ISO string."""
    try:
        us = int(prtime_microsec)
        if us <= 0:
            return "1970-01-01 00:00:00"
        unix_seconds = us / 1000000.0
        dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "1970-01-01 00:00:00"


def normalize_iso_timestamp(ts_val: Any) -> str:
    """Standardizes arbitrary date strings/timestamps into 'YYYY-MM-DD HH:MM:SS' UTC."""
    if not ts_val:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    
    ts_str = str(ts_val).strip()
    try:
        # Check if numeric epoch (seconds or milliseconds)
        if ts_str.isdigit():
            epoch = int(ts_str)
            if epoch > 1000000000000:  # milliseconds
                epoch = epoch / 1000.0
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S")

        # Parse via pandas for robust format handling
        pdt = pd.to_datetime(ts_str, utc=True)
        return pdt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Fallback simplistic string cleanup
        clean = ts_str.replace("T", " ")[:19]
        return clean if len(clean) >= 10 else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ==============================================================================
# 2. URL REDACTION & HOSTNAME EXTRACTION
# ==============================================================================

def redact_sensitive_url(url: str) -> str:
    """Redacts credentials, tokens, and sensitive query parameter values in URLs for UI display."""
    if not url or not isinstance(url, str):
        return ""
    try:
        parsed = urlparse(url)
        # Redact username and password if embedded in netloc: user:pass@host
        netloc = parsed.netloc
        if "@" in netloc:
            creds, host = netloc.split("@", 1)
            netloc = f"[REDACTED_AUTH]@{host}"
        
        # Redact known sensitive query parameter values
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            redacted_params = []
            for k, vals in params.items():
                if k.lower() in SENSITIVE_PARAM_NAMES:
                    redacted_params.append((k, "[REDACTED]"))
                else:
                    for v in vals:
                        redacted_params.append((k, v))
            new_query = urlencode(redacted_params)
        else:
            new_query = ""

        return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    except Exception:
        return url


def extract_hostname(url: str) -> str:
    """Extracts lowercase hostname or host:port from URL."""
    if not url or not isinstance(url, str):
        return "UNKNOWN"
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc or parsed.path.split("/")[0]
        # Strip user:pass if present
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]
        return netloc.lower().strip() or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def is_direct_ip(hostname: str) -> bool:
    """Determines whether a hostname string is a raw IPv4 or IPv6 address."""
    if not hostname or hostname == "UNKNOWN":
        return False
    host_only = hostname.split(":")[0].strip("[]")
    try:
        ipaddress.ip_address(host_only)
        return True
    except ValueError:
        return False


def is_punycode(hostname: str) -> bool:
    """Detects whether a hostname utilizes punycode internationalized domain encoding (xn--)."""
    if not hostname:
        return False
    return "xn--" in hostname.lower()


def extract_non_standard_port(url: str) -> Optional[int]:
    """Returns the port number if a non-standard port is specified in the URL."""
    try:
        parsed = urlparse(url)
        if parsed.port and parsed.port not in STANDARD_WEB_PORTS:
            return parsed.port
    except Exception:
        pass
    return None


# ==============================================================================
# 3. FORMAT AUTO-DETECTION & PARSERS
# ==============================================================================

def detect_browser_artifact_type(file_path: Union[str, Path]) -> str:
    """Detects artifact type: 'CHROMIUM_SQLITE', 'FIREFOX_SQLITE', 'JSON', 'CSV', or 'UNKNOWN'."""
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Read first 100 bytes to check SQLite header
    with open(p, "rb") as f:
        header = f.read(100)

    if header.startswith(b"SQLite format 3\x00"):
        # Inspect SQLite schema read-only
        try:
            conn = sqlite3.connect(f"file:{p.resolve()}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = {r[0] for r in cursor.fetchall()}
            conn.close()

            if "moz_places" in tables or "moz_historyvisits" in tables:
                return "FIREFOX_SQLITE"
            if "urls" in tables or "visits" in tables or "downloads" in tables:
                return "CHROMIUM_SQLITE"
            return "SQLITE_GENERIC"
        except Exception:
            return "SQLITE_GENERIC"

    # Check for JSON
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            content = f.read(2048).strip()
            if content.startswith(("{", "[")):
                return "JSON"
    except Exception:
        pass

    # Check for CSV
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline()
            if "," in first_line or "\t" in first_line or ";" in first_line:
                return "CSV"
    except Exception:
        pass

    return "UNKNOWN"


def parse_csv_artifact(file_path: Union[str, Path], browser_name: str = "Generic") -> Tuple[List[Dict[str, Any]], int, int]:
    """Parses browser history or downloads CSV into normalized event records."""
    events = []
    skipped = 0
    valid = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        # Sniff dialect or default to comma
        sample = f.read(2048)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample)
        except Exception:
            dialect = csv.excel

        reader = csv.DictReader(f, dialect=dialect)
        for row_idx, raw_row in enumerate(reader, start=1):
            row = {k.strip().lower(): (v.strip() if v else "") for k, v in raw_row.items() if k}
            
            url = row.get("url") or row.get("source_url") or row.get("download_url") or ""
            target_path = row.get("target_path") or row.get("filename") or row.get("download_filename") or ""
            
            # If neither URL nor download file path is present, skip
            if not url and not target_path:
                skipped += 1
                continue

            event_type = "DOWNLOAD" if (target_path or "download" in row.get("event_type", "").lower()) else "PAGE_VISIT"
            timestamp = normalize_iso_timestamp(row.get("timestamp") or row.get("date") or row.get("visit_time"))
            
            page_title = row.get("title") or row.get("page_title") or ("Download" if event_type == "DOWNLOAD" else "Untitled")
            visit_count = 1
            try:
                visit_count = int(row.get("visit_count") or 1)
            except Exception:
                visit_count = 1

            hostname = extract_hostname(url)
            dl_filename = Path(target_path).name if target_path else ""

            events.append({
                "browser": browser_name,
                "event_type": event_type,
                "timestamp_utc": timestamp,
                "url": url,
                "hostname": hostname,
                "page_title": page_title,
                "visit_count": visit_count,
                "referrer": row.get("referrer") or row.get("referer") or "",
                "download_filename": dl_filename,
                "download_path": target_path,
                "source_record_number": row_idx
            })
            valid += 1

    return events, valid, skipped


def parse_json_artifact(file_path: Union[str, Path], browser_name: str = "Generic") -> Tuple[List[Dict[str, Any]], int, int]:
    """Parses JSON browser history exports into normalized event records."""
    events = []
    valid = 0
    skipped = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    items = data
    if isinstance(data, dict):
        # Look for standard keys like 'Browser History', 'history', 'downloads', 'records'
        for key in ["Browser History", "history", "downloads", "records", "items", "visits"]:
            if key in data and isinstance(data[key], list):
                items = data[key]
                break
        if isinstance(items, dict):
            items = [items]

    if not isinstance(items, list):
        raise ValueError("JSON file does not contain a recognizable list of browser records.")

    for row_idx, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            skipped += 1
            continue

        url = item.get("url") or item.get("source_url") or item.get("download_url") or ""
        target_path = item.get("target_path") or item.get("filename") or item.get("download_filename") or ""

        if not url and not target_path:
            skipped += 1
            continue

        event_type = "DOWNLOAD" if (target_path or "download" in str(item.get("event_type", "")).lower()) else "PAGE_VISIT"
        timestamp = normalize_iso_timestamp(
            item.get("timestamp") or item.get("date") or item.get("time_usec") or item.get("visit_time")
        )
        page_title = item.get("title") or item.get("page_title") or ("Download" if event_type == "DOWNLOAD" else "Untitled")
        try:
            visit_count = int(item.get("visit_count", 1))
        except Exception:
            visit_count = 1

        hostname = extract_hostname(url)
        dl_filename = Path(target_path).name if target_path else ""

        events.append({
            "browser": browser_name,
            "event_type": event_type,
            "timestamp_utc": timestamp,
            "url": url,
            "hostname": hostname,
            "page_title": page_title,
            "visit_count": visit_count,
            "referrer": item.get("referrer") or item.get("referer") or "",
            "download_filename": dl_filename,
            "download_path": target_path,
            "source_record_number": row_idx
        })
        valid += 1

    return events, valid, skipped


def parse_chromium_sqlite_artifact(file_path: Union[str, Path], browser_name: str = "Chromium / Edge") -> Tuple[List[Dict[str, Any]], int, int]:
    """Parses Chromium/Edge History SQLite database read-only."""
    events = []
    valid = 0
    skipped = 0

    p = Path(file_path).resolve()
    # Open SQLite in read-only mode using URI
    uri = f"file:{p.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {r[0] for r in cursor.fetchall()}

        # 1. Parse URL visits
        if "urls" in tables:
            # Check available columns in urls
            cursor.execute("PRAGMA table_info(urls);")
            url_cols = {r["name"] for r in cursor.fetchall()}

            visit_query = """
            SELECT u.id, u.url, u.title, u.visit_count, u.last_visit_time
            FROM urls u
            """
            cursor.execute(visit_query)
            for r in cursor.fetchall():
                raw_url = r["url"] or ""
                if not raw_url:
                    skipped += 1
                    continue
                ts = convert_webkit_timestamp(r["last_visit_time"] or 0)
                hostname = extract_hostname(raw_url)
                events.append({
                    "browser": browser_name,
                    "event_type": "PAGE_VISIT",
                    "timestamp_utc": ts,
                    "url": raw_url,
                    "hostname": hostname,
                    "page_title": r["title"] or "Untitled",
                    "visit_count": r["visit_count"] or 1,
                    "referrer": "",
                    "download_filename": "",
                    "download_path": "",
                    "source_record_number": r["id"]
                })
                valid += 1

        # 2. Parse Downloads
        if "downloads" in tables:
            cursor.execute("PRAGMA table_info(downloads);")
            dl_cols = {r["name"] for r in cursor.fetchall()}

            # Columns differ across Chromium versions: current_path or target_path, start_time
            path_col = "current_path" if "current_path" in dl_cols else ("target_path" if "target_path" in dl_cols else "id")
            url_col = "url" if "url" in dl_cols else ("tab_url" if "tab_url" in dl_cols else "")
            
            dl_query = f"SELECT id, start_time, {path_col} as fpath" + (f", {url_col} as src_url" if url_col else "") + " FROM downloads;"
            cursor.execute(dl_query)
            for r in cursor.fetchall():
                fpath = r["fpath"] or ""
                src_url = r["src_url"] if url_col and "src_url" in r.keys() else ""
                ts = convert_webkit_timestamp(r["start_time"] or 0)
                fname = Path(fpath).name if fpath else "unknown_download"

                events.append({
                    "browser": browser_name,
                    "event_type": "DOWNLOAD",
                    "timestamp_utc": ts,
                    "url": src_url,
                    "hostname": extract_hostname(src_url) if src_url else "UNKNOWN",
                    "page_title": f"Download: {fname}",
                    "visit_count": 1,
                    "referrer": "",
                    "download_filename": fname,
                    "download_path": fpath,
                    "source_record_number": r["id"]
                })
                valid += 1

    finally:
        conn.close()

    return events, valid, skipped


def parse_firefox_sqlite_artifact(file_path: Union[str, Path], browser_name: str = "Firefox") -> Tuple[List[Dict[str, Any]], int, int]:
    """Parses Firefox places.sqlite database read-only."""
    events = []
    valid = 0
    skipped = 0

    p = Path(file_path).resolve()
    uri = f"file:{p.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {r[0] for r in cursor.fetchall()}

        if "moz_places" in tables:
            # Query joined with moz_historyvisits if available
            if "moz_historyvisits" in tables:
                query = """
                SELECT p.id, p.url, p.title, p.visit_count, v.visit_date
                FROM moz_places p
                JOIN moz_historyvisits v ON p.id = v.place_id
                """
            else:
                query = "SELECT id, url, title, visit_count, last_visit_date as visit_date FROM moz_places;"

            cursor.execute(query)
            for r in cursor.fetchall():
                raw_url = r["url"] or ""
                if not raw_url:
                    skipped += 1
                    continue
                ts = convert_firefox_timestamp(r["visit_date"] or 0)
                events.append({
                    "browser": browser_name,
                    "event_type": "PAGE_VISIT",
                    "timestamp_utc": ts,
                    "url": raw_url,
                    "hostname": extract_hostname(raw_url),
                    "page_title": r["title"] or "Untitled",
                    "visit_count": r["visit_count"] or 1,
                    "referrer": "",
                    "download_filename": "",
                    "download_path": "",
                    "source_record_number": r["id"]
                })
                valid += 1
        else:
            raise ValueError("Invalid Firefox database: moz_places table not found.")

    finally:
        conn.close()

    return events, valid, skipped


# ==============================================================================
# 4. EXPLAINABLE SUSPICIOUS ACTIVITY INDICATORS
# ==============================================================================

def analyze_forensic_indicators(
    events: List[Dict[str, Any]],
    burst_threshold: int = 8,
    burst_window_seconds: int = 15,
    correlation_window_seconds: int = 300
) -> List[Dict[str, Any]]:
    """Evaluates rule-based forensic indicators across normalized events with explainability."""
    indicators = []

    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda e: e.get("timestamp_utc", ""))

    # 1. Event-level rule evaluations
    for evt in sorted_events:
        url = evt.get("url") or ""
        hostname = evt.get("hostname") or ""
        evt_type = evt.get("event_type") or ""
        dl_name = evt.get("download_filename") or ""
        dl_ext = Path(dl_name).suffix.lower() if dl_name else (Path(urlparse(url).path).suffix.lower() if url else "")
        ts = evt.get("timestamp_utc", "")
        evt_id = evt.get("event_id") or ""
        src_rec = f"{evt.get('source_filename', 'artifact')}:rec#{evt.get('source_record_number', '?')}"

        # 1. DIRECT_IP_ACCESS
        if is_direct_ip(hostname):
            indicators.append({
                "indicator_name": "DIRECT_IP_ACCESS",
                "severity": "MEDIUM",
                "event_id": evt_id,
                "observed_value": hostname,
                "description": f"HTTP/HTTPS request routed directly to an IP address without domain name resolution.",
                "reason": "Direct IP navigation bypasses standard DNS logging and is frequently observed in command-and-control communication or staging servers (though also common in internal networks).",
                "timestamp_utc": ts,
                "source_record": src_rec
            })

        # 2. EXECUTABLE_DOWNLOAD
        if evt_type == "DOWNLOAD" and dl_ext in EXECUTABLE_EXTENSIONS:
            indicators.append({
                "indicator_name": "EXECUTABLE_DOWNLOAD",
                "severity": "HIGH",
                "event_id": evt_id,
                "observed_value": dl_name or url,
                "description": f"Browser recorded acquisition of an executable file artifact ({dl_ext}).",
                "reason": "Binary executables introduce arbitrary code execution risks. Note: Download recording does not constitute proof of execution.",
                "timestamp_utc": ts,
                "source_record": src_rec
            })

        # 3. SCRIPT_DOWNLOAD
        if evt_type == "DOWNLOAD" and dl_ext in SCRIPT_EXTENSIONS:
            indicators.append({
                "indicator_name": "SCRIPT_DOWNLOAD",
                "severity": "HIGH",
                "event_id": evt_id,
                "observed_value": dl_name or url,
                "description": f"Browser recorded acquisition of a script or automation payload ({dl_ext}).",
                "reason": "Script files (.ps1, .bat, .vbs, .js) can bypass endpoint policies and execute arbitrary interpreter instructions.",
                "timestamp_utc": ts,
                "source_record": src_rec
            })

        # 4. PUNYCODE_HOSTNAME
        if is_punycode(hostname):
            indicators.append({
                "indicator_name": "PUNYCODE_HOSTNAME",
                "severity": "MEDIUM",
                "event_id": evt_id,
                "observed_value": hostname,
                "description": f"Hostname uses Internationalized Domain Name (IDN) punycode prefix ('xn--').",
                "reason": "Punycode hostnames may be legitimate foreign language domains or employed in homograph attacks spoofing recognized corporate domains.",
                "timestamp_utc": ts,
                "source_record": src_rec
            })

        # 5. NON_STANDARD_PORT
        port = extract_non_standard_port(url)
        if port:
            indicators.append({
                "indicator_name": "NON_STANDARD_PORT",
                "severity": "LOW",
                "event_id": evt_id,
                "observed_value": f"Port {port} on {hostname}",
                "description": f"Web traffic directed to non-standard HTTP port {port}.",
                "reason": "Non-standard web ports (outside 80, 443, 8080, 8443) may indicate custom administrative consoles, alternate proxy ports, or staging nodes.",
                "timestamp_utc": ts,
                "source_record": src_rec
            })

    # 6. REPEATED_VISIT_BURST (Aggregated window evaluation)
    # Detect high volume of visits within burst_window_seconds
    if len(sorted_events) >= burst_threshold:
        for i in range(len(sorted_events) - burst_threshold + 1):
            window = sorted_events[i: i + burst_threshold]
            try:
                t0 = datetime.fromisoformat(window[0]["timestamp_utc"])
                t1 = datetime.fromisoformat(window[-1]["timestamp_utc"])
                delta_sec = (t1 - t0).total_seconds()
                if 0 <= delta_sec <= burst_window_seconds:
                    first_evt = window[0]
                    indicators.append({
                        "indicator_name": "REPEATED_VISIT_BURST",
                        "severity": "LOW",
                        "event_id": first_evt.get("event_id", ""),
                        "observed_value": f"{burst_threshold} visits in {int(delta_sec)}s",
                        "description": f"High-frequency browsing burst: {burst_threshold} requests within {int(delta_sec)} seconds.",
                        "reason": "Rapid visit frequency can indicate automated scraping, web spidering, redirect loops, or multi-resource loading.",
                        "timestamp_utc": first_evt.get("timestamp_utc", ""),
                        "source_record": f"Burst starting around {first_evt.get('timestamp_utc')}"
                    })
                    break  # Flag one burst alert per sequence
            except Exception:
                pass

    # 7. VISIT_DOWNLOAD_CORRELATION
    # Identify download events occurring shortly after visiting a host
    downloads = [e for e in sorted_events if e.get("event_type") == "DOWNLOAD"]
    visits = [e for e in sorted_events if e.get("event_type") == "PAGE_VISIT"]

    for dl in downloads:
        dl_ts_str = dl.get("timestamp_utc", "")
        dl_host = dl.get("hostname", "")
        try:
            dl_dt = datetime.fromisoformat(dl_ts_str)
            for v in visits:
                v_ts_str = v.get("timestamp_utc", "")
                v_dt = datetime.fromisoformat(v_ts_str)
                time_diff = (dl_dt - v_dt).total_seconds()
                # If visit occurred within correlation_window_seconds before download
                if 0 <= time_diff <= correlation_window_seconds and (v.get("hostname") == dl_host or dl_host == "UNKNOWN"):
                    indicators.append({
                        "indicator_name": "VISIT_DOWNLOAD_CORRELATION",
                        "severity": "MEDIUM",
                        "event_id": dl.get("event_id", ""),
                        "observed_value": f"Visit {v.get('hostname')} -> Download {dl.get('download_filename')} ({int(time_diff)}s)",
                        "description": f"Web navigation to host {v.get('hostname')} closely correlated in time ({int(time_diff)}s) with file download.",
                        "reason": "Correlating delivery visits with downloaded payloads reconstructs the delivery path of untrusted files.",
                        "timestamp_utc": dl_ts_str,
                        "source_record": f"Visit #{v.get('source_record_number')} -> Download #{dl.get('source_record_number')}"
                    })
                    break
        except Exception:
            pass

    return indicators


# ==============================================================================
# 5. DATA INGESTION & PERSISTENCE
# ==============================================================================

def ingest_browser_artifact(
    investigation_id: str,
    file_path: Union[str, Path],
    browser_type_override: Optional[str] = None
) -> Dict[str, Any]:
    """Ingests a browser artifact, parses events, persists them, and runs indicator analysis.
    
    Prevents duplicate imports if the identical file hash is already ingested for this case.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Artifact file not found: {file_path}")

    hashes = compute_file_hashes(path)
    source_sha256 = hashes["sha256"]
    file_size = path.stat().st_size
    filename = path.name

    # Check for existing duplicate import for this investigation
    existing = execute_query(
        "SELECT id, import_timestamp, total_records FROM webtrace_imports WHERE investigation_id = ? AND source_sha256 = ?",
        (investigation_id, source_sha256)
    )
    if existing:
        return {
            "status": "DUPLICATE_IMPORT",
            "import_id": existing[0]["id"],
            "message": f"Artifact with SHA-256 {source_sha256[:16]}... has already been imported into this investigation.",
            "total_records": existing[0]["total_records"]
        }

    # Format detection
    format_type = detect_browser_artifact_type(path)
    browser_name = browser_type_override or (
        "Chromium / Edge" if format_type == "CHROMIUM_SQLITE" else (
            "Firefox" if format_type == "FIREFOX_SQLITE" else "Generic"
        )
    )

    # Parse records
    if format_type == "CHROMIUM_SQLITE":
        events, valid_count, skipped_count = parse_chromium_sqlite_artifact(path, browser_name)
    elif format_type == "FIREFOX_SQLITE":
        events, valid_count, skipped_count = parse_firefox_sqlite_artifact(path, browser_name)
    elif format_type == "JSON":
        events, valid_count, skipped_count = parse_json_artifact(path, browser_name)
    elif format_type == "CSV":
        events, valid_count, skipped_count = parse_csv_artifact(path, browser_name)
    else:
        # Fallback attempt as CSV
        try:
            events, valid_count, skipped_count = parse_csv_artifact(path, browser_name)
            format_type = "CSV"
        except Exception as e:
            raise ValueError(f"Unable to parse browser artifact format for: {filename}. Detected format: {format_type}. Error: {str(e)}")

    import_id = f"WTI-{uuid.uuid4().hex[:8].upper()}"

    # 1. Insert Import record
    execute_commit(
        """
        INSERT INTO webtrace_imports (
            id, investigation_id, source_filename, browser_type, format_type,
            source_sha256, file_size_bytes, total_records, valid_records, skipped_records
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            import_id, investigation_id, filename, browser_name, format_type,
            source_sha256, file_size, len(events) + skipped_count, valid_count, skipped_count
        )
    )

    # 2. Batch insert normalized events
    event_params = []
    for evt in events:
        evt_id = f"WTE-{uuid.uuid4().hex[:8].upper()}"
        evt["event_id"] = evt_id
        evt["import_id"] = import_id
        evt["investigation_id"] = investigation_id
        evt["source_filename"] = filename
        event_params.append((
            evt_id, import_id, investigation_id, evt["browser"], evt["event_type"],
            evt["timestamp_utc"], evt["url"], evt["hostname"], evt["page_title"],
            evt["visit_count"], evt["referrer"], evt["download_filename"],
            evt["download_path"], filename, evt["source_record_number"], None
        ))

    if event_params:
        execute_many(
            """
            INSERT INTO webtrace_events (
                id, import_id, investigation_id, browser, event_type, timestamp_utc,
                url, hostname, page_title, visit_count, referrer, download_filename,
                download_path, source_filename, source_record_number, linked_evidence_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            event_params
        )

    # 3. Run indicator engine and insert findings
    indicators = analyze_forensic_indicators(events)
    ind_params = []
    for ind in indicators:
        ind_id = f"WTI-IND-{uuid.uuid4().hex[:8].upper()}"
        ind_params.append((
            ind_id, import_id, ind.get("event_id"), ind["indicator_name"],
            ind["severity"], ind.get("observed_value", ""), ind.get("description", ""),
            ind.get("reason", ""), ind.get("timestamp_utc", ""), ind.get("source_record", "")
        ))

    if ind_params:
        execute_many(
            """
            INSERT INTO webtrace_indicators (
                id, import_id, event_id, indicator_name, severity,
                observed_value, description, reason, timestamp_utc, source_record
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ind_params
        )

    return {
        "status": "SUCCESS",
        "import_id": import_id,
        "format_type": format_type,
        "source_sha256": source_sha256,
        "total_records": len(events) + skipped_count,
        "valid_records": valid_count,
        "skipped_records": skipped_count,
        "indicator_count": len(indicators)
    }


# ==============================================================================
# 6. QUERY & REPORTING HELPERS
# ==============================================================================

def get_webtrace_overview_stats(investigation_id: str) -> Dict[str, Any]:
    """Computes real-time overview counts for the WEBTRACE module."""
    imports = execute_query("SELECT id FROM webtrace_imports WHERE investigation_id = ?", (investigation_id,))
    import_ids = [r["id"] for r in imports]
    
    if not import_ids:
        return {
            "total_events": 0,
            "unique_hostnames": 0,
            "total_downloads": 0,
            "flagged_events": 0,
            "source_artifacts": 0
        }

    q_events = execute_query(
        """
        SELECT COUNT(*) as c, COUNT(DISTINCT hostname) as uh,
               SUM(CASE WHEN event_type = 'DOWNLOAD' THEN 1 ELSE 0 END) as dls
        FROM webtrace_events WHERE investigation_id = ?
        """,
        (investigation_id,)
    )[0]

    q_ind = execute_query(
        """
        SELECT COUNT(*) as c FROM webtrace_indicators i
        JOIN webtrace_imports m ON i.import_id = m.id
        WHERE m.investigation_id = ?
        """,
        (investigation_id,)
    )[0]

    return {
        "total_events": q_events["c"],
        "unique_hostnames": q_events["uh"],
        "total_downloads": q_events["dls"] or 0,
        "flagged_events": q_ind["c"],
        "source_artifacts": len(imports)
    }


def get_webtrace_events(
    investigation_id: str,
    event_type: Optional[str] = None,
    hostname_search: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves normalized events for an investigation with optional filters."""
    params = [investigation_id]
    where = ["investigation_id = ?"]

    if event_type and event_type != "ALL":
        where.append("event_type = ?")
        params.append(event_type)

    if hostname_search:
        where.append("(hostname LIKE ? OR url LIKE ? OR page_title LIKE ?)")
        term = f"%{hostname_search.strip()}%"
        params.extend([term, term, term])

    query = f"""
    SELECT id, import_id, browser, event_type, timestamp_utc, url, hostname,
           page_title, visit_count, referrer, download_filename, download_path,
           source_filename, source_record_number, linked_evidence_id
    FROM webtrace_events
    WHERE {' AND '.join(where)}
    ORDER BY timestamp_utc ASC, rowid ASC
    """
    return execute_query(query, tuple(params))


def get_webtrace_indicators(investigation_id: str) -> List[Dict[str, Any]]:
    """Retrieves all rule-based forensic indicators for an investigation."""
    query = """
    SELECT i.id, i.import_id, i.event_id, i.indicator_name, i.severity,
           i.observed_value, i.description, i.reason, i.timestamp_utc, i.source_record
    FROM webtrace_indicators i
    JOIN webtrace_imports m ON i.import_id = m.id
    WHERE m.investigation_id = ?
    ORDER BY i.timestamp_utc ASC, i.rowid ASC
    """
    return execute_query(query, (investigation_id,))


def link_download_to_evidence(event_id: str, evidence_id: str) -> int:
    """Links a browser download event to a registered CHAINLOCK evidence artifact."""
    return execute_commit(
        "UPDATE webtrace_events SET linked_evidence_id = ? WHERE id = ?",
        (evidence_id, event_id)
    )
