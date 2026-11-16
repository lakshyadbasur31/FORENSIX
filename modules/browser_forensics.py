"""Browser Forensics parsing and analysis module.

Extracts, normalizes, and analyzes browser artefacts:
- Web Navigation History
- File Download Records
- Domain extraction and frequency profiling
"""
import csv
import re
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Any, Union
import pandas as pd


def extract_domain(url: str) -> str:
    """Extracts the registered domain or host from a URL."""
    if not url or not isinstance(url, str):
        return "UNKNOWN"
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0] or "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def parse_browser_history_csv(file_path: Union[str, Path]) -> pd.DataFrame:
    """Parses a browser history CSV file into a standardized pandas DataFrame.
    
    Expected CSV fields (flexible matching):
    timestamp, url, title, visit_count, typed_count
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Browser history file not found: {file_path}")

    df = pd.read_csv(path)
    # Normalize column names to lowercase stripped
    df.columns = [c.strip().lower() for c in df.columns]

    # Guarantee required columns exist or fill default
    if "timestamp" not in df.columns:
        df["timestamp"] = ""
    if "url" not in df.columns:
        df["url"] = ""
    if "title" not in df.columns:
        df["title"] = "Untitled"
    if "visit_count" not in df.columns:
        df["visit_count"] = 1

    df["domain"] = df["url"].apply(extract_domain)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.sort_values(by="timestamp", ascending=True)


def parse_browser_downloads_csv(file_path: Union[str, Path]) -> pd.DataFrame:
    """Parses browser download records into a structured DataFrame.
    
    Expected CSV fields:
    timestamp, target_path, source_url, total_bytes, mime_type, state
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Browser downloads file not found: {file_path}")

    df = pd.read_csv(path)
    df.columns = [c.strip().lower() for c in df.columns]

    for col in ["timestamp", "target_path", "source_url", "total_bytes", "mime_type"]:
        if col not in df.columns:
            df[col] = ""

    df["source_domain"] = df["source_url"].apply(extract_domain)
    df["filename"] = df["target_path"].apply(lambda p: Path(str(p)).name if p else "unknown")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.sort_values(by="timestamp", ascending=True)


def analyze_browser_artefacts(history_df: pd.DataFrame, downloads_df: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
    """Generates analytical summaries from browser history and downloads."""
    total_visits = len(history_df)
    unique_domains = history_df["domain"].nunique() if "domain" in history_df else 0

    domain_counts = {}
    if "domain" in history_df and not history_df.empty:
        domain_counts = history_df["domain"].value_counts().head(10).to_dict()

    downloads_count = len(downloads_df) if downloads_df is not None and not downloads_df.empty else 0

    return {
        "total_visits": total_visits,
        "unique_domains": unique_domains,
        "top_domains": domain_counts,
        "downloads_recorded": downloads_count
    }
