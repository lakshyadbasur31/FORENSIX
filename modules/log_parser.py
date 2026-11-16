"""Log parsing module for authentication, network, and security event logs.

Extracts structured events from raw text and log formats using regex patterns.
"""
import re
from pathlib import Path
from typing import List, Dict, Any, Union


# Standard authentication log patterns (e.g., auth.log / secure / syslog)
AUTH_LOG_REGEX = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\.\-]+)(?:\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)

FAILED_LOGIN_REGEX = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE)
ACCEPTED_LOGIN_REGEX = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE)


def parse_auth_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parses a single line of an authentication log."""
    line = line.strip()
    if not line:
        return None

    match = AUTH_LOG_REGEX.match(line)
    if not match:
        # Fallback simplistic timestamp parsing
        parts = line.split(" ", 3)
        if len(parts) >= 4:
            return {
                "timestamp": f"{parts[0]} {parts[1]}",
                "host": parts[2],
                "process": "unknown",
                "message": parts[3],
                "event_type": "GENERIC_LOG",
                "severity": "INFO"
            }
        return None

    data = match.groupdict()
    msg = data["message"]
    
    failed_match = FAILED_LOGIN_REGEX.search(msg)
    if failed_match:
        return {
            "timestamp": data["timestamp"],
            "host": data["host"],
            "process": data["process"],
            "message": msg,
            "event_type": "AUTH_FAILED",
            "actor": failed_match.group("user"),
            "source_ip": failed_match.group("ip"),
            "severity": "WARNING"
        }

    accepted_match = ACCEPTED_LOGIN_REGEX.search(msg)
    if accepted_match:
        return {
            "timestamp": data["timestamp"],
            "host": data["host"],
            "process": data["process"],
            "message": msg,
            "event_type": "AUTH_SUCCESS",
            "actor": accepted_match.group("user"),
            "source_ip": accepted_match.group("ip"),
            "severity": "NOTICE"
        }

    return {
        "timestamp": data["timestamp"],
        "host": data["host"],
        "process": data["process"],
        "message": msg,
        "event_type": "SYSTEM_EVENT",
        "actor": "system",
        "source_ip": None,
        "severity": "INFO"
    }


def parse_auth_log_file(file_path: Union[str, Path]) -> List[Dict[str, Any]]:
    """Parses an entire authentication log file into structured records."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    records = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = parse_auth_log_line(line)
            if parsed:
                records.append(parsed)
    return records
