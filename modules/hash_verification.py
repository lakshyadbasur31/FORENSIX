"""Cryptographic hashing and integrity verification module.

Computes SHA-256, SHA-1, and MD5 hashes using chunked streaming to handle
files of arbitrary sizes without exhausting system memory.
"""
import hashlib
from pathlib import Path
from typing import Dict, Union, Optional


def compute_file_hashes(file_path: Union[str, Path], chunk_size: int = 65536) -> Dict[str, str]:
    """Computes SHA-256, SHA-1, and MD5 for the target file via streaming chunks.
    
    Args:
        file_path: Path to the target file.
        chunk_size: Size in bytes for buffered reads (default 64KB).
        
    Returns:
        Dictionary containing lowercase hex digests for 'sha256', 'sha1', 'md5'.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Target evidence file does not exist: {file_path}")

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest()
    }


def compute_bytes_hash(data: bytes, algorithm: str = "sha256") -> str:
    """Computes a cryptographic hash for raw byte streams."""
    hasher = getattr(hashlib, algorithm.lower(), None)
    if not hasher:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    h = hasher()
    h.update(data)
    return h.hexdigest()


def verify_integrity(file_path: Union[str, Path], expected_sha256: str) -> Dict[str, Union[bool, str]]:
    """Verifies whether the current file hash matches the stored baseline hash.
    
    Args:
        file_path: Path to the file to check.
        expected_sha256: Baseline expected SHA-256 hex digest.
        
    Returns:
        Dict with 'is_valid', 'current_sha256', 'expected_sha256', and status note.
    """
    computed = compute_file_hashes(file_path)
    current_sha256 = computed["sha256"]
    is_valid = current_sha256.lower() == expected_sha256.strip().lower()

    return {
        "is_valid": is_valid,
        "current_sha256": current_sha256,
        "expected_sha256": expected_sha256.strip().lower(),
        "status": "INTEGRITY_VERIFIED" if is_valid else "INTEGRITY_COMPROMISED"
    }
