"""Unit tests for cryptographic hashing and integrity verification."""
import tempfile
from pathlib import Path
from modules.hash_verification import compute_file_hashes, compute_bytes_hash, verify_integrity


def test_compute_bytes_hash():
    data = b"FORENSIX_TEST_STRING"
    # Known SHA-256 for b"FORENSIX_TEST_STRING"
    import hashlib
    expected = hashlib.sha256(data).hexdigest()
    result = compute_bytes_hash(data, "sha256")
    assert result == expected


def test_file_hashes_generation():
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write("Digital Evidence Content for Forensic Unit Test\n")
        tf_path = Path(tf.name)

    try:
        hashes = compute_file_hashes(tf_path)
        assert "sha256" in hashes
        assert "sha1" in hashes
        assert "md5" in hashes
        assert len(hashes["sha256"]) == 64
        assert len(hashes["md5"]) == 32

        # Verify integrity check passes
        verification = verify_integrity(tf_path, hashes["sha256"])
        assert verification["is_valid"] is True
        assert verification["status"] == "INTEGRITY_VERIFIED"

        # Verify tamper detection
        bad_hash = "a" * 64
        bad_verification = verify_integrity(tf_path, bad_hash)
        assert bad_verification["is_valid"] is False
        assert bad_verification["status"] == "INTEGRITY_COMPROMISED"

    finally:
        if tf_path.exists():
            tf_path.unlink()
