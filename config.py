"""Configuration constants and paths for the FORENSIX platform."""
import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SAMPLE_EVIDENCE_DIR = DATA_DIR / "sample_evidence"
VAULT_STORAGE_DIR = DATA_DIR / "vault_storage"
REPORTS_DIR = BASE_DIR / "reports"
DATABASE_DIR = BASE_DIR / "database"

# Database file path
DB_PATH = DATABASE_DIR / "forensix.db"
SCHEMA_PATH = DATABASE_DIR / "schema.sql"

# Application metadata
APP_TITLE = "FORENSIX"
APP_SUBTITLE = "Integrated Digital Forensics, Evidence Integrity & Incident Reconstruction Platform"
TAGLINE = "Preserve. Investigate. Reconstruct."
VERSION = "1.0.0-phase1"

# Hash algorithms supported
SUPPORTED_HASH_ALGORITHMS = ["sha256", "sha1", "md5"]

# Ensure key directories exist
for path in [DATA_DIR, SAMPLE_EVIDENCE_DIR, VAULT_STORAGE_DIR, REPORTS_DIR, DATABASE_DIR]:
    path.mkdir(parents=True, exist_ok=True)
