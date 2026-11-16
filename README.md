# FORENSIX

> **Preserve. Investigate. Reconstruct.**
> Integrated Digital Forensics, Evidence Integrity & Cyber Incident Reconstruction Platform.

---

## 1. Overview

**FORENSIX** is an integrated, local digital forensics and incident investigation platform designed to ingest digital artifacts, verify cryptographic integrity, inspect browser forensics, track tamper-evident chains of custody, correlate cross-module telemetry, prioritize threats explainably, and chronologically reconstruct multi-stage cyber incidents.

All processing runs **100% locally**. No third-party cloud APIs, external telemetry, proprietary model dependencies, or external paid services are required.

---

## 2. Architecture & Modules

```
FORENSIX/
│
├── app.py                     # Main Streamlit application shell & multi-workspace routing
├── config.py                  # Global path configuration & system settings
├── requirements.txt           # Python dependency specifications
│
├── modules/                   # Core business & forensic logic (No UI code)
│   ├── hash_verification.py   # Streaming SHA-256/SHA-1/MD5 calculation & integrity checks
│   ├── evidence_manager.py    # Evidence ingestion, vault isolation, status audits
│   ├── chain_of_custody.py    # Hash-linked verifiable custody audit trails & migration
│   ├── webtrace.py            # SQLite/CSV/JSON browser history parsing & indicator heuristics
│   ├── tracefusion.py         # Cross-module correlation engine & unified timeline ledger
│   ├── sentinel.py            # Explainable rule-based risk prioritization (0–100 scale)
│   ├── recon_x.py             # Incident reconstruction, milestone intervals & 15-section dossier
│   ├── log_parser.py          # SSH/auth.log parsing & regex tokenization
│   ├── event_normalizer.py    # Unifies heterogeneous artifacts into a standard schema
│   ├── event_correlator.py    # Attack stage correlation & brute force detection
│   └── incident_reconstruction.py # Database ledger & chronological event reconstruction
│
├── database/                  # SQLite persistence tier
│   ├── db.py                  # Thread-safe connections & parameterized query runners
│   └── schema.sql             # Relational DDL (investigations, evidence, custody, events, webtrace)
│
├── dashboard/                 # Streamlit presentation views
│   ├── overview.py            # Case overview, stats, case selector & demo loader
│   ├── evidence_vault.py      # CHAINLOCK: Evidence registration, verification & custody
│   ├── browser_lab.py         # WEBTRACE: History parsing, downloads & forensic indicators
│   ├── tracefusion_view.py    # TRACEFUSION: Correlation matrix & unified forensic ledger
│   ├── sentinel_view.py       # SENTINEL: Risk gauge, observation breakdown & action matrix
│   ├── recon_x_view.py        # RECON-X: Milestone interval analysis & interactive dossier preview
│   ├── incident_timeline.py   # Activity timeline (Legacy)
│   └── investigation_report.py# Investigation report (Legacy)
│
├── data/
│   ├── sample_evidence/       # Controlled simulated demonstration datasets
│   └── vault_storage/         # Read-only isolated evidence working copies
│
├── reports/                   # Saved examination reports & generated dossiers
└── tests/                     # Automated unit testing suite (38 passing tests)
    ├── test_hashing.py        # Cryptographic hashing & tamper-detection tests
    ├── test_database.py       # SQLite schema, ingestion, and custody tests
    ├── test_chainlock.py      # CHAINLOCK registration, verification, tampering & custody chain
    ├── test_webtrace.py       # WEBTRACE Chrome/Firefox parsing, redaction, indicators & exports
    ├── test_tracefusion.py    # TRACEFUSION UTC normalization, direct/hash/temporal correlations
    ├── test_sentinel.py       # SENTINEL deterministic risk scoring, deduplication & capping
    └── test_recon_x.py        # RECON-X stage detection, milestone intervals, Plotly & dossier
```

---

## 3. Forensic Capability Breakdown

### Module 1: CHAINLOCK (Evidence Integrity & Cryptographic Custody)
- **Multi-Format Ingestion:** Ingests TXT, CSV, JSON, PDF, PNG, JPG, ZIP, LOG, DOCX, and raw binaries into segregated vault storage.
- **Cryptographic Fingerprinting:** Computes streaming SHA-256, SHA-1, and MD5 digests.
- **Tamper-Evident Chain of Custody:** Maintains a hash-linked block chain (`current_event_hash = SHA256(event_id + previous_hash + action + timestamp + actor + details)`) with legacy chain reconciliation bridges.
- **Live Integrity Audits:** Detects modified, missing, or altered files with zero-byte protection and path-traversal prevention.

### Module 2: WEBTRACE (Browser History & Download Analytics)
- **Artifact Ingestion:** Parses Chrome/Chromium (`history.db`) and Firefox (`places.sqlite`) databases, as well as CSV and JSON browser extracts.
- **Timestamp Normalization:** Converts WebKit (microseconds since 1601) and PRTime (microseconds since 1970) epochs into standardized UTC datetime records.
- **URL Parameter Redaction:** Automatically sanitizes sensitive URL query parameters (e.g., `token`, `auth`, `password`, `session`, `apikey`, `secret`).
- **Forensic Heuristics:** Detects suspicious downloads (`.exe`, `.bat`, `.ps1`, `.zip`), direct-IP connections with non-standard ports, repetitive request bursts, and data exfiltration markers.

### Module 3: TRACEFUSION (Cross-Module Forensic Correlation)
- **Normalized Event Model:** Normalizes disparate records across `custody_events`, `evidence`, `webtrace_events`, and `forensic_events` into a unified timeline schema with microsecond UTC sorting.
- **Correlation Rules:**
  - `DIRECT_LINK`: Foreign key links between browser downloads and registered evidence files.
  - `HASH_MATCH`: Identical SHA-256 hashes linking custody events and disk artifacts.
  - `FILENAME_MATCH`: Matching downloaded filenames and registered evidence.
  - `COMBINED_CORRELATION`: Mutual validation by both filename and SHA-256 hash.
  - `HOST_MATCH`: Correlation between network login IPs and browser destination hostnames.
  - `TEMPORAL_PROXIMITY`: Identifies telemetry events clustered within a 15-minute causal window.

### Module 4: SENTINEL (Explainable Threat Prioritization)
- **Deterministic 0–100 Scoring Model:** Strictly rule-based, deterministic scoring without black-box ML or simulated hallucinated scores.
  - `+30`: Cryptographic evidence integrity mismatch (proven disk tampering).
  - `+25`: Correlated web download directly linked to registered disk evidence.
  - `+20`: Executable / archive payload downloaded from external web origin.
  - `+15`: High-frequency authentication failure cluster (brute force pattern).
  - `+10`: Direct-IP access over non-standard services / high ports.
- **Score Deduplication & Ceiling:** Deduplicates observation instances to prevent artificial inflation and hard-caps scores at 100.
- **Prioritization Tiers:** Categorized into `LOW` (0–29), `MEDIUM` (30–59), `HIGH` (60–79), and `CRITICAL` (80–100).
- **Explainable Findings:** Every risk contributor details the exact forensic observation, timestamp, artifact reference, and prioritized mitigation action.

### Module 5: RECON-X (Incident Reconstruction & Forensic Reporting)
- **Attack Phase Grouping:** Classifies telemetry into standard DFIR phases: *Initial Reconnaissance / Probing*, *Authentication & Access*, *Web Navigation & Payload Acquisition*, *Evidence Ingestion & System Modifications*, and *Persistence / Execution*.
- **Milestone Interval Analysis:** Calculates exact human-readable elapsed durations between sequential incident milestones (e.g., Recon to Ingestion duration).
- **Interactive Plotly Timeline:** Color-coded multi-lane visualization mapping events by source module and chronological order.
- **15-Section Forensic Dossier:** Compiles a comprehensive investigation report complying with strict DFIR standards (Executive Summary, Evidence Manifest, Cryptographic Ledger, Threat Prioritization, Interval Analysis, Correlation Matrix, and Formal Limitations).
- **Multi-Format Export:** Generates Markdown reports, structured JSON exports, CSV chronological ledgers, and standalone printable HTML documents ready for PDF generation.

---

## 4. Quick Start & Execution

### 1. Environment Setup
```bash
# Activate existing virtual environment or create a new one
python -m venv venv
.\venv\Scripts\activate   # On Windows
source venv/bin/activate  # On Linux/macOS

pip install -r requirements.txt
```

### 2. Run Comprehensive Test Suite
```bash
python -m pytest tests/ -v
```
*(All 38 automated unit tests pass across all six project phases).*

### 3. Launch Streamlit Forensic Application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 5. Demonstration Scenario & Workflow

1. Navigate to **`🔎 Investigation Overview`** and verify active case `CAS-2026-DEMO` (or click *Load Realistic Demonstration Data*).
2. Open **`🔒 Evidence Vault & Integrity (CHAINLOCK)`** to view registered evidence items, run live SHA-256 integrity verifications, and audit the hash-linked custody chain.
3. Switch to **`🌐 Browser Forensics (WEBTRACE)`** to ingest browser databases or inspect parsed HTTP events, domain distributions, and security flags.
4. Open **`🧬 Forensic Correlation (TRACEFUSION)`** to view cross-module correlation linkages between browser downloads and evidence files, accompanied by the unified chronological ledger.
5. Access **`🛡️ Threat Prioritization (SENTINEL)`** to evaluate the explainable 0–100 risk score, observation breakdown, and prioritized investigator actions.
6. Launch **`🧭 Incident Reconstruction (RECON-X)`** to analyze the attack progression milestones, inspect the multi-lane Plotly timeline, and export the comprehensive 15-section forensic dossier in Markdown, JSON, CSV, or Printable HTML.

---

## 6. Forensic Disclaimers & Evidentiary Boundaries

FORENSIX provides forensic assistance and local integrity verification using standard cryptographic hashing (SHA-256) and deterministic correlation algorithms. 
- Distinctions are strictly maintained between **Observed Facts** (verifiable database logs and cryptographic hashes), **Indicators** (heuristic patterns), **Correlations** (deterministic rule-based linkages), and **Investigator Hypotheses**.
- Forensic indicators do not constitute definitive proof of legal maliciousness or intent; all findings require verification and contextual analysis by a certified forensic examiner.
- Ingested files and logs are verified against baseline digests stored in the local SQLite repository.
