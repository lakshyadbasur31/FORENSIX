# FORENSIX

> **Preserve. Investigate. Reconstruct.**

**FORENSIX** is an integrated local digital forensics and cyber incident reconstruction platform designed to preserve digital evidence, verify cryptographic integrity, analyze browser artifacts, correlate forensic telemetry, prioritize threats, and reconstruct multi-stage security incidents.

The platform follows a complete forensic workflow:

**Evidence → Integrity → Artifact Analysis → Correlation → Threat Prioritization → Incident Reconstruction**

---

## Overview

FORENSIX brings multiple digital forensic capabilities together into a single Streamlit-based investigation platform.

It is designed around six major phases:

| Phase | Module | Purpose |
|---|---|---|
| 1 | **Foundation** | Investigation management and forensic data infrastructure |
| 2 | **CHAINLOCK** | Evidence integrity and tamper-evident chain of custody |
| 3 | **WEBTRACE** | Browser history, downloads, and forensic artifact analysis |
| 4 | **TRACEFUSION** | Cross-module forensic correlation |
| 5 | **SENTINEL** | Explainable threat scoring and investigator prioritization |
| 6 | **RECON-X** | Incident reconstruction and forensic reporting |

All forensic processing is performed **locally** using Python, SQLite, and deterministic analysis logic. The system does not require external cloud APIs, paid services, or black-box AI models.

---

## Architecture

```text
FORENSIX/
│
├── app.py
├── config.py
├── requirements.txt
│
├── modules/
│   ├── hash_verification.py
│   ├── evidence_manager.py
│   ├── chain_of_custody.py
│   ├── webtrace.py
│   ├── tracefusion.py
│   ├── sentinel.py
│   ├── recon_x.py
│   ├── log_parser.py
│   ├── event_normalizer.py
│   ├── event_correlator.py
│   └── incident_reconstruction.py
│
├── database/
│   ├── db.py
│   └── schema.sql
│
├── dashboard/
│   ├── overview.py
│   ├── evidence_vault.py
│   ├── browser_lab.py
│   ├── tracefusion_view.py
│   ├── sentinel_view.py
│   ├── recon_x_view.py
│   ├── incident_timeline.py
│   └── investigation_report.py
│
├── data/
│   └── sample_evidence/
│
└── tests/
    ├── test_hashing.py
    ├── test_database.py
    ├── test_chainlock.py
    ├── test_webtrace.py
    ├── test_tracefusion.py
    ├── test_sentinel.py
    └── test_recon_x.py
```

Generated runtime artifacts such as the local SQLite database, evidence vault, Python cache, and environment secrets are intentionally excluded from version control.

---

# Forensic Capabilities

## 1. CHAINLOCK — Evidence Integrity & Cryptographic Custody

CHAINLOCK provides the evidence preservation and integrity layer of FORENSIX.

### Capabilities

- Multi-format evidence ingestion
- Segregated local evidence storage
- Streaming **SHA-256, SHA-1, and MD5** hashing
- Evidence registration and metadata tracking
- Live integrity verification
- Tamper detection
- Missing/modified evidence detection
- Path traversal protection
- Hash-linked chain-of-custody records
- Custody chain verification and reconciliation

The chain-of-custody mechanism links forensic actions using cryptographic hashes, providing an auditable sequence of evidence handling events.

---

## 2. WEBTRACE — Browser Forensics

WEBTRACE analyzes browser artifacts and extracts forensic indicators from browsing activity.

### Supported artifacts

- Chrome / Chromium history databases
- Firefox `places.sqlite`
- CSV browser exports
- JSON browser exports
- Download records

### Analysis capabilities

- Browser history parsing
- Download tracking
- Timestamp normalization
- Suspicious URL detection
- Suspicious download detection
- Direct-IP connection detection
- Request burst analysis
- Potential data-exfiltration indicators
- Sensitive URL parameter redaction

Browser timestamps from different formats and epochs are normalized into a common UTC representation for downstream correlation.

---

## 3. TRACEFUSION — Cross-Module Forensic Correlation

TRACEFUSION connects evidence from otherwise separate forensic modules into a unified investigation timeline.

### Normalized event model

Events from sources such as:

- Evidence records
- Chain-of-custody events
- Browser activity
- Forensic events
- Authentication logs

are normalized into a common forensic event structure.

### Correlation rules

**DIRECT_LINK**  
Connects browser downloads directly associated with registered evidence.

**HASH_MATCH**  
Correlates artifacts sharing the same SHA-256 hash.

**FILENAME_MATCH**  
Correlates matching filenames across forensic sources.

**COMBINED_CORRELATION**  
Provides stronger correlation when filename and SHA-256 evidence agree.

**HOST_MATCH**  
Correlates authentication/network activity with browser destination hosts.

**TEMPORAL_PROXIMITY**  
Identifies events occurring within a defined 15-minute causal proximity window.

The result is a unified chronological forensic ledger with correlation confidence and rationale.

---

## 4. SENTINEL — Explainable Threat Prioritization

SENTINEL converts forensic observations into a deterministic **0–100 risk score**.

It deliberately uses transparent rule-based scoring rather than black-box machine learning.

### Risk scoring

| Observation | Score |
|---|---:|
| Cryptographic evidence integrity mismatch | +30 |
| Correlated web download linked to registered evidence | +25 |
| Executable/archive payload from external origin | +20 |
| High-frequency authentication failure pattern | +15 |
| Direct-IP access over non-standard/high ports | +10 |

Scores are deduplicated and capped at 100.

### Risk levels

| Score | Risk |
|---:|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

Every finding includes an explanation of the contributing forensic observation and a prioritized investigator action.

---

## 5. RECON-X — Incident Reconstruction

RECON-X transforms correlated forensic events into a chronological incident narrative.

### Incident stages

1. **Initial Reconnaissance / Probing**
2. **Authentication & Access**
3. **Web Navigation & Payload Acquisition**
4. **Evidence Ingestion & System Modifications**
5. **Persistence / Execution**

### Capabilities

- Incident stage classification
- Chronological event reconstruction
- Milestone interval analysis
- Elapsed-time calculation
- Multi-lane Plotly timeline
- Cross-module event visualization
- Correlation matrix integration
- Threat prioritization integration
- Comprehensive forensic dossier generation

RECON-X maintains a strict distinction between:

**Facts → Indicators → Correlations → Hypotheses**

This prevents forensic observations from being presented as unsupported conclusions.

---

# End-to-End Investigation Workflow

```text
                    ┌─────────────────┐
                    │   Investigation │
                    │    Foundation   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    CHAINLOCK    │
                    │ Evidence + Hash │
                    │   + Custody     │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    WEBTRACE     │
                    │ Browser Artifacts│
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   TRACEFUSION   │
                    │  Correlation    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    SENTINEL     │
                    │ Threat Scoring  │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     RECON-X     │
                    │ Reconstruction  │
                    │  + Reporting   │
                    └─────────────────┘
```

---

# Technology Stack

- **Python**
- **Streamlit**
- **SQLite**
- **Pandas**
- **Plotly**
- **Pytest**
- Standard Python cryptographic hashing utilities
- Deterministic forensic correlation and scoring algorithms

---

# Testing & Validation

FORENSIX includes an automated test suite covering the complete forensic pipeline.

### Validation result

**38 tests passed — 100% pass rate**

The test suite covers:

- Cryptographic hashing
- Evidence registration
- Evidence integrity verification
- Chain-of-custody validation
- Browser artifact parsing
- Timestamp normalization
- URL redaction
- Forensic indicator detection
- Cross-module correlation
- Temporal correlation
- Threat scoring
- Risk deduplication
- Incident stage detection
- Milestone interval analysis
- RECON-X dossier generation
- Multi-format report exports
- Empty-case handling
- End-to-end investigation workflow

### End-to-end validation

```text
Investigation
     ↓
CHAINLOCK
     ↓
WEBTRACE
     ↓
TRACEFUSION
     ↓
SENTINEL
     ↓
RECON-X
     ↓
Markdown / JSON / CSV / HTML
```

---

# Quick Start

## 1. Clone the repository

```bash
git clone https://github.com/<YOUR_USERNAME>/FORENSIX.git
cd FORENSIX
```

## 2. Create a virtual environment

### Windows

```powershell
python -m venv venv
.\venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

## 4. Run the test suite

```bash
python -m pytest tests/ -v
```

Expected result:

```text
38 passed
```

## 5. Launch FORENSIX

```bash
streamlit run app.py
```

Then open:

```text
http://localhost:8501
```

---

# Demonstration Workflow

FORENSIX includes controlled simulated evidence for demonstrating the complete investigation pipeline.

A typical demonstration can follow this workflow:

1. Open **Investigation Overview**.
2. Load the demonstration investigation.
3. Open **Evidence Vault & Integrity (CHAINLOCK)**.
4. Verify evidence hashes and inspect the custody chain.
5. Open **Browser Forensics (WEBTRACE)**.
6. Inspect browser history, downloads, timestamps, and forensic indicators.
7. Open **Forensic Correlation (TRACEFUSION)**.
8. Examine relationships between browser events and registered evidence.
9. Open **Threat Prioritization (SENTINEL)**.
10. Review the deterministic risk score and investigator actions.
11. Open **Incident Reconstruction (RECON-X)**.
12. Review the reconstructed incident timeline and milestone intervals.
13. Export the investigation dossier as Markdown, JSON, CSV, or printable HTML.

---

# Forensic Boundaries

FORENSIX is an investigative assistance platform and does not replace professional forensic examination.

The system distinguishes between:

- **Observed Facts** — directly verifiable forensic records
- **Indicators** — heuristic or suspicious patterns
- **Correlations** — deterministic relationships between artifacts
- **Hypotheses** — investigator interpretations requiring additional validation

A forensic indicator or correlation should not automatically be interpreted as proof of malicious intent or legal culpability.

All findings should be independently verified and interpreted within the appropriate investigative and legal context.

---

# Security & Privacy

FORENSIX is designed for local forensic analysis.

- No external telemetry is required.
- No cloud forensic storage is required.
- No paid API is required.
- Sensitive configuration files are excluded through `.gitignore`.
- Generated evidence vault contents are excluded from version control.
- The local SQLite database is excluded from version control.
- Python cache and runtime artifacts are excluded from version control.

---

# Future Scope

Potential extensions include:

- Additional browser artifact parsers
- Windows Event Log integration
- Linux system log ingestion
- Network packet analysis
- Malware triage integration
- YARA-based artifact scanning
- Pluggable threat-intelligence feeds
- Case-to-case forensic comparison
- Advanced evidence visualization
- Signed forensic report packages

---

## Project Status

**Status: Fully Implemented, Tested & Demo Ready**

**38 automated tests passed — 100% pass rate**

**FORENSIX**

> **Preserve. Investigate. Reconstruct.**