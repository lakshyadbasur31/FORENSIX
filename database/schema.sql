-- Schema for FORENSIX Digital Forensics Platform
-- SQLite dialect with strict relationships and metadata integrity

CREATE TABLE IF NOT EXISTS investigations (
    id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    lead_investigator TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    evidence_name TEXT NOT NULL,
    source_path TEXT NOT NULL,
    vault_path TEXT,
    file_size_bytes INTEGER NOT NULL,
    file_type TEXT,
    mime_type TEXT,
    sha256 TEXT NOT NULL,
    md5 TEXT,
    sha1 TEXT,
    acquired_by TEXT NOT NULL,
    acquisition_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    integrity_status TEXT DEFAULT 'VERIFIED',
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS custody_events (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    performed_by TEXT NOT NULL,
    notes TEXT,
    verified_hash TEXT,
    previous_event_hash TEXT,
    current_event_hash TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS forensic_events (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    event_type TEXT NOT NULL,
    source TEXT NOT NULL,
    actor TEXT,
    description TEXT NOT NULL,
    raw_record TEXT,
    severity TEXT DEFAULT 'INFO',
    is_simulated INTEGER DEFAULT 0,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

-- WEBTRACE Module Persistence Tables
CREATE TABLE IF NOT EXISTS webtrace_imports (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    source_filename TEXT NOT NULL,
    browser_type TEXT NOT NULL,
    format_type TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    import_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total_records INTEGER DEFAULT 0,
    valid_records INTEGER DEFAULT 0,
    skipped_records INTEGER DEFAULT 0,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webtrace_events (
    id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    browser TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    url TEXT,
    hostname TEXT,
    page_title TEXT,
    visit_count INTEGER DEFAULT 1,
    referrer TEXT,
    download_filename TEXT,
    download_path TEXT,
    source_filename TEXT,
    source_record_number INTEGER,
    linked_evidence_id TEXT,
    FOREIGN KEY (import_id) REFERENCES webtrace_imports(id) ON DELETE CASCADE,
    FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS webtrace_indicators (
    id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL,
    event_id TEXT,
    indicator_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    observed_value TEXT,
    description TEXT,
    reason TEXT,
    timestamp_utc TEXT,
    source_record TEXT,
    FOREIGN KEY (import_id) REFERENCES webtrace_imports(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES webtrace_events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence(investigation_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id);
CREATE INDEX IF NOT EXISTS idx_custody_timestamp ON custody_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_investigation ON forensic_events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON forensic_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_webtrace_imports_inv ON webtrace_imports(investigation_id);
CREATE INDEX IF NOT EXISTS idx_webtrace_events_imp ON webtrace_events(import_id);
CREATE INDEX IF NOT EXISTS idx_webtrace_events_inv ON webtrace_events(investigation_id);
CREATE INDEX IF NOT EXISTS idx_webtrace_events_ts ON webtrace_events(timestamp_utc);
CREATE INDEX IF NOT EXISTS idx_webtrace_indicators_imp ON webtrace_indicators(import_id);
