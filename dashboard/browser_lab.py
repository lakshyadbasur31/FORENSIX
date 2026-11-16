"""WEBTRACE — Browser History Analysis & Web Activity Reconstruction Dashboard.

Features:
- Import Panel: CSV, JSON, Chromium History, Firefox places.sqlite
- Overview Metrics
- Browsing Timeline with Redacted Sensitive URLs
- Domain Intelligence & Frequency Distributions
- Download Investigation with CHAINLOCK linking
- Explainable Suspicious Activity Panel
- Data Export (CSV & JSON)
"""
import io
import json
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path
from modules.webtrace import (
    ingest_browser_artifact,
    get_webtrace_overview_stats,
    get_webtrace_events,
    get_webtrace_indicators,
    link_download_to_evidence,
    redact_sensitive_url,
    detect_browser_artifact_type
)
from modules.evidence_manager import list_evidence
from config import SAMPLE_EVIDENCE_DIR


def render():
    st.markdown("## 🌐 WEBTRACE — Browser Forensics & Web Activity Reconstruction")
    st.markdown("Forensic browser artifact parser, timeline reconstruction, domain intelligence, and explainable activity analysis.")

    active_inv = st.session_state.get("active_investigation_id")
    if not active_inv:
        st.warning("⚠️ Please select or initialize an active investigation in the Overview tab first.")
        return

    # Navigation Tabs within WEBTRACE
    tab_import, tab_timeline, tab_domains, tab_downloads, tab_indicators, tab_export = st.tabs([
        "📥 Import Artifact",
        "⏱️ Activity Timeline",
        "🌐 Domain Intelligence",
        "💾 Downloads Lab",
        "🚨 Suspicious Activity",
        "📤 Export Dossier"
    ])

    # ==============================================================================
    # TAB 1: IMPORT ARTIFACT
    # ==============================================================================
    with tab_import:
        st.markdown("### 📥 Ingest Browser Forensics Artifact")
        st.markdown(
            "Upload browser history artifacts from user-provided copies. "
            "Supported formats: **CSV exports**, **JSON exports**, **Chromium History** (Chrome/Edge SQLite), "
            "and **Firefox places.sqlite**."
        )

        col_in1, col_in2 = st.columns([3, 2])
        with col_in1:
            uploaded_file = st.file_uploader(
                "Select Browser History or Downloads Artifact",
                type=["csv", "json", "sqlite", "db", ""],
                help="Only upload files explicitly collected as evidence. FORENSIX runs locally and never scans live browser sessions."
            )
        with col_in2:
            browser_override = st.selectbox(
                "Browser Type Override (Optional):",
                ["Auto-Detect", "Google Chrome", "Microsoft Edge", "Mozilla Firefox", "Generic / Other"],
                help="Select if format detection is ambiguous or to enforce a specific browser attribution."
            )

        if uploaded_file is not None:
            # Save uploaded buffer safely to a temp file for inspection
            temp_dir = Path("data/sample_evidence")
            temp_dir.mkdir(parents=True, exist_ok=True)
            temp_artifact = temp_dir / f"upload_{uploaded_file.name}"
            with open(temp_artifact, "wb") as f:
                f.write(uploaded_file.getbuffer())

            try:
                # Preview metadata
                file_size = temp_artifact.stat().st_size
                detected_fmt = detect_browser_artifact_type(temp_artifact)
                from modules.hash_verification import compute_file_hashes
                h = compute_file_hashes(temp_artifact)

                st.markdown("#### 🔍 Artifact Pre-Ingestion Analysis")
                c_p1, c_p2, c_p3 = st.columns(3)
                c_p1.write(f"**Filename:** `{uploaded_file.name}`")
                c_p2.write(f"**Detected Format:** `{detected_fmt}`")
                c_p3.write(f"**Size:** {file_size:,} bytes")
                st.caption(f"**Source SHA-256:** `{h['sha256']}`")

                b_type = None if browser_override == "Auto-Detect" else browser_override

                if st.button("🚀 Parse & Ingest Artifact into Investigation", use_container_width=True):
                    with st.spinner("Parsing records, converting timestamps to UTC, and evaluating indicators..."):
                        ingest_result = ingest_browser_artifact(
                            investigation_id=active_inv,
                            file_path=temp_artifact,
                            browser_type_override=b_type
                        )

                        if ingest_result["status"] == "DUPLICATE_IMPORT":
                            st.warning(f"⚠️ {ingest_result['message']}")
                        else:
                            st.success(
                                f"✅ Ingestion successful! Parsed {ingest_result['valid_records']} valid records "
                                f"({ingest_result['skipped_records']} skipped). "
                                f"Generated {ingest_result['indicator_count']} forensic indicators."
                            )
                            st.rerun()
            except Exception as ex:
                st.error(f"Error inspecting or parsing artifact: {str(ex)}")

        st.markdown("---")
        st.markdown("#### Quick Load Demonstration Datasets")
        c_demo1, c_demo2 = st.columns(2)
        with c_demo1:
            if st.button("📥 Load Simulated Browser History CSV (Nov 16, 2026)", use_container_width=True):
                demo_path = SAMPLE_EVIDENCE_DIR / "browser_history_simulated.csv"
                if demo_path.exists():
                    res = ingest_browser_artifact(active_inv, demo_path, "Google Chrome (Simulated)")
                    st.info(f"Loaded demo history: {res.get('status')}")
                    st.rerun()
        with c_demo2:
            if st.button("📥 Load Simulated Browser Downloads CSV (Nov 16, 2026)", use_container_width=True):
                demo_path = SAMPLE_EVIDENCE_DIR / "browser_downloads_simulated.csv"
                if demo_path.exists():
                    res = ingest_browser_artifact(active_inv, demo_path, "Google Chrome (Simulated)")
                    st.info(f"Loaded demo downloads: {res.get('status')}")
                    st.rerun()

    # ==============================================================================
    # OVERVIEW METRICS BAR
    # ==============================================================================
    stats = get_webtrace_overview_stats(active_inv)
    st.markdown("---")
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total Events", stats["total_events"])
    m2.metric("Unique Hostnames", stats["unique_hostnames"])
    m3.metric("Download Records", stats["total_downloads"])
    m4.metric("Flagged Indicators", stats["flagged_events"], delta_color="inverse")
    m5.metric("Source Artifacts", stats["source_artifacts"])

    # Load events for downstream analysis
    events = get_webtrace_events(active_inv)
    indicators = get_webtrace_indicators(active_inv)

    # ==============================================================================
    # TAB 2: BROWSING TIMELINE
    # ==============================================================================
    with tab_timeline:
        st.markdown("### ⏱️ Chronological Browsing Timeline")
        
        if not events:
            st.info("No browser records available. Ingest an artifact in the Import tab.")
        else:
            f1, f2, f3 = st.columns([2, 2, 1])
            with f1:
                type_filter = st.selectbox("Filter Event Type:", ["ALL", "PAGE_VISIT", "DOWNLOAD"], key="tl_type_filter")
            with f2:
                search_term = st.text_input("🔍 Search Hostname, URL or Title:", placeholder="Search...", key="tl_search")
            with f3:
                redact_toggle = st.checkbox("Redact Credentials & Tokens", value=True, help="Masks passwords, api keys, and bearer tokens in query parameters.")

            filtered_events = get_webtrace_events(active_inv, event_type=type_filter, hostname_search=search_term)

            if filtered_events:
                df_tl = pd.DataFrame(filtered_events)
                if redact_toggle:
                    df_tl["display_url"] = df_tl["url"].apply(redact_sensitive_url)
                else:
                    df_tl["display_url"] = df_tl["url"]

                display_cols = ["timestamp_utc", "browser", "event_type", "hostname", "page_title", "display_url", "visit_count"]
                df_display = df_tl[display_cols].copy()
                df_display.rename(columns={
                    "timestamp_utc": "Timestamp (UTC)",
                    "browser": "Browser",
                    "event_type": "Event Class",
                    "hostname": "Hostname",
                    "page_title": "Page Title",
                    "display_url": "URL",
                    "visit_count": "Visits"
                }, inplace=True)

                st.dataframe(df_display, use_container_width=True, hide_index=True)

                # Expandable Raw Source Record Inspector
                st.markdown("#### 🔬 Detailed Event Provenance Inspector")
                event_options = {e["id"]: f"[{e['timestamp_utc']}] {e['hostname']} - {e['page_title'][:40]}" for e in filtered_events[:100]}
                selected_event_id = st.selectbox("Inspect Event Details:", list(event_options.keys()), format_func=lambda x: event_options[x])
                
                if selected_event_id:
                    target_evt = next(e for e in filtered_events if e["id"] == selected_event_id)
                    e_col1, e_col2 = st.columns(2)
                    with e_col1:
                        st.write(f"- **Event ID:** `{target_evt['id']}`")
                        st.write(f"- **Import ID:** `{target_evt['import_id']}`")
                        st.write(f"- **Source File:** `{target_evt['source_filename']}` (Record #{target_evt['source_record_number']})")
                        st.write(f"- **Timestamp (UTC):** `{target_evt['timestamp_utc']}`")
                        st.write(f"- **Browser:** {target_evt['browser']}")
                    with e_col2:
                        st.write(f"- **Hostname:** `{target_evt['hostname']}`")
                        st.write(f"- **Page Title:** {target_evt['page_title']}")
                        st.write(f"- **Referrer:** `{target_evt['referrer'] or 'None'}`")
                        st.caption("RAW RECORD URL:")
                        st.code(target_evt["url"], language="text")
            else:
                st.warning("No events match the search filter.")

    # ==============================================================================
    # TAB 3: DOMAIN INTELLIGENCE
    # ==============================================================================
    with tab_domains:
        st.markdown("### 🌐 Domain Intelligence & Host Frequency")

        if not events:
            st.info("No browser records available. Ingest an artifact in the Import tab.")
        else:
            df_all = pd.DataFrame(events)
            if not df_all.empty and "hostname" in df_all.columns:
                host_counts = df_all["hostname"].value_counts().reset_index()
                host_counts.columns = ["Hostname", "Visit Count"]

                col_c1, col_c2 = st.columns([3, 2])
                with col_c1:
                    fig = px.bar(
                        host_counts.head(15),
                        x="Hostname",
                        y="Visit Count",
                        title="Top Visited Hostnames",
                        color="Visit Count",
                        color_continuous_scale="Tealgrn",
                        template="plotly_dark"
                    )
                    fig.update_layout(height=340, margin=dict(l=20, r=20, t=40, b=20))
                    st.plotly_chart(fig, use_container_width=True)

                with col_c2:
                    st.markdown("#### Host Activity Ledger")
                    st.dataframe(host_counts, use_container_width=True, hide_index=True)

                st.markdown("---")
                st.markdown("#### Temporal Distribution (Visits by Hour)")
                try:
                    df_all["dt"] = pd.to_datetime(df_all["timestamp_utc"], errors="coerce")
                    df_all["hour"] = df_all["dt"].dt.hour
                    hourly = df_all["hour"].value_counts().sort_index().reset_index()
                    hourly.columns = ["Hour of Day (UTC)", "Requests"]
                    
                    fig_time = px.line(
                        hourly,
                        x="Hour of Day (UTC)",
                        y="Requests",
                        markers=True,
                        title="Activity by Hour of Day",
                        template="plotly_dark"
                    )
                    fig_time.update_layout(height=260, margin=dict(l=20, r=20, t=40, b=20))
                    st.plotly_chart(fig_time, use_container_width=True)
                except Exception:
                    pass

    # ==============================================================================
    # TAB 4: DOWNLOADS LAB
    # ==============================================================================
    with tab_downloads:
        st.markdown("### 💾 Download Investigation & CHAINLOCK Linkage")
        st.markdown(
            "> **Forensic Caution**: A browser download record confirms an HTTP payload transfer was logged by the browser. "
            "It does **not** prove execution, file opening, or that the file has been acquired as verified digital evidence."
        )

        downloads = [e for e in events if e.get("event_type") == "DOWNLOAD"]

        if not downloads:
            st.info("No download records available for this investigation.")
        else:
            df_dl = pd.DataFrame(downloads)
            st.dataframe(
                df_dl[["timestamp_utc", "download_filename", "hostname", "url", "download_path", "linked_evidence_id"]].rename(columns={
                    "timestamp_utc": "Timestamp (UTC)",
                    "download_filename": "Filename",
                    "hostname": "Origin Hostname",
                    "url": "Source URL",
                    "download_path": "Local Download Path",
                    "linked_evidence_id": "Linked CHAINLOCK Evidence"
                }),
                use_container_width=True,
                hide_index=True
            )

            st.markdown("---")
            st.markdown("#### 🔗 Link Download Record to Registered CHAINLOCK Evidence")
            col_l1, col_l2, col_l3 = st.columns(3)

            dl_map = {d["id"]: f"{d['download_filename']} ({d['timestamp_utc']})" for d in downloads}
            with col_l1:
                selected_dl = st.selectbox("Select Download Record:", list(dl_map.keys()), format_func=lambda x: dl_map[x])

            # Fetch active registered evidence for this investigation
            evidence_items = list_evidence(investigation_id=active_inv)
            ev_map = {e["id"]: f"{e['evidence_name']} [{e['id']}]" for e in evidence_items}

            with col_l2:
                if evidence_items:
                    selected_ev = st.selectbox("Link to CHAINLOCK Evidence Item:", list(ev_map.keys()), format_func=lambda x: ev_map[x])
                else:
                    st.info("No CHAINLOCK evidence registered in this investigation.")
                    selected_ev = None

            with col_l3:
                st.write("")
                st.write("")
                if st.button("🔗 Establish Linkage", disabled=selected_ev is None):
                    link_download_to_evidence(selected_dl, selected_ev)
                    st.success(f"Linked download record to evidence `{selected_ev}`!")
                    st.rerun()

    # ==============================================================================
    # TAB 5: SUSPICIOUS ACTIVITY
    # ==============================================================================
    with tab_indicators:
        st.markdown("### 🚨 Explainable Forensic Activity Indicators")
        st.markdown(
            "Rule-based detection identifying noteworthy technical anomalies. "
            "Forensic conclusions require corroboration; indicators highlight patterns for investigator evaluation."
        )

        if not indicators:
            st.info("✓ No forensic indicators detected for the currently imported browser activity.")
        else:
            # Group indicators by severity
            high_count = sum(1 for i in indicators if i["severity"] == "HIGH")
            med_count = sum(1 for i in indicators if i["severity"] == "MEDIUM")
            low_count = sum(1 for i in indicators if i["severity"] == "LOW")

            ci1, ci2, ci3 = st.columns(3)
            ci1.metric("HIGH Severity", high_count)
            ci2.metric("MEDIUM Severity", med_count)
            ci3.metric("LOW Severity", low_count)

            st.markdown("---")
            for ind in indicators:
                color = "🔴" if ind["severity"] == "HIGH" else ("🟠" if ind["severity"] == "MEDIUM" else "🔵")
                with st.expander(f"{color} [{ind['severity']}] {ind['indicator_name']}: {ind['observed_value']}"):
                    st.markdown(f"**Observed Fact / Value:** `{ind['observed_value']}`")
                    st.markdown(f"**Description:** {ind['description']}")
                    st.markdown(f"**Forensic Context & Reason:** {ind['reason']}")
                    st.markdown(f"**Timestamp (UTC):** `{ind['timestamp_utc']}`")
                    st.markdown(f"**Source Provenance:** `{ind['source_record']}`")

    # ==============================================================================
    # TAB 6: EXPORT DOSSIER
    # ==============================================================================
    with tab_export:
        st.markdown("### 📤 Export Forensic Artifact Dossier")
        st.markdown("Export normalized records and explainable indicator findings for reporting or external review.")

        if not events:
            st.info("No browser events available to export.")
        else:
            col_ex1, col_ex2 = st.columns(2)
            with col_ex1:
                st.markdown("#### Normalized Event Ledger (CSV)")
                df_export = pd.DataFrame(events)
                csv_bytes = df_export.to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📊 Download Normalized Events (.csv)",
                    data=csv_bytes,
                    file_name=f"WEBTRACE_Normalized_Events_{active_inv}.csv",
                    mime="text/csv",
                    use_container_width=True
                )

            with col_ex2:
                st.markdown("#### Investigation Summary (JSON)")
                summary_payload = {
                    "module": "WEBTRACE",
                    "platform": "FORENSIX v1.0",
                    "investigation_id": active_inv,
                    "overview_metrics": stats,
                    "indicators": indicators,
                    "event_count": len(events)
                }
                json_bytes = json.dumps(summary_payload, indent=2).encode("utf-8")
                st.download_button(
                    label="📑 Download Investigation Summary (.json)",
                    data=json_bytes,
                    file_name=f"WEBTRACE_Summary_{active_inv}.json",
                    mime="application/json",
                    use_container_width=True
                )
