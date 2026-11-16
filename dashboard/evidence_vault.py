"""Evidence Vault dashboard page for FORENSIX (CHAINLOCK Interface).

Provides comprehensive digital evidence registration, real-time SHA-256 integrity audits,
tamper detection, and cryptographic hash-chain custody verification.
"""
import streamlit as st
import pandas as pd
from pathlib import Path
from modules.evidence_manager import (
    register_evidence,
    list_evidence,
    verify_evidence_integrity,
    get_vault_statistics,
    ALLOWED_EXTENSIONS
)
from modules.chain_of_custody import (
    get_custody_history,
    verify_custody_chain,
    record_custody_event,
    migrate_legacy_custody_events
)
from config import VAULT_STORAGE_DIR


def format_bytes(bytes_count: int) -> str:
    """Formats bytes into human readable string."""
    if not bytes_count or bytes_count <= 0:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}" if unit != "B" else f"{bytes_count} B"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def render():
    st.markdown("## 🔒 Digital Evidence Vault & CHAINLOCK")
    st.markdown("Forensically ingest digital artefacts, calculate SHA-256 fingerprints, verify integrity, and inspect tamper-evident custody chains.")

    active_inv = st.session_state.get("active_investigation_id")
    if not active_inv:
        st.warning("⚠️ Please select or initialize an active investigation in the Overview tab first.")
        return

    # Real Metrics Bar (No hardcoded figures)
    stats = get_vault_statistics(investigation_id=active_inv)
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Registered Evidence", stats["total_items"])
    m2.metric("Storage Footprint", format_bytes(stats["total_bytes"]))
    m3.metric("Verified (Match)", stats["verified_count"])
    m4.metric("Mismatches (Alert)", stats["mismatch_count"], delta_color="inverse")
    m5.metric("Missing Files", stats["missing_count"], delta_color="inverse")

    st.markdown("---")

    # Evidence Registration Section
    with st.expander("📥 Ingest New Digital Evidence Artifact (CHAINLOCK Registration)", expanded=False):
        uploaded_file = st.file_uploader(
            "Select evidence file to ingest into vault",
            type=[ext.lstrip(".") for ext in ALLOWED_EXTENSIONS],
            help="Supported: TXT, CSV, JSON, PDF, PNG, JPG/JPEG, ZIP, LOG, DOCX. Original file will never be modified."
        )
        c1, c2 = st.columns(2)
        with c1:
            acquired_by = st.text_input("Acquiring Investigator / Examiner *", value="Lead Examiner", key="reg_acquired_by")
        with c2:
            custom_name = st.text_input("Evidence Display Label (optional)", placeholder="e.g., extracted_firmware_dump.bin", key="reg_name")
        ev_desc = st.text_area("Acquisition Context & Provenance", placeholder="Source device, serial number, physical seizure notes...", key="reg_desc")

        if st.button("🔐 Ingest & Calculate Cryptographic Fingerprint", disabled=uploaded_file is None):
            if uploaded_file is not None:
                # Safely save uploaded buffer to temporary holding location before vault isolation
                temp_holding_dir = Path("data/sample_evidence")
                temp_holding_dir.mkdir(parents=True, exist_ok=True)
                temp_holding_file = temp_holding_dir / f"upload_{uploaded_file.name}"
                with open(temp_holding_file, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                try:
                    result = register_evidence(
                        investigation_id=active_inv,
                        source_path=str(temp_holding_file),
                        acquired_by=acquired_by.strip() or "Examiner",
                        evidence_name=custom_name.strip() or uploaded_file.name,
                        description=ev_desc.strip()
                    )
                    st.success(f"✅ Evidence secured into vault! Assigned ID: `{result['id']}`")
                    st.write(f"- **Filename:** `{result['original_filename']}` ({format_bytes(result['file_size_bytes'])})")
                    st.write(f"- **MIME Type:** `{result['mime_type']}`")
                    st.write(f"- **Baseline SHA-256:** `{result['sha256']}`")
                    st.rerun()
                except Exception as e:
                    st.error(f"Registration failure: {str(e)}")
                finally:
                    if temp_holding_file.exists():
                        try:
                            temp_holding_file.unlink()
                        except Exception:
                            pass

    # Fetch evidence records for current case
    evidence_list = list_evidence(investigation_id=active_inv)

    if not evidence_list:
        st.info("ℹ️ No digital evidence registered for this investigation yet. Ingest an evidence file above or load the demonstration scenario from the Overview page.")
        return

    # Search & Filtering
    st.markdown("### 📋 Evidence Repository Ledger")
    search_col1, search_col2 = st.columns([3, 1])
    with search_col1:
        search_query = st.text_input("🔍 Search by Artifact Name, ID, or SHA-256:", placeholder="Type to filter...").strip().lower()
    with search_col2:
        status_filter = st.selectbox("Status Filter:", ["ALL", "MATCH / VERIFIED", "MISMATCH", "MISSING"])

    filtered_list = []
    for item in evidence_list:
        # Search query matching
        match_query = (
            not search_query or
            search_query in item["id"].lower() or
            search_query in item["evidence_name"].lower() or
            search_query in item["sha256"].lower()
        )
        # Status matching
        status = item.get("integrity_status", "VERIFIED")
        if status_filter == "MATCH / VERIFIED":
            match_status = status in ("MATCH", "VERIFIED")
        elif status_filter == "MISMATCH":
            match_status = status in ("MISMATCH", "TAMPERED_OR_CORRUPT")
        elif status_filter == "MISSING":
            match_status = status == "MISSING"
        else:
            match_status = True

        if match_query and match_status:
            filtered_list.append(item)

    if filtered_list:
        ev_df = pd.DataFrame(filtered_list)
        ev_df["size_formatted"] = ev_df["file_size_bytes"].apply(format_bytes)
        display_df = ev_df[["id", "evidence_name", "size_formatted", "file_type", "mime_type", "sha256", "integrity_status", "acquired_by", "acquisition_date"]].copy()
        display_df.rename(columns={
            "id": "Evidence ID",
            "evidence_name": "Artifact Name",
            "size_formatted": "File Size",
            "file_type": "Ext",
            "mime_type": "MIME Type",
            "sha256": "Baseline SHA-256",
            "integrity_status": "Integrity State",
            "acquired_by": "Acquired By",
            "acquisition_date": "Timestamp (UTC)"
        }, inplace=True)
        st.dataframe(display_df, use_container_width=True, hide_index=True)
    else:
        st.warning("No evidence records match the current filter criteria.")

    st.markdown("---")

    # Item Detailed View & Verification Action
    st.markdown("### 🛡️ Evidence Audit & Integrity Verification")
    ev_options = {row["id"]: f"{row['evidence_name']} [{row['id']}]" for row in evidence_list}
    selected_ev = st.selectbox(
        "Select Evidence Artifact to Inspect:",
        options=list(ev_options.keys()),
        format_func=lambda x: ev_options[x],
        key="selected_evidence_dropdown"
    )

    if selected_ev:
        item = next(e for e in evidence_list if e["id"] == selected_ev)

        d1, d2 = st.columns([3, 2])
        with d1:
            st.markdown(f"#### Artifact: `{item['evidence_name']}`")
            st.write(f"- **Evidence ID:** `{item['id']}`")
            st.write(f"- **MIME Type:** `{item.get('mime_type') or 'N/A'}` | **Size:** {format_bytes(item['file_size_bytes'])}")
            st.write(f"- **Acquired By:** {item['acquired_by']} on `{item['acquisition_date']}`")
            st.write(f"- **Description:** {item.get('description') or 'No notes recorded.'}")
            st.write(f"- **Vault Location:** `{item.get('vault_path')}`")
            st.caption("REGISTERED BASELINE SHA-256:")
            st.code(item["sha256"], language="text")

        with d2:
            st.markdown("#### Real-time Integrity Check")
            verifier_name = st.text_input("Examiner Conducting Check:", value="Analyst", key="check_examiner_name")
            
            if st.button("⚡ Recalculate & Verify SHA-256", use_container_width=True):
                with st.spinner("Streaming file and recalculating cryptographic digest..."):
                    try:
                        v_result = verify_evidence_integrity(selected_ev, verified_by=verifier_name)
                        res = v_result["result"]
                        
                        if res == "MATCH":
                            st.success(f"✅ **MATCH**: Current content matches registered baseline fingerprint.")
                            st.code(f"Current:  {v_result['current_sha256']}\nBaseline: {v_result['registered_sha256']}", language="text")
                        elif res == "MISMATCH":
                            st.error(f"❌ **MISMATCH**: Content differs from registered fingerprint! Potential tampering.")
                            st.code(f"Current:  {v_result['current_sha256']}\nBaseline: {v_result['registered_sha256']}", language="text")
                        elif res == "MISSING":
                            st.error(f"🚫 **MISSING**: The stored evidence file cannot be found in the vault path.")
                        st.rerun()
                    except Exception as err:
                        st.error(f"Verification error: {str(err)}")

            st.markdown("---")
            st.markdown("#### Manual Custody Event")
            manual_action = st.selectbox("Record Action:", ["ACCESSED", "EXPORTED"], key="manual_action_select")
            action_notes = st.text_input("Action Justification / Notes:", placeholder="e.g. Exported copy for timeline correlation")
            if st.button("📝 Log Custody Action"):
                record_custody_event(
                    evidence_id=selected_ev,
                    action=manual_action,
                    performed_by=verifier_name,
                    notes=action_notes
                )
                st.success(f"Logged {manual_action} in CHAINLOCK custody trail.")
                st.rerun()

        # Chain of Custody History & Cryptographic Linkage Audit
        st.markdown("---")
        st.markdown(f"### 🔗 CHAINLOCK Cryptographic Custody Trail for `{selected_ev}`")
        
        # Verify custody hash chain
        chain_audit = verify_custody_chain(selected_ev)
        c_status_col1, c_status_col2 = st.columns([3, 1])
        with c_status_col1:
            if chain_audit["status"] == "CHAIN_INTEGRITY_VERIFIED":
                st.success(f"🛡️ **Custody Chain Verified**: All {chain_audit['total_events']} events maintain unbroken cryptographic hash linkage.")
            elif chain_audit["status"] == "CONTAINS_UNVERIFIED_LEGACY_EVENTS":
                st.warning(f"⚠️ **Legacy Records Detected**: {chain_audit['legacy_events_count']} pre-CHAINLOCK custody event(s) lack original cryptographic signatures. This is an audit status difference, not intentional file/data tampering.")
                for b in chain_audit["broken_events"]:
                    st.caption(f"- Event `{b['event_id']}`: {b.get('details', b['reason'])}")
            elif chain_audit["status"] == "CHAIN_TAMPER_DETECTED":
                st.error(f"🚨 **Tampering Detected**: Custody hash chain integrity compromised! Broken records: {len(chain_audit['broken_events'])}")
                for b in chain_audit["broken_events"]:
                    st.caption(f"- Event `{b['event_id']}`: {b['reason']}")
            else:
                st.info(f"Custody Status: {chain_audit['status']}")

        with c_status_col2:
            if chain_audit["status"] == "CONTAINS_UNVERIFIED_LEGACY_EVENTS":
                if st.button("🔄 Migrate Legacy Chain", help="Explicitly migrates unhashed historical events into a documented cryptographically linked chain."):
                    m_res = migrate_legacy_custody_events(selected_ev, migrated_by=verifier_name)
                    st.success(f"Migrated {m_res['migrated_count']} legacy event(s). Chain cryptographically bridged!")
                    st.rerun()

        coc_events = get_custody_history(selected_ev)
        if coc_events:
            coc_df = pd.DataFrame(coc_events)[["id", "timestamp", "action", "performed_by", "notes", "previous_event_hash", "current_event_hash"]]
            coc_df.rename(columns={
                "id": "Event ID",
                "timestamp": "Timestamp (UTC)",
                "action": "Action",
                "performed_by": "Actor",
                "notes": "Action Details",
                "previous_event_hash": "Previous Event Hash",
                "current_event_hash": "Current Event Hash"
            }, inplace=True)
            st.dataframe(coc_df, use_container_width=True, hide_index=True)
        else:
            st.caption("No custody events recorded for this artifact.")
