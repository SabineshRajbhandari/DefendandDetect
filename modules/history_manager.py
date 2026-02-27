import streamlit as st
from services.database_service import DatabaseService
from services.report_service import ReportService
import pandas as pd
from datetime import datetime

def toggle_scan(scan_id):
    """Callback to sync individual checkbox with master set."""
    cb_key = f"bulk_sel_{scan_id}"
    if st.session_state.get(cb_key):
        st.session_state.selected_scans.add(scan_id)
    else:
        st.session_state.selected_scans.discard(scan_id)

def select_all_callback(all_ids, select=True):
    """Callback to sync all checkboxes with master set."""
    for sid in all_ids:
        st.session_state[f"bulk_sel_{sid}"] = select
        if select:
            st.session_state.selected_scans.add(sid)
        else:
            st.session_state.selected_scans.discard(sid)

def delete_selected_callback():
    """Callback to delete selected scans and clean up state."""
    if not st.session_state.selected_scans:
        return
    
    DatabaseService.delete_scans(list(st.session_state.selected_scans))
    
    # Clean up session state keys
    for sid in st.session_state.selected_scans:
        key = f"bulk_sel_{sid}"
        if key in st.session_state:
            del st.session_state[key]
            
    st.session_state.selected_scans = set()
    st.success("Selected items removed successfully.")

def clear_all_callback():
    """Callback to clear all history and state."""
    DatabaseService.clear_history()
    st.session_state.selected_scans = set()
    for key in list(st.session_state.keys()):
        if key.startswith("bulk_sel_"):
            del st.session_state[key]
    st.success("History cleared successfully.")

def show_history_manager():
    st.header("📂 Security Activity Manager")
    st.markdown("""
        Review, audit, and export your personal security intelligence history. 
        Use this page to track past analyses, restore results, or download consolidated reports for offline auditing.
    """)

    # Initialize selection state if missing
    if "selected_scans" not in st.session_state:
        st.session_state.selected_scans = set()

    recent_scans = DatabaseService.get_recent_scans(limit=100)
    
    if not recent_scans:
        st.info("🔎 **No Activity Found**: Your history is currently empty. Start using the security modules to build your audit log.")
        return

    # Header Controls
    all_ids = {s['id'] for s in recent_scans}
    is_all_selected = all_ids.issubset(st.session_state.selected_scans)
    selected_count = len(st.session_state.selected_scans)
    
    col_select, col_download, col_remove = st.columns([1, 1, 1])
    
    with col_select:
        if is_all_selected:
            st.button("🔓 Deselect All", on_click=select_all_callback, args=(all_ids, False), use_container_width=True)
        else:
            st.button("✅ Select All", on_click=select_all_callback, args=(all_ids, True), type="secondary", use_container_width=True)

    with col_download:
        with st.popover("📥 Download", use_container_width=True):
            if st.session_state.selected_scans:
                st.markdown(f"### 📥 Download Selected ({selected_count})")
                selected_data = [s for s in recent_scans if s['id'] in st.session_state.selected_scans]
                
                # Show summary list
                with st.expander(f"Review {selected_count} items", expanded=False):
                    for s in selected_data:
                        st.write(f"- **{s['type']}**: {s['input'][:40]}...")
                
                batch_fmt = st.selectbox("Format", ["JSON", "CSV"], key="dl_fmt_sel")
                
                if batch_fmt == "JSON":
                    report_data = ReportService.generate_batch_report(selected_data)
                    ext, mime = "json", "application/json"
                else:
                    df = pd.DataFrame(selected_data)
                    report_data = df.to_csv(index=False)
                    ext, mime = "csv", "text/csv"

                st.download_button(
                    label=f"Confirm {ext.upper()} Download",
                    data=report_data,
                    file_name=f"security_audit_batch_{datetime.now().strftime('%Y%m%d')}.{ext}",
                    mime=mime,
                    use_container_width=True,
                    type="primary"
                )
            else:
                st.markdown("### 🌍 Download Full History")
                st.info("No items selected. Prepare a full CSV export of all audit logs.")
                
                full_df = pd.DataFrame(recent_scans)
                full_csv = full_df.to_csv(index=False)
                
                st.download_button(
                    label="Confirm Full CSV Download",
                    data=full_csv,
                    file_name=f"security_full_history_{datetime.now().strftime('%Y%m%d')}.csv",
                    mime="text/csv",
                    use_container_width=True,
                    type="primary"
                )

    with col_remove:
        if st.session_state.selected_scans:
            with st.popover(f"🗑️ Remove ({selected_count})", use_container_width=True):
                st.warning(f"This will permanently delete **{selected_count}** selected entries.")
                
                # Show summary list of what's being removed
                selected_data = [s for s in recent_scans if s['id'] in st.session_state.selected_scans]
                with st.container(height=150):
                    for s in selected_data:
                        st.caption(f"ID {s['id']}: {s['type']} - {s['input'][:30]}...")
                
                if st.button("🔥 Confirm Removal", type="primary", use_container_width=True, on_click=delete_selected_callback):
                    st.rerun()
        else:
            with st.popover("🗑️ Clear All", use_container_width=True):
                st.error("⚠️ **CRITICAL ACTION**: This will permanently wipe your entire security audit history.")
                st.info(f"Total entries to be cleared: {len(recent_scans)}")
                
                if st.button("🚨 WIPE ALL DATA", type="primary", use_container_width=True, on_click=clear_all_callback):
                    st.rerun()

    st.markdown("---")

    # Search and Filter UI
    col_type_filter, col_sort_filter, col_spacer = st.columns([1, 1, 1.5])
    
    with col_type_filter:
        type_options = ["All Categories", "PHISHING", "URL", "HASH", "CVE", "LOG"]
        selected_type = st.selectbox("Filter by Category", type_options, label_visibility="collapsed")
        
    with col_sort_filter:
        sort_order = st.selectbox("Sort Order", ["Newest First", "Oldest First"], label_visibility="collapsed")

    # Filtering Logic
    filtered_scans = recent_scans
    
    # Apply Type Filter
    if selected_type != "All Categories":
        filtered_scans = [s for s in filtered_scans if s['type'] == selected_type]

    # Apply Sort Logic
    if sort_order == "Oldest First":
        filtered_scans = sorted(filtered_scans, key=lambda x: x['id'])
    else:
        filtered_scans = sorted(filtered_scans, key=lambda x: x['id'], reverse=True)

    # Table View
    if not filtered_scans:
        st.info(f"🔎 **No {selected_type} records found**: Your history is currently empty for this category.")
        return

    has_multi_select = len(st.session_state.selected_scans) > 1

    for scan in filtered_scans:
        # Professional 12-hour format
        try:
            dt_obj = datetime.strptime(scan['timestamp'], "%Y-%m-%d %H:%M:%S")
            pretty_ts = dt_obj.strftime("%b %d, %Y - %I:%M %p")
        except:
            pretty_ts = scan['timestamp']

        with st.container(border=True):
            cols = st.columns([0.5, 2.5, 4.5, 2.5])
            
            with cols[0]:
                cb_key = f"bulk_sel_{scan['id']}"
                if cb_key not in st.session_state:
                    st.session_state[cb_key] = scan['id'] in st.session_state.selected_scans
                
                st.checkbox("", key=cb_key, on_change=toggle_scan, args=(scan['id'],), label_visibility="collapsed")
            
            with cols[1]:
                st.markdown(f"**{scan['type']}** `#{scan['id']}`")
                st.caption(f"📅 {pretty_ts}")
            
            with cols[2]:
                display_input = scan['input'][:100] + ("..." if len(scan['input']) > 100 else "")
                st.text(display_input)
            
            with cols[3]:
                col_view, col_dl_ind = st.columns([1, 1])
                with col_view:
                    if st.button("🔍 Restore", key=f"view_{scan['id']}", use_container_width=True):
                        st.session_state.restored_result = scan
                        page_map = {
                            "PHISHING": "Phishing Detector",
                            "URL": "URL Analyzer",
                            "HASH": "File Hash Scanner",
                            "CVE": "CVE Explainer",
                            "LOG": "Log Translator"
                        }
                        if scan['type'] in page_map:
                            st.session_state.page = page_map[scan['type']]
                            st.query_params["page"] = st.session_state.page
                            st.rerun()
                
                with col_dl_ind:
                    if not has_multi_select:
                        # Individual JSON download for history
                        ind_json = ReportService.generate_json_report(scan['type'], scan['input'], scan['result'])
                        st.download_button(
                            "📥", 
                            ind_json, 
                            file_name=f"audit_{scan['id']}_{scan['type'].lower()}.json",
                            mime="application/json",
                            key=f"dl_ind_{scan['id']}",
                            use_container_width=True
                        )
