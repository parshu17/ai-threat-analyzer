# app.py
import streamlit as st
from modules import collector, analyzer, visualizer
import pandas as pd
from config import DATA_FILE
import json
import os

# Optional modules (may not be present; import lazily)
try:
    from modules import geo as geo_mod
except Exception:
    geo_mod = None

try:
    from modules import mitre_map
except Exception:
    mitre_map = None

try:
    from modules import anomaly as anomaly_mod
except Exception:
    anomaly_mod = None

try:
    from modules import malware as malware_mod
except Exception:
    malware_mod = None

try:
    from modules import shodan_helper
except Exception:
    shodan_helper = None

try:
    from modules import summarizer
except Exception:
    summarizer = None

# Page config
st.set_page_config(page_title="AI Threat Intelligence Dashboard", layout="wide")

st.title("🔥 ThreatVision AI")

# -----------------------
# Caching / Load helpers
# -----------------------
@st.cache_data(ttl=60)  # default refresh every 60 seconds
def cached_load_default():
    return collector.load_data()

def force_fetch_and_save():
    """Force fetch from configured feeds and save to DATA_FILE."""
    try:
        d = collector.fetch_abuseipdb_blacklist()
        collector.save_data(d)
        st.success(f"Fetched & saved {len(d.get('data', []))} records.")
        return d
    except Exception as e:
        st.error(f"Fetch failed: {e}")
        return None

# -----------------------
# Layout: Controls & View
# -----------------------
col1, col2 = st.columns([1, 3])

with col1:
    st.header("Controls")
    st.markdown("**Data Source**")
    if st.button("Fetch latest from AbuseIPDB"):
        force_fetch_and_save()
        # Clear cache after fetch so UI shows new data
        try:
            st.experimental_rerun()
        except Exception:
            pass

    st.write("---")
    st.markdown("**Load local data**")
    uploaded = st.file_uploader("Upload JSON data (optional)", type=["json"])
    if uploaded:
        try:
            d = json.load(uploaded)
            collector.save_data(d)
            st.success("Uploaded and saved to local data file.")
            try:
                st.experimental_rerun()
            except Exception:
                pass
        except Exception as e:
            st.error(f"Failed to load JSON: {e}")

    st.write("---")
    st.markdown("**Auto-refresh**")
    ttl = st.number_input("Cache TTL (seconds)", min_value=10, max_value=3600, value=60, step=10)
    st.markdown("Note: Change TTL then press 'Clear Cache' to apply.")
    if st.button("Clear Cache"):
        # clear streamlit cache and reload
        st.cache_data.clear()
        st.success("Cache cleared. Reloading...")
        try:
            st.experimental_rerun()
        except Exception:
            pass

    st.write("---")
    st.markdown("**Geo / Enrichment**")
    if geo_mod is None:
        st.info("Geo enrichment module not available. Add modules/geo.py to enable.")
    else:
        if st.button("Enrich data with Geo (ipinfo)"):
            # load raw data and do enrichment
            d = collector.load_data()
            raw = d.get("data", [])
            if not raw:
                st.warning("No data to enrich. Fetch or upload data first.")
            else:
                df = pd.json_normalize(raw)
                # attempt to discover an IP column
                possible_ip_cols = [c for c in df.columns if "ip" in c.lower()]
                if not possible_ip_cols:
                    st.error("No IP-like column found in data (look for columns containing 'ip').")
                else:
                    ip_col = possible_ip_cols[0]
                    with st.spinner("Enriching geo info (may be rate-limited)..."):
                        df_geo = geo_mod.enrich_df_with_geo(df, ip_field=ip_col)
                        # save enriched results
                        out_path = "data/geo_enriched.json"
                        os.makedirs("data", exist_ok=True)
                        df_geo.to_json(out_path, orient="records", force_ascii=False)
                        st.success(f"Geo enrichment done. Saved to {out_path}")
                        try:
                            st.experimental_rerun()
                        except Exception:
                            pass

    st.write("---")
    st.markdown("**Shodan & Malware**")
    shodan_ip = st.text_input("Shodan lookup IP (enter and press Enter)", value="")
    if shodan_ip:
        if shodan_helper is None:
            st.info("Shodan module not available. Add modules/shodan_helper.py and SHODAN_API_KEY to use.")
        else:
            with st.spinner("Querying Shodan..."):
                res = shodan_helper.shodan_lookup_ip(shodan_ip)
                st.subheader(f"Shodan result for {shodan_ip}")
                st.json(res)

    uploaded_file = st.file_uploader("Upload file to hash/scan (optional)", type=None, key="file_scan")
    if uploaded_file is not None:
        content = uploaded_file.read()
        if malware_mod is None:
            st.info("Malware helper module not available. Add modules/malware.py to enable hashing and VT lookup.")
            # Still show hashes locally
            import hashlib
            md5 = hashlib.md5(content).hexdigest()
            sha1 = hashlib.sha1(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()
            st.json({"md5": md5, "sha1": sha1, "sha256": sha256})
        else:
            hashes = malware_mod.file_hashes(content)
            st.json(hashes)
            if st.button("Query VirusTotal (sha256)"):
                with st.spinner("Querying VirusTotal..."):
                    vt = malware_mod.vt_file_lookup_by_hash(hashes.get("sha256"))
                    st.json(vt)

with col2:
    st.header("Threat Feed & Analysis")

    # Use cached loader with dynamic TTL by wrapping into local cache function if TTL != default.
    # Because st.cache_data decorator requires a constant TTL at definition time, we will reload cache manually if TTL differs.
    data = cached_load_default()
    raw = data.get("data", [])

    st.write(f"Fetched at: {data.get('fetched_at')}")
    if not raw:
        st.info("No data available. Click fetch (left) or upload a JSON export.")
    else:
        # normalize into DataFrame safely
        df = pd.json_normalize(raw)

        # try to find text field candidates for NLP
        text_candidates = [c for c in df.columns if df[c].dtype == object]
        if not text_candidates:
            st.error("No text-like columns found for analysis.")
        else:
            text_field = st.selectbox("Text field to analyze", options=text_candidates, index=0)
            st.write(f"Using `{text_field}` for NLP classification")

            # Option: summarization toggle (manual)
            do_summarize = st.checkbox("Generate short summary for each record (may be slow on CPU)", value=False)
            # Option: run MITRE mapping
            do_mitre = st.checkbox("Add MITRE ATT&CK tags (keyword mapping)", value=True)
            # Option: perform anomaly detection
            do_anomaly = st.checkbox("Run anomaly detection (IsolationForest) on numeric features", value=True)

            # analyze records (classification + optional summary + mitre)
            with st.spinner("Running NLP classification..."):
                records = df.to_dict(orient="records")
                analyzed = analyzer.analyze_list(records, text_field)

                # Add MITRE tags if available and enabled
                if do_mitre and mitre_map is not None:
                    for r in analyzed:
                        text = r.get(text_field) or r.get("comment") or str(r)
                        r["_mitre"] = mitre_map.map_text_to_mitre(text)
                else:
                    # if MITRE not available, make empty tags
                    for r in analyzed:
                        r["_mitre"] = []

                # Summarize if requested and summarizer available
                if do_summarize:
                    if summarizer is None:
                        st.warning("Summarizer module not available. Add modules/summarizer.py to enable.")
                        for r in analyzed:
                            r["_summary"] = ""
                    else:
                        for r in analyzed:
                            txt = r.get(text_field) or r.get("comment") or ""
                            r["_summary"] = summarizer.summarize_text(txt, max_length=60)

                df2 = pd.json_normalize(analyzed)

            # show top labels
            if "_label" in df2.columns:
                st.subheader("Top labels")
                fig = visualizer.bar_count(df2, "_label", title="Threat categories")
                if fig:
                    st.plotly_chart(fig, use_container_width=True)

                    # Show raw analyzed data (first 50 rows)
        st.subheader("Raw / analyzed (first 50 rows)")
        st.dataframe(df2.head(50), use_container_width=True)

        # MITRE ATT&CK Summary
        if "_mitre" in df2.columns:
            # Ensure values are strings
            df2["_mitre"] = df2["_mitre"].apply(
                lambda x: x if isinstance(x, str) else "Unknown Technique"
            )

            # Count MITRE techniques
            mitre_counts = df2["_mitre"].value_counts().reset_index()
            mitre_counts.columns = ["MITRE Technique", "Count"]

            if not mitre_counts.empty:
                st.subheader("MITRE ATT&CK Technique Summary")
                st.dataframe(mitre_counts, use_container_width=True)


            # show raw table (first 50)
            st.subheader("Raw / analyzed (first 50 rows)")
            st.dataframe(df2.head(50))

            # Add simple numeric feature columns for anomaly detection
            if do_anomaly:
                # create simple numeric features if exist
                df2["text_len"] = df2[text_field].astype(str).str.len() if text_field in df2.columns else 0
                # ports_count: try to detect 'ports' or similar field
                if "ports" in df2.columns:
                    df2["ports_count"] = df2["ports"].apply(lambda x: len(x) if isinstance(x, list) else (int(x) if pd.notna(x) and str(x).isdigit() else 0))
                else:
                    df2["ports_count"] = 0

                # run anomaly detection if module available
                if anomaly_mod is None:
                    st.info("Anomaly module not available. Add modules/anomaly.py to enable anomaly detection.")
                else:
                    numeric_cols = ["text_len", "ports_count"]
                    try:
                        df_anom = anomaly_mod.detection_on_numeric(df2, numeric_cols)
                        # display anomalies
                        anom_count = df_anom["_is_anomaly"].sum() if "_is_anomaly" in df_anom.columns else 0
                        st.subheader(f"Anomalies detected: {int(anom_count)}")
                        if anom_count > 0:
                            st.dataframe(df_anom[df_anom["_is_anomaly"]].head(50))
                    except Exception as e:
                        st.error(f"Anomaly detection failed: {e}")

            # time series if a suitable column exists
            date_cols = [c for c in df2.columns if "date" in c.lower() or "time" in c.lower() or "fetched_at" in c.lower()]
            if date_cols:
                ts_col = date_cols[0]
                st.subheader("Events over time")
                fig2 = visualizer.time_series_count(df2, ts_col, freq="D")
                if fig2:
                    st.plotly_chart(fig2, use_container_width=True)

            # Geo map: try to load geo_enriched.json if present
            geo_path = "data/geo_enriched.json"
            if os.path.exists(geo_path):
                try:
                    st.subheader("Attack map (Geo enriched)")
                    df_geo = pd.read_json(geo_path, orient="records")
                    if "geo_lat" in df_geo.columns and "geo_lon" in df_geo.columns:
                        fig_map = visualizer.world_map(df_geo, lat_col="geo_lat", lon_col="geo_lon", hover_cols=["ipAddress","geo_country"], title="Attack Map")
                        if fig_map:
                            st.plotly_chart(fig_map, use_container_width=True)
                    else:
                        st.info("Geo file exists but no geo_lat/geo_lon columns found. Enrich using 'Enrich data with Geo' first.")
                except Exception as e:
                    st.error(f"Failed to render geo map: {e}")
            else:
                st.info("No geo-enriched file found. Use 'Enrich data with Geo' in Controls to populate attack map.")

# Footer / tips
st.write("---")
st.markdown("**Tips:**")
st.markdown("- Use the 'Fetch latest' button to pull threat data from AbuseIPDB (requires API key in .env).")
st.markdown("- Add optional API keys in `.env`: `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `IPINFO_TOKEN`.")
st.markdown("- Heavy operations (summarization, model downloads) are CPU and network intensive on first run.")
