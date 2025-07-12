import streamlit as st
import os
import plotly.express as px
from plotly import graph_objects as go
import pandas as pd
from datetime import time
import altair as alt
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from model_func.enrich_func import enrich_suspicious_ips as s


# Initialize session variable safely
if "apply_date_filter" not in st.session_state:
    st.session_state.apply_date_filter = False

#filter by hours func
def get_time_range(preset):
    if preset == "Office Hours (9AM-6PM)":
        return time(9, 0), time(18, 0)
    elif preset == "Night Activity (10PM-6AM)":
        return time(22, 0), time(6, 0)
    elif preset == "Early Morning (4AM-9AM)":
        return time(4, 0), time(9, 0)
    else:
        return time(0, 0), time(23, 59)


#title
st.markdown("""
    <div style='text-align: center; padding: 10px 0 20px 0;'>
        <h1>🌐 Enrich Suspicious IPs 🌐 <br>(GeoIP + WHOIS)</h1>
        <h4 style='margin-top: -10px; color:#1f77b4;'>...Get Data About The IPs...</h4>
    </div>
""", unsafe_allow_html=True)
st.markdown("---")

#session path
case_folder = st.session_state.get("resolved_case_path" , "")
if isinstance(case_folder, dict) and "path" in case_folder:
    # Auto-correct legacy value
    case_folder = case_folder["path"]
    st.session_state.resolved_case_path = case_folder  
elif not isinstance(case_folder, str):
    st.error(f"❌ Invalid session value for 'resolved_case_path': {type(case_folder)}\n{case_folder}")
    st.stop()


#files path
ranked_path = os.path.join(case_folder, "ranked_suspicious_ips.csv")
if not os.path.exists(ranked_path):
    st.error(f"`ranked_suspicious_ips.csv` not found at:\n{ranked_path}")
    st.stop()

#loading ips
df_ranked = pd.read_csv(ranked_path)
suspicious_ips = df_ranked['ip'].dropna().unique().tolist()

case_name = os.path.basename(case_folder)
st.subheader(f"Case Name: `{case_name}`")
st.write(f"Case Path: `{case_folder}`")
st.write(f"Detected `{len(suspicious_ips)}` suspicious IPs to process.")

# start process
if st.button("Start Enrichment"):
    with st.spinner("Fetching GeoIP & WHOIS details..."):
        new_count = s(suspicious_ips, case_folder)
    if new_count == 0:
        st.success(" No new suspicious IPs found. Master list already up to date.")
    else:
        st.success(f"Enriched and saved details for `{new_count}` new IP(s).")
        st.info("🔗 Files saved: `suspicious_ip_geo_whois.csv`, `master_suspicious_ip_report.csv`, `linked_logs.csv`")
        st.rerun()  


#--------------------------------------------------------------------------------------------------------------------------------------------------
# visuals

enriched_path = os.path.join(case_folder,"suspicious_ip_geo_whois.csv")
if os.path.exists(enriched_path):
    df_enriched = pd.read_csv(enriched_path)

    # Merge risk metadata if missing
    for col in ["risk_level", "suspicion_probability", "timestamp"]:
        if col not in df_enriched.columns and col in df_ranked.columns:
            df_enriched = pd.merge(df_enriched, df_ranked[["ip", col]], on="ip", how="left")

#------------------------------------------------------------------------------------------------------------------------------------------------------------  
    st.markdown("---")
    st.subheader("📋 Enriched IP Data Table")
    if {"risk_level", "country", "timestamp"}.issubset(df_enriched.columns):
       df_enriched["timestamp"] = pd.to_datetime(df_enriched["timestamp"], errors="coerce")

       timestamp_valid = df_enriched["timestamp"].notna().any()
       min_date = df_enriched["timestamp"].min().date()
       max_date = df_enriched["timestamp"].max().date()

       col1, col2, col3, col4 = st.columns(4)

       with col1:
          risk_filter = st.selectbox("🔍 Filter by Risk Level", options=["All"] + sorted(df_enriched["risk_level"].dropna().unique()))

       with col2:
           country_filter = st.selectbox("🌍 Filter by Country", options=["All"] + sorted(df_enriched["country"].dropna().unique()))
       if timestamp_valid:
         with col3:
               
               date_range = st.date_input("🗓️ Filter by Date Range", value=(min_date, max_date), min_value=min_date, max_value=max_date)
               if st.button("✅ Apply Date Filter"):
                  st.session_state.apply_date_filter = not st.session_state.apply_date_filter

               if st.session_state.apply_date_filter:
                   st.success("Date filter is ACTIVE (click to remove)")
           

         with col4:
           time_filter = st.selectbox(
              "🕒Time Filter",
             options=["All Time", "Office Hours (9AM-6PM)", "Night Activity (10PM-6AM)", "Early Morning (4AM-9AM)"]
             )
       else:
           date_range = None
           time_filter = "All Time"

       #apply filters 
       filtered_df = df_enriched.copy()

       if risk_filter != "All":
         filtered_df = filtered_df[filtered_df["risk_level"] == risk_filter]

       if country_filter != "All":
         filtered_df = filtered_df[filtered_df["country"] == country_filter]

       if time_filter != "All Time":
          start_time, end_time = get_time_range(time_filter)
          if start_time < end_time:
            filtered_df = filtered_df[
             (filtered_df["timestamp"].dt.time >= start_time) & 
             (filtered_df["timestamp"].dt.time <= end_time)
           ]
          else:
           filtered_df = filtered_df[
            (filtered_df["timestamp"].dt.time >= start_time) |
            (filtered_df["timestamp"].dt.time <= end_time)
        ]
          
       if st.session_state.apply_date_filter and date_range and len(date_range) == 2:
         start_date, end_date = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
         filtered_df = filtered_df[
         (filtered_df["timestamp"] >= start_date) & 
         (filtered_df["timestamp"] <= end_date)
          ]
       
               
       

       st.markdown(f"### Showing `{len(filtered_df)}` matching records")
       
       st.dataframe(filtered_df)
       custom_filename = st.text_input("Enter filename for download (without .csv)" , value = "filtered_suspicious_ips")

       st.download_button(
           label="⬇️ Download Filtered CSV",
           data=filtered_df.to_csv(index=False),
           file_name=f"{custom_filename.strip() or 'filtered_suspicious_ips'}.csv",
           mime="text/csv"
       )
    else:
       st.dataframe(df_enriched)

#-----------------------------------------------------------------------------------------------------------------------------------------------
    # country-wise bar chart
    if 'country' in df_enriched.columns:
        st.markdown("### 🌍 Distribution by Country")
        country_counts = filtered_df['country'].value_counts().reset_index()
        country_counts.columns = ['Country', 'Count']

        fig = px.bar(
         country_counts,
         x="Country",
         y="Count",
         text="Count",
         color="Country", 
         title="Suspicious IPs per Country"
         )

        fig.update_layout(
          width=2000, 
          height=500,
          showlegend=False,
          xaxis=dict(tickangle=45)
         )

        st.plotly_chart(fig, use_container_width=True)
        
#---------------------------------------------------------------------------------------------------------------------------------------
# timebased chart
    if 'timestamp' in df_enriched.columns:
        st.markdown("### 📆 Suspicious IP Activity Timeline")
        df_enriched['timestamp'] = pd.to_datetime(df_enriched['timestamp'], errors='coerce')
        df_enriched = df_enriched.dropna(subset=['timestamp'])
        
        if not df_enriched.empty:
            daily_activity = filtered_df.groupby(filtered_df['timestamp'].dt.date).size()
            st.line_chart(daily_activity)

            # geo timeline animation
            st.markdown("### 🗺️ GeoIP Map of Suspicious IPs ")
            filtered_df["date_str"] = filtered_df["timestamp"].dt.date.astype(str)
            if "risk_level" in df_enriched.columns:
                fig = px.scatter_mapbox(
                filtered_df,
                lat="latitude",
                lon="longitude",
                color="risk_level",
                hover_name="ip",
                animation_frame="date_str",
                zoom=2, 
                size_max=15,
                mapbox_style="carto-positron",
                title="Suspicious IPs Over Time "
            )

            fig.update_layout(margin={"r":0,"t":40,"l":0,"b":0})

            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Timestamp data not available or improperly formatted.")
#-------------------------------------------------------------------------------------------------------------------------------------------------------------
    if {"asn_description", "country"}.issubset(df_enriched.columns):
       st.markdown("### 🧭 IP Route Mapping (Source → ASN → Country)")
       filtered_df["source"] = "This Device"
       TOP_N = 10
       top_asns = df_enriched["asn_description"].value_counts().nlargest(TOP_N).index
       df_enriched["asn_description"] = df_enriched["asn_description"].apply(lambda x: x if x in top_asns else "Other")
       
       top_countries = df_enriched["country"].value_counts().nlargest(10).index
       df_enriched["country"] = df_enriched["country"].apply(lambda x: x if x in top_countries else "Other")
       sunburst_df = filtered_df[["source", "asn_description", "country"]].dropna()
       fig = px.sunburst(
          sunburst_df,
          path=["source", "asn_description", "country"],
          title="📊 Source → ASN → Country Mapping",
          color_discrete_sequence=px.colors.qualitative.Pastel,
          width=8000,
          height=600
        )
       st.plotly_chart(fig, use_container_width=True)
       st.markdown("<h3>🧠 Auto-Generated Summary for the above graph</h3>", unsafe_allow_html=True)
       with st.expander("click to expand"):
           if filtered_df.empty:
                st.info("No data available after filtering to generate a summary.")

           else:
                #network diversity
                num_unique_asns = filtered_df["asn_description"].nunique()
                num_unique_countries = filtered_df["country"].nunique()
                st.markdown(f"""
                 - 🌐 **Connected to `{num_unique_asns}` distinct ASNs**
                 - 🗺️ **Across `{num_unique_countries}` countries**
                  """)
               
                # high risk asn
                high_risk_asns = filtered_df[filtered_df["risk_level"] == "High"]["asn_description"].value_counts().head(3)
                if not high_risk_asns.empty:
                   st.markdown("#### ⚠️ High-Risk ASN Summary:")
                   for asn, count in high_risk_asns.items():
                       st.markdown(f"- `{asn}`: {count} high-risk connections")

                else:
                   st.success("✅ No high-risk ASNs identified.")
                   
                # unexpected countries
                suspicious_countries = {"CN", "RU", "IR", "KP"}                                  #update this
                connected_countries = set(filtered_df["country"].dropna().unique())
                unexpected = connected_countries & suspicious_countries

                if unexpected:
                    st.error(f"🚩 Unexpected routing through high-risk countries: {', '.join(unexpected)}")
                else:
                    st.success(" No unexpected country-level routes.")

                # vpn host
                suspicious_asn_keywords = [
                     "M247", "CHOOPA", "DIGITALOCEAN", "TOR", "MULLVAD", "NORDVPN", "OVH", "NETCUP", "TUNNEL", "SHADOWSOCKS"
                 ]
                pattern = "|".join(suspicious_asn_keywords)
                vpn_hosts = filtered_df[filtered_df["asn_description"].str.contains(pattern, case=False, na=False)]

                if not vpn_hosts.empty:
                   st.markdown("### 🕵️ Detected possible VPN / bulletproof hosting connections:")
                   st.dataframe(vpn_hosts[["ip", "asn_description", "country"]].drop_duplicates())
                else:
                    st.info("✅ No known VPN or bulletproof infrastructure detected.")

                risky = filtered_df[filtered_df["risk_level"] == "High"]

                top_risky_asns = (
                 risky.groupby(["asn_description", "risk_level"])
                    .size()
                    .reset_index(name="Count")
                    .rename(columns={"asn_description": "ASN"})
                    .sort_values("Count", ascending=False)
                    .head(5)
                )

                
                risk_color_scale = alt.Scale(domain=["High", "Medium", "Low"],
                                            range=["#e74c3c", "#f1c40f", "#2ecc71"]  )

                if not top_risky_asns.empty:
                  st.markdown("### 📊 Top High-Risk ASN Bar Chart")

                  chart = alt.Chart(top_risky_asns).mark_bar().encode(
                         x=alt.X("Count:Q", title="Number of High-Risk IPs"),
                         y=alt.Y("ASN:N", sort="-x", title="ASN Description"),
                         color=alt.Color("risk_level:N", scale=risk_color_scale, title="Risk Level"),
                         tooltip=["ASN","risk_level" ,"Count"]
                         ).properties(
                             width=600,
                             height=300
                         ).configure_axis(
                            labelFontSize=12,
                            titleFontSize=14
                         ).configure_title(
                             fontSize=16
                         )
                  st.altair_chart(chart, use_container_width=True)
else:
    st.info("Run enrichment to generate visualizations")


# Back Button 
if st.button("⬅️ Back to Case View"):
    st.switch_page("pages/case_creation.py")











