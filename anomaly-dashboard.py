import streamlit as st
import pandas as pd
import os

# Set page config 
st.set_page_config(page_title="Anomaly Detection Dashboard", layout="centered")

st.title("🔐 Simple Anomaly Response Dashboard")

# File names
ANOMALY_FILE = "anomaly_results.csv"
RESOLVED_FILE = "resolved_anomalies.csv"


ANOMALY_FILE = "anomaly_results.csv"

if not os.path.exists(ANOMALY_FILE):
    st.error("❌ 'anomaly_results.csv' not found. Please ensure it exists in the same directory.")
    st.stop()

df = pd.read_csv(ANOMALY_FILE)


required_columns = ['rule_names', 'observation_name']
missing_cols = [col for col in required_columns if col not in df.columns]

if missing_cols:
    st.error(f"❌ Missing expected columns in CSV: {', '.join(missing_cols)}")
    st.stop()

if 'id' not in df.columns:
    df.reset_index(drop=True, inplace=True)
    df['id'] = df.index

# Valid country codes whitelist (add more as needed)
VALID_COUNTRY_CODES = {"IN", "US", "AE", "CA"}


if 'rule_names' in df.columns:
    st.write("Unique rule_names values:", df['rule_names'].dropna().unique())
else:
    st.write("No 'rule_names' column found.")

if 'observation_name' in df.columns:
    st.write("Unique observation_name values:", df['observation_name'].dropna().unique())
else:
    st.write("No 'observation_name' column found.")

st.write("Unique src_ip_country_code values:", sorted(set(str(c).strip().upper() for c in df['src_ip_country_code'].dropna())))

# Classification function
def classify_anomaly(row):
    rule_names = str(row.get("rule_names", "")).lower()
    observation_name = str(row.get("observation_name", "")).lower()
    country_code = row.get("src_ip_country_code")
    country_code_str = str(country_code).strip().upper() if pd.notna(country_code) else ""

    # Use the 'is_anomaly' flag if present and ==1
    if 'is_anomaly' in row and int(row['is_anomaly']) == 1:
        if "suspicious" in rule_names:
            return "suspicious web traffic"
        if "adversary" in observation_name:
            return "adversary interaction"
        # If anomaly flagged but no rule match, generic anomaly
        return "anomaly detected"

    # Fallback check by rule names
    if "suspicious" in rule_names:
        return "suspicious web traffic"
    if "adversary" in observation_name:
        return "adversary interaction"

    # Country code check
    if country_code_str and country_code_str.isalpha():
        if country_code_str not in VALID_COUNTRY_CODES:
            return "foreign traffic"
        else:
            return "benign"

    # If country code missing or invalid
    return "benign"

# Prepare user & ip columns
df['ip'] = df['src_ip']

if 'source.name' in df.columns:
    df['user'] = df['source.name']
else:
    df['user'] = df['src_ip_country_code'].fillna('unknown').astype(str)


df['anomaly_type'] = df.apply(classify_anomaly, axis=1)

# Justification messages
justification_dict = {
    "suspicious web traffic": lambda row: f"🔒 ACTION: Web request from `{row['ip']}` flagged as suspicious. Host: `{row['user']}`.",
    "adversary interaction": lambda row: f"⚠️ ACTION: Detected adversary infrastructure interaction on `{row['user']}`.",
    "foreign traffic": lambda row: f"🌍 ACTION: Traffic from country code `{row['src_ip_country_code']}` being logged for review.",
    "anomaly detected": lambda row: f"❗ ACTION: Generic anomaly detected for `{row['user']}` from IP `{row['ip']}`.",
    "benign": lambda row: "✅ No suspicious activity detected."
}

# Load resolved IDs
if os.path.exists(RESOLVED_FILE):
    resolved_df = pd.read_csv(RESOLVED_FILE)
    resolved_ids = set(str(i) for i in resolved_df["id"])
else:
    resolved_ids = set()

# UI loop showing anomalies not yet resolved
for index, row in df.iterrows():
    anomaly_id = str(row.get("id", f"Unknown-{index}"))
    if anomaly_id in resolved_ids:
        continue  # skip resolved

    if row['anomaly_type'] == "benign":
        continue  # skip benign for cleaner UI

    with st.expander(f"Anomaly #{anomaly_id}: {row['anomaly_type']}"):
        st.write(f"👤 **User**: `{row['user']}`")
        st.write(f"🌐 **IP**: `{row['ip']}`")

        justification_func = justification_dict.get(row['anomaly_type'], lambda r: "No justification available.")
        justification = justification_func(row)

        st.warning(f"📝 Justification: {justification}")

        if st.button(f"✅ Mark as Resolved #{anomaly_id}", key=anomaly_id):
            resolved_ids.add(anomaly_id)
            resolved_row = pd.DataFrame([row])
            if os.path.exists(RESOLVED_FILE):
                resolved_row.to_csv(RESOLVED_FILE, mode='a', header=False, index=False)
            else:
                resolved_row.to_csv(RESOLVED_FILE, index=False)

            st.success("Marked as resolved! Please refresh or rerun the app.")
            st.stop()

pending = len(df[df['anomaly_type'] != 'benign']) - len(resolved_ids)
if pending == 0:
    st.success("🎉 All anomalies resolved!")
else:
    st.info(f"⚠️ {pending} anomalies still pending resolution.")
anomalies_only = df[df['is_anomaly'] == 1]
print(anomalies_only[['id', 'src_ip', 'src_ip_country_code', 'rule_names', 'observation_name', 'anomaly_type']])
print("\nAnomaly Types:", anomalies_only['anomaly_type'].value_counts())
