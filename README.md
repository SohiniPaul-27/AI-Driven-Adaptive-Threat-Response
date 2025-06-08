 Anomaly Detection & Response Dashboard

This is a lightweight, interactive Streamlit web app that helps visualize and manually resolve network anomalies based on custom rule triggers and IP-based heuristics.

🚀 Features

- Reads anomaly data from a CSV file
- 📌 Classifies anomalies as:
  - Suspicious Web Traffic
  - Adversary Infrastructure Interaction
  - Foreign Traffic
  - Benign
- Heuristic logic based on:
  - IP country codes
  - Rule names and observations (if available)
- Resolved anomalies are tracked separately
- Justifications for flagged actions
- Safe rerun after marking an anomaly as resolved

📁 Files

- anomaly_results.csv – Primary input file containing all anomalies
- resolved_anomalies.csv– App-generated file storing resolved anomaly records
- app.py – Streamlit-based anomaly dashboard

📊 Sample Anomaly Classification Logic


if "Suspicious Web Traffic" in rule_names:
    return "suspicious web traffic"
elif "Adversary" in observation_name:
    return "adversary interaction"
elif src_ip_country_code not in ["IN", "US", "AE", "CA"]:
    return "foreign traffic"
else:
    return "benign"

How to Run:
pip install -r requirements.txt
streamlit run app.py
(Make sure anomaly_results.csv is in the same directory.)
