import asyncio

try:
    loop = asyncio.get_running_loop()
except RuntimeError:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import torch
import torch.nn as nn
import torch.optim as optim
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import streamlit as st
import os



# Step 2: Upload Your Dataset
filename = "CloudWatch_Traffic_Web_Attack.csv"
df = pd.read_csv(filename)


time_columns = ["creation_time", "end_time", "time"]
for col in time_columns:
    # Use pd.to_datetime and convert to int64 nanoseconds, then to seconds
    df[col] = pd.to_datetime(df[col], errors='coerce').view(np.int64) // 10**9

# Encode categorical variables
categorical_cols = ["src_ip", "src_ip_country_code"]
le = LabelEncoder()
for col in categorical_cols:
    df[col] = le.fit_transform(df[col].astype(str))

# Select features for modeling
features = ["bytes_in", "bytes_out"] + time_columns + categorical_cols



# Split dataframe to preserve indices
df_train, df_test = train_test_split(df, test_size=0.2, random_state=42)

# Prepare training features and fit scaler only on training data
X_train = df_train[features].fillna(0).values
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)

# Prepare test features and transform using training scaler
X_test = df_test[features].fillna(0).values
X_test_scaled = scaler.transform(X_test)

# Convert to PyTorch tensors
X_train_tensor = torch.FloatTensor(X_train_scaled)
X_test_tensor = torch.FloatTensor(X_test_scaled)

# --------------------------------------------
# Step 5: Define Autoencoder Model with Skip Connections
class SkipAutoencoder(nn.Module):
    def __init__(self, input_dim):
        super(SkipAutoencoder, self).__init__()
        self.encoder1 = nn.Sequential(nn.Linear(input_dim, 32), nn.ReLU())
        self.encoder2 = nn.Sequential(nn.Linear(32, 16), nn.ReLU(), nn.Linear(16, 8))
        self.decoder1 = nn.Sequential(nn.Linear(8, 16), nn.ReLU())
        self.decoder2 = nn.Sequential(nn.Linear(48, 32), nn.ReLU(), nn.Linear(32, input_dim))

    def forward(self, x):
        x1 = self.encoder1(x)
        x2 = self.encoder2(x1)
        x3 = self.decoder1(x2)
        x_cat = torch.cat((x3, x1), dim=1)
        out = self.decoder2(x_cat)
        return out

input_dim = X_train.shape[1]
model = SkipAutoencoder(input_dim)
criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

epochs = 20
batch_size = 128

model.train()
for epoch in range(epochs):
    epoch_loss = 0
    for i in range(0, len(X_train_tensor), batch_size):
        batch = X_train_tensor[i:i + batch_size]
        optimizer.zero_grad()
        outputs = model(batch)
        loss = criterion(outputs, batch)
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()
    print(f"Epoch [{epoch+1}/{epochs}], Loss: {epoch_loss:.4f}")

# --------------------------------------------
# Step 7: Evaluate Model on Test Data
model.eval()
with torch.no_grad():
    test_output = model(X_test_tensor)
    mse = nn.MSELoss(reduction='none')(test_output, X_test_tensor).mean(dim=1)


thresh = mse.mean() + 3 * mse.std()
anomalies = mse > thresh

print(f"\n🔍 Anomaly Threshold: {thresh:.4f}")
print(f"🚨 Total Anomalies Detected: {anomalies.sum().item()} out of {len(mse)}")

# --------------------------------------------
# Step 9: Save Output with Anomaly Scores
results_df = df_test[features].copy()
results_df['reconstruction_error'] = mse.numpy()
results_df['is_anomaly'] = anomalies.numpy().astype(int)
results_df['timestamp'] = pd.to_datetime(results_df['time'], unit='s', errors='coerce')

results_df.to_csv("anomaly_results.csv", index=False)


# Step 10: Plot Histogram of Anomaly Scores
plt.figure(figsize=(10, 6))
sns.histplot(mse.numpy(), bins=50, kde=True)
plt.axvline(thresh.item(), color='red', linestyle='--', label='Threshold')
plt.title("Reconstruction Error Distribution")
plt.xlabel("MSE (Reconstruction Error)")
plt.ylabel("Frequency")
plt.legend()
plt.show()


def calculate_text_metrics_simple(text):
    if not isinstance(text, str):
        return 0, 0, 0, 0

    words = text.split()
    sentences = [s for s in text.split('.') if s.strip()]
    word_count = len(words)
    unique_word_count = len(set(words))
    sentence_count = len(sentences)
    avg_word_length = sum(len(word) for word in words) / word_count if word_count > 0 else 0
    return word_count, unique_word_count, sentence_count, avg_word_length


# Calculate text metrics for anomalies if applicable
if 'results_df' in locals():
    anomalies_df = results_df[results_df['is_anomaly'] == 1].copy()
else:
    anomalies_df = pd.DataFrame()

text_column = None
if 'description' in anomalies_df.columns:
    text_column = 'description'
elif 'log_text' in anomalies_df.columns:
    text_column = 'log_text'

if text_column and not anomalies_df.empty:
    print(f"Processing text metrics for column: {text_column}")
    anomalies_df['metrics'] = anomalies_df[text_column].apply(calculate_text_metrics_simple)
    anomalies_df[['word_count', 'unique_word_count', 'sentence_count', 'avg_word_length']] = \
        pd.DataFrame(anomalies_df['metrics'].tolist(), index=anomalies_df.index)
    anomalies_df.drop('metrics', axis=1, inplace=True)
elif not text_column:
    print("No relevant text column ('description', 'log_text', etc.) found in anomalies_df.")
elif anomalies_df.empty:
    print("No anomalies detected, skipping text metric calculation.")

# Provide fallback description if missing
if 'description' not in anomalies_df.columns and not anomalies_df.empty:
    anomalies_df['description'] = anomalies_df.apply(
        lambda row: f"Anomaly detected with bytes_in={row['bytes_in']}, bytes_out={row['bytes_out']}, score={row['reconstruction_error']:.4f}",
        axis=1
    )


def run_responder_dashboard():
    df = pd.read_csv("anomaly_results.csv")

    st.title("📊 Anomaly Responder Dashboard")

    if df.empty:
        st.info("No anomalies detected.")
        return

    if "resolved" not in df.columns:
        df["resolved"] = False

    for i, row in df.iterrows():
        if not df.loc[i, "resolved"]:
            with st.expander(f"Anomaly #{i+1}: {row.get('observation_name', 'Unknown')}"):
                st.write("**Rule Triggered:**", row.get("rule_names", "N/A"))
                st.write("**Justification:**", row.get("justification", "No justification provided."))
                if st.button(f"✅ Resolve Anomaly #{i+1}", key=f"resolve_{i}"):
                    df.loc[i, "resolved"] = True
                    df.to_csv("analyzed_anomalies.csv", index=False)
                    st.success("Anomaly resolved. Please rerun the app.")

    unresolved = df["resolved"].value_counts().get(False, 0)
    st.write(f"🟠 **Unresolved Anomalies Remaining:** {unresolved}")

# --------------------------------------------
# Streamlit UI: Justification Dashboard (responder_agent.py)

def run_justification_dashboard():
    file_path = "analyzed_anomalies.csv"
    if not os.path.exists(file_path):
        st.error("❌ analyzed_anomalies.csv not found. Please run analyzer_agent.py first.")
        st.stop()

    df = pd.read_csv(file_path)
    st.title("🔍 Anomaly Justification Dashboard")
    st.markdown("This dashboard shows detected anomalies and their justifications.")

    if 'resolved_ids' not in st.session_state:
        st.session_state.resolved_ids = set()

    for idx, row in df.iterrows():
        unique_id = f"{row.get('observation_name', 'obs')}-{idx}"
        if unique_id in st.session_state.resolved_ids:
            continue

        with st.expander(f"🚨 Observation: {row.get('observation_name', 'Unknown')}"):
            st.write(f"**Rule Triggered:** {row.get('rule_names', 'N/A')}")
            st.write(f"**Justification:** {row.get('justification', '[Not explained]')}")

            if st.button("✅ Mark as Resolved", key=unique_id):
                st.session_state.resolved_ids.add(unique_id)
                st.success("Marked as resolved.")
                st.experimental_rerun()

    remaining = len(df) - len(st.session_state.resolved_ids)
    st.info(f"📝 {remaining} unresolved anomalies remaining.")

if __name__ == "__main__":

    pass

import pandas as pd

results_df = pd.DataFrame([
    {"anomaly_type": "unknown IP login", "ip": "192.168.2.45", "user": "admin1"},
    {"anomaly_type": "too many failed logins", "ip": "192.168.2.10", "user": "guest1"},
    {"anomaly_type": "normal login", "ip": "127.0.0.1", "user": "test_user"},
])

# Add stable ID
results_df.reset_index(drop=True, inplace=True)
results_df['id'] = results_df.index

# Save to CSV for dashboard
results_df.to_csv("anomaly_results.csv", index=False)
print("✅ anomaly_results.csv saved with correct structure.")

results_df.reset_index(drop=True, inplace=True)
results_df['id'] = results_df.index
results_df.to_csv("anomaly_results.csv", index=False)
