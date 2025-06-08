import streamlit as st
import torch
from torch_geometric.data import Data
import re


MITRE_MAPPING = {
    'T1059': ['powershell', 'cmd.exe', 'command line', 'shell'], # Command and Scripting Interpreter
    'T1041': ['ftp', 'http upload', 'exfiltrate'], # Exfiltration Over C2 Channel
    'T1071': ['http', 'https', 'dns', 'domain name system'], # Application Layer Protocol
    'T1003': ['lsass', 'mimikatz', 'credential dump'], # OS Credential Dumping
    'T1136': ['new user', 'useradd', 'net user'], # Create Account
}

def fingerprint_logs(log_lines):
    """
    Scan logs for MITRE ATT&CK techniques keywords.
    Returns a list of dictionaries, each indicating a detected technique
    and the corresponding log line that triggered the detection.
    """
    detected_techniques = []

    for line in log_lines:
        lower_line = line.lower()
        for technique_id, keywords in MITRE_MAPPING.items():
            # Check if any of the keywords for the current technique are in the log line
            # Using regex with word boundaries (\b) for more precise keyword matching
            if any(re.search(r'\b' + re.escape(kw) + r'\b', lower_line) for kw in keywords):
                detected_techniques.append({
                    'technique_id': technique_id,
                    'log_line': line.strip(), # Remove leading/trailing whitespace
                    'matched_keywords': [kw for kw in keywords if re.search(r'\b' + re.escape(kw) + r'\b', lower_line)]
                })
                # Once a technique is detected in a line, move to the next line
                break
    return detected_techniques

# In a real scenario, this would involve actual LLM calls with RAG from MITRE ATT&CK.
# from llm_rag import generate_explanation
def generate_explanation(technique_id, log_line):
    """
    Mock function to generate an explanation for a detected technique.
    In a real scenario, this would use an LLM (e.g., Gemini-2.0-flash via API)
    with RAG from MITRE ATT&CK details.
    """
    explanations = {
        'T1059': f"Detected command-line execution often associated with initial access or execution. The log line '{log_line}' suggests a scripting interpreter was used.",
        'T1041': f"Identified data exfiltration attempt. The log line '{log_line}' shows data being sent out via a suspicious protocol.",
        'T1071': f"Application layer protocol usage was observed. The log line '{log_line}' indicates common network communication that could be C2 or data transfer.",
        'T1003': f"Potential credential dumping activity. The log line '{log_line}' mentions keywords related to memory access or credential theft tools.",
        'T1136': f"New user account creation detected. The log line '{log_line}' indicates a new user was added, which could be legitimate or malicious.",
        'DEFAULT': f"Anomalous activity detected based on MITRE ATT&CK technique {technique_id}. Log: '{log_line}'. This could indicate various malicious behaviors."
    }
    return explanations.get(technique_id, explanations['DEFAULT'])
# --- END MOCK llm_rag.py content ---

class GraphSAGE(torch.nn.Module):
    """
    Mock GraphSAGE model for demonstration purposes.
    It doesn't perform actual graph convolutions.
    """
    def __init__(self, dim_in, dim_h, dim_out):
        super().__init__()
        self.linear1 = torch.nn.Linear(dim_in, dim_h)
        self.linear2 = torch.nn.Linear(dim_h, dim_out)

    def forward(self, x, edge_index):
        # In a real GNN, this would involve message passing and aggregation
        # For this mock, we just pass through linear layers.
        x = torch.relu(self.linear1(x))
        x = self.linear2(x)
        return x

def predict_gnn(model, data):
    """
    Mock function to predict GNN output.
    In a real scenario, this would run inference on a trained GNN model.
    """
    # For demonstration, return a mock prediction based on the first feature
    # In a real scenario, this would use the GNN model to make predictions
    # e.g., model(data.x, data.edge_index).argmax(dim=1)
    if data.x is not None:
        # Simulate some prediction, perhaps based on input features
        # For simplicity, let's just return a mock "threat score" for each node
        return torch.sigmoid(torch.tensor([0.8, 0.2, 0.9])) # Mock scores
    return torch.tensor([])



# --- Streamlit App ---
st.set_page_config(layout="wide", page_title="AI Threat Detection Dashboard")

st.title("🔒 AI Threat Detection and Explanation Dashboard")
st.markdown("This dashboard demonstrates real-time log fingerprinting, AI-driven explanation, and mock GNN threat analysis.")

st.sidebar.header("Input Logs")
user_logs = st.sidebar.text_area("Paste your logs here", "\n".join([
    "User 'john.doe' executed: powershell.exe -NoP -NonI -Exec Bypass",
    "System update downloaded via HTTPS.",
    "Attempted data exfiltration to malicious.server.com via FTP.",
    "DNS query for new_malicious_domain.com",
    "Failed login attempt for user 'admin' from 192.168.1.100.",
    "A user account 'evil_hacker' was created on the domain.",
    "Process 1234 accessed LSASS memory.",
    "Normal system startup.",
    "User logged in from office network.",
    "Application started successfully."
]), height=300)
input_logs = [line.strip() for line in user_logs.splitlines() if line.strip()]

# Fingerprint logs
detected_anomalies = fingerprint_logs(input_logs)

st.header("Detected MITRE ATT&CK Techniques")

if not detected_anomalies:
    st.info("🥳 No suspicious activity detected in logs.")
else:
    for idx, detection in enumerate(detected_anomalies):
        technique = detection['technique_id']
        line = detection['log_line']
        matched_keywords = detection['matched_keywords']

        with st.expander(f"🚨 Detection {idx+1}: **{technique}** - {line}"):
            st.markdown(f"**Log Line:** `{line}`")
            st.markdown(f"**Matched Keywords:** `{', '.join(matched_keywords)}`")

            # Generate explanation
            explanation = generate_explanation(technique, line)
            st.subheader("🧠 LLM Justification / Explanation:")
            st.info(explanation)

            # Mock threat graph data for GNN inference
            # In a real application, this graph would be dynamically built
            # based on relationships between entities (users, IPs, processes)
            # from multiple correlated log entries.
            x = torch.tensor([[1, 0], [0, 1], [1, 1]], dtype=torch.float)  # 3 nodes with 2 features each
            edge_index = torch.tensor([[0, 1, 1, 2], [1, 0, 2, 1]], dtype=torch.long)  # edges
            
            data = Data(x=x, edge_index=edge_index)

            # Initialize mock GNN model
            model = GraphSAGE(dim_in=2, dim_h=4, dim_out=2)
           

            preds = predict_gnn(model, data)

            st.subheader("📊 Mock GNN Prediction on Threat Graph Nodes:")
            st.write("*(In a real scenario, GNN would analyze relationships between entities for complex threat patterns)*")
            st.json({"node_predictions_mock": preds.tolist()})

            # Push to mock SOAR (display JSON)
            st.subheader("🚀 Mock SOAR Action:")
            soar_action = {
                "action": "alert_security_team",
                "technique_id": technique,
                "log_line": line,
                "explanation": explanation,
                "gnn_prediction_mock": preds.tolist(),
                "priority": "high" if technique in ['T1059', 'T1003'] else "medium"
            }
            st.json(soar_action)
            st.button(f"Mark as Resolved {idx+1}") # Mock button for resolution