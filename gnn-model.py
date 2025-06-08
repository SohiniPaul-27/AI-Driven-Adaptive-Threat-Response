import streamlit as st
import torch
import torch.nn.functional as F # Added F for functional API calls 
from torch_geometric.nn import SAGEConv 
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


# --- REAL gnn_model.py content (as provided by user) ---
class GraphSAGE(torch.nn.Module):
    """
    A simple GraphSAGE model for graph node classification.
    It includes two SAGEConv layers with ReLU activation and dropout.
    """
    def __init__(self, dim_in, dim_h, dim_out):
        super().__init__()
        # First GraphSAGE layer
        self.sage1 = SAGEConv(dim_in, dim_h)
        # Second GraphSAGE layer
        self.sage2 = SAGEConv(dim_h, dim_out)

    def forward(self, x, edge_index):
        """
        Forward pass through the GraphSAGE model.
        Args:
            x (Tensor): Node feature matrix.
            edge_index (Tensor): Graph connectivity in COO format.
        Returns:
            Tensor: Output logits for node classification.
        """
        # Apply first SAGEConv layer, followed by ReLU activation
        h = self.sage1(x, edge_index)
        h = torch.relu(h)
        # Apply dropout for regularization during training
        h = F.dropout(h, p=0.5, training=self.training)
        # Apply second SAGEConv layer
        h = self.sage2(h, edge_index)
        return h

@torch.no_grad()
def predict_gnn(model, data):
    """
    Performs inference using the trained GNN model.
    Sets the model to evaluation mode, computes logits,
    and returns the predicted class indices.
    Args:
        model (torch.nn.Module): The trained GraphSAGE model.
        data (torch_geometric.data.Data): The graph data object.
    Returns:
        Tensor: Predicted class indices for each node.
    """
    model.eval() # Set the model to evaluation mode (disables dropout, batchnorm updates)
    logits = model(data.x, data.edge_index) # Get the raw logits from the model
    preds = logits.argmax(dim=1) # Get the predicted class by finding the index of the max logit
    return preds



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
            # The 'x' (node features) and 'edge_index' (graph connectivity)
            # would come from actual log parsing and correlation.
            x = torch.tensor([[1, 0], [0, 1], [1, 1]], dtype=torch.float)  # Example: 3 nodes with 2 features each
            edge_index = torch.tensor([[0, 1, 1, 2], [1, 0, 2, 1]], dtype=torch.long)  # Example: edges
            
            data = Data(x=x, edge_index=edge_index)

            # Initialize GNN model with the actual GraphSAGE class
            # The dim_out (number of output classes) should match your classification task
            # Here, it's set to 2 for a binary classification example (e.g., malicious/benign)
            model = GraphSAGE(dim_in=2, dim_h=4, dim_out=2) # Using the real GraphSAGE class now
            
            preds = predict_gnn(model, data) # Using the real predict_gnn function now

            st.subheader("📊 GNN Prediction on Threat Graph Nodes:")
            st.write("*(In a real scenario, GNN would analyze relationships between entities for complex threat patterns)*")
            st.json({"node_predictions": preds.tolist()}) # Changed key from _mock to just _predictions

            # Push to mock SOAR (display JSON)
            st.subheader("🚀 Mock SOAR Action:")
            soar_action = {
                "action": "alert_security_team",
                "technique_id": technique,
                "log_line": line,
                "explanation": explanation,
                "gnn_prediction": preds.tolist(), 
                "priority": "high" if technique in ['T1059', 'T1003'] else "medium"
            }
            st.json(soar_action)
            st.button(f"Mark as Resolved {idx+1}") # Mock button for resolution

