import re

# Simple example MITRE ATT&CK technique mapping keywords
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
            if any(re.search(r'\b' + re.escape(kw) + r'\b', lower_line) for kw in keywords):
                # Using regex with word boundaries (\b) for more precise keyword matching
                # This prevents partial matches (e.g., 'shell' matching 'seashell')
                detected_techniques.append({
                    'technique_id': technique_id,
                    'log_line': line.strip(), # Remove leading/trailing whitespace
                    'matched_keywords': [kw for kw in keywords if re.search(r'\b' + re.escape(kw) + r'\b', lower_line)]
                })
                break # Move to the next log line after finding a match for any technique
    return detected_techniques

if __name__ == "__main__":
    print("--- Running Log Fingerprinting Example ---")

    sample_logs = [
        "User 'john.doe' executed: powershell.exe -NoP -NonI -Exec Bypass",
        "System update downloaded via HTTPS.",
        "Attempted data exfiltration to malicious.server.com via FTP.",
        "DNS query for new_malicious_domain.com",
        "Failed login attempt for user 'admin' from 192.168.1.100.",
        "A user account 'evil_hacker' was created on the domain.",
        "Process 1234 accessed LSASS memory."
    ]

    print("\n--- Processing Sample Logs ---")
    for log in sample_logs:
        print(f"Log: {log}")

    detections = fingerprint_logs(sample_logs)

    print("\n--- Detected MITRE ATT&CK Techniques ---")
    if detections:
        for d in detections:
            print(f"Technique ID: {d['technique_id']}")
            print(f"  Matched Log: \"{d['log_line']}\"")
            print(f"  Keywords: {', '.join(d['matched_keywords'])}")
            print("-" * 20)
    else:
        print("No MITRE ATT&CK techniques detected in sample logs.")

    print("\n--- Example with no matches ---")
    no_match_logs = [
        "Normal system startup.",
        "User logged in from office network.",
        "Application started successfully."
    ]
    no_detections = fingerprint_logs(no_match_logs)
    if no_detections:
        print("Unexpected detections in no_match_logs.")
    else:
        print("Correctly, no techniques detected in no-match logs.")

    print("\n--- Log Fingerprinting Example Complete ---")
