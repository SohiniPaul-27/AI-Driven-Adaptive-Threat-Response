def generate_explanation(technique_id, log_line):
    """
    Simple prompt-engineered explanation for flagged logs.
    In practice, replace this with a local RAG or LLM API call.
    """
    explanations = {
        'T1059': "This log entry indicates possible command execution via shell or PowerShell, which could be used for malicious purposes.",
        'T1041': "This entry suggests data exfiltration via FTP or HTTP upload channels.",
        'T1071': "Indicates potential C2 communication over common protocols like HTTP, HTTPS, or DNS.",
    }
    base_exp = explanations.get(technique_id, "No explanation available.")

    prompt = f"Explain the following security alert:\nTechnique: {technique_id}\nLog: {log_line}\n\nExplanation:\n{base_exp}"

    return prompt
