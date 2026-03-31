def classify_threat(features):
    """
    Returns (threat_type, confidence)
    """

    process_count = features["process_count"]
    network = features["network_connections"]
    persistence = features["persistence_detected"]

    # Benign case
    if process_count == 0 and network == 0 and persistence == 0:
        return "Benign", "High"

    # Backdoor / RAT
    if persistence == 1 and network > 0:
        return "Backdoor / RAT", "High"

    # Trojan Downloader
    if network > 0 and persistence == 0:
        return "Trojan Downloader", "Medium"

    # Generic Malware
    if process_count >= 3:
        return "Generic Malware", "Medium"

    return "Unknown Suspicious", "Low"
