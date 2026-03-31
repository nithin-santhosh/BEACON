def heuristic_classify(features):
    """
    Returns classification and reason
    """

    process_count = features["process_count"]
    network_connections = features["network_connections"]
    persistence = features["persistence_detected"]

    # Rule 1: Persistence is highly suspicious
    if persistence == 1:
        return "SUSPICIOUS", "Persistence mechanism detected"

    # Rule 2: Network + process activity
    if network_connections > 0 and process_count > 1:
        return "SUSPICIOUS", "Network activity with process spawning"

    # Rule 3: Excessive process creation
    if process_count >= 8:
        return "SUSPICIOUS", "Excessive process creation"

    return "BENIGN", "No suspicious behavior detected"
