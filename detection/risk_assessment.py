def compute_risk_level(verdict):
    """
    Maps heuristic verdict to forensic risk level.

    Verdicts:
    - BENIGN  -> LOW
    - SUSPICIOUS -> MEDIUM
    - BLOCKED -> HIGH
    """

    if verdict == "BLOCKED":
        return "HIGH"

    if verdict == "SUSPICIOUS":
        return "MEDIUM"

    # BENIGN (displayed as SAFE)
    return "LOW"
