# Simple local malware hash database lookup

KNOWN_MALWARE_HASHES = {
    # Example hashes (you can add more later)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "name": "Example Backdoor",
        "source": "Internal test set"
    }
}


def lookup_hash(sha256):
    """
    Returns malware info if hash is known, else None
    """
    return KNOWN_MALWARE_HASHES.get(sha256)
