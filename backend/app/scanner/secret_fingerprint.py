import hashlib
import re

def compute_fingerprint(secret: str) -> str:
    """
    Compute a deterministic SHA-256 fingerprint for a secret.
    The secret is normalized (stripped of wrapping quotes and whitespace)
    before hashing. Raw secret is never persisted.
    """
    normalized = secret.strip().strip("\"'`").strip()
    hasher = hashlib.sha256()
    hasher.update(normalized.encode('utf-8'))
    return f"sha256:{hasher.hexdigest()[:16]}"

def mask_secret(secret: str) -> str:
    """
    Safely mask a secret for UI display and reporting.
    Retains minimal prefix/suffix when helpful for identification (e.g., AKIA...)
    while obscuring the core credential payload.
    """
    s = secret.strip().strip("\"'`").strip()
    length = len(s)

    if length <= 4:
        return "****"
    elif length <= 8:
        return s[:2] + "****" + s[-1:]
    elif length <= 16:
        return s[:3] + "********" + s[-2:]
    else:
        # For longer secrets, show up to 4 prefix chars (e.g., AKIA, ghp_) and 4 suffix chars
        prefix_len = 4
        suffix_len = 4
        stars_len = min(length - (prefix_len + suffix_len), 16)
        return s[:prefix_len] + ("*" * stars_len) + s[-suffix_len:]
