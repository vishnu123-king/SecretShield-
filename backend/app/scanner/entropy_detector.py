import math
import re
from typing import Dict, Tuple

# Pre-compiled patterns for common low-entropy or pseudo-random non-secrets
UUID_PATTERN = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
HEX_HASH_PATTERN = re.compile(r'^[0-9a-fA-F]{32,64}$')
COMMON_WORDS = {
    'password', 'secret', 'changeme', 'admin', 'administrator', 'root',
    'localhost', 'development', 'production', 'test', 'example', 'placeholder'
}

def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string:
    H = - sum(p(x) * log2(p(x)))
    Higher entropy indicates higher randomness (likely an API key or generated secret).
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies: Dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)

def analyze_entropy(candidate: str, threshold: float = 3.5) -> Tuple[bool, float, str]:
    """
    Analyze if candidate string has significant entropy for credential detection.
    Returns (is_high_entropy, entropy_score, explanation).
    """
    candidate = candidate.strip("\"'` ")
    
    # Too short to measure meaningful entropy
    if len(candidate) < 12:
        return False, calculate_shannon_entropy(candidate), "Candidate too short for entropy evaluation"

    # Filter out common obvious non-secrets
    if UUID_PATTERN.match(candidate):
        return False, calculate_shannon_entropy(candidate), "Matches UUID format (likely non-secret identifier)"

    if candidate.lower() in COMMON_WORDS:
        return False, calculate_shannon_entropy(candidate), "Matches common dictionary word/placeholder"

    entropy = calculate_shannon_entropy(candidate)

    # Base64 strings typically have entropy > 4.2
    # Hex strings typically have entropy > 3.0
    # Alphanumeric random secrets typically have entropy > 3.8
    if entropy >= 4.5:
        return True, entropy, f"Very high Shannon entropy ({entropy:.2f}), strongly indicative of high-randomness secret/key"
    elif entropy >= threshold:
        return True, entropy, f"Elevated Shannon entropy ({entropy:.2f}), potential high-entropy token or credential"
    else:
        return False, entropy, f"Low Shannon entropy ({entropy:.2f}), likely structured text or low-randomness string"
