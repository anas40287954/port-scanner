"""Utility functions shared across modules."""

def clean_banner(data: bytes) -> str:
    """Fast banner cleaning: keep printable ASCII + newlines."""
    if not data:
        return ""

    trans_table = bytearray(256)
    for i in range(256):
        if 32 <= i <= 126 or i in (10, 13, 9):
            trans_table[i] = i
        else:
            trans_table[i] = 63  # '?'

    cleaned = bytes(bytearray(data).translate(trans_table))
    return cleaned.decode('ascii', errors='ignore')[:100].strip()