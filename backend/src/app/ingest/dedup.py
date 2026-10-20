"""Content-hash deduplication.

Hashing the raw record alone would merge genuinely repeated lines (the same
"Failed password" twice in one second), which would undercount brute force. So the key
also includes how many times that exact record has already appeared in the batch.
Re-uploading the same file still produces identical keys and dedups to zero.
"""

import hashlib
from collections import Counter


class DedupKeyer:
    def __init__(self) -> None:
        self._seen: Counter[str] = Counter()

    def key(self, source_type: str, raw: str) -> str:
        base = hashlib.sha256(f"{source_type}\0{raw}".encode()).hexdigest()
        n = self._seen[base]
        self._seen[base] += 1
        if n == 0:
            return base
        return hashlib.sha256(f"{base}\0{n}".encode()).hexdigest()
