"""Trust-on-first-use hashing -- detect source changes between scans."""

import json
import sys
from pathlib import Path

STORE_PATH = Path.home() / ".pre-mcp" / "trust-store.json"


def load() -> dict:
    if STORE_PATH.exists():
        try:
            return json.loads(STORE_PATH.read_text())
        except Exception:
            return {}
    return {}


def save(store: dict) -> None:
    try:
        STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        STORE_PATH.write_text(json.dumps(store, indent=2))
    except OSError as e:
        print(f"[warn] could not write trust store: {e}", file=sys.stderr)


_FIRST_SCAN = object()  # sentinel

def check(identifier: str, current_hash: str):
    """
    Returns _FIRST_SCAN sentinel if never scanned before.
    Returns None if hash unchanged since last scan.
    Returns previous hash string if source has changed.
    """
    store = load()
    prev = store.get(identifier)
    if prev is None:
        return _FIRST_SCAN
    return prev if prev != current_hash else None


def record(identifier: str, source_hash: str) -> None:
    store = load()
    store[identifier] = source_hash
    save(store)
