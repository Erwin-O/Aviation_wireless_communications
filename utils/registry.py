# utils/registry.py
from __future__ import annotations
import json, os
from functools import lru_cache
from typing import Dict, Any

# Root of repo, one level up from utils/
ROOT = os.path.dirname(os.path.dirname(__file__))
CONFIG_DIR = os.path.join(ROOT, "config")

@lru_cache(maxsize=1)
def load_airports_db() -> Dict[str, Any]:
    path = os.path.join(CONFIG_DIR, "airports_db.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

@lru_cache(maxsize=1)
def load_aircraft_db() -> Dict[str, Any]:
    path = os.path.join(CONFIG_DIR, "aircraft_db.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _norm_space(s: str) -> str:
    """Normalize spaces and separators for comparison."""
    return " ".join(
        (s or "")
        .replace("_", " ")
        .replace("-", " ")
        .replace("/", " ")
        .upper()
        .split()
    )