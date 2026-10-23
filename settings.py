# settings.py
"""
Central runtime configuration for the Secure Aviation Messaging Prototype.

All scripts pull their defaults from here. Override any value via CLI flags.
"""

# --- MQTT broker ---
BROKER_HOST      = "127.0.0.1"
BROKER_PORT      = 1883
CLIENT_KEEPALIVE = 60           # seconds

# --- MQTT topic namespace ---
TOPIC_BASE = "aviation"         # root prefix for all topics

# --- Cryptographic algorithms (informational labels) ---
# The data-plane MAC is Ascon-Mac and is no longer selectable: a protocol
# that names its primitives in one place has nothing to dispatch on.
MAC_ALG     = "Ascon-Mac"       # data-plane MAC (informational)
KEY_SIG_ALG = "Ed25519"         # control-plane signing algorithm

# --- Feature flags ---
REQUIRE_KEY_SIG = False         # enforce Ed25519 signature on KEY before accepting session

# --- Logging ---
# LOG_LEVEL:  "WIRE"    – raw wire payloads only
#             "LIMITED" – + key events (sessions, handovers, errors)
#             "FULL"    – + verbose debug
LOG_LEVEL   = "LIMITED"

# LOG_FORMAT: "TXT"  – human-readable  logs/<component>.txt
#             "JSON" – machine-readable logs/<component>.jsonl
#             "BOTH" – both simultaneously
LOG_FORMAT  = "BOTH"

# LOG_BACKUP: rename existing log to .prev before opening on startup
LOG_BACKUP  = True
