import pickle
import base64
import json
import yaml

# CWE-502: Insecure Deserialization — pickle.loads on user-controlled data


def save_session(data: dict) -> str:
    """Serialize session data to base64-encoded pickle."""
    return base64.b64encode(pickle.dumps(data)).decode()


def load_session(token: str) -> dict:
    """Deserialize session from base64-encoded pickle.

    Attacker can craft a pickle payload that executes arbitrary code on load.
    """
    raw = base64.b64decode(token.encode())
    return pickle.loads(raw)  # CWE-502: Arbitrary code execution


def load_user_preferences(prefs_yaml: str) -> dict:
    """Load user preferences from YAML string.

    CWE-502: yaml.load without Loader allows arbitrary Python object instantiation.
    """
    return yaml.load(prefs_yaml)  # should be yaml.safe_load


def restore_cart(cart_b64: str) -> list:
    """Restore shopping cart from serialized data."""
    try:
        # CWE-502: Deserializes attacker-controlled pickle blob from cookie
        raw = base64.b64decode(cart_b64)
        return pickle.loads(raw)
    except Exception:
        return []
