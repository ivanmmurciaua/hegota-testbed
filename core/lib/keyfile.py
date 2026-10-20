"""Load the funded key from env or a local .poc_key file, NEVER pasted into chat.

Resolution order:
  1. env PQ_DEPLOYER_KEY (or POC_PRIVATE_KEY)
  2. env PQ_KEYFILE path
  3. a local .poc_key next to this file (gitignored)
"""
import os

from eth_keys import keys

_HERE = os.path.dirname(os.path.abspath(__file__))
_LOCAL = os.path.join(_HERE, ".poc_key")


def _read_file(path: str) -> str:
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def load_key():
    """Return (pk_hex, checksum_address). Never prints the key."""
    pk_hex = os.environ.get("PQ_DEPLOYER_KEY") or os.environ.get("POC_PRIVATE_KEY")
    if not pk_hex:
        path = os.environ.get("PQ_KEYFILE") or _LOCAL
        pk_hex = _read_file(path)
    if not pk_hex:
        raise SystemExit(
            "No key. Set PQ_DEPLOYER_KEY (hex), PQ_KEYFILE (a path), or put a funded "
            "key in a local .poc_key (chmod 600, gitignored)."
        )
    addr = keys.PrivateKey(bytes.fromhex(pk_hex.removeprefix("0x"))).public_key.to_checksum_address()
    return pk_hex, addr
