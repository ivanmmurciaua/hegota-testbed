"""Central, env-driven network config for the Hegota testbed.

The Hegota devnet re-genesises and even changes chainId/RPC domain often (privacy
8141 -> hegota 3151908 ...). Nothing here is hardcoded into the PoCs: this module
resolves the live network from env (with current defaults) and PATCHES pq-dksap at
import time so every PoC uses the right chain/RPC/faucet/singleton without edits and
WITHOUT touching pq-dksap. Imported by `_pqdksap.py`, so any PoC that imports
`_pqdksap` first is automatically on the current network.

Overridable by env:
  PQ_RPC_URL   (default https://rpc1.hegota.ethrex.xyz)
  PQ_CHAIN_ID  (default 3151908)
  PQ_FAUCET_URL(default https://faucet.hegota.ethrex.xyz/api/claim)
  PQ_SINGLETON (else read from .anchors.json "singleton", written by anchor.py)
"""
import json
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
ANCHORS = _HERE / ".anchors.json"

# Make the vendored pq_dksap importable standalone (so netcfg works even if imported
# before _pqdksap). Mirrors _pqdksap's default (../vendor); PQ_DKSAP overrides.
_PQ_DKSAP = os.path.abspath(os.environ.get(
    "PQ_DKSAP", os.path.join(str(_HERE), "..", "vendor")))
if _PQ_DKSAP not in sys.path:
    sys.path.insert(0, _PQ_DKSAP)

DEFAULT_RPC = "https://rpc1.hegota.ethrex.xyz"
DEFAULT_CHAIN_ID = 3151908
DEFAULT_FAUCET = "https://faucet.hegota.ethrex.xyz/api/claim"

# Make config.py (which reads PQ_RPC_URL at import) pick the right RPC. setdefault:
# honour an explicit override, else current hegota.
os.environ.setdefault("PQ_RPC_URL", DEFAULT_RPC)

RPC_URL = os.environ["PQ_RPC_URL"]
CHAIN_ID = int(os.environ.get("PQ_CHAIN_ID", str(DEFAULT_CHAIN_ID)))
FAUCET_URL = os.environ.get("PQ_FAUCET_URL", DEFAULT_FAUCET)


def _anchors() -> dict:
    try:
        return json.loads(ANCHORS.read_text())
    except (OSError, ValueError):
        return {}


def resolve_singleton() -> str:
    return os.environ.get("PQ_SINGLETON") or _anchors().get("singleton", "")


def resolve(key: str) -> str:
    """Any anchored address (singleton, factory, ...) by key; env PQ_<KEY> wins."""
    return os.environ.get("PQ_" + key.upper()) or _anchors().get(key, "")


SINGLETON = resolve_singleton()


def _patch_pq_dksap() -> None:
    """Patch pq-dksap modules in place so all downstream code uses the live network.
    pq-dksap stays untouched on disk; this only rebinds module globals at runtime."""
    from pq_dksap import config as cfg, rpc as rpcmod
    cfg.CHAIN_ID = CHAIN_ID
    cfg.RPC_URL = RPC_URL
    cfg.FAUCET_URL = FAUCET_URL
    if SINGLETON:
        cfg.SINGLETON = SINGLETON
    rpcmod.RPC_URL = RPC_URL
    rpcmod.FAUCET_URL = FAUCET_URL


_patch_pq_dksap()


def summary() -> str:
    return (f"net: chainId={CHAIN_ID} rpc={RPC_URL} faucet={FAUCET_URL} "
            f"singleton={SINGLETON or '(unset: run anchor.py)'}")
