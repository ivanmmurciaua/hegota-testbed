"""Read-only bridge to the vendored pq-dksap engine.

Puts the pq_dksap package on sys.path. The default points at the vendored engine
under ../vendor; override with PQ_DKSAP if it lives elsewhere.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT = os.path.join(_HERE, "..", "vendor")
PQ_DKSAP = os.path.abspath(os.environ.get("PQ_DKSAP", _DEFAULT))

if not os.path.isdir(os.path.join(PQ_DKSAP, "pq_dksap")):
    raise SystemExit(
        f"pq_dksap engine not found under {PQ_DKSAP}. "
        "Set PQ_DKSAP to the directory that contains the pq_dksap package."
    )

if PQ_DKSAP not in sys.path:
    sys.path.insert(0, PQ_DKSAP)

# Env-driven network config: patches pq-dksap (chainId/RPC/faucet/singleton) for the
# live Hegota network, so every PoC that imports _pqdksap first is on the current net
# without edits. Must run after the sys.path insert above (netcfg imports pq_dksap).
import netcfg  # noqa: E402,F401
