#!/usr/bin/env bash
# THE ONE COMMAND. Runs the unified dual-network "sponsored post-quantum ETH send" PoC
# end to end on BOTH networks: ethrex privacy-8141 (leanSphincs-s) and Daisugi chainId
# 1337 (SPHINCS-G Gen1). It drives the two proven halves through derive -> fund -> execute,
# runs one listener loop that polls both counterfactual accounts until funded, and prints
# one unified summary. Nothing in the hegota-testbed or delta1 is modified (read-only).
#
# Optional env:
#   PQ_TESTBED              path to the hegota-testbed (default: this folder's parent)
#   PQ_KEYFILE              ethrex cold-faucet funder (keyfile pattern), 8141-funded EOA
#   PQ_DAISUGI_FUNDER_KEY   daisugi cold-faucet funder private key, 1337-funded EOA
#   ETHREX_LISTEN_TIMEOUT / DAISUGI_LISTEN_TIMEOUT   per-chain listener timeouts (seconds)
#
# Usage:
#   bash run_dual.sh                # both chains
#   bash run_dual.sh ethrex         # one chain only
#   bash run_dual.sh daisugi
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DUAL_STATE_DIR="$HERE"
# This folder lives at <testbed>/poc-dual-sponsored, so the testbed root is its parent.
export PQ_TESTBED="${PQ_TESTBED:-$(cd "$HERE/.." && pwd)}"

PY="$PQ_TESTBED/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
echo "== orchestrator python: $PY =="

# One-time daisugi reference fetch (idempotent): the SPHINCS-G signer + codec vendor_ref.
if [ ! -d "$PQ_TESTBED/backends/daisugi/vendor_ref" ]; then
  echo "== daisugi vendor_ref missing; running backends/daisugi/setup.sh =="
  ( cd "$PQ_TESTBED/backends/daisugi" && ./setup.sh ) || {
    echo "daisugi setup.sh failed; the daisugi half cannot run"; exit 1; }
fi

exec "$PY" "$HERE/orchestrate.py" "$@"
