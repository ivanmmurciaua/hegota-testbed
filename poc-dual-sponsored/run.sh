#!/usr/bin/env bash
# Run the ethrex-half dual-sponsored PoC against live Hegota (privacy-8141).
# Points PYTHONPATH at the hegota-testbed (READ-ONLY; nothing in the repo is modified)
# and sets the privacy-8141 envelope flags, exactly as the testbed's own run.sh does.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This folder lives at <testbed>/poc-dual-sponsored, so the testbed root is its parent.
TESTBED="${PQ_TESTBED:-$(cd "$HERE/.." && pwd)}"
CORE="$TESTBED/core"

export PQ_DKSAP="$CORE/vendor"
export PYTHONPATH="$CORE/pocs:$CORE/lib:$CORE/vendor${PYTHONPATH:+:$PYTHONPATH}"

# Live ethrex Hegota backend (mirrors backends/ethrex/env).
export PQ_RPC_URL="${PQ_RPC_URL:-https://rpc1.privacy.ethrex.xyz}"
export PQ_CHAIN_ID="${PQ_CHAIN_ID:-8141}"
export PQ_FAUCET_URL="${PQ_FAUCET_URL:-https://faucet.privacy.ethrex.xyz/api/claim}"
export PQ_FEE_NESTED="${PQ_FEE_NESTED:-1}"
export PQ_OMIT_RECENT_ROOTS="${PQ_OMIT_RECENT_ROOTS:-1}"
# Not used by the leanSphincs path, but netcfg/poc_paymaster read it at import.
export PQ_SINGLETON="${PQ_SINGLETON:-0x1602bef8eaa64f9fd3cdf4331473400deee70201}"

PY="$TESTBED/.venv/bin/python"
[ -x "$PY" ] || PY="python3"
echo "== python: $PY =="
"$PY" "$HERE/dual_sponsored_ethrex.py"
