#!/usr/bin/env bash
# Run the Hegota rail testbed against a selected backend (client/network).
#
#   ./run.sh [backend] [poc.py ...]
#
# backend defaults to "ethrex"; each backend is a folder under backends/<name>/
# holding an `env` file with its network parameters. The shared testbed lives in
# core/ and is dialect-specific (ethrex: 8-field envelope, ML-DSA inline). Pointing
# the CORE PoCs at a different-dialect network is expected to fail; a failure is a
# reported signal, the testbed is never modified to force a pass.
#
# A backend may instead ship its OWN dialect PoCs by overriding RUNNER / POCS_DIR /
# DEFAULT_POCS in its env (the daisugi backend does this: a Node signer+codec in
# backends/daisugi/pocs). The defaults below preserve the ethrex behavior exactly.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="$HERE/core"

# First arg selects a backend only if it names an existing backend folder.
BACKEND="ethrex"
if [ "$#" -gt 0 ] && [ -d "$HERE/backends/$1" ]; then BACKEND="$1"; shift; fi
BENV="$HERE/backends/$BACKEND/env"
if [ ! -f "$BENV" ]; then
  echo "unknown backend '$BACKEND'. available:"; ls "$HERE/backends" 2>/dev/null
  exit 2
fi

echo "== backend: $BACKEND =="
# shellcheck disable=SC1090
. "$BENV"
# core is split into pocs/ (PoCs + artifacts), lib/ (codec, config, key, bridge) and
# vendor/ (pq_dksap, dilithium_py, polyntt). Make all three importable, and point the
# engine resolver at vendor/.
export PQ_DKSAP="$CORE/vendor"
export PYTHONPATH="$CORE/pocs:$CORE/lib:$CORE/vendor${PYTHONPATH:+:$PYTHONPATH}"

PY="${PYTHON:-python3}"
# Dialect-aware runner. Defaults reproduce the ethrex behavior byte-for-byte:
# python interpreter, PoCs in core/pocs, the core PoCs (incl. the paymaster) when none
# are named. A backend env may override RUNNER (python|node), POCS_DIR, and DEFAULT_POCS.
RUNNER="${RUNNER:-python}"
POCS_DIR="${POCS_DIR:-$CORE/pocs}"

if [ "$#" -gt 0 ]; then
  POCS=("$@")
elif [ -n "${DEFAULT_POCS:-}" ]; then
  read -r -a POCS <<< "$DEFAULT_POCS"
else
  POCS=("poc_r.py" "poc_k_retest.py" "poc_f_selfpay.py" "poc_d.py" "poc_e.py" "poc_paymaster.py")
fi

rc=0
for f in "${POCS[@]}"; do
  echo "################ [$BACKEND] $f ################"
  case "$RUNNER" in
    python) "$PY" "$POCS_DIR/$f" ;;
    node)   node "$POCS_DIR/$f" ;;
    *) echo "unknown RUNNER '$RUNNER' (expected python or node)"; exit 2 ;;
  esac
  code=$?
  [ "$code" -ne 0 ] && { echo ">>>> $f exit=$code"; rc=1; }
  echo
done
echo "ALL DONE (backend=$BACKEND rc=$rc)"
exit "$rc"
