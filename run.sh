#!/usr/bin/env bash
# Run the Hegota rail testbed against a selected backend (client/network).
#
#   ./run.sh [backend] [poc.py ...]
#
# backend defaults to "ethrex"; each backend is a folder under backends/<name>/
# holding an `env` file with its network parameters. The shared testbed lives in
# core/ and is dialect-specific (ethrex: 8-field envelope, ML-DSA inline). Pointing
# it at a different-dialect network (e.g. daisugi) is expected to fail until that
# dialect gets its own codec/signer backend; a failure is a reported signal, the
# testbed is never modified to force a pass.
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
POCS=("poc_r.py" "poc_k_retest.py" "poc_f_selfpay.py" "poc_d.py" "poc_e.py")
[ "$#" -gt 0 ] && POCS=("$@")

rc=0
for f in "${POCS[@]}"; do
  echo "################ [$BACKEND] $f ################"
  "$PY" "$CORE/pocs/$f"
  code=$?
  [ "$code" -ne 0 ] && { echo ">>>> $f exit=$code"; rc=1; }
  echo
done
echo "ALL DONE (backend=$BACKEND rc=$rc)"
exit "$rc"
