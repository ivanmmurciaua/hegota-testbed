#!/usr/bin/env bash
# Fetch the pinned asanso/AA-PQ reference into vendor_ref/ and install the Node deps
# the signer and submission path need. Run once:  ./backends/daisugi/setup.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REF_DIR="$HERE/vendor_ref/AA-PQ"
REPO_URL="https://github.com/asanso/AA-PQ.git"
# Pinned commit of asanso/AA-PQ. The Daisugi dialect (digest, wrapper, account
# format) is version-pinned to this devnet; re-verify if you bump it.
PIN="a4b1d73b843987412f8423ae601b531e4c83bce7"

echo "== daisugi setup =="
echo "reference: $REPO_URL @ $PIN"

if [ -d "$REF_DIR/.git" ] && [ "$(git -C "$REF_DIR" rev-parse HEAD 2>/dev/null || true)" = "$PIN" ]; then
  echo "reference already at pinned commit, skipping clone"
else
  rm -rf "$REF_DIR"
  mkdir -p "$REF_DIR"
  git -C "$REF_DIR" init -q
  git -C "$REF_DIR" remote add origin "$REPO_URL"
  # Shallow-fetch only the pinned commit.
  git -C "$REF_DIR" fetch -q --depth 1 origin "$PIN"
  git -C "$REF_DIR" checkout -q FETCH_HEAD
  echo "fetched reference at $(git -C "$REF_DIR" rev-parse HEAD)"
fi

echo "== installing Node deps (ethers@6, @noble/hashes, hash-wasm) =="
# Installed at the backend root so both our pocs/ and the fetched reference modules
# resolve node_modules by walking up. node_modules/ is gitignored.
( cd "$HERE" && npm install --no-fund --no-audit >/dev/null )
echo "done. now run:  ./run.sh daisugi"
