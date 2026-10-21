# Hegota rail testbed (self-contained, multi-backend)

Self-contained proof-of-concepts that assert the Hegota frame transaction rail works
on a given network, with a folder-level abstraction so the same testbed can be pointed
at different client/testnets by selecting a backend.

## Layout

```
core/                 the shared, self-contained testbed (dialect-specific)
  pocs/               the PoCs and their contract artifacts (kept together
                      because each PoC loads its .bin relative to its own dir)
    poc_r.py          recent roots (8272)
    poc_k_retest.py   keyed nonces (8250)
    poc_f_selfpay.py  frame-tx (8141) + ML-DSA gate, self-pay
    poc_d.py          pay-by-nick (directory root in 8272)
    poc_e.py          PQ smart wallet (arbitrary call, inline ML-DSA)
    *.bin, *.yul      contract artifacts
  lib/                frametx8.py (8-field codec), netcfg.py, keyfile.py, _pqdksap.py
  vendor/             the engine: pq_dksap/ (RPC, ML-DSA, ML-KEM, stealth),
                      dilithium_py/ (ETHDilithium, matches the on-chain verifier),
                      polyntt/ (dilithium_py dependency)

backends/<name>/env   per-network config (rpc, chainId, faucet, envelope flags,
                      verifier/singleton). One folder per client/testnet.
  ethrex/             ethrex Hegota (privacy-8141). The dialect core is written for.
  daisugi/            Daisugi (Nethermind, chainId 1337). Distinct dialect.

run.sh                ./run.sh [backend] [poc.py ...]
requirements.txt      pure pip deps (numpy + Ethereum helper libs)
```

The engine is vendored in `core/`, so nothing is fetched from outside this folder.
Only numpy and the Ethereum helper libs come from pip.

## Backends

A backend is a folder with an `env` file of network parameters, and optionally its own
dialect PoCs. `run.sh [backend]` selects one (default `ethrex`). If a backend fails,
that is the reported signal; the testbed is never modified to force a pass.

ethrex Hegota and Daisugi are distinct, experimental testnets, neither a frozen standard
and not interoperable. They implement the rail differently, so each has its own dialect.
A capability one has natively may simply not exist on the other, which is a valid result,
not a failure.

- `ethrex` (Python, `core/pocs`): green. Frame transactions (8141), keyed nonces (8250),
  recent roots (8272), ML-DSA inline signatures verified on-chain, self-pay.
- `daisugi` (Node, `backends/daisugi/pocs`): green. Frame-tx-only, SPHINCS-G hash-based
  signatures carried outside the tx and aggregated off-chain (a `DEP_VERIFY` frame plus
  the block recursive STARK), submitted via `eth_sendProofWrapper`. Verified: a
  signature-gated ETH transfer (good signature moves value, forged signature rejected)
  and arbitrary calls as the account.

### Capability differences (verified on-chain)

Not every capability maps across. On Daisugi:

| capability (ethrex) | on Daisugi |
| --- | --- |
| keyed nonces (8250) | not available: only the canonical nonce key 0 is accepted, `0x...8250` is a revert stub, no independent lanes |
| recent roots (8272) | does not exist: `0x...8272` has no code. Daisugi uses a time-deadline predeploy (`0x...8141`) and block-level aggregation instead |
| arbitrary call via SENDER | available (smart-wallet behavior, executes as the account) |
| pay-by-nick on a native root gate | not available natively (no 8272); only as a plain resolver contract plus a SENDER payment |

So the ethrex features built on native predeploys (8250 keyed lanes, 8272 recent roots)
are not reachable in that form on Daisugi; its rail is frame transactions plus aggregated
post-quantum signatures, not predeploy-backed state gates.

## Run

### 1. Create a virtualenv and install the pip deps

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Provide a funded key (never written into a tracked file)

```sh
export PQ_DEPLOYER_KEY=0x...          # the hex key directly, or:
export PQ_KEYFILE=/path/to/.poc_key   # a path to a funded key file
```

### 3. Run a backend

```sh
./run.sh                           # ethrex (default), all five PoCs
./run.sh ethrex poc_r.py           # ethrex, a subset
./run.sh daisugi poc_r.py          # daisugi (expected to fail for now)
```

## Notes

- `run.sh` loads `backends/<name>/env` and sets `PQ_DKSAP=core`, so the PoCs import the
  vendored engine. Override any env var on the command line to point a backend at a
  re-genesised network without editing files.
- This testnet mines in bursts; a stalled confirmation is network latency, not a PoC
  failure.
