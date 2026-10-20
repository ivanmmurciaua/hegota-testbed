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

A backend is just a folder with an `env` file of network parameters. The core PoCs
are dialect-specific (ethrex: 8-field envelope, ML-DSA inline signatures, predeploys
0x...8250 and 0x...8272). Running them against a different-dialect network is expected
to fail until that dialect gets its own codec and signature backend. **If a backend
fails, that is the reported signal; the testbed is never modified to force a pass.**

- **ethrex**: runs green (8141 + 8250 + 8272 + ML-DSA self-pay gate).
- **daisugi**: carried over as-is. Daisugi uses LeanSPHINCS aggregated off-chain via a
  `DEP_VERIFY` (mode 0x4) frame, a different envelope and chainId 1337, so the ML-DSA
  PoCs fail here. The backend exists so the abstraction is complete; a real Daisugi
  codec/signer is phase 2b.

ethrex Hegota and Daisugi are distinct, experimental testnets and neither is a frozen
standard, so frame-tx compatibility between them is not assumed.

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
