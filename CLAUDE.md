# Hegota rail testbed

Self-contained, multi-backend testbed that asserts the Hegota frame-transaction rail
works on a given network. It is an experimental research testbed, not an official
standard, and not production code.

## What this is

Five proof-of-concepts, each asserting one capability of the rail against a live
network, plus a folder-level backend abstraction so the same core testbed can be
pointed at different client/testnets by selecting a backend.

- `poc_r`         recent roots (EIP-8272)
- `poc_k_retest`  keyed nonces (EIP-8250)
- `poc_f_selfpay` frame transactions (EIP-8141) + ML-DSA gate, self-pay
- `poc_d`         pay-by-nick (directory root in 8272)
- `poc_e`         PQ smart wallet (arbitrary call, inline ML-DSA)

## Layout

- `core/pocs/`   the PoCs and their contract artifacts (.bin/.yul; each PoC loads its
                 artifacts relative to its own directory, so they live together)
- `core/lib/`    frame-tx codec (frametx8), network config (netcfg), key loader
                 (keyfile), engine bridge (_pqdksap)
- `core/vendor/` the engine, THIRD PARTY, read-only: pq_dksap, dilithium_py
                 (ETHDilithium, matches the on-chain verifier), polyntt
- `backends/<name>/env`  per-network config: rpc, chainId, faucet, envelope flags,
                 verifier/singleton. One folder per client/testnet.
- `run.sh [backend] [poc.py ...]`  backend selector; default backend is ethrex.

## How to run

```sh
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
export PQ_KEYFILE=/path/to/funded/.poc_key   # or PQ_DEPLOYER_KEY=0x...
./run.sh ethrex              # all green on privacy-8141
./run.sh daisugi poc_r.py    # expected to fail until a daisugi backend exists
```

Verify any change by running the real network through `run.sh`. Never verify by
editing a PoC.

## Hard rules

- NEVER modify the testbed to force a pass. If a PoC fails on a network, that failure
  is the reported signal: report it and stop. Do not patch gas, encoding, paths, or
  anything in `core/` to turn a red into a green. A patched testbed measures the patch,
  not the network.
- `core/vendor/` is vendored third-party code. Treat it read-only; do not edit it.
- Backends differ in dialect (envelope, signature scheme, predeploys). ethrex Hegota
  and Daisugi are DISTINCT testnets, not interoperable, and neither is a frozen
  standard. Do not assume one network's behavior from another.
- Code and comments in English. No em-dash anywhere. No local absolute paths in tracked
  files (use env vars or paths relative to the repo). Secrets (keys) come from env only
  and are never committed.
- git is the user's: never commit, push, init, or touch remotes. Edit files and hand
  over the commit message.

## State

- ethrex backend: GREEN, 5/5 on privacy-8141 (8141 + 8250 + 8272 + ML-DSA self-pay).
- daisugi backend: stub. Daisugi (Nethermind, chainId 1337) uses LeanSPHINCS hash-based
  signatures aggregated off-chain via a DEP_VERIFY (mode 0x4) frame (EIP-8288) and a
  different envelope, so the ethrex-dialect PoCs fail there on purpose. A real Daisugi
  codec and signer is future work (phase 2b).

## Subagents

Two focused agents keep the two dialects' knowledge separate (see `.claude/agents/`):

- `ethrex-rail`: owns the green ethrex dialect (8141/8250/8272, ML-DSA inline via the
  ZKNOX verifier, 8-field envelope). Use it to run, maintain, or extend the ethrex
  backend and its PoCs.
- `daisugi-explorer`: unbiased. Builds the Daisugi backend from its own primary sources
  (EIP-8288, LeanSPHINCS, leanVM, the Daisugi explorer/RPC). It must NOT assume the
  ethrex dialect; it starts from zero on Daisugi's own envelope, scheme, and predeploys.
