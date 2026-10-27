# Dual-network sponsored post-quantum ETH send

One command runs the SAME proof-of-concept on BOTH rail testnets:

- ethrex privacy-8141, leanSphincs-s (hash-based), Python core PoCs
- Daisugi (Nethermind) chainId 1337, SPHINCS-G Gen1, Node backend PoCs

On each network a post-quantum account that:

1. has a COUNTERFACTUAL address, computed BEFORE any deploy as a pure function of its
   public key + initcode via CREATE2 (no EOA in the derivation);
2. RECEIVES ETH at that address while it still has no code (the value to send onward);
3. is DEPLOYED WITHOUT any EOA: an openSponsor CONTRACT is the frame-tx sender and pays
   the deploy gas. Its VERIFY frame APPROVEs execution + payment unconditionally (no
   signature, no witness read); a DEFAULT frame calls the generic CREATE2 factory to
   place the account. No EOA signs TX1;
4. then makes a NATIVE ETH SEND to a fresh recipient whose GAS is paid by a funded
   PaymasterGated CONTRACT (operator ECDSA baked in code), NOT self-pay.

Net per chain: account funded with X, recipient receives exactly the moved value, the
account pays ZERO gas (sponsor pays the deploy, paymaster pays the send). Two negatives
(tampered account witness, tampered operator witness) are rejected at validation.

This is an experimental research testbed, not an official standard, not production.

## The one command

```sh
cd poc-dual-sponsored
bash run_dual.sh                 # both chains
bash run_dual.sh ethrex          # one chain only (optional)
bash run_dual.sh daisugi
```

`run_dual.sh` sets each chain's env, runs `backends/daisugi/setup.sh` once if
`vendor_ref` is missing, then runs `orchestrate.py`: the single driver + the one listener
loop + the unified summary. A live failure is reported and stops that chain; a green is
never faked.

## Prerequisites

- The Python venv with the testbed requirements:
  `python3 -m venv ../.venv && ../.venv/bin/pip install -r ../requirements.txt`
  (the leanSphincs path needs the vendored engine under `../core/vendor`).
- The daisugi backend set up once (fetches the pinned signer reference and installs the
  Node deps `ethers@6`, `@noble/hashes`, `hash-wasm`): `../backends/daisugi/setup.sh`
  (node 22+, git, npm). `run_dual.sh` runs it automatically if `vendor_ref` is absent.

Nothing under `core/` or `backends/` is modified: both halves import those pieces
READ-ONLY (the ethrex half via `../core` on `PYTHONPATH`; the daisugi half via relative
imports of `../backends/daisugi/pocs/{pq_frame_lib,pq_account_gen}.mjs`, whose node deps
resolve from `../backends/daisugi/node_modules`).

## The four phases

1. DERIVE  each half generates a fresh key + recipient, computes its counterfactual
   account, verifies the on-chain singletons have code (never a fake pass), writes a local
   state file. The driver prints both accounts and recipients.
2. LISTEN  the driver launches each half's `fund` step and runs ONE poll loop reading both
   chains' account balances by direct JSON-RPC until ETH arrives at each counterfactual
   account (per-chain timeout; ethrex 900 s, daisugi 600 s, env-overridable). A chain
   proceeds only once its account is observed funded AND its fund step exited cleanly.
3. EXECUTE for each funded chain: the no-EOA openSponsor deploy (TX1), then the
   paymaster-paid PQ send (TX2, account zero gas), plus the two negatives.
4. SUMMARY one unified table per chain: deploy tx (payer == sponsor), spend tx (payer ==
   paymaster), account zero gas, recipient received == value.

## Funding (honest note)

Funding is FAUCET-FIRST and is the stand-in for a real external deposit into the
counterfactual account. If a faucet is cold, an optional ENV FUNDER is the documented
fallback; it is only ever a funder/deployer EOA that signs NO rail transaction, and its
key is never written to a tracked file (keyfile pattern / env only):

- ethrex: `PQ_KEYFILE=/path/to/funded/.poc_key` (or `PQ_DEPLOYER_KEY=0x...`), an
  8141-funded EOA. The faucet drips a large fixed amount to a throwaway EOA, which then
  sends a controlled amount to the account.
- daisugi: `PQ_DAISUGI_FUNDER_KEY=0x...`, a 1337-funded EOA. The faucet funds the account
  directly (it keeps the drip; the spend is measured as a relative delta).

Either way the listener gate is a real on-chain balance read of the counterfactual
account, independent of the fund step.

## On-chain infrastructure pins (env-overridable; on-chain infra, not secrets)

These are devnet singletons; a re-genesis changes them (and thus every derived address).
All are re-verified to have code at `derive`. Each is env-overridable.

ethrex (privacy-8141):

| role | address | env var |
| --- | --- | --- |
| generic CREATE2 factory | `0xd0526914f1045eb6ec89f9a93c8599306f9f667a` | `PQ_FACTORY` |
| openSponsor | `0x655aab4c59b587fd7882ff6566198b40c45a7f21` | `PQ_OPEN_SPONSOR` |
| leanSphincs verifier | `0xae3bA3e1...` (from `poc_leansphincs_s`) | (inherited) |
| leanSphincs frame module | `0xAA481E83...` (from `poc_leansphincs_s`) | (inherited) |

daisugi (chainId 1337): the openSponsor, factory, impl and paymaster are deployed
deterministically via the Arachnid proxy at run time (stable addresses across runs,
idempotent via `hasCode`). The reused SPHINCS-G verifier is
`0xf505AD2Cff58b84E145D637d99Fae0617B5685BE`.

## Envelope flags

The ethrex half runs with the privacy-8141 envelope flags (set by `run_dual.sh` /
`orchestrate.py` / `run.sh`, env-overridable):
`PQ_RPC_URL=https://rpc1.privacy.ethrex.xyz`, `PQ_CHAIN_ID=8141`,
`PQ_FAUCET_URL=https://faucet.privacy.ethrex.xyz/api/claim`, `PQ_FEE_NESTED=1`,
`PQ_OMIT_RECENT_ROOTS=1`, plus the leanSphincs singletons. The daisugi half uses
`PQ_RPC_URL=https://daisugi.fyi/rpc`, `PQ_CHAIN_ID=1337`.

## Files

- `run_dual.sh`                 the one command (per-chain env + setup + orchestrator).
- `orchestrate.py`              the driver, the single listener loop, the unified summary.
- `dual_sponsored_ethrex.py`    the ethrex half (modes `derive|fund|execute|all`).
- `dual_sponsored_daisugi.mjs`  the daisugi half (same three-mode dispatch).
- `run.sh`                      ethrex-only env wrapper for a direct single-process run.

Per-run `*.state.json`, `*.result.json`, `*.run.log` and `*.out` files are written here
and are gitignored (they hold the fresh keys for the run).
