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
    poc_paymaster.py  frame-native paymaster (third party pays the gas)
    poc_leansphincs_s.py  hash-based PQ self-pay (leanSphincs-s, in-frame verify)
    *.bin, *.yul      contract artifacts
  lib/                frametx8.py (8-field codec), netcfg.py, keyfile.py, _pqdksap.py
  vendor/             the engine: pq_dksap/ (RPC, ML-DSA, ML-KEM, stealth),
                      dilithium_py/ (ETHDilithium, matches the on-chain verifier),
                      polyntt/ (dilithium_py dependency),
                      leansphincs/ (leanSphincs-s keccak signer, MIT, pip-only)

backends/<name>/env   per-network config (rpc, chainId, faucet, envelope flags,
                      verifier/singleton). One folder per client/testnet.
  ethrex/             ethrex Hegota (privacy-8141). The dialect core is written for.
  daisugi/            Daisugi (Nethermind, chainId 1337). Distinct dialect, own Node PoCs:
    poc_submit.mjs      self-pay account create (aggregated, Gen2)
    poc_transfer.mjs    SPHINCS-gated ETH transfer (aggregated, Gen2)
    poc_call.mjs        arbitrary call as the account (smart wallet)
    poc_pq_selfpay.mjs  in-frame SPHINCS self-pay (Gen1)
    poc_paymaster_pq.mjs PQ account + paymaster contract, both contracts (Gen1, tx 0xd2ea386b)
    poc_paymaster.mjs   k1-EOA paymaster, kept as plumbing baseline

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
  signatures, two paths: aggregated (Gen2, a `DEP_VERIFY` frame plus the block recursive
  STARK, `eth_sendProofWrapper`) and inline (Gen1, verified in-frame by a staticcall to the
  live SPHINCS verifier, `eth_sendRawTransaction`). Verified: a SPHINCS-gated ETH transfer,
  arbitrary calls as the account, and a PQ account sponsored by a paymaster contract (both
  contracts, no rail-role EOA, Gen1, tx 0xd2ea386b).

### A second signature scheme on ethrex: leanSphincs-s

`poc_leansphincs_s.py` runs a HASH-based PQ signature on the same ethrex rail, next
to the lattice ML-DSA PoCs. leanSphincs-s (leanSphincs small: h=26, k=13, a=12,
T=128, a 4164-byte signature) is a SPHINCS+ variant over Ethereum Keccak-256,
verified on-chain in ~249 keccak256 calls by the shared verifier
`0xae3bA3e1...3481a`. The spend is a two-frame self-pay: the VERIFY frame
delegatecalls the shared frame module `0xAA481E83...4295`, which SIGDATACOPYs the
ARBITRARY witness and staticcalls the verifier on `compute_sig_hash(tx)`, then
APPROVEs execution and payment; a SENDER frame moves the value. The account
self-pays (it is the frame-tx sender and payer), so the whole spend is ~288K gas
with no relayer, operator or paymaster. Where `poc_f_selfpay` gates a transfer
behind a ~5M-gas ML-DSA verify batched via `FLAG_ATOMIC_BATCH`, here the hash-based
verify runs inside the VERIFY frame itself.

The signer is the vendored MIT Python signer `core/vendor/leansphincs/` (pip-only,
needs only pycryptodome). At runtime the PoC keygens a fresh key, faucet-funds a
fresh throwaway EOA (falling back to a funded EOA from `PQ_DEPLOYER_KEY` only if the
faucet is rate-limited), deploys a fresh `SphincsFrameAccount`, self-pays a tiny
transfer, and checks the receipt (status, self-pay from/payer, value moved, gasUsed
~288K) plus a tampered-witness negative that simulation rejects. It is NOT in the
default `./run.sh ethrex` set (a distinct scheme, and the Python keygen adds a
couple of seconds); run it by name:

```sh
./run.sh ethrex poc_leansphincs_s.py
```

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

## The PoC matrix (how to read the set)

The PoCs vary along four independent axes. A file name only carries the first one, so
the set looks tangled until the axes are pulled apart:

1. Capability: what the transaction demonstrates (move value, self-pay, paymaster,
   smart-wallet call, pay-by-nick, recent roots, keyed nonces). This is the real content.
2. Signature world: classical k1/ECDSA (used to isolate the frame mechanics) versus
   post-quantum (ML-DSA on ethrex, SPHINCS-G on Daisugi).
3. Network / backend: ethrex (8141) versus Daisugi (1337). This is already the
   `backends/` folder axis.
4. Submission path (Daisugi only): Gen1 inline (`eth_sendRawTransaction`, signature in
   the tx) versus Gen2 aggregated (`eth_sendProofWrapper`, EIP-8288, signature outside
   the tx in the block STARK).

Two things that look like separate categories are not: keyed nonces and recent roots are
capabilities (axis 1), just ethrex-only ones; and aggregation is not a capability at all,
it is the Daisugi submission path (axis 4), orthogonal to what the transaction does.

Capability by backend (the cell names the PoC, its signature world, and, on Daisugi, its
submission path):

| capability (axis 1) | ethrex (ML-DSA) | Daisugi (SPHINCS-G) |
| --- | --- | --- |
| deploy / create a self-pay account | implicit in F | `poc_submit.mjs` (PQ, Gen2) |
| move ETH (SENDER) | part of F / E | `poc_transfer.mjs` (PQ, Gen2) |
| self-pay PQ gasless (account pays, PQ gate) | `poc_f_selfpay.py` | `poc_transfer.mjs` |
| smart wallet, arbitrary call | `poc_e.py` | `poc_call.mjs` (PQ) |
| paymaster, a third party pays the gas | `poc_paymaster.py` (account ML-DSA, operator ECDSA leaf) | `poc_paymaster_pq.mjs` (PQ SPHINCS account + paymaster contract, both contracts, Gen1 in-frame, green: tx 0xd2ea386b). The old k1-EOA `poc_paymaster.mjs` is kept as a plumbing baseline. PQ via Gen2 aggregated (cheap) is the open frontier |
| recent roots (freshness) | `poc_r.py` | not available |
| pay-by-nick (directory) | `poc_d.py` | plain resolver only, no native root gate |
| keyed nonces (lanes) | `poc_k_retest.py` | key 0 only |

The k1 cell is a checkpoint, not a ceiling: the Daisugi paymaster was first proven with
ECDSA on the Gen1 path to isolate the sponsorship mechanics. The account signature can be
post-quantum there too. It has two forms, and only one is missing:

- PQ SPHINCS via Gen1 (inline): BUILT AND GREEN (`poc_paymaster_pq.mjs`, tx 0xd2ea386b).
  The account's SPHINCS signature is verified in the frame by a staticcall to the live
  SPHINCS verifier (gas-heavy: account VERIFY ~415k + paymaster VERIFY ~70k = ~485k, under
  the 500k validation-prefix budget), and a paymaster contract pays. Both the account and
  the paymaster are contracts; no EOA in a rail role.
- PQ SPHINCS via Gen2 (aggregated, EIP-8288): the signature moves out of the tx into the
  block STARK, so the sponsored transfer would stay cheap (~3k per verify instead of ~485k).
  This is the one still-empty cell: the public portal's `validateProofWrapper` hardcodes a
  single self-pay VERIFY (flags 0x03), so a sponsored aggregated layout needs a direct node
  RPC (our own Daisugi node) or an upstream relaxation of that profile.

Joining the aggregated path with sponsorship (cheap + fully PQ + a third party pays) is
the open combo. It is admission-blocked by the public portal's profile, not by consensus.

## Run

### Setup (once, per backend)

```sh
# ethrex (Python): venv + pip deps
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# daisugi (Node): fetch the pinned PQ reference + npm install
./backends/daisugi/setup.sh
```

### ethrex (needs a funded key, never written into a tracked file)

```sh
export PQ_KEYFILE=/path/to/.poc_key   # or: export PQ_DEPLOYER_KEY=0x...
./run.sh                              # ethrex (default), all six PoCs
./run.sh ethrex poc_paymaster.py      # a subset
```

### daisugi (no key: the PoCs self-fund from the faucet)

```sh
./run.sh daisugi                      # all daisugi PoCs
./run.sh daisugi poc_paymaster_pq.mjs # just the PQ account + paymaster contract milestone
```

A faucet cooldown error is rate limiting, not a PoC failure: retry later.

## Notes

- `run.sh` loads `backends/<name>/env` and sets `PQ_DKSAP=core`, so the PoCs import the
  vendored engine. Override any env var on the command line to point a backend at a
  re-genesised network without editing files.
- This testnet mines in bursts; a stalled confirmation is network latency, not a PoC
  failure.
