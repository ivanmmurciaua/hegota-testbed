# Daisugi backend

Daisugi (Nethermind, chainId 1337) is a distinct testnet from ethrex Hegota, not
interoperable. It verifies SPHINCS-G (hash-based) signatures aggregated off-chain via a
DEP_VERIFY (mode 0x4) frame (EIP-8288); the signature travels outside the transaction and
is submitted with `eth_sendProofWrapper`. So this backend ships its own Node signer+codec
PoCs instead of the ethrex-dialect core PoCs.

## Setup (once)

```sh
./backends/daisugi/setup.sh
```

Clones the pinned `asanso/AA-PQ` reference into `vendor_ref/` and `npm install`s the deps
(`ethers@6`, `@noble/hashes`, `hash-wasm`). Needs node 22+, git, npm.

## Run

```sh
./run.sh daisugi
```

Runs `pocs/poc_submit.mjs`: generates a fresh SPHINCS-G key, derives the clone account,
funds it from the faucet, signs the v2 digest, assembles the proof wrapper, submits via
`eth_sendProofWrapper` against `PQ_RPC_URL`, and polls for receipt status `0x1`. Network
config is in `env`.

The dialect (digest, wrapper, account format) is version-pinned to this devnet via the
commit in `setup.sh`; re-verify against the RPC if it re-genesises or the pin is bumped.

## Gen1 in-frame PQ paymaster (post-quantum, all contracts)

Besides the Gen2 aggregated path, Daisugi also exposes the Gen1 native path: a type-0x06
frame tx submitted with `eth_sendRawTransaction`, carrying its witnesses INLINE, where a
VERIFY frame runs the target's own code to check its signature and `APPROVE` a scope. Two
PoCs build a post-quantum paymaster on this path where every rail role is a contract (only
the faucet-funded deployer is an EOA):

- `pocs/pq_account_gen.mjs`  our own generator for the native-opcode bytecode: the in-frame
  SPHINCS account runtime (byte-for-byte identical to the pinned reference impl at APPROVE
  scope 3, asserted on-chain), a CREATE2 clone factory (Yul, compiled with `solc`), and a
  k1 paymaster that `ecrecover`s a baked-in operator over the canonical digest.
- `pocs/pq_frame_lib.mjs`    shared glue: RPC, faucet, receipts, Arachnid deploys, and the
  reused SPHINCS signer + native-frame codec from `vendor_ref/`.
- `pocs/poc_pq_selfpay.mjs`  STEP A: a SPHINCS account clone verifies its signature in-frame
  and self-pays a transfer (scope 3). De-risks the in-frame PQ verify (it fits the 500k
  validation-prefix budget: the SPHINCS VERIFY frame uses ~384k gas).
- `pocs/poc_paymaster_pq.mjs`  STEP B: an execution-only SPHINCS account (scope 2) sponsored
  by a paymaster CONTRACT that approves payment via an operator `ecrecover`. The paymaster
  pays the gas (`receipt.payer` == paymaster, account balance delta == only the moved value).
  Replaces the k1-EOA checkpoint `pocs/poc_paymaster.mjs` (kept on disk).

Both prove a NEGATIVE too: a corrupted signature makes the in-frame VERIFY revert and the
validation-prefix simulation reject the tx, so nothing moves.

Notes grounded in the vendored Nethermind consensus source (`aggregation/frames/consensus/`):
the public-mempool validation prefix sums the leading VERIFY frames' execution-gas limits
and must be <= 500k; witness i pairs with the i-th VERIFY frame (so a payment-approving
paymaster at the second VERIFY reads witness index 1, matching the default-code
`sigIndex = pay ? 1 : 0` rule); a frame approving execution must target the sender.
