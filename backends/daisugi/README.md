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
