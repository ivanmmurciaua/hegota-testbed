"""Network and deployment configuration for the ethrex Hegota privacy testnet."""
import os

RPC_URL = os.environ.get("PQ_RPC_URL", "https://rpc1.privacy.ethrex.xyz")
FAUCET_URL = "https://faucet.privacy.ethrex.xyz/api/claim"
CHAIN_ID = 8141

# Shared, already-deployed post-quantum verifier (ZKNOX ETHDilithium + verifyInline).
# One instance serves every stealth account; the public key is passed inline.
SINGLETON = "0x06c03c98c9c6223787cc21ae0dd386312eb94813"

# ML-DSA-44 (Dilithium2) sizes for the ETH-optimized (keccak-PRNG) variant.
PK_DEPLOY_LEN = 22400   # expanded public key (A_hat || tr || t1)
SIG_LEN = 2420          # raw signature (cTilde || z || h)

GAS_PRICE = 10 ** 8   # 0.1 gwei (baseFee on this chain is a few wei)

# CREATE2 deployer for counterfactual stealth accounts. Deployed once per chain
# (scripts/deploy_factory or demo `factory-deploy`); set PQ_FACTORY to reuse it.
FACTORY = os.environ.get("PQ_FACTORY", "")

# Repo-relative paths to the compiled bytecode.
_HERE = os.path.dirname(__file__)
ACCOUNT_BIN = os.path.join(_HERE, "..", "contracts", "Account.bin")
FACTORY_BIN = os.path.join(_HERE, "..", "contracts", "Factory.bin")
VAULT_BIN = os.path.join(_HERE, "..", "contracts", "Vault.bin")


def _read_bin(path: str) -> bytes:
    with open(path) as f:
        return bytes.fromhex(f.read().strip())


def account_creation_code() -> bytes:
    return _read_bin(ACCOUNT_BIN)


def factory_creation_code() -> bytes:
    return _read_bin(FACTORY_BIN)


def vault_creation_code() -> bytes:
    return _read_bin(VAULT_BIN)
