"""Persistent post-quantum vault (see contracts/Vault.sol).

A normal contract that holds funds swept in from stealth accounts and releases
them only on a valid ML-DSA signature, verified onchain by the shared singleton
in NORMAL execution (not the gas-capped frame-tx prefix), so the signature is a
HARD gate. A relayer submits `withdraw` and pays gas; the signature binds the
destination and amount, so the relayer cannot steal or redirect.

This module derives the vault's ML-DSA key from the owner's seed, predicts its
counterfactual CREATE2 address, signs a withdraw, and builds an unsigned withdraw
calldata (no ML-DSA signature) that a plain k1 call reverts on, to show the funds
are post-quantum protected.
"""
import hashlib
from dataclasses import dataclass

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_canonical_address

from . import mldsa, rpc, stealth
from .config import CHAIN_ID, SINGLETON, vault_creation_code
from .legacytx import sign_legacy

_VAULT_KEY_SALT = b"pq-dksap/vault-key/v1"
WITHDRAW_SELECTOR = keccak(text="withdraw(address,uint256,bytes,bytes)")[:4]
_NONCE_SELECTOR = keccak(text="nonce()")[:4]
_VERIFY_SELECTOR = keccak(text="verifyInline(bytes,bytes32,bytes)")[:4]
VALID = "0x024ad318"


@dataclass
class VaultKey:
    """The owner's persistent ML-DSA key for the vault (standard, not blinded),
    derived from their seed so it survives across sessions."""
    pk: object
    sk: object
    pk_deploy: bytes         # expanded pk the verifier consumes, inline at withdraw
    commit: bytes            # keccak256(pk_deploy), bound into the vault address

    @classmethod
    def from_seed(cls, seed: bytes) -> "VaultKey":
        vseed = keccak(seed + _VAULT_KEY_SALT)
        pk, sk = mldsa.keypair(vseed)
        pkd = mldsa.expanded_pk(pk)
        return cls(pk, sk, pkd, keccak(pkd))

    @classmethod
    def from_root(cls, root: bytes, index: int = 0) -> "VaultKey":
        """Derive the vault key from a 32-byte owner root + an index (HD-style).
        Deterministic: the same root always re-derives the same vaults, so a vault
        can be re-loaded and its ownership checked across sessions, while different
        indices give different vaults. The root comes from `prf_root` (post-quantum,
        a passkey secret) or `pin_root` (fallback, wallet signature + a user PIN)."""
        return cls.from_seed(keccak(root + b"/vault-index/" + int(index).to_bytes(4, "big")))


def prf_root(secret_hex: str) -> bytes:
    """Owner root from a WebAuthn PRF secret. That secret lives in the
    authenticator's secure element and is not recoverable from any public key, so
    the vault key is post-quantum at the root: stealing or breaking the k1 wallet
    does not yield it."""
    secret = bytes.fromhex(secret_hex[2:] if secret_hex.startswith("0x") else secret_hex)
    return keccak(secret + b"/prf-root/v1")


def pin_root(sig_hex: str, pin: str) -> bytes:
    """Owner root from a wallet signature plus a user PIN or passphrase, when the
    authenticator has no PRF. The PIN never leaves the client and is not derivable
    from any public value, and scrypt makes guessing it against the public vault
    address expensive, so a stolen (or quantum-broken) k1 key ALONE cannot
    re-derive the vault key: the attacker also needs the PIN. Use a strong
    passphrase, not a 4-digit PIN."""
    sig = bytes.fromhex(sig_hex[2:] if sig_hex.startswith("0x") else sig_hex)
    return hashlib.scrypt(pin.encode("utf-8"), salt=sig, n=2 ** 15, r=8, p=1,
                          dklen=32, maxmem=64 * 1024 * 1024)


def vault_init_code(commit: bytes) -> bytes:
    """CREATE2 init code: Vault creation bytecode + abi.encode(commit, singleton)."""
    args = abi_encode(["bytes32", "address"], [commit, to_canonical_address(SINGLETON)])
    return vault_creation_code() + args


def predict_vault_address(factory: str, commit: bytes) -> str:
    """The vault's counterfactual CREATE2 address (salt = commit)."""
    inner = keccak(vault_init_code(commit))
    return "0x" + keccak(b"\xff" + to_canonical_address(factory) + commit + inner)[12:].hex()


def deploy_calldata(commit: bytes) -> str:
    """Calldata to send TO the factory (from any wallet) to CREATE2 the vault:
    salt || init_code. The sender pays the gas; the result is the predicted
    address. Returned as 0x-hex."""
    return "0x" + (commit + vault_init_code(commit)).hex()


def deploy_vault(deployer_hex: str, deployer: str, factory: str, commit: bytes):
    """Deploy the vault via the CREATE2 factory (relayer pays gas, no owner-EOA
    link). Returns (vault_address, receipt)."""
    data = commit + vault_init_code(commit)   # salt || init_code, factory calldata
    gas = rpc.estimate_gas({"from": deployer, "to": factory, "data": "0x" + data.hex()})
    nonce = rpc.get_nonce(deployer)
    raw, _ = sign_legacy(deployer_hex, nonce=nonce, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 100_000, to=factory, value=0, data=data, chain_id=CHAIN_ID)
    return predict_vault_address(factory, commit), stealth._wait(rpc.send_raw(raw))


def vault_nonce(vault_addr: str) -> int:
    """Read the vault's replay nonce (0 if not deployed yet)."""
    if len(rpc.get_code(vault_addr)) <= 2:
        return 0
    return int(rpc.eth_call({"to": vault_addr, "data": "0x" + _NONCE_SELECTOR.hex()}), 16)


def withdraw_message(vault_addr: str, dest: str, amount: int, nonce: int) -> bytes:
    """The 32-byte message the ML-DSA key signs: binds dest, amount, this vault,
    the chain, and the nonce (matches Vault.withdraw's keccak(abi.encode(...)))."""
    return keccak(abi_encode(
        ["address", "uint256", "uint256", "address", "uint256"],
        [dest, amount, nonce, vault_addr, CHAIN_ID]))


def sign_withdraw(vkey: VaultKey, vault_addr: str, dest: str, amount: int, nonce: int) -> bytes:
    return mldsa.sign(vkey.sk, withdraw_message(vault_addr, dest, amount, nonce))


def withdraw_calldata(dest: str, amount: int, pk_deploy: bytes, sig: bytes) -> bytes:
    return WITHDRAW_SELECTOR + abi_encode(
        ["address", "uint256", "bytes", "bytes"], [dest, amount, pk_deploy, sig])


def would_verify(pk_deploy: bytes, m: bytes, sig: bytes) -> str:
    """Offchain check (free eth_call) that the singleton accepts this signature."""
    data = _VERIFY_SELECTOR + abi_encode(["bytes", "bytes32", "bytes"], [pk_deploy, m, sig])
    return rpc.eth_call({"to": SINGLETON, "data": "0x" + data.hex(), "gas": hex(50_000_000)})[:10]


def relay_withdraw(relayer_hex: str, relayer: str, vkey: VaultKey, vault_addr: str,
                   dest: str, amount: int):
    """The relayer submits an ML-DSA-authorized withdraw and pays gas. Returns the
    receipt. The relayer cannot steal: the signature fixes dest and amount."""
    nonce = vault_nonce(vault_addr)
    sig = sign_withdraw(vkey, vault_addr, dest, amount, nonce)
    data = withdraw_calldata(dest, amount, vkey.pk_deploy, sig)
    gas = rpc.estimate_gas({"from": relayer, "to": vault_addr, "data": "0x" + data.hex()})
    tx_nonce = rpc.get_nonce(relayer)
    raw, _ = sign_legacy(relayer_hex, nonce=tx_nonce, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 200_000, to=vault_addr, value=0, data=data, chain_id=CHAIN_ID)
    return stealth._wait(rpc.send_raw(raw))


def unsigned_withdraw_calldata(vault_addr: str, dest: str, amount: int, pk_deploy: bytes) -> str:
    """Calldata for a plain withdraw with NO valid ML-DSA signature (an empty one).
    Sent from an ordinary k1 wallet it just reverts with `vault: bad signature`,
    which is the point: the funds are post-quantum protected. Returned as 0x-hex,
    ready for eth_call or a wallet."""
    empty = b"\x00" * mldsa.SIG_LEN
    return "0x" + withdraw_calldata(dest, amount, pk_deploy, empty).hex()
