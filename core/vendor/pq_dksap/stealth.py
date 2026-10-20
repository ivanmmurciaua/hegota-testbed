"""Stealth account lifecycle: derive a key, deploy the account, build and sign a
post-quantum spend over EIP-8141 frame transactions."""
import time
from dataclasses import dataclass

from eth_utils import keccak, to_canonical_address

from . import mldsa, rpc
from .config import CHAIN_ID, account_creation_code, factory_creation_code
from .frametx import (
    Frame, FrameTx, Signature, MODE_DEFAULT, MODE_SENDER, MODE_VERIFY,
    FLAG_APPROVE_EXECUTION_AND_PAYMENT, FLAG_NONE, SCHEME_ARBITRARY,
)
from .legacytx import create_address, sign_legacy


# -- Gas pricing, always read from the chain (never hardcoded) --------------
def legacy_gas_price() -> int:
    """Gas price for legacy (deploy / funding) txs: the node's suggestion + 20%."""
    return rpc.gas_price() * 6 // 5


def current_fees() -> tuple[int, int]:
    """(max_priority_fee, max_fee) for a frame tx, read live from the chain.

    The node's priority suggestion is conservative (inflated) on an idle chain,
    so we bid a small slice of it: enough to clear inclusion, far below the
    suggestion, so the retained max_cost stays close to the real charge and
    little is stranded. (We deliberately do NOT echo recent blocks' priority,
    which on a quiet chain is just this demo's own earlier overpayments.)"""
    base = rpc.base_fee()
    priority = max(rpc.max_priority_fee() // 55, base)
    return priority, base * 2 + priority


@dataclass
class StealthKey:
    seed: bytes
    pk: object
    sk: object
    pk_deploy: bytes
    commit: bytes   # keccak256(pk_deploy), the account's key commitment

    @classmethod
    def from_seed(cls, seed: bytes) -> "StealthKey":
        pk, sk = mldsa.keypair(seed)
        pk_deploy = mldsa.expanded_pk(pk)
        return cls(seed, pk, sk, pk_deploy, keccak(pk_deploy))


def deploy_account(funder_hex: str, funder: str, key: StealthKey, fund_wei: int):
    """Deploy the stealth account (endowed with fund_wei) and return its address.

    The account is created with its key commitment appended as the constructor
    argument, so a single compiled artifact serves any stealth key. Funding via
    CREATE endows the account without running its runtime.
    """
    init = account_creation_code() + key.commit
    call = {"from": funder, "data": "0x" + init.hex(), "value": hex(fund_wei)}
    gas = rpc.estimate_gas(call)
    nonce = rpc.get_nonce(funder)
    addr = create_address(funder, nonce)
    raw, _ = sign_legacy(funder_hex, nonce=nonce, gas_price=legacy_gas_price(), gas_limit=gas + 100_000,
                         to=None, value=fund_wei, data=init, chain_id=CHAIN_ID)
    txh = rpc.send_raw(raw)
    receipt = _wait(txh)
    return addr, receipt


def build_spend(account: str, dest: str, value: int) -> FrameTx:
    """Build the unsigned spend: [VERIFY(cheap approve), DEFAULT(verify gate),
    SENDER(move value)] with an empty ARBITRARY signature placeholder."""
    return FrameTx(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            # DEFAULT execution_gas sized to the ~4.8M ML-DSA verify + margin.
            # max_gas (sum of frame limits) sets the up-front max-cost the payer
            # must hold; kept small so the account needs minimal ETH parked.
            Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, None, 50_000, 45_000, 0, b""),
            Frame(MODE_DEFAULT, FLAG_NONE, None, 8_000_000, 300_000, 0, b""),
            # SENDER state_gas must cover the EIP-8037 NEW_ACCOUNT charge when the
            # recipient is a fresh address (~200k+ on ethrex); too low reverts.
            Frame(MODE_SENDER, FLAG_NONE, dest, 100_000, 500_000, value, b""),
        ],
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        **dict(zip(("max_priority_fee_per_gas", "max_fee_per_gas"), current_fees())),
    )


def authorize(tx: FrameTx, key: StealthKey) -> bytes:
    """Sign the tx's canonical sig_hash with ML-DSA and place pk||sig inline in
    the ARBITRARY signature. Returns the sig_hash that was signed."""
    h = tx.sig_hash()
    sig = mldsa.sign(key.sk, h)
    assert mldsa.verify(key.pk, h, sig), "local ML-DSA verify failed"
    tx.signatures[0].signature = key.pk_deploy + sig
    return h


# --------------------------------------------------------------------------
# Counterfactual (CREATE2) path: predict the address, fund it bare, then let a
# single self-paid frame transaction deploy the account and sweep in one shot.
# --------------------------------------------------------------------------
def stealth_init_code(commit: bytes) -> bytes:
    """The account's CREATE2 init code: creation bytecode + the key commitment
    constructor argument. keccak256 of this feeds the address prediction."""
    return account_creation_code() + commit


def predict_stealth_address(factory: str, commit: bytes) -> str:
    """CREATE2 address of the stealth account: keccak(0xff ++ factory ++ salt ++
    keccak(init_code))[12:], with salt = commit. A pure function of public data,
    so the payer can compute (and fund) it before it is deployed."""
    inner = keccak(stealth_init_code(commit))
    body = b"\xff" + to_canonical_address(factory) + commit + inner
    return "0x" + keccak(body)[12:].hex()


def deploy_factory(funder_hex: str, funder: str):
    """One-time deploy of the CREATE2 factory. Returns (address, receipt)."""
    init = factory_creation_code()
    gas = rpc.estimate_gas({"from": funder, "data": "0x" + init.hex()})
    nonce = rpc.get_nonce(funder)
    addr = create_address(funder, nonce)
    raw, _ = sign_legacy(funder_hex, nonce=nonce, gas_price=legacy_gas_price(), gas_limit=gas + 50_000,
                         to=None, value=0, data=init, chain_id=CHAIN_ID)
    return addr, _wait(rpc.send_raw(raw))


def fund_address(funder_hex: str, funder: str, addr: str, wei: int):
    """Plain value transfer to a bare (not-yet-deployed) address."""
    # This chain charges a large NEW_ACCOUNT cost on a transfer to a fresh
    # address (~207k, well above the 21k base), so estimate rather than guess.
    nonce = rpc.get_nonce(funder)
    gas = rpc.estimate_gas({"from": funder, "to": addr, "value": hex(wei)})
    raw, _ = sign_legacy(funder_hex, nonce=nonce, gas_price=legacy_gas_price(), gas_limit=gas + 50_000,
                         to=addr, value=wei, data=b"", chain_id=CHAIN_ID)
    return _wait(rpc.send_raw(raw))


# Deploy+spend frame gas limits (execution, state). Structural (the ML-DSA verify
# needs its ~5M); the fee that multiplies them is read live from the chain.
_DEPLOY_FRAMES_GAS = [(58_000, 400_000), (40_000, 45_000), (8_000_000, 300_000), (100_000, 500_000)]


def sweep_reserve_wei() -> int:
    """Wei the stealth must keep back to self-pay a deploy+sweep: the up-front
    max cost = Σ(limits) × the live max_fee. Draining everything above this to the
    payout leaves only the unavoidable max_cost - gasUsed residue. The +10% covers
    the calldata floor of the large inline signature and the intrinsic cost."""
    _, max_fee = current_fees()
    return sum(e + s for e, s in _DEPLOY_FRAMES_GAS) * max_fee * 11 // 10


def build_deploy_spend(factory: str, account: str, commit: bytes, dest: str, value: int) -> FrameTx:
    """Self-paid deploy+spend (DeploySelfVerify shape). One frame transaction:
      0 DEFAULT  -> factory, data = salt||init_code : CREATE2s the account at `account`
      1 VERIFY   : the (now deployed) account approves execution + payment
      2 DEFAULT  : the ~4.8M ML-DSA verify, revert-gated
      3 SENDER   : moves the value to `dest`
    Frames 0+1 form the validation prefix, gas-capped at MAX_VERIFY_GAS (100k):
    execution_gas below is sized conservatively and TUNED against the first live
    measurement (the heavy state cost of the deploy is in the state pool)."""
    deploy_data = commit + stealth_init_code(commit)   # salt || init_code
    return FrameTx(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            # TEMP gas split, to be tuned after the first onchain measurement.
            Frame(MODE_DEFAULT, FLAG_NONE, factory, *_DEPLOY_FRAMES_GAS[0], 0, deploy_data),
            Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, None, *_DEPLOY_FRAMES_GAS[1], 0, b""),
            Frame(MODE_DEFAULT, FLAG_NONE, None, *_DEPLOY_FRAMES_GAS[2], 0, b""),
            Frame(MODE_SENDER, FLAG_NONE, dest, *_DEPLOY_FRAMES_GAS[3], value, b""),
        ],
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        **dict(zip(("max_priority_fee_per_gas", "max_fee_per_gas"), current_fees())),
    )


def _wait(txhash, timeout=1000):
    t0 = time.time()
    last = 0
    while time.time() - t0 < timeout:
        r = rpc.get_receipt(txhash)
        if r:
            return r
        el = int(time.time() - t0)
        if el - last >= 15:
            print(f"      ... still waiting for confirmation ({el}s; this testnet mines in "
                  f"bursts and can stall for minutes)", flush=True)
            last = el
        time.sleep(3)
    return None
