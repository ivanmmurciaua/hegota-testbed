"""Gasless sponsorship over EIP-8141 (see contracts/Sponsor.yul).

A SPONSOR contract is the frame-tx sender; its VERIFY code approves execution +
payment (scope 3) only when the operator signed the transaction's canonical
sig_hash, so the SPONSOR pays the whole tx gas. A DEFAULT frame then calls any
target (the CREATE2 factory to deploy a vault, or vault.withdraw with an inline
ML-DSA signature), and the end user pays ZERO ETH.

Verified on ethrex eip8141-v2 and live on Hegota: APPROVE payment sets
`payer = frame.target` with no `payer == tx.sender` check, but execution approval
requires `frame_target == tx.sender`, so the sponsor must BE the sender. The
operator signature binds sig_hash, so it authorizes exactly this tx and cannot be
replayed onto another; a wrong signature is rejected in the validation prefix.
"""
import os

from eth_keys import keys
from eth_utils import to_canonical_address

from . import rpc, stealth
from .config import CHAIN_ID
from .frametx import (
    Frame, FrameTx, Signature, MODE_VERIFY, MODE_DEFAULT,
    FLAG_APPROVE_EXECUTION_AND_PAYMENT, FLAG_NONE, SCHEME_ARBITRARY,
)
from .legacytx import sign_legacy, create_address

_HERE = os.path.dirname(__file__)
_SPONSOR_BIN = os.path.join(_HERE, "..", "contracts", "Sponsor.bin")

# The VERIFY prefix only needs the ecrecover + APPROVE (measured ~5.5k gas on
# Hegota), so a tight cap keeps the sponsor's fronted max-cost small.
_VERIFY_EXEC_GAS = 80_000
_VERIFY_STATE_GAS = 50_000

# DEFAULT-frame (exec, state) budgets, proven onchain (scripts/poc_sponsor_vault):
# a fresh vault CREATE2 (big state charge) and the ~5M-gas ML-DSA verify.
DEPLOY_GAS = (3_000_000, 3_000_000)
WITHDRAW_GAS = (6_000_000, 1_000_000)


def sponsor_creation() -> bytes:
    with open(_SPONSOR_BIN) as f:
        return bytes.fromhex(f.read().strip())


def sponsor_init_code(operator: str) -> bytes:
    """Creation bytecode + the 32-byte operator address the sponsor gates on."""
    return sponsor_creation() + b"\x00" * 12 + to_canonical_address(operator)


def deploy_sponsor(deployer_hex: str, deployer: str, operator: str, endow_wei: int):
    """One-time: deploy the sponsor (operator baked in) and endow it via CREATE, so
    it holds the balance it fronts for gas. Returns (sponsor_address, receipt)."""
    data = sponsor_init_code(operator)
    n = rpc.get_nonce(deployer)
    addr = create_address(deployer, n)
    try:
        gas = rpc.estimate_gas({"from": deployer, "data": "0x" + data.hex(), "value": hex(endow_wei)})
    except Exception:
        gas = 400_000
    raw, _ = sign_legacy(deployer_hex, nonce=n, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 120_000, to=None, value=endow_wei, data=data,
                         chain_id=CHAIN_ID)
    return addr, stealth._wait(rpc.send_raw(raw))


def build_sponsored(sponsor: str, operator_hex: str, target: str, calldata: bytes,
                    exec_gas: int, state_gas: int, value: int = 0) -> FrameTx:
    """Build and operator-sign a sponsored frame tx: the sponsor approves+pays, a
    DEFAULT frame calls `target` with `calldata`. Returns the ready-to-broadcast tx.
    The user signs and pays nothing here; the operator (this backend) authorizes."""
    priority, max_fee = stealth.current_fees()
    tx = FrameTx(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(sponsor), sender=sponsor,
        frames=[
            Frame(mode=MODE_VERIFY, flags=FLAG_APPROVE_EXECUTION_AND_PAYMENT,
                  target=None, execution_gas=_VERIFY_EXEC_GAS, state_gas=_VERIFY_STATE_GAS,
                  value=0, data=b""),
            Frame(mode=MODE_DEFAULT, flags=FLAG_NONE, target=target,
                  execution_gas=exec_gas, state_gas=state_gas, value=value, data=calldata),
        ],
        signatures=[Signature(scheme=SCHEME_ARBITRARY, signer=None, msg=b"", signature=b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )
    sk = keys.PrivateKey(bytes.fromhex(operator_hex.removeprefix("0x")))
    sig = sk.sign_msg_hash(tx.sig_hash())
    tx.signatures[0].signature = (sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big")
                                  + bytes([sig.v + 27]))
    return tx


def relay_sponsored(sponsor: str, operator_hex: str, target: str, calldata: bytes,
                    exec_gas: int, state_gas: int, value: int = 0, timeout: int = 240):
    """Build, broadcast, and wait: the sponsor pays gas for a call the user made
    for free. Returns the receipt."""
    tx = build_sponsored(sponsor, operator_hex, target, calldata, exec_gas, state_gas, value)
    return stealth._wait(rpc.send_raw(tx.encode_hex()), timeout=timeout)
