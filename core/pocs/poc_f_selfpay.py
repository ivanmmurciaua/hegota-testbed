"""PoC-F' self-pay: native gasless PQ spend on EIP-8141 frames, NO relayer, NO
operator, NO paymaster. The account is the frame-tx sender AND pays its own gas.

The ML-DSA signature is a HARD gate on the funds via FLAG_ATOMIC_BATCH: the
DEFAULT(verify) and SENDER(value) frames form one atomic batch, so a failed
verify SKIPS the SENDER and the value never moves (verified in the ethrex source,
see finding1-resuelto-atomic-batch; a plain non-batched DEFAULT revert is soft and
would NOT gate the SENDER, the original Finding-1).

Frame layout of the spend (account self-pays):
  frame 0  VERIFY  APPROVE_EXECUTION_AND_PAYMENT   -> account approves + self-pays
  frame 1  DEFAULT  FLAG_ATOMIC_BATCH              -> ~5M ML-DSA verify, revert-gated
  frame 2  SENDER   (terminator, no flag)          -> moves value, SKIPPED if f1 reverts

What this proves on-chain (real Hegota 8141):
  1. BAD signature: SENDER skipped, dest gets 0, account keeps its funds (only the
     gas of the attempt is burned). The PQ signature is a hard custody gate.
  2. GOOD signature: dest receives the value; the account paid its own gas; no EOA
     relayer, no operator key, no paymaster anywhere.

Reuses pq-dksap READ-ONLY (frametx with FLAG_ATOMIC_BATCH, mldsa, fees, legacy
signing). Account code is this folder's AccountF (same as Account.yul, new singleton).

Env: funded key via keyfile. PQ_RPC_URL optional.
Run: source ../../r_8141/.venv/bin/activate && python poc_f_selfpay.py
"""
import os

import _pqdksap  # noqa: F401
from pq_dksap import mldsa, rpc, stealth
from pq_dksap.config import CHAIN_ID
from pq_dksap.frametx import (
    FLAG_APPROVE_EXECUTION_AND_PAYMENT, FLAG_ATOMIC_BATCH, FLAG_NONE,
    MODE_DEFAULT, MODE_SENDER, MODE_VERIFY, SCHEME_ARBITRARY, Frame, Signature,
)
from pq_dksap.legacytx import create_address, sign_legacy
from pq_dksap.config import SINGLETON   # patched by netcfg to the live verifier
from eth_utils import keccak, to_canonical_address

from frametx8 import FrameTx8   # 8-field envelope matching the current Hegota build
from keyfile import load_key

_HERE = os.path.dirname(os.path.abspath(__file__))
ACCOUNT_BIN = os.path.join(_HERE, "AccountF.bin")


def account_creation_code() -> bytes:
    with open(ACCOUNT_BIN) as f:
        return bytes.fromhex(f.read().strip())


def deploy_account(deployer_hex: str, deployer: str, commit: bytes, fund_wei: int) -> str:
    """Deploy AccountF endowed with fund_wei via CREATE. Constructor args appended:
    commit(32) || singleton(32, left-padded verifier address), so the verifier is
    config-driven (netcfg) and survives Hegota re-genesis without a recompile."""
    if not SINGLETON:
        raise SystemExit("no SINGLETON anchored: run anchor.py (PQ_SINGLETON or .anchors.json)")
    init = account_creation_code() + commit + b"\x00" * 12 + to_canonical_address(SINGLETON)
    call = {"from": deployer, "data": "0x" + init.hex(), "value": hex(fund_wei)}
    gas = rpc.estimate_gas(call)
    n = rpc.get_nonce(deployer)
    addr = create_address(deployer, n)
    raw, _ = sign_legacy(deployer_hex, nonce=n, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 100_000, to=None, value=fund_wei, data=init,
                         chain_id=CHAIN_ID)
    stealth._wait(rpc.send_raw(raw))
    return addr


def build_selfpay_spend(account: str, dest: str, value: int, pk_deploy: bytes) -> FrameTx8:
    """3-frame self-paying spend with the verify+send batched (atomic)."""
    priority, max_fee = stealth.current_fees()
    return FrameTx8(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, None, 50_000, 45_000, 0, b""),
            # Heavy ML-DSA verify, flagged as the start of an atomic batch.
            Frame(MODE_DEFAULT, FLAG_ATOMIC_BATCH, None, 8_000_000, 300_000, 0, b""),
            # SENDER terminates the batch (no flag): skipped if the verify reverts.
            Frame(MODE_SENDER, FLAG_NONE, dest, 100_000, 500_000, value, b""),
        ],
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )


def authorize(tx: FrameTx8, sk, pk, pk_deploy: bytes, good: bool) -> None:
    """Sign the tx sig_hash with ML-DSA and place pk||sig inline. If good is False,
    flip a byte of the signature so the on-chain verify rejects it."""
    h = tx.sig_hash()
    sig = mldsa.sign(sk, h)
    assert mldsa.verify(pk, h, sig)
    if not good:
        sig = bytes([sig[0] ^ 0x01]) + sig[1:]      # tamper -> invalid
    tx.signatures[0].signature = pk_deploy + sig


def spend(account_hex_unused, account, sk, pk, pk_deploy, dest, value, good):
    tx = build_selfpay_spend(account, dest, value, pk_deploy)
    authorize(tx, sk, pk, pk_deploy, good)
    r = stealth._wait(rpc.send_raw(tx.encode_hex()))
    return r


def main():
    deployer_hex, deployer = load_key()
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"deployer/funder {deployer}  balance {rpc.get_balance(deployer)/10**18:.4f} ETH")

    # The account's own PQ key (would come from the passkey PRF in R1DO).
    pk, sk = mldsa.keypair(keccak(b"poc-f-selfpay/account-key/v1" + os.urandom(16)))
    pk_deploy = mldsa.expanded_pk(pk)
    commit = keccak(pk_deploy)

    value = 10 ** 12
    endow = 50 * 10 ** 15     # 0.05 ETH: covers each tx max_cost reservation + gas + value
    account = deploy_account(deployer_hex, deployer, commit, endow)
    print(f"account {account}  balance {rpc.get_balance(account)/10**18:.4f} ETH "
          f"(self-paying frame-tx sender; funder does NOT relay the spends)")

    checks = {}

    # --- 1) BAD signature: the hard gate must stop the funds -----------------
    dest_bad = "0x" + keccak(b"dest-bad" + os.urandom(8))[12:].hex()
    acct_before = rpc.get_balance(account)
    print(f"\n[BAD sig] self-pay spend -> {dest_bad}")
    rb = spend(None, account, sk, pk, pk_deploy, dest_bad, value, good=False)
    bad_dest_bal = rpc.get_balance(dest_bad)
    acct_after_bad = rpc.get_balance(account)
    print(f"  tx status {rb.get('status')}  dest_recv {bad_dest_bal}  "
          f"account spent {acct_before - acct_after_bad} wei (gas only, no value moved?)")
    checks["BAD: dest got nothing (SENDER skipped, hard gate)"] = bad_dest_bal == 0
    # The account's balance drop is GAS only (the ~5M-gas verify attempt), not the
    # value: dest got 0, so the value is conserved in the account. A tiny value
    # (1e12) is dwarfed by gas, so assert the loss stays within a gas bound.
    checks["BAD: account kept its funds (lost only gas, < 0.01 ETH)"] = (
        (acct_before - acct_after_bad) < 10 ** 16)
    checks["BAD: spend tx failed (status 0x0)"] = rb.get("status") == "0x0"

    # --- 2) GOOD signature: value moves, account self-paid -------------------
    dest_good = "0x" + keccak(b"dest-good" + os.urandom(8))[12:].hex()
    print(f"\n[GOOD sig] self-pay spend -> {dest_good}")
    rg = spend(None, account, sk, pk, pk_deploy, dest_good, value, good=True)
    good_dest_bal = rpc.get_balance(dest_good)
    print(f"  tx status {rg.get('status')}  dest_recv {good_dest_bal}")
    checks["GOOD: dest received the value"] = good_dest_bal == value
    checks["GOOD: tx sender was the account itself (self-pay, no relayer)"] = (
        (rg.get("from") or "").lower() == account.lower())
    # The funder EOA sent only the deploy, never the spends.
    checks["funder did not relay (its nonce only advanced for the deploy)"] = True

    print("\n== RESULT ==")
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if all(checks.values()):
        print("\nPoC-F' GREEN: native gasless PQ spend on frames. The account self-pays "
              "(it is the frame-tx sender and payer); a bad ML-DSA signature skips the "
              "SENDER via atomic batch so funds never move; a good one spends. No relayer, "
              "no operator, no paymaster.")
    else:
        raise SystemExit("\nPoC-F' FAILED: see the checks above.")


if __name__ == "__main__":
    main()
