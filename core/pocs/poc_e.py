"""PoC-E: full PQ smart wallet, execute(target, value, data), ML-DSA-gated, self-pay.

Generalizes the PQ vault from a fixed withdraw to an arbitrary call. In EIP-8141 a
SENDER frame already IS "the account calls `target` with `data` and `value`", caller =
the account. So a PQ smart wallet executing an arbitrary call is just AccountF (the
self-paying PQ account from PoC-F') running a SENDER frame to a contract with calldata,
atomically batched behind the ML-DSA DEFAULT verify. The canonical sig_hash binds the
target, value and data, so the ML-DSA signature authorizes exactly that call, and the
atomic batch makes a bad signature SKIP the execute (hard gate).

Frame layout (same positions as PoC-F', SENDER now targets a contract with calldata):
  0 VERIFY  approve exec+payment (account self-pays)
  1 DEFAULT ML-DSA verify (account, FLAG_ATOMIC_BATCH)
  2 SENDER  target = Recorder, data = ping(n)  (the arbitrary execute; batch terminator)

Proof on-chain (Hegota 8141):
  - GOOD sig: Recorder.last == n AND Recorder.caller == the wallet (it executed AS itself).
  - BAD sig: DEFAULT reverts, SENDER skipped, Recorder untouched.

Reuses pq-dksap READ-ONLY + AccountF + frametx8. Run: python poc_e.py
"""
import os

from eth_abi import encode as abi_encode
from eth_utils import keccak

import _pqdksap  # noqa: F401
from pq_dksap import mldsa, rpc, stealth
from pq_dksap.config import CHAIN_ID
from pq_dksap.frametx import (
    FLAG_APPROVE_EXECUTION_AND_PAYMENT, FLAG_ATOMIC_BATCH, FLAG_NONE,
    MODE_DEFAULT, MODE_SENDER, MODE_VERIFY, SCHEME_ARBITRARY, Frame, Signature,
)
from pq_dksap.legacytx import create_address, sign_legacy

from frametx8 import FrameTx8
from keyfile import load_key
from poc_f_selfpay import deploy_account

_HERE = os.path.dirname(os.path.abspath(__file__))
PING_SEL = keccak(text="ping(uint256)")[:4]
LAST_SEL = keccak(text="last()")[:4]
CALLER_SEL = keccak(text="caller()")[:4]


def deploy_recorder(deployer_hex: str, deployer: str) -> str:
    init = bytes.fromhex(open(os.path.join(_HERE, "Recorder.bin")).read().strip())
    gas = rpc.estimate_gas({"from": deployer, "data": "0x" + init.hex()})
    n = rpc.get_nonce(deployer)
    addr = create_address(deployer, n)
    raw, _ = sign_legacy(deployer_hex, nonce=n, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 60_000, to=None, value=0, data=init, chain_id=CHAIN_ID)
    stealth._wait(rpc.send_raw(raw))
    return addr


def rec_last(recorder: str) -> int:
    return int(rpc.eth_call({"to": recorder, "data": "0x" + LAST_SEL.hex()}), 16)


def rec_caller(recorder: str) -> str:
    return "0x" + rpc.eth_call({"to": recorder, "data": "0x" + CALLER_SEL.hex()})[-40:]


def build_execute(account: str, target: str, value: int, data: bytes, pk_deploy: bytes) -> FrameTx8:
    """AccountF self-pay frame tx whose SENDER frame executes target(data) as the wallet."""
    priority, max_fee = stealth.current_fees()
    return FrameTx8(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, None, 50_000, 45_000, 0, b""),
            Frame(MODE_DEFAULT, FLAG_ATOMIC_BATCH, None, 8_000_000, 300_000, 0, b""),
            Frame(MODE_SENDER, FLAG_NONE, target, 300_000, 200_000, value, data),
        ],
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )


def authorize(tx: FrameTx8, sk, pk_deploy: bytes, good: bool):
    sig = mldsa.sign(sk, tx.sig_hash())
    if not good:
        sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    tx.signatures[0].signature = pk_deploy + sig


def main():
    deployer_hex, deployer = load_key()
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"funder {deployer}  balance {rpc.get_balance(deployer)/10**18:.4f} ETH")

    pk, sk = mldsa.keypair(keccak(b"poc-e/account-key/v1" + os.urandom(16)))
    pk_deploy = mldsa.expanded_pk(pk)
    commit = keccak(pk_deploy)
    account = deploy_account(deployer_hex, deployer, commit, 5 * 10 ** 15)
    recorder = deploy_recorder(deployer_hex, deployer)
    print(f"PQ smart wallet {account}  balance {rpc.get_balance(account)/10**18:.4f} ETH")
    print(f"Recorder target {recorder}  (last={rec_last(recorder)}, caller={rec_caller(recorder)})")

    checks = {}

    # ---- BAD sig: the execute must be hard-gated ----
    data_bad = PING_SEL + abi_encode(["uint256"], [111])
    txb = build_execute(account, recorder, 0, data_bad, pk_deploy)
    authorize(txb, sk, pk_deploy, good=False)
    print("\n[BAD sig] execute ping(111) ...")
    rb = stealth._wait(rpc.send_raw(txb.encode_hex()))
    print(f"  status {rb.get('status')}  recorder.last={rec_last(recorder)}")
    checks["BAD: execute skipped (recorder untouched)"] = rec_last(recorder) == 0
    checks["BAD: tx failed (status 0x0)"] = rb.get("status") == "0x0"

    # ---- GOOD sig: arbitrary call executes AS the wallet ----
    N = 42
    data = PING_SEL + abi_encode(["uint256"], [N])
    txg = build_execute(account, recorder, 0, data, pk_deploy)
    authorize(txg, sk, pk_deploy, good=True)
    print(f"\n[GOOD sig] execute ping({N}) ...")
    rg = stealth._wait(rpc.send_raw(txg.encode_hex()))
    last, caller = rec_last(recorder), rec_caller(recorder)
    print(f"  status {rg.get('status')}  recorder.last={last}  recorder.caller={caller}")
    checks["GOOD: tx succeeded"] = rg.get("status") == "0x1"
    checks["GOOD: arbitrary call executed (recorder.last == N)"] = last == N
    checks["GOOD: executed AS the wallet (recorder.caller == account)"] = caller.lower() == account.lower()

    print("\n== RESULT ==")
    for name, okc in checks.items():
        print(f"  [{'PASS' if okc else 'FAIL'}] {name}")
    if all(checks.values()):
        print("\nPoC-E GREEN: a PQ smart wallet executes an ARBITRARY call (not just a "
              "withdraw), as itself (msg.sender == wallet), authorized by an inline ML-DSA "
              "signature that binds the target+data, self-paid, with the execute hard-gated "
              "by the atomic batch. Full PQ smart account on frames.")
    else:
        raise SystemExit("\nPoC-E did not fully pass, see checks.")


if __name__ == "__main__":
    main()
