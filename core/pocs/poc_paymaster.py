"""PoC: a frame-NATIVE PAYMASTER on the ethrex Hegota rail (EIP-8141).

The 4337-style paymaster model done natively in frames, which did not exist yet:
  - The ACCOUNT (a PQ ML-DSA smart account) is the frame-tx SENDER. It orders and
    signs the action with ML-DSA, and its VERIFY frame approves EXECUTION ONLY
    (APPROVE opcode scope 2). It does NOT approve payment, so it does not pay gas.
  - A separate PAYMASTER contract runs in its OWN VERIFY frame (as that frame's
    target, NOT the sender) and approves PAYMENT (APPROVE opcode scope 1). ethrex
    then sets payer = frame.target with no payer==sender check, so the paymaster
    pays all the gas. It gates on an operator ECDSA signature over this exact tx.

This is explicitly NOT the "sponsor-as-sender" model (where the sponsor is the tx
sender/payer and the account moves inside). Here the account is the sender and the
paymaster is a distinct payer named by a non-sender VERIFY frame's payment approval.

Frame layout (4 frames):
  0 VERIFY  target = account (sender)  -> AccountP APPROVE(scope 2) execution only
  1 VERIFY  target = Paymaster         -> Paymaster ecrecover(operator) then APPROVE(scope 1) payment
  2 DEFAULT target = account  ATOMIC   -> ~5M ML-DSA verify, revert-gated
  3 SENDER  target = dest, value       -> moves a tiny value; skipped if frame 2 reverts

On-chain proof (real Hegota 8141):
  - status 0x1, dest received the value (the action happened).
  - ACCOUNT balance dropped by exactly the moved value (ZERO gas).
  - PAYMASTER balance dropped by gasUsed * effectiveGasPrice (ALL the gas).
  - receipt.from == the account (the account is the sender).
  Negative: a bad operator signature makes the Paymaster VERIFY revert, so it never
  APPROVEs payment -> no payer -> ethrex rejects the tx in the validation prefix
  (the action does not happen; without a paymaster the account would have to self-pay).

Reuses pq-dksap READ-ONLY (mldsa, rpc, stealth fees, legacy signing). Contracts are
this folder's AccountP (execution-only approve) and Paymaster (payment approve).

Env: PQ_RPC_URL, PQ_CHAIN_ID=8141, PQ_FEE_NESTED=1, PQ_OMIT_RECENT_ROOTS=1,
PQ_SINGLETON=<verifier>. Funded key via keyfile. Run: ./run.sh
"""
import os
import shutil
import subprocess
import tempfile

from eth_keys import keys
from eth_utils import keccak, to_canonical_address

import _pqdksap  # noqa: F401  (path + env-driven network patch; must import first)
from pq_dksap import mldsa, rpc, stealth
from pq_dksap.config import CHAIN_ID, SINGLETON
from pq_dksap.frametx import (
    FLAG_ATOMIC_BATCH, FLAG_NONE,
    MODE_DEFAULT, MODE_SENDER, MODE_VERIFY, SCHEME_ARBITRARY, Frame, Signature,
)
from pq_dksap.legacytx import create_address, sign_legacy

from frametx8 import FrameTx8
from keyfile import load_key

_HERE = os.path.dirname(os.path.abspath(__file__))

# Approval scope BITMASK, verified against the live ethrex node AND the EIP-8141 spec:
#   0x1 = PAYMENT, 0x2 = EXECUTION, 0x3 = both.
# This is the SAME encoding for the frame `flags` field and for the APPROVE opcode arg.
# (NB: pq-dksap's FLAG_APPROVE_EXECUTION / FLAG_APPROVE_PAYMENT constant NAMES are
# swapped relative to this; it never showed because every prior PoC used 0x3 = both.
# The node pre-validates the frame flags at submission: a frame whose flags declare
# EXECUTION (0x2) must have an empty target or target == tx.sender.)
SCOPE_PAYMENT = 0x1
SCOPE_EXECUTION = 0x2
# The account's VERIFY declares EXECUTION (its target is the sender); the paymaster's
# VERIFY declares PAYMENT (its target is the paymaster, a non-sender). Overridable.
ACCT_VERIFY_FLAGS = int(os.environ.get("PQ_ACCT_FLAGS", str(SCOPE_EXECUTION)), 0)
PM_VERIFY_FLAGS = int(os.environ.get("PQ_PM_FLAGS", str(SCOPE_PAYMENT)), 0)


def _read_bin(name: str) -> bytes:
    with open(os.path.join(_HERE, name)) as f:
        return bytes.fromhex(f.read().strip())


# The gated paymaster bakes the operator address into CODE (no storage), because the
# validation prefix forbids a non-sender frame from reading storage. PaymasterGated.bin
# is PaymasterGated.yul.tmpl compiled once with this placeholder operator; at runtime we
# byte-substitute the real operator into the committed bytecode, so no toolchain (solc)
# is needed on the chain / at run time. To regenerate the .bin: see rebuild_gated_bin().
_GATED_PLACEHOLDER = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"   # 20-byte operator marker


def gated_paymaster_init(operator: str) -> bytes:
    """Init bytecode of the operator-gated, storage-free paymaster, with `operator`
    substituted into the committed PaymasterGated.bin (no solc at run time)."""
    with open(os.path.join(_HERE, "PaymasterGated.bin")) as f:
        tmpl_hex = f.read().strip()
    op = operator.lower().removeprefix("0x")
    assert len(op) == 40, op
    if tmpl_hex.count(_GATED_PLACEHOLDER) != 1:
        raise SystemExit("PaymasterGated.bin placeholder not found exactly once; rebuild it.")
    return bytes.fromhex(tmpl_hex.replace(_GATED_PLACEHOLDER, op))


def rebuild_gated_bin() -> None:
    """Recompile PaymasterGated.bin from the .tmpl with the placeholder operator. Needs
    solc; run manually when the template changes, not during the PoC."""
    solc = shutil.which("solc")
    with open(os.path.join(_HERE, "PaymasterGated.yul.tmpl")) as f:
        src = f.read().replace("__OPERATOR__", _GATED_PLACEHOLDER)
    with tempfile.NamedTemporaryFile("w", suffix=".yul", delete=False) as tf:
        tf.write(src)
        path = tf.name
    try:
        out = subprocess.run([solc, "--strict-assembly", "--optimize", "--bin", path],
                             capture_output=True, text=True, check=True)
    finally:
        os.unlink(path)
    with open(os.path.join(_HERE, "PaymasterGated.bin"), "w") as f:
        f.write(out.stdout.strip().splitlines()[-1].strip())


def deploy_init(deployer_hex: str, deployer: str, init: bytes, value: int) -> str:
    """Deploy raw init bytecode via CREATE, endowed with `value` wei."""
    call = {"from": deployer, "data": "0x" + init.hex(), "value": hex(value)}
    gas = rpc.estimate_gas(call)
    n = rpc.get_nonce(deployer)
    addr = create_address(deployer, n)
    raw, _ = sign_legacy(deployer_hex, nonce=n, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 100_000, to=None, value=value, data=init,
                         chain_id=CHAIN_ID)
    stealth._wait(rpc.send_raw(raw))
    return addr


def deploy(deployer_hex: str, deployer: str, bin_name: str, suffix: bytes, value: int) -> str:
    """Deploy a contract via CREATE, endowed with `value` wei, constructor args in suffix."""
    init = _read_bin(bin_name) + suffix
    call = {"from": deployer, "data": "0x" + init.hex(), "value": hex(value)}
    gas = rpc.estimate_gas(call)
    n = rpc.get_nonce(deployer)
    addr = create_address(deployer, n)
    raw, _ = sign_legacy(deployer_hex, nonce=n, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 100_000, to=None, value=value, data=init,
                         chain_id=CHAIN_ID)
    stealth._wait(rpc.send_raw(raw))
    return addr


def k1_sig_rsv(sig_hash: bytes, priv_hex: str) -> bytes:
    """65-byte r||s||v operator signature (v = 27/28), the layout the Paymaster reads."""
    s = keys.PrivateKey(bytes.fromhex(priv_hex.removeprefix("0x"))).sign_msg_hash(sig_hash)
    return s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big") + bytes([27 + s.v])


def build_tx(account: str, paymaster: str, dest: str, value: int) -> FrameTx8:
    """The 4-frame paymaster transaction (sender = account; payer will be paymaster)."""
    priority, max_fee = stealth.current_fees()
    return FrameTx8(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            # 0: account approves EXECUTION only (target = sender account).
            Frame(MODE_VERIFY, ACCT_VERIFY_FLAGS, None, 50_000, 45_000, 0, b""),
            # 1: paymaster approves PAYMENT (target = the paymaster, a non-sender).
            Frame(MODE_VERIFY, PM_VERIFY_FLAGS, paymaster, 100_000, 50_000, 0, b""),
            # 2: heavy ML-DSA verify, start of the atomic batch (revert-gated).
            Frame(MODE_DEFAULT, FLAG_ATOMIC_BATCH, None, 8_000_000, 300_000, 0, b""),
            # 3: SENDER terminates the batch; moves the value, skipped if frame 2 reverts.
            Frame(MODE_SENDER, FLAG_NONE, dest, 100_000, 500_000, value, b""),
        ],
        # sig 0 = account ML-DSA (read by AccountP, index 0); sig 1 = operator k1 (read
        # by Paymaster, index 1). Both msg empty, so both are elided from the canonical
        # sig_hash and can sign a hash committing to the whole tx.
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b""),
                    Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )


def authorize(tx: FrameTx8, sk, pk, pk_deploy: bytes, operator_hex: str,
              good_mldsa: bool = True, good_operator: bool = True) -> None:
    h = tx.sig_hash()
    sig = mldsa.sign(sk, h)
    assert mldsa.verify(pk, h, sig)
    if not good_mldsa:
        sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    tx.signatures[0].signature = pk_deploy + sig            # account ML-DSA (index 0)
    opsig = k1_sig_rsv(h, operator_hex)
    if not good_operator:
        opsig = opsig[:10] + bytes([opsig[10] ^ 0x01]) + opsig[11:]  # tamper -> wrong recover
    tx.signatures[1].signature = opsig                      # operator k1 (index 1)


def _gas_cost(receipt) -> int:
    used = int(receipt.get("gasUsed", "0x0"), 16)
    egp = receipt.get("effectiveGasPrice")
    return used * int(egp, 16) if egp else 0


def main():
    deployer_hex, deployer = load_key()
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"singleton verifier {SINGLETON}")
    print(f"funder {deployer}  balance {rpc.get_balance(deployer)/10**18:.4f} ETH")
    if not SINGLETON:
        raise SystemExit("no SINGLETON anchored: set PQ_SINGLETON")

    # Account PQ key (would come from the passkey PRF in R1DO).
    pk, sk = mldsa.keypair(keccak(b"paymaster-poc/account-key/v1" + os.urandom(16)))
    pk_deploy = mldsa.expanded_pk(pk)
    commit = keccak(pk_deploy)

    # Operator key that authorizes the paymaster (kept in env/ephemeral, never printed).
    operator_hex = os.environ.get("PQ_OPERATOR_KEY") or "0x" + os.urandom(32).hex()
    operator = keys.PrivateKey(bytes.fromhex(operator_hex[2:])).public_key.to_checksum_address()

    value = 10 ** 12                     # the tiny value the account deliberately moves
    acct_endow = 20 * 10 ** 15           # 0.02 ETH: only to fund the value move, NOT gas
    pm_endow = 50 * 10 ** 15             # 0.05 ETH: the paymaster's gas budget

    acct_suffix = commit + b"\x00" * 12 + to_canonical_address(SINGLETON)
    account = deploy(deployer_hex, deployer, "AccountP.bin", acct_suffix, acct_endow)
    # Gated, STORAGE-FREE paymaster: the operator is baked into code (no SLOAD), so the
    # paymaster's VERIFY frame does not read non-sender storage in the validation prefix.
    pm_init = gated_paymaster_init(operator)
    paymaster = deploy_init(deployer_hex, deployer, pm_init, pm_endow)
    print(f"account (sender)  {account}  balance {rpc.get_balance(account)/10**18:.4f} ETH")
    print(f"paymaster (payer) {paymaster}  balance {rpc.get_balance(paymaster)/10**18:.4f} ETH"
          f"  (operator-gated, operator baked in code)")

    checks = {}

    # --- NEGATIVE: paymaster gate fails (bad operator sig) -> tx must be rejected -----
    dest_neg = "0x" + keccak(b"dest-neg" + os.urandom(8))[12:].hex()
    txn = build_tx(account, paymaster, dest_neg, value)
    authorize(txn, sk, pk, pk_deploy, operator_hex, good_mldsa=True, good_operator=False)
    acct_before_neg = rpc.get_balance(account)
    pm_before_neg = rpc.get_balance(paymaster)
    print("\n[NEGATIVE] bad operator signature: paymaster must NOT approve payment ...")
    rejected = False
    try:
        rn = stealth._wait(rpc.send_raw(txn.encode_hex()))
        status = rn.get("status") if rn else None
        print(f"  mined? status {status}")
    except rpc.RpcError as e:
        rejected = True
        print(f"  rejected at submission (validation prefix): {str(e)[:160]}")
        rn, status = None, None
    dest_neg_bal = rpc.get_balance(dest_neg)
    acct_after_neg = rpc.get_balance(account)
    pm_after_neg = rpc.get_balance(paymaster)
    # Pass if the tx was rejected, or (if mined) it failed and the action did not happen.
    neg_ok = rejected or (status == "0x0")
    checks["NEG: no payment approval -> tx rejected / failed (not status 0x1)"] = neg_ok
    checks["NEG: the action did NOT happen (dest got nothing)"] = dest_neg_bal == 0
    checks["NEG: nobody was charged gas for the rejected tx "
           "(account & paymaster balances unchanged)"] = (
        acct_after_neg == acct_before_neg and pm_after_neg == pm_before_neg)

    # --- POSITIVE: account approves exec, paymaster approves payment, action runs -----
    dest = "0x" + keccak(b"dest-pos" + os.urandom(8))[12:].hex()
    txp = build_tx(account, paymaster, dest, value)
    authorize(txp, sk, pk, pk_deploy, operator_hex, good_mldsa=True, good_operator=True)
    acct_before = rpc.get_balance(account)
    pm_before = rpc.get_balance(paymaster)
    dest_before = rpc.get_balance(dest)
    print(f"\n[POSITIVE] account orders value move -> {dest}, paymaster pays gas ...")
    rp = stealth._wait(rpc.send_raw(txp.encode_hex()))
    status = rp.get("status") if rp else None
    acct_after = rpc.get_balance(account)
    pm_after = rpc.get_balance(paymaster)
    dest_after = rpc.get_balance(dest)
    acct_delta = acct_before - acct_after
    pm_delta = pm_before - pm_after
    dest_delta = dest_after - dest_before
    gas_cost = _gas_cost(rp) if rp else 0
    txh = rp.get("transactionHash") if rp else None
    sender = (rp.get("from") or "").lower() if rp else ""
    print(f"  tx {txh}  status {status}")
    print(f"  account delta   {acct_delta} wei  (value moved = {value})")
    print(f"  paymaster delta {pm_delta} wei  (gasUsed*effGasPrice = {gas_cost})")
    print(f"  dest received   {dest_delta} wei")
    print(f"  receipt.from    {sender}  (account = {account.lower()})")

    checks["POS: tx succeeded (status 0x1)"] = status == "0x1"
    checks["POS: the action happened (dest received the value)"] = dest_delta == value
    checks["POS: receipt sender is the ACCOUNT (not the paymaster)"] = sender == account.lower()
    checks["POS: ACCOUNT paid ZERO gas (balance dropped by exactly the value)"] = (
        acct_delta == value)
    checks["POS: PAYMASTER paid the gas (balance dropped > 0)"] = pm_delta > 0
    if gas_cost:
        checks["POS: PAYMASTER delta == gasUsed*effectiveGasPrice (it paid ALL the gas)"] = (
            pm_delta == gas_cost)

    print("\n== RESULT ==")
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if all(checks.values()):
        print("\nPAYMASTER GREEN: a frame-native paymaster works on ethrex. The account is "
              "the tx sender and approves EXECUTION only; a separate paymaster, named by a "
              "non-sender VERIFY frame's PAYMENT approval, pays all the gas; the account "
              "pays only the value it moves. A failed paymaster gate rejects the tx. This is "
              "the 4337 paymaster model native in frames, distinct from sponsor-as-sender.")
    else:
        raise SystemExit("\nPAYMASTER PoC did not fully pass; see the checks above.")


if __name__ == "__main__":
    main()
