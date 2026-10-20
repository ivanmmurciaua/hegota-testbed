"""PoC-R: recent roots (EIP-8272) on the current Hegota build.

Proves the native "validate membership/freshness against a recent root, in the
mempool prefix, without touching storage" primitive, the substrate for a native
directory / pay-by-nick (PoC-D).

Mechanics (verified against the deployed source, commit 4738681, and the predeploy
geas scripts/hegota-testnet/recent_root/main.eas):

  RECENT_ROOT predeploy = 0x...8272, selected by calldata length:
    WRITE    64 bytes salt(32)||root(32), value 0:
             source_id   = keccak256(msg.sender[20] || salt[32])
             entry_hash  = keccak256(ENTRY_DOMAIN   || source_id || u64_be(S)        || root)
             storage_key = keccak256(STORAGE_DOMAIN || source_id || u64_be(S % 8192))
             storage[storage_key] = entry_hash, S = current EIP-7843 slot (SLOTNUM)
    VALIDATE n*72 bytes of (source_id||u64_be(slot)||root): each slot < current_slot,
             current_slot - slot <= 8191, and the stored entry_hash must match.

  Canonical recent-root VERIFIER frame: VERIFY, target 0x...8272, flags 0, value 0,
  state_gas 0, data = 1..16 packed 72-byte tuples. A failing tuple reverts the frame,
  which fails the validation prefix and invalidates the tx.

This PoC: a known caller (the funder) WRITEs a root; then a self-paying AccountF
frame tx REFERENCES it in a recent-root verifier frame (plus the ML-DSA hard gate +
self-pay from PoC-F'). Good tuple -> the spend goes through; a tampered root ->
the prefix reverts and nothing moves.

Frame layout (4 frames, matches AccountF's VERIFY@nframes-3 / DEFAULT@nframes-2):
  0 VERIFY  recent-root verifier (target 0x8272)         membership/freshness gate
  1 VERIFY  approve exec+payment (account, self-pay)
  2 DEFAULT ML-DSA verify (account, FLAG_ATOMIC_BATCH)   PQ hard gate
  3 SENDER  move value (terminator of the batch)

Env: funded key via keyfile. Run: source ../../r_8141/.venv/bin/activate && python poc_r.py
"""
import os
import time

from eth_utils import keccak, to_canonical_address

import _pqdksap  # noqa: F401
from pq_dksap import mldsa, rpc, stealth
from pq_dksap.config import CHAIN_ID
from pq_dksap.frametx import (
    FLAG_APPROVE_EXECUTION_AND_PAYMENT, FLAG_ATOMIC_BATCH, FLAG_NONE,
    MODE_DEFAULT, MODE_SENDER, MODE_VERIFY, SCHEME_ARBITRARY, Frame, Signature,
)
from pq_dksap.legacytx import sign_legacy

from frametx8 import FrameTx8
from keyfile import load_key
from poc_f_selfpay import deploy_account

RECENT_ROOT = "0x0000000000000000000000000000000000008272"
ENTRY_DOMAIN = keccak(b"RECENT_ROOT_ENTRY")
STORAGE_DOMAIN = keccak(b"RECENT_ROOT_STORAGE")
RING = 8192


def current_slot() -> int:
    return int(rpc.rpc("eth_getBlockByNumber", ["latest", False])["slotNumber"], 16)


def block_slot(block_number_hex: str) -> int:
    return int(rpc.rpc("eth_getBlockByNumber", [block_number_hex, False])["slotNumber"], 16)


def source_id(caller: str, salt: bytes) -> bytes:
    return keccak(to_canonical_address(caller) + salt)      # keccak(addr[20] || salt[32])


def entry_hash(src: bytes, slot: int, root: bytes) -> bytes:
    return keccak(ENTRY_DOMAIN + src + slot.to_bytes(8, "big") + root)


def storage_key(src: bytes, slot: int) -> bytes:
    return keccak(STORAGE_DOMAIN + src + (slot % RING).to_bytes(8, "big"))


def write_root(caller_hex: str, caller: str, salt: bytes, root: bytes):
    """WRITE a recent root: legacy call to 0x8272 with salt||root. Returns the receipt."""
    data = salt + root
    n = rpc.get_nonce(caller)
    gas = rpc.estimate_gas({"from": caller, "to": RECENT_ROOT, "data": "0x" + data.hex()})
    raw, _ = sign_legacy(caller_hex, nonce=n, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 60_000, to=RECENT_ROOT, value=0, data=data, chain_id=CHAIN_ID)
    return stealth._wait(rpc.send_raw(raw))


def tuple_bytes(src: bytes, slot: int, root: bytes) -> bytes:
    return src + slot.to_bytes(8, "big") + root            # 32 + 8 + 32 = 72


def build_spend(account: str, src: bytes, slot: int, root: bytes, dest: str, value: int,
                pk_deploy: bytes) -> FrameTx8:
    priority, max_fee = stealth.current_fees()
    return FrameTx8(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            Frame(MODE_VERIFY, FLAG_NONE, RECENT_ROOT, 100_000, 0, 0, tuple_bytes(src, slot, root)),
            Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, None, 60_000, 45_000, 0, b""),
            Frame(MODE_DEFAULT, FLAG_ATOMIC_BATCH, None, 8_000_000, 300_000, 0, b""),
            Frame(MODE_SENDER, FLAG_NONE, dest, 100_000, 500_000, value, b""),
        ],
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )


def authorize(tx: FrameTx8, sk, pk_deploy: bytes):
    tx.signatures[0].signature = pk_deploy + mldsa.sign(sk, tx.sig_hash())


def main():
    caller_hex, caller = load_key()
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"funder/caller {caller}  balance {rpc.get_balance(caller)/10**18:.4f} ETH")
    print(f"RECENT_ROOT code bytes: {(len(rpc.get_code(RECENT_ROOT))-2)//2}")

    pk, sk = mldsa.keypair(keccak(b"poc-r/account-key/v1" + os.urandom(16)))
    pk_deploy = mldsa.expanded_pk(pk)
    commit = keccak(pk_deploy)
    account = deploy_account(caller_hex, caller, commit, 5 * 10 ** 15)
    print(f"account {account}  balance {rpc.get_balance(account)/10**18:.4f} ETH")

    # 1) WRITE a root (the "directory" publishes its set root). root is opaque here.
    salt = os.urandom(32)
    root = keccak(b"poc-r/set-merkle-root")
    src = source_id(caller, salt)
    print(f"\nwriting root to 0x8272 (source_id {src.hex()[:16]}...) ...")
    wr = write_root(caller_hex, caller, salt, root)
    S = block_slot(wr["blockNumber"])
    print(f"  written at slot {S} (block {int(wr['blockNumber'],16)})")

    # self-check: the predeploy stored entry_hash under storage_key
    sk_key = storage_key(src, S)
    stored = rpc.rpc("eth_getStorageAt", [RECENT_ROOT, "0x" + sk_key.hex(), "latest"])
    ok_store = bytes.fromhex(stored[2:]).rjust(32, b"\x00") == entry_hash(src, S, root)
    print(f"  storage[storage_key] == entry_hash(root): {ok_store}")

    # 2) wait until the slot advances (reference needs slot < current_slot)
    while current_slot() <= S:
        time.sleep(2)
    print(f"  current slot advanced to {current_slot()} (> {S}); reference is in-window")

    checks = {"write recorded (storage == entry_hash)": ok_store}

    # 3) GOOD: reference the real (source_id, S, root)
    dest_g = "0x" + keccak(b"poc-r-dest-good" + os.urandom(8))[12:].hex()
    txg = build_spend(account, src, S, root, dest_g, 10 ** 12, pk_deploy)
    authorize(txg, sk, pk_deploy)
    print(f"\n[GOOD tuple] spend referencing the real recent root -> {dest_g}")
    rg = stealth._wait(rpc.send_raw(txg.encode_hex()))
    good_bal = rpc.get_balance(dest_g)
    print(f"  status {rg.get('status')}  dest_recv {good_bal}")
    checks["GOOD: recent-root reference accepted, spend succeeded"] = rg.get("status") == "0x1"
    checks["GOOD: dest received the value"] = good_bal == 10 ** 12

    # 4) BAD: same (source_id, slot) but a tampered root -> entry_hash mismatch -> revert
    dest_b = "0x" + keccak(b"poc-r-dest-bad" + os.urandom(8))[12:].hex()
    bad_root = bytes([root[0] ^ 0x01]) + root[1:]
    txb = build_spend(account, src, S, bad_root, dest_b, 10 ** 12, pk_deploy)
    authorize(txb, sk, pk_deploy)
    print(f"\n[BAD tuple] spend referencing a tampered root -> {dest_b}")
    bad_rejected = False
    try:
        rb = stealth._wait(rpc.send_raw(txb.encode_hex()))
        bad_rejected = (rb is None) or (rb.get("status") == "0x0")
        print(f"  status {rb.get('status') if rb else None}")
    except Exception as e:
        bad_rejected = True
        print(f"  rejected (expected): {e}")
    checks["BAD: tampered root rejected (membership gate holds)"] = bad_rejected
    checks["BAD: dest got nothing"] = rpc.get_balance(dest_b) == 0

    print("\n== RESULT ==")
    for name, okc in checks.items():
        print(f"  [{'PASS' if okc else 'FAIL'}] {name}")
    if all(checks.values()):
        print("\nPoC-R GREEN: a recent-root verifier frame gates a spend on a root the "
              "predeploy recorded recently, validated in the prefix without touching the "
              "directory's storage. Real root -> spend; tampered root -> rejected. This is "
              "the native substrate for pay-by-nick / a validatable pool (PoC-D).")
    else:
        raise SystemExit("\nPoC-R did not fully pass, see checks.")


if __name__ == "__main__":
    main()
