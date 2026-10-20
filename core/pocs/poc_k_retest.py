"""PoC-K retest with the 8-field envelope: does a NON-ZERO keyed nonce (EIP-8250)
work on the current Hegota build?

Earlier PoC-K concluded "non-zero keyed rejected by the public pool" from a
MalformedData, but that encoder was 9-field (stale). Now that frametx8 (8 fields)
is green, retest keyed properly: a self-paying AccountF spend on nonce_key = 1.

Changelog note: the FIRST use of a keyed nonce costs 97,920 STATE gas (charged on
the payment APPROVE in the VERIFY frame), so the VERIFY frame carries enough state
budget (prefix cap is 500,000).

Checks: the spend is included, dest receives the value, the (account, key=1)
NONCE_MANAGER slot advances 0 -> 1, and the account's LEGACY nonce does NOT move
(non-zero keys bypass the linear domain). If so, EIP-8250 keyed nonces are LIVE
for self-paying accounts on this build.
"""
import os

from eth_utils import keccak, to_canonical_address

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
from poc_f_selfpay import account_creation_code, deploy_account

NONCE_MANAGER = "0x0000000000000000000000000000000000008250"


def nm_slot(sender: str, key: int) -> bytes:
    return keccak(to_canonical_address(sender).rjust(32, b"\x00") + key.to_bytes(32, "big"))


def nm_seq(sender: str, key: int) -> int:
    if key == 0:
        return rpc.get_nonce(sender)
    raw = rpc.rpc("eth_getStorageAt", [NONCE_MANAGER, "0x" + nm_slot(sender, key).hex(), "latest"])
    return int(raw, 16)


def main():
    deployer_hex, deployer = load_key()
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"deployer {deployer}  balance {rpc.get_balance(deployer)/10**18:.4f} ETH")
    print(f"NONCE_MANAGER code bytes: {(len(rpc.get_code(NONCE_MANAGER))-2)//2} (EIP-8250 predeploy)")

    pk, sk = mldsa.keypair(keccak(b"poc-k-retest/key/v1" + os.urandom(16)))
    pk_deploy = mldsa.expanded_pk(pk)
    commit = keccak(pk_deploy)

    value = 10 ** 12
    endow = 5 * 10 ** 15      # 0.005 ETH; max_cost is ~0.00003 ETH, so this is ample
    account = deploy_account(deployer_hex, deployer, commit, endow)
    print(f"account {account}  balance {rpc.get_balance(account)/10**18:.4f} ETH")

    KEY = 1
    legacy_before = nm_seq(account, 0)
    key_seq_before = nm_seq(account, KEY)
    print(f"\nBEFORE: legacy nonce {legacy_before}, key[{KEY}] seq {key_seq_before}")

    dest = "0x" + keccak(b"keyed-dest" + os.urandom(8))[12:].hex()
    priority, max_fee = stealth.current_fees()
    tx = FrameTx8(
        chain_id=CHAIN_ID, nonce=key_seq_before, sender=account, nonce_keys=[KEY],
        frames=[
            # VERIFY carries >=97,920 state gas for the first keyed-nonce write.
            Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, None, 60_000, 150_000, 0, b""),
            Frame(MODE_DEFAULT, FLAG_ATOMIC_BATCH, None, 8_000_000, 300_000, 0, b""),
            Frame(MODE_SENDER, FLAG_NONE, dest, 100_000, 500_000, value, b""),
        ],
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )
    h = tx.sig_hash()
    tx.signatures[0].signature = pk_deploy + mldsa.sign(sk, h)
    print(f"spend on key[{KEY}] (seq {key_seq_before}) -> {dest}")
    try:
        r = stealth._wait(rpc.send_raw(tx.encode_hex()))
    except Exception as e:
        print("SEND ERROR:", e)
        raise SystemExit(f"keyed send rejected: {e}")

    legacy_after = nm_seq(account, 0)
    key_seq_after = nm_seq(account, KEY)
    dest_bal = rpc.get_balance(dest)
    print(f"AFTER:  tx status {r.get('status')}, legacy nonce {legacy_after}, "
          f"key[{KEY}] seq {key_seq_after}, dest_recv {dest_bal}")

    checks = {
        "spend included (status 0x1)": r.get("status") == "0x1",
        "dest received the value": dest_bal == value,
        f"key[{KEY}] seq advanced 0 -> 1": key_seq_after == key_seq_before + 1,
        "legacy nonce did NOT move (non-zero key bypasses linear)": legacy_after == legacy_before,
    }
    print("\n== RESULT ==")
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if all(checks.values()):
        print("\nKEYED NONCES LIVE: a non-zero keyed-nonce frame tx is accepted on this "
              "build. PoC-K's earlier 'rejected' verdict was the stale 9-field format, not "
              "a keyed gate. Keyed nonces work for self-paying accounts.")
    else:
        raise SystemExit("\nKeyed retest did not fully pass, see checks.")


if __name__ == "__main__":
    main()
