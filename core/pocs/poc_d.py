"""PoC-D: native pay-by-nick directory, gated by EIP-8272 recent roots (+ PoC-R).

A directory maps nick -> stealth meta-address. It publishes the merkle root of its
entries to the RECENT_ROOT predeploy (0x...8272). Resolving "nick -> metaAddr" is then
a native, storage-free membership check: DirectoryResolver.resolve STATICCALLs 0x8272
to authenticate the root (recent + genuinely committed by the directory) and verifies
a merkle proof of keccak(nick||metaAddr) against that same root. One call, sound
(a forged root reverts at the 0x8272 step), no live directory-storage read.

What this proves on-chain (real Hegota 8141):
  - eth_call (free): a real member resolves; a non-member reverts; a forged/unpublished
    root reverts (the recent-root gate).
  - frame-tx (native gating): a self-paying account runs resolve(member) in a DEFAULT
    frame atomically batched with a SENDER that pays the resolved address. Member ->
    the pay-by-nick transfer goes through; non-member -> resolve reverts, SENDER skipped,
    nothing moves.

Builds on PoC-R (recent roots) and reuses the 8-field frame envelope + self-pay.
Reuses pq-dksap READ-ONLY. Run: source ../../r_8141/.venv/bin/activate && python poc_d.py
"""
import os

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_canonical_address

import _pqdksap  # noqa: F401
from pq_dksap import rpc, stealth
from pq_dksap.config import CHAIN_ID
from pq_dksap.frametx import (
    FLAG_APPROVE_EXECUTION_AND_PAYMENT, FLAG_ATOMIC_BATCH, FLAG_NONE,
    MODE_DEFAULT, MODE_SENDER, MODE_VERIFY, SCHEME_ARBITRARY, Frame, Signature,
)
from pq_dksap.legacytx import create_address, sign_legacy

from frametx8 import FrameTx8
from keyfile import load_key
from poc_r import RECENT_ROOT, source_id, write_root, block_slot, current_slot

_HERE = os.path.dirname(os.path.abspath(__file__))
RESOLVE_SEL = keccak(text="resolve(bytes32,uint64,bytes32,bytes32,bytes32,bytes32[])")[:4]


# ---- merkle (sorted-pair keccak, matches DirectoryResolver.sol) ------------
def leaf(nick: bytes, meta: bytes) -> bytes:
    return keccak(nick + meta)


def _parent(a: bytes, b: bytes) -> bytes:
    return keccak(a + b) if a <= b else keccak(b + a)


def merkle_root_and_proof(leaves: list[bytes], idx: int):
    """Return (root, proof) for leaf at idx. Odd node is promoted (OZ-style)."""
    proof = []
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_parent(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote odd
        if idx ^ 1 < len(level):      # sibling exists at this level
            proof.append(level[idx ^ 1])
        idx //= 2
        level = nxt
    return level[0], proof


# ---- deploy + calls --------------------------------------------------------
def deploy(deployer_hex: str, deployer: str, bin_path: str, endow: int = 0) -> str:
    init = bytes.fromhex(open(os.path.join(_HERE, bin_path)).read().strip())
    call = {"from": deployer, "data": "0x" + init.hex()}
    if endow:
        call["value"] = hex(endow)
    gas = rpc.estimate_gas(call)
    n = rpc.get_nonce(deployer)
    addr = create_address(deployer, n)
    raw, _ = sign_legacy(deployer_hex, nonce=n, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 80_000, to=None, value=endow, data=init, chain_id=CHAIN_ID)
    stealth._wait(rpc.send_raw(raw))
    return addr


def resolve_calldata(src: bytes, slot: int, root: bytes, nick: bytes, meta: bytes, proof: list[bytes]) -> bytes:
    return RESOLVE_SEL + abi_encode(
        ["bytes32", "uint64", "bytes32", "bytes32", "bytes32", "bytes32[]"],
        [src, slot, root, nick, meta, proof])


def eth_call_resolve(resolver: str, cd: bytes):
    """Returns (ok, err). ok=True if resolve did not revert."""
    try:
        rpc.eth_call({"to": resolver, "data": "0x" + cd.hex(), "gas": hex(5_000_000)})
        return True, None
    except Exception as e:
        return False, str(e)


def main():
    deployer_hex, deployer = load_key()
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"funder {deployer}  balance {rpc.get_balance(deployer)/10**18:.4f} ETH")

    # ---- build a tiny directory: nick -> meta-address --------------------
    entries = [
        (b"alice".ljust(32, b"\x00"), keccak(b"alice-meta-address")),
        (b"bob".ljust(32, b"\x00"), keccak(b"bob-meta-address")),
        (b"carol".ljust(32, b"\x00"), keccak(b"carol-meta-address")),
        (b"dave".ljust(32, b"\x00"), keccak(b"dave-meta-address")),
    ]
    leaves = [leaf(n, m) for n, m in entries]
    root, proof = merkle_root_and_proof(leaves, 1)   # prove "bob"
    bob_nick, bob_meta = entries[1]
    print(f"directory: {len(entries)} entries, root {root.hex()[:16]}..., proving 'bob'")

    # ---- deploy resolver + publish the directory root to 0x8272 ----------
    resolver = deploy(deployer_hex, deployer, "DirectoryResolver.bin")
    print(f"DirectoryResolver {resolver}")
    salt = os.urandom(32)
    src = source_id(deployer, salt)                  # the directory's namespace
    wr = write_root(deployer_hex, deployer, salt, root)
    S = block_slot(wr["blockNumber"])
    print(f"published root at slot {S} (source_id {src.hex()[:16]}...)")
    while current_slot() <= S:
        import time; time.sleep(2)

    checks = {}

    # ---- eth_call cases (free) -------------------------------------------
    ok, _ = eth_call_resolve(resolver, resolve_calldata(src, S, root, bob_nick, bob_meta, proof))
    checks["eth_call: real member (bob) resolves"] = ok

    _, wrongmeta_leaves = None, None
    ok2, err2 = eth_call_resolve(resolver, resolve_calldata(src, S, root, b"mallory".ljust(32, b"\x00"), keccak(b"x"), proof))
    checks["eth_call: non-member (mallory) reverts"] = not ok2

    forged = bytes([root[0] ^ 0x01]) + root[1:]
    # need a proof against the forged root; reuse proof (won't matter, the 8272 gate fails first)
    ok3, err3 = eth_call_resolve(resolver, resolve_calldata(src, S, forged, bob_nick, bob_meta, proof))
    checks["eth_call: forged/unpublished root reverts (8272 gate)"] = not ok3

    # ---- native frame-tx gating: pay-by-nick ------------------------------
    account = deploy(deployer_hex, deployer, "ApproveAccount.bin", endow=5 * 10 ** 15)
    print(f"\nself-pay account {account}  balance {rpc.get_balance(account)/10**18:.4f} ETH")
    value = 10 ** 12

    def pay_by_nick(nick, meta, prf, dest, tag):
        tx = FrameTx8(
            chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
            frames=[
                Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, None, 60_000, 60_000, 0, b""),
                Frame(MODE_DEFAULT, FLAG_ATOMIC_BATCH, resolver, 600_000, 100_000, 0,
                      resolve_calldata(src, S, root, nick, meta, prf)),
                Frame(MODE_SENDER, FLAG_NONE, dest, 100_000, 500_000, value, b""),
            ],
            signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
            max_priority_fee_per_gas=stealth.current_fees()[0],
            max_fee_per_gas=stealth.current_fees()[1],
        )
        try:
            r = stealth._wait(rpc.send_raw(tx.encode_hex()))
            print(f"  [{tag}] status {r.get('status')}  dest_recv {rpc.get_balance(dest)}")
            return r
        except Exception as e:
            print(f"  [{tag}] rejected: {e}")
            return None

    # resolved payout address for a nick = last 20 bytes of its meta commitment (symbolic).
    # The address is deterministic, so measure the balance DELTA (it may carry a balance
    # from earlier runs on a long-lived chain), not the absolute value.
    dest_bob = "0x" + bob_meta.hex()[24:]
    bob_before = rpc.get_balance(dest_bob)
    print("[GOOD] pay-by-nick to resolved 'bob' ...")
    rg = pay_by_nick(bob_nick, bob_meta, proof, dest_bob, "GOOD")
    checks["frame GOOD: member resolve gates a successful pay"] = (rg is not None and rg.get("status") == "0x1")
    checks["frame GOOD: resolved dest received value"] = rpc.get_balance(dest_bob) - bob_before == value

    dest_mal = "0x" + keccak(b"mallory-dest")[12:].hex()
    print("[BAD] pay-by-nick to non-member 'mallory' ...")
    rb = pay_by_nick(b"mallory".ljust(32, b"\x00"), keccak(b"x"), proof, dest_mal, "BAD")
    bad_blocked = (rb is None) or (rb.get("status") == "0x0")
    checks["frame BAD: non-member rejected/failed"] = bad_blocked
    checks["frame BAD: dest got nothing"] = rpc.get_balance(dest_mal) == 0

    print("\n== RESULT ==")
    for name, okc in checks.items():
        print(f"  [{'PASS' if okc else 'FAIL'}] {name}")
    if all(checks.values()):
        print("\nPoC-D GREEN: native pay-by-nick. A directory publishes its merkle root to "
              "0x8272; resolving nick->metaAddr authenticates that recent root and proves "
              "membership in one storage-free call, and it gates a payment in a frame tx. "
              "Member pays; non-member and forged roots are rejected. Discovery moat, native.")
    else:
        raise SystemExit("\nPoC-D did not fully pass, see checks.")


if __name__ == "__main__":
    main()
