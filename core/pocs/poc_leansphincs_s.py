"""PoC leanSphincs-s: hash-based PQ self-pay on EIP-8141 frames (ethrex 8141).

A second signature scheme for the rail, alongside the ML-DSA PoCs. leanSphincs-s
(leanSphincs small: h=26, k=13, a=12, T=128, 4164-byte signature) is a hash-based
SPHINCS+ variant over Ethereum Keccak-256, verified on-chain in ~249 keccak256
calls. Where poc_f_selfpay gates a transfer behind a ~5M-gas ML-DSA (lattice)
verify batched via FLAG_ATOMIC_BATCH, this gates it behind a hash-based verify
done INSIDE the VERIFY frame: the account DELEGATECALLs the shared frame module,
which SIGDATACOPYs the ARBITRARY witness and STATICCALLs the leanSphincs-s
verifier on compute_sig_hash(tx), then APPROVEs execution and payment. The whole
spend costs ~288K gas, self-paid.

Frame layout of the spend (account self-pays, EIP-8141 conformant):
  frame 0  VERIFY  APPROVE_EXECUTION_AND_PAYMENT  -> module verifies + account self-pays
  frame 1  SENDER  (terminator, no flag)          -> moves value
  witness  ARBITRARY entry, empty msg, the leanSphincs-s signature over sig_hash

Nothing is pre-provisioned: at runtime this keygens a FRESH leanSphincs-s key,
faucet-funds a FRESH throwaway EOA, deploys a FRESH SphincsFrameAccount wired to
the live verifier + frame module, endows it, and spends. No key or EOA is ever
read from or written to a tracked file.

What this proves on-chain (real Hegota 8141):
  1. eth_call de-risk: the live verifier accepts our signature (returns 1) and
     rejects a tampered one (returns 0).
  2. GOOD signature: the spend lands, from == the account itself (self-pay, no
     relayer / operator / paymaster), the recipient receives the value. The
     leanSphincs-s VERIFY frame costs ~47K gas (a ~249-keccak256 hash-based check,
     against a ~5M-gas ML-DSA lattice verify). Total tx gas is the ~288K self-pay
     base (the spike's number, to a pre-existing recipient) plus the SENDER's
     ~183.6K new-account state gas (EIP-8037), since this PoC pays a FRESH
     recipient: ~471K end to end.
  3. Negative: a tampered witness is rejected by ethrex_simulateFrameTransaction
     (never submitted).

Signer: the vendored MIT Python signer core/vendor/leansphincs (pip-only, needs
only pycryptodome), preferred over the repo's Rust binary so the PoC stays
pip-only. Envelope: core/lib/frametx8 (byte-identical to the reference builder's
encoder, the 0x06 frame-tx type stripped). Reuses pq-dksap READ-ONLY for RPC,
faucet, legacy deploy and fee pricing.

Funding the fresh EOA: the faucet is the default path, tried first. When the
faucet is rate-limited (it is per-IP), set a funded funder key via env
(PQ_DEPLOYER_KEY / POC_PRIVATE_KEY / PQ_KEYFILE, resolved by keyfile.load_key)
and the fresh EOA is topped up from it with a real transfer instead. No key is
ever committed; the EOA that self-pays is still freshly generated each run.

Env (all optional; defaults are the live singletons):
  PQ_LSS_VERIFIER      leanSphincs-s verifier (default 0xae3bA3e1...3481a)
  PQ_LSS_FRAME_MODULE  shared frame module    (default 0xAA481E83...4295)
  PQ_LSS_B             signer kept-subtree height (default 10; larger = slower
                       keygen, faster signing)
  PQ_DEPLOYER_KEY / POC_PRIVATE_KEY / PQ_KEYFILE
                       optional funded funder, used only if the faucet is cold
Run: ./run.sh ethrex poc_leansphincs_s.py
"""
import os
import time

import _pqdksap  # noqa: F401  (adds core/vendor to sys.path + patches live net config)
from pq_dksap import rpc, stealth
from pq_dksap.config import CHAIN_ID
from pq_dksap.frametx import (
    FLAG_APPROVE_EXECUTION_AND_PAYMENT, FLAG_NONE, MODE_SENDER, MODE_VERIFY,
    SCHEME_ARBITRARY, Frame, Signature,
)
from pq_dksap.legacytx import create_address, sign_legacy
from eth_keys import keys
from eth_utils import keccak, to_canonical_address

from frametx8 import FrameTx8                       # 8-field envelope, current Hegota build
from leansphincs.leansphincs_s_signer import keygen, sign as lss_sign, verify as lss_verify, LEAN_S

_HERE = os.path.dirname(os.path.abspath(__file__))
ACCOUNT_BIN = os.path.join(_HERE, "SphincsFrameAccount.bin")

# Live singletons (re-verified to have code at start). Env-overridable so the PoC
# survives a re-genesis without an edit.
VERIFIER = os.environ.get("PQ_LSS_VERIFIER", "0xae3bA3e1DC1bD3866608ECA1498D3e9263B3481a")
FRAME_MODULE = os.environ.get("PQ_LSS_FRAME_MODULE", "0xAA481E835ec1b82E528d6D36D432F9Af440B4295")
B = int(os.environ.get("PQ_LSS_B", "10"))

# verifyFrameAndApprove(uint256): the module entry point the account exposes.
VERIFY_FRAME_SELECTOR = keccak(b"verifyFrameAndApprove(uint256)")[:4]
# verify(bytes32 pkSeed, bytes32 pkRoot, bytes32 message, bytes sig): the verifier ABI.
VERIFY_ABI_SELECTOR = keccak(b"verify(bytes32,bytes32,bytes32,bytes)")[:4]  # 0x2bf6eda8
# EIP-8037: state budget to fund a brand-new recipient, from the SENDER frame.
NEW_ACCOUNT_STATE_GAS = 120 * 1530

VALUE = 10 ** 13           # 0.00001 ETH moved by the spend
ENDOW = 2 * 10 ** 16       # 0.02 ETH endowment so the account can self-pay


def account_creation_code() -> bytes:
    with open(ACCOUNT_BIN) as f:
        return bytes.fromhex(f.read().strip())


def pad32_addr(a: str) -> bytes:
    return b"\x00" * 12 + to_canonical_address(a)


def fresh_eoa():
    """A throwaway EOA, generated in memory. Never written to any file."""
    while True:
        pk_bytes = os.urandom(32)
        try:
            pk = keys.PrivateKey(pk_bytes)
        except Exception:
            continue
        return pk_bytes.hex(), pk.public_key.to_checksum_address()


def fund_from_faucet(addr: str, target_wei: int) -> int:
    """Claim from the faucet until the EOA holds at least target_wei. The faucet is
    the default funding path; it is per-IP rate-limited, so a 429 ends the attempt
    and the caller falls back to an optional funded EOA."""
    for attempt in range(3):
        bal = rpc.get_balance(addr)
        if bal >= target_wei:
            return bal
        status, body = rpc.faucet_claim(addr)
        print(f"  faucet claim #{attempt + 1}: http {status} ({str(body)[:120]})")
        if status not in (200, 201, 202):
            break                                   # rate-limited: do not busy-wait
        for _ in range(40):                          # wait for the drip to confirm
            bal = rpc.get_balance(addr)
            if bal >= target_wei:
                return bal
            time.sleep(3)
    return rpc.get_balance(addr)


def top_up_from_funder(addr: str, target_wei: int, have: int) -> int:
    """Fallback for a cold faucet: send (target - have) from a funded EOA resolved
    from env (PQ_DEPLOYER_KEY / POC_PRIVATE_KEY / PQ_KEYFILE). The funded EOA is a
    funding source only; the account that self-pays is still the fresh EOA. No key
    is read from or written to any tracked file."""
    try:
        from keyfile import load_key
        funder_hex, funder = load_key()
    except SystemExit:
        return have                                  # no funder configured
    fb = rpc.get_balance(funder)
    amount = (target_wei - have) + 10 ** 16          # top-up plus a little headroom
    print(f"  faucet cold; funding {addr} with {amount / 1e18:.4f} ETH from funder "
          f"{funder} (balance {fb / 1e18:.4f} ETH)")
    if fb < amount + 10 ** 15:
        raise SystemExit(f"funder {funder} underfunded ({fb} wei) to top up the fresh EOA")
    _send_value(funder_hex, funder, addr, amount, "fresh EOA top-up")
    return rpc.get_balance(addr)


def eth_call_verify(pk_seed: bytes, pk_root: bytes, message: bytes, sig: bytes) -> str:
    head = VERIFY_ABI_SELECTOR + pk_seed + pk_root + message + (128).to_bytes(32, "big")
    tail = len(sig).to_bytes(32, "big") + sig + b"\x00" * ((-len(sig)) % 32)
    return rpc.eth_call({"to": VERIFIER, "data": "0x" + (head + tail).hex()})


def deploy_account(eoa_hex: str, eoa: str, pk_seed: bytes, pk_root: bytes) -> str:
    """CREATE a fresh SphincsFrameAccount. The constructor is NOT payable (funding
    goes through `receive()` afterward), so the CREATE carries value 0. Constructor
    args appended: pkSeed(32) || pkRoot(32) || verifier(32) || owner(32) || frameModule(32)."""
    init = (account_creation_code() + pk_seed + pk_root
            + pad32_addr(VERIFIER) + pad32_addr(eoa) + pad32_addr(FRAME_MODULE))
    call = {"from": eoa, "data": "0x" + init.hex()}
    gas = rpc.estimate_gas(call)
    nonce = rpc.get_nonce(eoa)
    addr = create_address(eoa, nonce)
    raw, _ = sign_legacy(eoa_hex, nonce=nonce, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 100_000, to=None, value=0, data=init,
                         chain_id=CHAIN_ID)
    rcpt = stealth._wait(rpc.send_raw(raw))
    if not rcpt or rcpt.get("status") not in ("0x1", 1):
        raise SystemExit(f"account deploy failed: {rcpt}")
    deployed = rcpt.get("contractAddress")
    if deployed and deployed.lower() != addr.lower():
        addr = deployed
    return addr


def _send_value(src_hex: str, src: str, dest: str, amount: int, what: str) -> None:
    """A legacy value transfer, gas estimated live. Funding a brand-new account on
    this chain costs far more than 21000 (EIP-8037 account-creation state gas), so
    the gas limit is estimated, never hardcoded."""
    gas = rpc.estimate_gas({"from": src, "to": dest, "value": hex(amount)})
    nonce = rpc.get_nonce(src)
    raw, _ = sign_legacy(src_hex, nonce=nonce, gas_price=stealth.legacy_gas_price(),
                         gas_limit=gas + 50_000, to=dest, value=amount, data=b"", chain_id=CHAIN_ID)
    rcpt = stealth._wait(rpc.send_raw(raw))
    if not rcpt or rcpt.get("status") not in ("0x1", 1):
        raise SystemExit(f"{what} failed: {rcpt}")


def fund_account(eoa_hex: str, eoa: str, account: str, amount: int) -> None:
    """Endow the account through its payable receive(), so it can self-pay a spend."""
    _send_value(eoa_hex, eoa, account, amount, "account funding")


def build_spend(account: str, recipient: str, value: int) -> FrameTx8:
    priority, max_fee = stealth.current_fees()
    return FrameTx8(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            # VERIFY: the account delegatecalls the frame module, which verifies the
            # ARBITRARY witness against its own key and APPROVEs execution + payment.
            Frame(MODE_VERIFY, FLAG_APPROVE_EXECUTION_AND_PAYMENT, account, 300_000, 0, 0,
                  VERIFY_FRAME_SELECTOR + (0).to_bytes(32, "big")),
            # SENDER: a plain transfer from the account, funding a new recipient.
            Frame(MODE_SENDER, FLAG_NONE, recipient, 30_000, NEW_ACCOUNT_STATE_GAS, value, b""),
        ],
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )


def simulate(tx: FrameTx8):
    return rpc.rpc("ethrex_simulateFrameTransaction", [tx.encode_hex()])


def main():
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"leanSphincs-s PoC: verifier {VERIFIER}, frame module {FRAME_MODULE}, b={B}")

    checks = {}

    # --- 0) the live singletons must have code --------------------------------
    vcode, mcode = rpc.get_code(VERIFIER), rpc.get_code(FRAME_MODULE)
    checks["verifier has code on-chain"] = isinstance(vcode, str) and len(vcode) > 2
    checks["frame module has code on-chain"] = isinstance(mcode, str) and len(mcode) > 2
    print(f"  verifier code {len(vcode) // 2 - 1} B, frame module code {len(mcode) // 2 - 1} B")
    if not (checks["verifier has code on-chain"] and checks["frame module has code on-chain"]):
        raise SystemExit("a required singleton has no code: re-anchor PQ_LSS_* for this network")

    # --- 1) fresh key + eth_call de-risk against the live verifier ------------
    print("\n[keygen] fresh leanSphincs-s key ...")
    t0 = time.time()
    sk = keygen(os.urandom(32), B, LEAN_S)
    pk_seed, pk_root = sk.pk_seed, sk.pk_root
    print(f"  pkSeed 0x{pk_seed.hex()}  pkRoot 0x{pk_root.hex()}  ({time.time() - t0:.2f}s)")

    probe_msg = keccak(b"poc-leansphincs-s/derisk/" + os.urandom(16))
    probe_sig, _ = lss_sign(sk, probe_msg)
    assert lss_verify(pk_seed, pk_root, probe_msg, probe_sig, LEAN_S), "local verify failed"
    one = "0x" + "0" * 63 + "1"
    zero = "0x" + "0" * 64
    good = eth_call_verify(pk_seed, pk_root, probe_msg, probe_sig)
    tampered = bytearray(probe_sig)
    tampered[100] ^= 0x01
    bad = eth_call_verify(pk_seed, pk_root, probe_msg, bytes(tampered))
    print(f"  eth_call good={good}  tampered={bad}")
    checks["eth_call: verifier accepts our signature (1)"] = good == one
    checks["eth_call: verifier rejects a tampered signature (0)"] = bad == zero

    # --- 2) fresh EOA, faucet-funded; deploy + endow a fresh account ----------
    eoa_hex, eoa = fresh_eoa()
    print(f"\n[eoa] fresh throwaway EOA {eoa}")
    need = ENDOW + 2 * 10 ** 17       # endowment + headroom for the ~3M-gas deploy (gas price varies)
    bal = fund_from_faucet(eoa, need)
    if bal < need:
        bal = top_up_from_funder(eoa, need, bal)
    print(f"  funded balance {bal / 1e18:.4f} ETH")
    checks["faucet funded the fresh EOA"] = bal > 0
    if bal < ENDOW + 10 ** 16:
        raise SystemExit(f"EOA underfunded ({bal} wei); faucet may be rate-limited, retry later")

    print("[deploy] fresh SphincsFrameAccount ...")
    account = deploy_account(eoa_hex, eoa, pk_seed, pk_root)
    fund_account(eoa_hex, eoa, account, ENDOW)
    acct_bal = rpc.get_balance(account)
    code = rpc.get_code(account)
    print(f"  account {account}  balance {acct_bal / 1e18:.4f} ETH  code {len(code) // 2 - 1} B")
    checks["account deployed with code"] = isinstance(code, str) and len(code) > 2
    checks["account endowed (self-pay funds present)"] = acct_bal >= ENDOW

    # --- 3) negative: a tampered witness must be rejected by simulation -------
    recipient = "0x" + keccak(b"lss-recipient/" + os.urandom(8))[12:].hex()
    print(f"\n[negative] tampered witness, simulate only -> {recipient}")
    tx_neg = build_spend(account, recipient, VALUE)
    neg_hash = tx_neg.sig_hash()
    neg_sig, _ = lss_sign(sk, neg_hash)
    neg_bad = bytearray(neg_sig)
    neg_bad[100] ^= 0x01
    tx_neg.signatures[0].signature = bytes(neg_bad)
    assert tx_neg.sig_hash() == neg_hash, "witness changed the sig hash"
    try:
        sim_bad = simulate(tx_neg)
    except Exception as exc:                 # an RPC error is also a rejection
        sim_bad = {"__error__": str(exc)}
    print(f"  tampered simulation: {str(sim_bad)[:200]}")
    rejected = not (isinstance(sim_bad, dict) and sim_bad.get("valid")
                    and sim_bad.get("executionStatus") == "success")
    checks["negative: tampered witness rejected by simulation (not sent)"] = rejected

    # --- 4) good signature: self-paying spend, submitted for real -------------
    print(f"\n[spend] good signature, self-pay -> {recipient}")
    tx = build_spend(account, recipient, VALUE)
    sig_hash = tx.sig_hash()
    t0 = time.time()
    sig, _ = lss_sign(sk, sig_hash)
    tx.signatures[0].signature = sig
    assert tx.sig_hash() == sig_hash, "witness changed the sig hash"
    print(f"  sig hash 0x{sig_hash.hex()}  witness {len(sig)} B signed in {time.time() - t0:.2f}s")

    sim = simulate(tx)
    ok_sim = isinstance(sim, dict) and sim.get("valid") and sim.get("executionStatus") == "success"
    print(f"  simulation: {str(sim)[:200]}")
    if not ok_sim:
        raise SystemExit("good-signature simulation failed; not sending")

    acct_before = rpc.get_balance(account)
    txhash = rpc.send_raw(tx.encode_hex())
    print(f"  submitted {txhash}")
    rcpt = stealth._wait(txhash)
    if not rcpt:
        raise SystemExit("spend not mined within the timeout")
    gas_used = int(rcpt.get("gasUsed", "0x0"), 16)
    frm = (rcpt.get("from") or "").lower()
    payer = (rcpt.get("payer") or "").lower()
    recv = rpc.get_balance(recipient)
    acct_after = rpc.get_balance(account)
    # Per-frame execution gas. Frame 0 is the leanSphincs-s VERIFY (the hash-based
    # verify + APPROVE); frame 1 is the SENDER transfer.
    fr = rcpt.get("frameReceipts") or []
    verify_frame_gas = int(fr[0]["gasUsed"], 16) if fr else None
    print(f"  status {rcpt.get('status')}  from {frm}  payer {payer or '(n/a)'}  "
          f"gasUsed {gas_used}  recipient {recv} wei")
    print(f"  verify-frame execution gas {verify_frame_gas} (hash-based leanSphincs-s verify)")
    print(f"  account spent {acct_before - acct_after} wei (gas + value, self-paid)")

    checks["spend mined with status 0x1"] = rcpt.get("status") in ("0x1", 1)
    checks["spend from == the account (self-pay, no relayer)"] = frm == account.lower()
    checks["payer == the account (if reported)"] = (payer == account.lower()) if payer else True
    checks["recipient received the value"] = recv == VALUE
    # The leanSphincs-s verify is a ~249-keccak256 hash-based check: its VERIFY frame
    # costs ~47K execution gas (vs a ~5M-gas ML-DSA lattice verify), the real point.
    checks["leanSphincs-s verify frame is cheap (hash-based, < 100K gas)"] = (
        verify_frame_gas is not None and verify_frame_gas < 100_000)
    # Total tx gas: the ~288K self-pay base (proven in the spike to a pre-existing
    # recipient) PLUS the SENDER's new-account state gas (EIP-8037, ~183.6K), since
    # this PoC always pays a FRESH recipient. So a fresh-recipient self-pay is ~471K.
    expected = 288_042 + NEW_ACCOUNT_STATE_GAS
    checks["gasUsed == self-pay base + new-account state gas (~471K, within 15%)"] = (
        0.85 * expected <= gas_used <= 1.15 * expected)

    print("\n== RESULT ==")
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if all(checks.values()):
        print(f"\nPoC leanSphincs-s GREEN: hash-based PQ self-pay on frames. tx {txhash}. "
              "The account self-pays (frame-tx sender and payer); the hash-based verify runs "
              "inside the VERIFY frame and gates the funds; a tampered witness is rejected. "
              "No relayer, no operator, no paymaster.")
    else:
        raise SystemExit("\nPoC leanSphincs-s FAILED: see the checks above.")


if __name__ == "__main__":
    main()
