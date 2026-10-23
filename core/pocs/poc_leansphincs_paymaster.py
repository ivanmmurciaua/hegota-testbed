"""PoC leanSphincs-s + frame-native PAYMASTER: a hash-based PQ account whose gas is
paid by a third-party paymaster CONTRACT, on ethrex Hegota (EIP-8141, privacy-8141).

The cheap ethrex twin of the Daisugi half-grail. Two contracts, NO EOA in a rail
role (the only EOA is the throwaway funder that faucet-claims and deploys):

  - The ACCOUNT is a SphincsFrameAccount (leanSphincs-s, hash-based SPHINCS+ over
    Keccak-256). It is the frame-tx SENDER. Its VERIFY frame delegatecalls the shared
    frame module, which hash-verifies the leanSphincs-s witness INSIDE the VERIFY frame
    and APPROVEs EXECUTION ONLY (frame flags 0x2 -> the module reads FRAMEPARAM(0x06)
    and calls APPROVE(0,0,2)). It does NOT approve payment, so it pays no gas.
  - A separate PaymasterGated contract runs in its OWN VERIFY frame (as that frame's
    target, a non-sender). It ecrecovers a baked operator ECDSA key over this exact
    canonical sig_hash and APPROVEs PAYMENT (scope 0x1). ethrex then sets
    payer = frame.target = the paymaster, with no payer==sender check, so the paymaster
    pays all the gas. PaymasterGated is storage-free (operator baked in code), as the
    validation prefix forbids a non-sender frame from reading non-sender storage.

This composes poc_leansphincs_s (the hash-based account, self-pay) with poc_paymaster
(the frame-native paymaster, built for an ML-DSA account). The novelty: the paymaster
is signature-scheme-agnostic (it only ecrecovers the operator and APPROVEs payment), so
the SAME PaymasterGated sponsors a HASH-BASED PQ account. Where poc_paymaster gates a
~5M-gas ML-DSA (lattice) verify in a DEFAULT atomic-batch frame, here the gate is a
~249-keccak256 hash-based verify done inside the VERIFY frame itself: no atomic batch is
needed, because a bad witness reverts the VERIFY frame -> no execution approval -> the
SENDER never runs.

Frame layout (3 frames; sender = account, payer = paymaster):
  0 VERIFY  target = account (sender)  flags 0x2  data = verifyFrameAndApprove(sigIndex 0)
            -> module hash-verifies signatures[0] (leanSphincs-s) + APPROVE execution
  1 VERIFY  target = paymaster         flags 0x1  data = (empty)
            -> PaymasterGated ecrecover(operator) over sig_hash + APPROVE payment
  2 SENDER  target = recipient, value
  witnesses: index 0 = leanSphincs-s ARBITRARY signature over the tx sig_hash
             index 1 = operator ECDSA r||s||v over the SAME sig_hash (read by PaymasterGated)
EXECUTION approval (frame 0) comes BEFORE the PAYMENT approval (frame 1), as ethrex
requires. Both witnesses carry an empty msg, so both are elided from the canonical
sig_hash and sign a hash committing to the whole transaction without a circular dep.

Verified from the deployed module 0xAA481E83...4295 (disassembled): the sigIndex
overload (calldatasize 0x80) range-checks sigIndex < signature-count and only requires
that one entry be ARBITRARY; there is NO witness-count==1 gate, so the account reading
index 0 is undisturbed by the operator witness at index 1.

On-chain proof (real Hegota 8141):
  - status 0x1; receipt.from == the account (the account is the sender).
  - ACCOUNT balance delta == exactly the moved value (ZERO gas).
  - PAYMASTER balance delta == gasUsed * effectiveGasPrice (ALL the gas); payer field,
    if the receipt reports it, == the paymaster, NOT the account.
  - recipient received the value.
  NEGATIVE: a bad operator ECDSA signature makes the PaymasterGated VERIFY revert, so it
  never APPROVEs payment -> no payer -> ethrex rejects the tx at validation
  (ethrex_simulateFrameTransaction returns invalid); nothing moves.

Nothing is pre-provisioned: at runtime this keygens a FRESH leanSphincs-s key, a FRESH
operator ECDSA key, a FRESH throwaway funder EOA (faucet-first, env funder fallback, the
same pattern as poc_leansphincs_s), deploys a FRESH SphincsFrameAccount and a FRESH
PaymasterGated bound to the operator, funds the PAYMASTER (it pays gas) and the account
(only for the value it moves), and submits. No key is ever written to a tracked file.

Reuses poc_leansphincs_s (fresh EOA / faucet / deploy / endow helpers, the leanSphincs
account) and poc_paymaster (PaymasterGated build+deploy, the operator-signature helper),
both imported read-only (their main() is guarded). Envelope: core/lib/frametx8.

Env (all optional; defaults are the live singletons, inherited from poc_leansphincs_s):
  PQ_LSS_VERIFIER      leanSphincs-s verifier (default 0xae3bA3e1...3481a)
  PQ_LSS_FRAME_MODULE  shared frame module    (default 0xAA481E83...4295)
  PQ_LSS_B             signer kept-subtree height (default 10)
  PQ_OPERATOR_KEY      operator ECDSA key for the paymaster gate (default: fresh)
  PQ_DEPLOYER_KEY / POC_PRIVATE_KEY / PQ_KEYFILE  optional funded funder (cold faucet)
Run: ./run.sh ethrex poc_leansphincs_paymaster.py
"""
import os
import time

import _pqdksap  # noqa: F401  (adds core/vendor to sys.path + patches live net config)
from pq_dksap import rpc, stealth
from pq_dksap.config import CHAIN_ID
from pq_dksap.frametx import (
    FLAG_NONE, MODE_SENDER, MODE_VERIFY, SCHEME_ARBITRARY, Frame, Signature,
)
from eth_keys import keys
from eth_utils import keccak

from frametx8 import FrameTx8
from leansphincs.leansphincs_s_signer import keygen, sign as lss_sign, verify as lss_verify, LEAN_S

# Reuse, read-only, the two PoCs this one composes. Their main() is __main__-guarded,
# so importing only pulls in helpers and the live singleton anchors.
import poc_leansphincs_s as lss
import poc_paymaster as pm

# Approval scope semantics, verified against the live node AND the deployed module's
# APPROVE(0,0,FRAMEPARAM(0x06)): 0x1 = PAYMENT, 0x2 = EXECUTION, 0x3 = both. (These are
# the REAL node semantics; pq-dksap's FLAG_APPROVE_* constant NAMES are swapped, which
# is why we use plain integers here, matching poc_paymaster.)
SCOPE_PAYMENT = 0x1
SCOPE_EXECUTION = 0x2

VALUE = 10 ** 13           # 0.00001 ETH moved by the spend
ACCT_ENDOW = 2 * 10 ** 15  # 0.002 ETH: ONLY to fund the value move, NEVER gas
PM_ENDOW = 50 * 10 ** 15   # 0.05 ETH: the paymaster's gas budget


def build_tx(account: str, paymaster: str, recipient: str, value: int) -> FrameTx8:
    """The 3-frame sponsored spend. sender = account; payer will be the paymaster.

    Frame 0 is the leanSphincs-s VERIFY (hash-verify signatures[0] + APPROVE execution,
    flags 0x2). Frame 1 is the paymaster VERIFY (ecrecover operator + APPROVE payment,
    flags 0x1). Frame 2 is the SENDER value move, authorized by the execution approval
    and funded by the account. No atomic batch: a bad witness reverts frame 0 or frame 1
    at validation, so the SENDER never runs.
    """
    priority, max_fee = stealth.current_fees()
    return FrameTx8(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(account), sender=account,
        frames=[
            # 0: account approves EXECUTION only (target = sender account). The module
            #    reads signatures[0] (sigIndex 0) and hash-verifies it before APPROVE.
            Frame(MODE_VERIFY, SCOPE_EXECUTION, account, 300_000, 0, 0,
                  lss.VERIFY_FRAME_SELECTOR + (0).to_bytes(32, "big")),
            # 1: paymaster approves PAYMENT (target = the paymaster, a non-sender).
            Frame(MODE_VERIFY, SCOPE_PAYMENT, paymaster, 100_000, 50_000, 0, b""),
            # 2: SENDER value move from the account, funding a fresh recipient.
            Frame(MODE_SENDER, FLAG_NONE, recipient, 30_000, lss.NEW_ACCOUNT_STATE_GAS, value, b""),
        ],
        # sig 0 = leanSphincs-s (read by the account module at index 0); sig 1 = operator
        # ECDSA (read by PaymasterGated at index 1). Both msg empty -> both elided from the
        # canonical sig_hash, so they sign a hash committing to the whole tx.
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b""),
                    Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )


def authorize(tx: FrameTx8, sk, pk_seed: bytes, pk_root: bytes, operator_hex: str,
              good_operator: bool = True):
    """Sign the tx: index 0 with the leanSphincs-s key, index 1 with the operator ECDSA
    key, both over the same canonical sig_hash. Returns the sig_hash. `good_operator`
    False tampers the operator signature so the paymaster gate ecrecovers a wrong signer."""
    h = tx.sig_hash()
    lsig, _ = lss_sign(sk, h)
    assert lss_verify(pk_seed, pk_root, h, lsig, LEAN_S), "local leanSphincs verify failed"
    tx.signatures[0].signature = lsig
    opsig = pm.k1_sig_rsv(h, operator_hex)
    if not good_operator:
        opsig = opsig[:10] + bytes([opsig[10] ^ 0x01]) + opsig[11:]  # tamper -> wrong recover
    tx.signatures[1].signature = opsig
    assert tx.sig_hash() == h, "a witness changed the sig hash (empty msg should elide it)"
    return h


def main():
    print(f"Hegota chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"leanSphincs-s + paymaster PoC: verifier {lss.VERIFIER}, "
          f"frame module {lss.FRAME_MODULE}, b={lss.B}")

    checks = {}

    # --- 0) the live singletons must have code --------------------------------
    vcode, mcode = rpc.get_code(lss.VERIFIER), rpc.get_code(lss.FRAME_MODULE)
    checks["verifier has code on-chain"] = isinstance(vcode, str) and len(vcode) > 2
    checks["frame module has code on-chain"] = isinstance(mcode, str) and len(mcode) > 2
    print(f"  verifier code {len(vcode) // 2 - 1} B, frame module code {len(mcode) // 2 - 1} B")
    if not (checks["verifier has code on-chain"] and checks["frame module has code on-chain"]):
        raise SystemExit("a required singleton has no code: re-anchor PQ_LSS_* for this network")

    # --- 1) fresh keys + eth_call de-risk against the live verifier -----------
    print("\n[keygen] fresh leanSphincs-s key ...")
    t0 = time.time()
    sk = keygen(os.urandom(32), lss.B, LEAN_S)
    pk_seed, pk_root = sk.pk_seed, sk.pk_root
    print(f"  pkSeed 0x{pk_seed.hex()}  pkRoot 0x{pk_root.hex()}  ({time.time() - t0:.2f}s)")

    # Fresh operator ECDSA key (never printed; kept in memory). Env-overridable.
    operator_hex = os.environ.get("PQ_OPERATOR_KEY") or "0x" + os.urandom(32).hex()
    operator = keys.PrivateKey(bytes.fromhex(operator_hex[2:])).public_key.to_checksum_address()
    print(f"  fresh operator ECDSA {operator}")

    probe_msg = keccak(b"poc-lss-paymaster/derisk/" + os.urandom(16))
    probe_sig, _ = lss_sign(sk, probe_msg)
    assert lss_verify(pk_seed, pk_root, probe_msg, probe_sig, LEAN_S), "local verify failed"
    one = "0x" + "0" * 63 + "1"
    zero = "0x" + "0" * 64
    good = lss.eth_call_verify(pk_seed, pk_root, probe_msg, probe_sig)
    tampered = bytearray(probe_sig)
    tampered[100] ^= 0x01
    bad = lss.eth_call_verify(pk_seed, pk_root, probe_msg, bytes(tampered))
    print(f"  eth_call good={good}  tampered={bad}")
    checks["eth_call: verifier accepts our signature (1)"] = good == one
    checks["eth_call: verifier rejects a tampered signature (0)"] = bad == zero

    # --- 2) fresh funder EOA, faucet-funded; deploy + endow both contracts -----
    eoa_hex, eoa = lss.fresh_eoa()
    print(f"\n[eoa] fresh throwaway funder EOA {eoa} (the ONLY EOA; no rail role)")
    need = ACCT_ENDOW + PM_ENDOW + 3 * 10 ** 17   # endowments + headroom for both deploys
    bal = lss.fund_from_faucet(eoa, need)
    if bal < need:
        bal = lss.top_up_from_funder(eoa, need, bal)
    print(f"  funded balance {bal / 1e18:.4f} ETH")
    checks["funder EOA funded"] = bal > 0
    if bal < ACCT_ENDOW + PM_ENDOW + 10 ** 16:
        raise SystemExit(f"funder underfunded ({bal} wei); faucet may be rate-limited, retry later")

    print("[deploy] fresh SphincsFrameAccount (the leanSphincs-s account, tx sender) ...")
    account = lss.deploy_account(eoa_hex, eoa, pk_seed, pk_root)
    lss.fund_account(eoa_hex, eoa, account, ACCT_ENDOW)   # only to move VALUE, never gas

    print("[deploy] fresh PaymasterGated (operator baked in code, storage-free, the payer) ...")
    pm_init = pm.gated_paymaster_init(operator)
    paymaster = pm.deploy_init(eoa_hex, eoa, pm_init, PM_ENDOW)

    acct_bal, pm_bal = rpc.get_balance(account), rpc.get_balance(paymaster)
    acode, pcode = rpc.get_code(account), rpc.get_code(paymaster)
    print(f"  account   (sender) {account}  balance {acct_bal / 1e18:.4f} ETH  code {len(acode)//2-1} B")
    print(f"  paymaster (payer)  {paymaster}  balance {pm_bal / 1e18:.4f} ETH  code {len(pcode)//2-1} B")
    checks["account deployed with code"] = isinstance(acode, str) and len(acode) > 2
    checks["paymaster deployed with code"] = isinstance(pcode, str) and len(pcode) > 2
    checks["account endowed only for the value move"] = acct_bal >= VALUE
    checks["paymaster endowed with a gas budget"] = pm_bal >= PM_ENDOW

    # --- 3) NEGATIVE: bad operator signature -> paymaster gate reverts, tx rejected ----
    recipient_neg = "0x" + keccak(b"lss-pm-neg/" + os.urandom(8))[12:].hex()
    print(f"\n[negative] bad operator signature, simulate only -> {recipient_neg}")
    tx_neg = build_tx(account, paymaster, recipient_neg, VALUE)
    authorize(tx_neg, sk, pk_seed, pk_root, operator_hex, good_operator=False)
    try:
        sim_bad = lss.simulate(tx_neg)
    except Exception as exc:                 # an RPC error is also a rejection
        sim_bad = {"__error__": str(exc)}
    print(f"  bad-operator simulation: {str(sim_bad)[:220]}")
    neg_rejected = not (isinstance(sim_bad, dict) and sim_bad.get("valid")
                        and sim_bad.get("executionStatus") == "success")
    checks["negative: bad operator sig rejected by simulation (not sent)"] = neg_rejected
    checks["negative: recipient got nothing (not sent)"] = rpc.get_balance(recipient_neg) == 0

    # --- 4) POSITIVE: good signatures, paymaster-sponsored spend, submitted ----
    recipient = "0x" + keccak(b"lss-pm-recipient/" + os.urandom(8))[12:].hex()
    print(f"\n[spend] good signatures, paymaster pays gas -> {recipient}")
    tx = build_tx(account, paymaster, recipient, VALUE)
    t0 = time.time()
    sig_hash = authorize(tx, sk, pk_seed, pk_root, operator_hex, good_operator=True)
    print(f"  sig hash 0x{sig_hash.hex()}  leanSphincs witness {len(tx.signatures[0].signature)} B  "
          f"operator witness {len(tx.signatures[1].signature)} B  signed in {time.time() - t0:.2f}s")

    sim = lss.simulate(tx)
    ok_sim = isinstance(sim, dict) and sim.get("valid") and sim.get("executionStatus") == "success"
    print(f"  simulation: {str(sim)[:220]}")
    if not ok_sim:
        raise SystemExit("good-signature simulation failed; not sending")

    acct_before = rpc.get_balance(account)
    pm_before = rpc.get_balance(paymaster)
    recv_before = rpc.get_balance(recipient)
    txhash = rpc.send_raw(tx.encode_hex())
    print(f"  submitted {txhash}")
    rcpt = stealth._wait(txhash)
    if not rcpt:
        raise SystemExit("spend not mined within the timeout")

    gas_used = int(rcpt.get("gasUsed", "0x0"), 16)
    gas_cost = pm._gas_cost(rcpt)
    frm = (rcpt.get("from") or "").lower()
    payer = (rcpt.get("payer") or "").lower()
    acct_after = rpc.get_balance(account)
    pm_after = rpc.get_balance(paymaster)
    recv_after = rpc.get_balance(recipient)
    acct_delta = acct_before - acct_after
    pm_delta = pm_before - pm_after
    recv_delta = recv_after - recv_before
    fr = rcpt.get("frameReceipts") or []
    verify_frame_gas = int(fr[0]["gasUsed"], 16) if fr else None
    print(f"  status {rcpt.get('status')}  from {frm}  payer {payer or '(not reported)'}  "
          f"gasUsed {gas_used}")
    print(f"  account   delta {acct_delta} wei  (value moved = {VALUE})")
    print(f"  paymaster delta {pm_delta} wei  (gasUsed*effGasPrice = {gas_cost})")
    print(f"  recipient received {recv_delta} wei")
    print(f"  verify-frame[0] execution gas {verify_frame_gas} (hash-based leanSphincs-s verify)")

    checks["POS: spend mined with status 0x1"] = rcpt.get("status") in ("0x1", 1)
    checks["POS: receipt sender is the ACCOUNT (not the paymaster)"] = frm == account.lower()
    checks["POS: ACCOUNT paid ZERO gas (balance delta == exactly the value)"] = acct_delta == VALUE
    checks["POS: recipient received the value"] = recv_delta == VALUE
    checks["POS: PAYMASTER paid the gas (balance dropped > 0)"] = pm_delta > 0
    if gas_cost:
        checks["POS: PAYMASTER delta == gasUsed*effectiveGasPrice (it paid ALL the gas)"] = (
            pm_delta == gas_cost)
    # payer, if the receipt reports it, must be the PAYMASTER and never the account.
    if payer:
        checks["POS: receipt payer == the PAYMASTER (not the account)"] = payer == paymaster.lower()
    # The leanSphincs-s verify is a ~249-keccak256 hash-based check: its VERIFY frame
    # costs < 100K gas, vs a ~5M-gas ML-DSA lattice verify (poc_paymaster).
    checks["POS: leanSphincs-s verify frame is cheap (hash-based, < 100K gas)"] = (
        verify_frame_gas is not None and verify_frame_gas < 100_000)

    print("\n== RESULT ==")
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if all(checks.values()):
        print(f"\nPoC leanSphincs-s + PAYMASTER GREEN: a hash-based PQ account sponsored by a "
              f"third-party paymaster CONTRACT on ethrex frames. tx {txhash}. The account is the "
              "frame-tx sender and approves EXECUTION only (gated by a hash-based verify inside "
              "its VERIFY frame); a separate storage-free PaymasterGated, named by a non-sender "
              "VERIFY frame's PAYMENT approval, pays ALL the gas; the account pays only the value "
              "it moves. A bad operator gate rejects the tx. No EOA in a rail role. This is the "
              "cheap ethrex twin of the Daisugi half-grail.")
    else:
        raise SystemExit("\nPoC leanSphincs-s + PAYMASTER FAILED: see the checks above.")


if __name__ == "__main__":
    main()
