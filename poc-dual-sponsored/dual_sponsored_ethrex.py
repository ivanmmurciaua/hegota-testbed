"""ETHREX HALF of a dual-network "sponsored post-quantum ETH send" PoC (privacy-8141).

End to end, on real Hegota 8141, a post-quantum (leanSphincs-s, hash-based) account that:

  1. has a COUNTERFACTUAL address, computed BEFORE any deploy as a pure function of its
     key + initcode via CREATE2 through the delta1 generic factory;
  2. RECEIVES ETH at that address (the value to be sent onward);
  3. is DEPLOYED WITHOUT any EOA, via an openSponsor frame transaction: the openSponsor
     CONTRACT is the frame-tx sender and pays the deploy gas; no EOA signs TX1;
  4. then makes a NATIVE ETH SEND to a fresh recipient where the GAS is paid by a funded
     PaymasterGated CONTRACT (operator ECDSA baked in code), NOT self-pay, so the
     account's received ETH reaches the recipient with no gas loss.

Net: account funded with X, recipient receives exactly the moved value, account pays
ZERO gas (sponsor pays the deploy, paymaster pays the send).

This PoC imports the hegota-testbed core artifacts READ-ONLY (via ../core on PYTHONPATH)
and does not modify anything under core/ or backends/. It reuses:
  - poc_leansphincs_s (leanSphincs account artifacts, fresh-EOA / faucet / fund helpers,
    the VERIFY selector, the eth_call de-risk), imported as `lss`;
  - poc_paymaster (PaymasterGated build + deploy, the operator-signature helper), as `pm`;
  - poc_leansphincs_paymaster (the 3-frame paymaster-sponsored spend + authorize), as `lpm`.

What is NEW here (not in the testbed) is the counterfactual CREATE2 placement, the no-EOA
openSponsor deploy (TX1), and the three-mode driver (derive / fund / execute) that lets a
single cross-chain orchestrator gate the no-EOA deploy on the account actually being funded.
The PROVEN rail logic (keygen, frame building, signing, gas, checks) is UNCHANGED from the
green single-run version; only the orchestration seams (JSON state in/out, which step runs
in which mode) were added.

Modes (dispatched by argv[1], default "all" = derive -> fund -> execute in one process):
  derive   generate a fresh key + recipient, compute the counterfactual account, verify the
           singletons, write <state>; prints the account + recipient. No chain writes.
  fund     read <state>; fund the account (faucet default, env funder fallback) and deploy +
           endow the paymaster; write the account's funded balance + paymaster into <state>.
  execute  read <state>; the two zero-gas rail txs (no-EOA sponsored deploy + paymaster send)
           plus the two negatives; write <result> with all tx hashes, payers and checks.

Counterfactual address scheme (route (a), the preferred one):
  initcode = SphincsFrameAccount creation code
             || pkSeed(32) || pkRoot(32) || pad32(verifier) || pad32(owner=0) || pad32(frameModule)
  salt     = keccak256(pkSeed || pkRoot)                       (the key commitment)
  address  = keccak256(0xff || factory || salt || keccak256(initcode))[12:]
owner is set to address(0) (SphincsFrameAccount.owner is bookkeeping-only, never used for
auth), so the address is a pure function of (key, verifier, frameModule, factory, salt),
with no EOA in the derivation.

Singletons are env-overridable (devnet re-genesis). All are re-verified to have code at
derive; a missing one stops the PoC (never a fake pass). No private key is ever written to
a tracked file: the leanSphincs key is regenerated from a fresh 32-byte seed (kept only in
the local state file for this run), the operator ECDSA key and the throwaway funder EOA are
generated fresh in memory. The local state/result files are gitignored, never committed.

Run: driven by run_dual.sh / orchestrate.py; see those. Direct single-process run:
  bash run.sh            # mode "all"
"""
import json
import os
import sys
import time

import _pqdksap  # noqa: F401  (adds core/vendor to sys.path + patches live net config)
from pq_dksap import rpc, stealth
from pq_dksap.config import CHAIN_ID
from pq_dksap.frametx import (
    FLAG_NONE, MODE_DEFAULT, MODE_SENDER, MODE_VERIFY, SCHEME_ARBITRARY, Frame, Signature,
)
from eth_utils import keccak, to_canonical_address, to_checksum_address

from frametx8 import FrameTx8
from leansphincs.leansphincs_s_signer import keygen, sign as lss_sign, verify as lss_verify, LEAN_S

# Reuse, READ-ONLY, the three testbed PoCs this one composes (their main() is guarded).
import poc_leansphincs_s as lss
import poc_paymaster as pm
import poc_leansphincs_paymaster as lpm

# Approval-scope bitmask (verified against the live node): 0x1 PAYMENT, 0x2 EXECUTION,
# 0x3 both. Used both for frame flags and for the APPROVE opcode arg.
SCOPE_EXECUTION_AND_PAYMENT = 0x3

# delta1 rail singletons on Hegota (src/lib/frame/network.ts). Env-overridable.
#   FACTORY: a GENERIC CREATE2 deployer, calldata = salt(32) || initcode, forwards value.
#   OPEN_SPONSOR: an open on-chain sponsor; its VERIFY frame APPROVEs exec+payment on a
#   zero-value call with no signature, so it pays the one-time deploy for anyone.
FACTORY = os.environ.get("PQ_FACTORY", "0xd0526914f1045eb6ec89f9a93c8599306f9f667a")
OPEN_SPONSOR = os.environ.get("PQ_OPEN_SPONSOR", "0x655aab4c59b587fd7882ff6566198b40c45a7f21")

# leanSphincs-s account singletons (inherited from poc_leansphincs_s; env-overridable).
VERIFIER = lss.VERIFIER
FRAME_MODULE = lss.FRAME_MODULE

# The account's owner field is set to the zero address so the counterfactual address is a
# pure function of the key + verifier + frameModule (no EOA in the derivation). owner is
# bookkeeping-only in SphincsFrameAccount; execution is gated solely by the PQ verify.
ZERO_OWNER = "0x" + "00" * 20

VALUE = 10 ** 14          # 0.0001 ETH sent onward to the recipient
ACCT_FUND = 2 * 10 ** 14  # 0.0002 ETH funded into the account (the value to send onward)
PM_ENDOW = lpm.PM_ENDOW   # 0.05 ETH paymaster gas budget (reused from the testbed)

# Scratchpad state / result files (the orchestrator sets DUAL_STATE_DIR; default = here).
STATE_DIR = os.environ.get("DUAL_STATE_DIR", os.path.dirname(os.path.abspath(__file__)))
STATE_PATH = os.path.join(STATE_DIR, "ethrex.state.json")
RESULT_PATH = os.path.join(STATE_DIR, "ethrex.result.json")


def _load_state() -> dict:
    with open(STATE_PATH) as f:
        return json.load(f)


def _save_state(state: dict) -> None:
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp, STATE_PATH)


def _save_result(result: dict) -> None:
    tmp = RESULT_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(result, f, indent=2)
    os.replace(tmp, RESULT_PATH)


def counterfactual(pk_seed: bytes, pk_root: bytes):
    """Compute the account's CREATE2 address BEFORE deploy, plus the initcode and salt.

    Returns (address, initcode, salt). The address is a pure function of the public
    inputs, computable off-chain with no EOA and no network call."""
    initcode = (lss.account_creation_code()
                + pk_seed + pk_root
                + lss.pad32_addr(VERIFIER)
                + lss.pad32_addr(ZERO_OWNER)
                + lss.pad32_addr(FRAME_MODULE))
    salt = keccak(pk_seed + pk_root)
    pre = b"\xff" + to_canonical_address(FACTORY) + salt + keccak(initcode)
    address = to_checksum_address("0x" + keccak(pre)[12:].hex())
    return address, initcode, salt


def build_deploy_tx(salt: bytes, initcode: bytes) -> FrameTx8:
    """TX1: the no-EOA sponsored deploy. sender = openSponsor (the payer); its VERIFY frame
    approves execution + payment with no signature; a DEFAULT frame calls the generic
    factory with salt || initcode to CREATE2-deploy the counterfactual account.

    Mirrors delta1 src/lib/frame/pq.worker.ts TX1, with the leanSphincs initcode."""
    priority, max_fee = stealth.current_fees()
    return FrameTx8(
        chain_id=CHAIN_ID, nonce=rpc.get_nonce(OPEN_SPONSOR), sender=OPEN_SPONSOR,
        frames=[
            # 0: VERIFY, target = self (the sponsor). The sponsor APPROVEs exec + payment
            #    (scope 0x3) unconditionally; target null => payer = sender = the sponsor.
            Frame(MODE_VERIFY, SCOPE_EXECUTION_AND_PAYMENT, None, 80_000, 50_000, 0, b""),
            # 1: DEFAULT, target = the generic CREATE2 factory, data = salt || initcode.
            #    The code deposit of the ~2.2 KB account is charged to STATE gas (EIP-8141),
            #    which dominates here (~4M); the CREATE2 exec itself is only ~26K. Set both
            #    generously (sponsor pays; unused gas is refunded) with ample state-gas room.
            Frame(MODE_DEFAULT, FLAG_NONE, FACTORY, 8_000_000, 6_000_000, 0, salt + initcode),
        ],
        # No EOA signature: the open sponsor needs none (its VERIFY approves unconditionally).
        signatures=[Signature(SCHEME_ARBITRARY, None, b"", b"")],
        max_priority_fee_per_gas=priority, max_fee_per_gas=max_fee,
    )


def tamper_account_sig(tx: FrameTx8) -> None:
    """Flip a byte of the leanSphincs witness (index 0) so the account's VERIFY frame
    rejects it. Keeps the sig_hash stable (msg is empty, so the witness is elided)."""
    s = bytearray(tx.signatures[0].signature)
    s[100] ^= 0x01
    tx.signatures[0].signature = bytes(s)


# ----------------------------------------------------------------------------------------
# MODE: derive
# ----------------------------------------------------------------------------------------
def derive() -> dict:
    print(f"[ethrex derive] chain {CHAIN_ID} @ {rpc.RPC_URL}")
    print(f"  factory {FACTORY}  openSponsor {OPEN_SPONSOR}")
    print(f"  leanSphincs verifier {VERIFIER}  frame module {FRAME_MODULE}  b={lss.B}")

    # every singleton must have code on the live network (never a fake pass) --------------
    singles = {
        "leanSphincs verifier": VERIFIER,
        "leanSphincs frame module": FRAME_MODULE,
        "CREATE2 factory": FACTORY,
        "open sponsor": OPEN_SPONSOR,
    }
    for name, addr in singles.items():
        code = rpc.get_code(addr)
        has = isinstance(code, str) and len(code) > 2
        print(f"  {name:26s} {addr}  code {len(code)//2-1 if has else 0} B  {'OK' if has else 'MISSING'}")
        if not has:
            raise SystemExit(f"singleton {name} has no code: re-anchor the env for this network")

    # fresh leanSphincs-s key (regenerable from a 32-byte seed) + eth_call de-risk ---------
    print("\n[keygen] fresh leanSphincs-s key ...")
    t0 = time.time()
    seed32 = os.urandom(32)
    sk = keygen(seed32, lss.B, LEAN_S)
    pk_seed, pk_root = sk.pk_seed, sk.pk_root
    print(f"  pkSeed 0x{pk_seed.hex()}  pkRoot 0x{pk_root.hex()}  ({time.time()-t0:.2f}s)")

    probe = keccak(b"dual-sponsored/derisk/" + os.urandom(16))
    psig, _ = lss_sign(sk, probe)
    assert lss_verify(pk_seed, pk_root, probe, psig, LEAN_S), "local verify failed"
    one, zero = "0x" + "0" * 63 + "1", "0x" + "0" * 64
    good = lss.eth_call_verify(pk_seed, pk_root, probe, psig)
    tam = bytearray(psig); tam[100] ^= 0x01
    bad = lss.eth_call_verify(pk_seed, pk_root, probe, bytes(tam))
    print(f"  eth_call good={good} tampered={bad}")
    if good != one or bad != zero:
        raise SystemExit("verifier de-risk failed (accept-good / reject-tampered); stopping")

    # counterfactual address, computed BEFORE any deploy -----------------------------------
    account, initcode, salt = counterfactual(pk_seed, pk_root)
    print("\n[counterfactual] address computed off-chain, pre-deploy")
    print(f"  salt (key commit)   0x{salt.hex()}")
    print(f"  initcode            {len(initcode)} B  keccak 0x{keccak(initcode).hex()}")
    print(f"  address             {account}")
    if rpc.get_code(account) not in ("0x", "", None):
        raise SystemExit(f"counterfactual account {account} already has code; stopping")

    recipient = "0x" + keccak(b"dual/recipient/" + os.urandom(8))[12:].hex()
    recipient = to_checksum_address(recipient)

    state = {
        "chain": "ethrex",
        "rpc": rpc.RPC_URL,
        "chain_id": CHAIN_ID,
        "seed32": seed32.hex(),
        "pk_seed": pk_seed.hex(),
        "pk_root": pk_root.hex(),
        "salt": salt.hex(),
        "initcode": initcode.hex(),
        "account": account,
        "recipient": recipient,
        "need_min": ACCT_FUND,                       # the account must receive at least this
        "need_eoa": ACCT_FUND + PM_ENDOW + 10 ** 17,  # account + paymaster endowment + gas
        "sponsor": OPEN_SPONSOR,
        "factory": FACTORY,
        "verifier": VERIFIER,
        "frame_module": FRAME_MODULE,
        "value": VALUE,
    }
    _save_state(state)
    print(f"\n[derive] state written -> {STATE_PATH}")
    print(f"  FUND THIS ACCOUNT: {account}  (>= {ACCT_FUND} wei)   recipient {recipient}")
    return state


# ----------------------------------------------------------------------------------------
# MODE: fund  (faucet default, env funder fallback) + deploy/endow the paymaster
# ----------------------------------------------------------------------------------------
def fund() -> dict:
    state = _load_state()
    account = state["account"]
    need_eoa = int(state["need_eoa"])
    print(f"[ethrex fund] account {account}")

    # fresh throwaway funder EOA (the ONLY EOA; faucet first, env funder fallback) ---------
    eoa_hex, eoa = lss.fresh_eoa()
    print(f"  fresh throwaway funder EOA {eoa} (funds contracts; signs NO rail tx)")
    bal_after_faucet = lss.fund_from_faucet(eoa, need_eoa)
    cold_faucet_used = bal_after_faucet < need_eoa
    bal = bal_after_faucet
    if cold_faucet_used:
        print("  faucet cold or insufficient; falling back to the env funder (PQ_KEYFILE)")
        bal = lss.top_up_from_funder(eoa, need_eoa, bal)
    print(f"  funder balance {bal/1e18:.4f} ETH  (cold-faucet fallback used: {cold_faucet_used})")
    if bal < need_eoa:
        raise SystemExit(f"funder underfunded ({bal} wei); faucet rate-limited and no env funder")

    # the account RECEIVES ETH at its counterfactual address (still no code) ---------------
    print(f"  sending {ACCT_FUND/1e18:.4f} ETH to the counterfactual account (pre-deploy)")
    lss._send_value(eoa_hex, eoa, account, ACCT_FUND, "account pre-funding")
    acct_bal = rpc.get_balance(account)
    acct_code = rpc.get_code(account)
    has_code = acct_code not in ("0x", "", None)
    print(f"  account balance {acct_bal/1e18:.4f} ETH  code {len(acct_code)//2-1 if has_code else 0} B")
    if acct_bal < ACCT_FUND:
        raise SystemExit(f"account underfunded after send ({acct_bal} wei)")
    if has_code:
        raise SystemExit("account already has code after funding; counterfactual broken")

    # deploy a fresh, funded PaymasterGated (operator baked in code) ------------------------
    from eth_keys import keys as _keys
    operator_hex = os.environ.get("PQ_OPERATOR_KEY") or "0x" + os.urandom(32).hex()
    operator = _keys.PrivateKey(bytes.fromhex(operator_hex[2:])).public_key.to_checksum_address()
    print(f"  deploy fresh PaymasterGated, operator {operator} baked in code")
    pm_init = pm.gated_paymaster_init(operator)
    paymaster = pm.deploy_init(eoa_hex, eoa, pm_init, PM_ENDOW)
    pcode = rpc.get_code(paymaster)
    pm_bal = rpc.get_balance(paymaster)
    print(f"  paymaster {paymaster}  balance {pm_bal/1e18:.4f} ETH  "
          f"code {len(pcode)//2-1 if pcode not in ('0x','',None) else 0} B")
    if not (isinstance(pcode, str) and len(pcode) > 2) or pm_bal < PM_ENDOW:
        raise SystemExit("paymaster deploy/endow failed")

    state.update({
        "paymaster": paymaster,
        "operator_hex": operator_hex,
        "operator": operator,
        "cold_faucet_used": cold_faucet_used,
        "account_funded_wei": acct_bal,
        "pm_endow": PM_ENDOW,
    })
    _save_state(state)
    print(f"[ethrex fund] account funded ({acct_bal} wei); paymaster ready; state updated")
    return state


# ----------------------------------------------------------------------------------------
# MODE: execute  (the two zero-gas rail txs + the two negatives)
# ----------------------------------------------------------------------------------------
def execute() -> dict:
    state = _load_state()
    account = state["account"]
    recipient = state["recipient"]
    paymaster = state["paymaster"]
    operator_hex = state["operator_hex"]
    seed32 = bytes.fromhex(state["seed32"])
    pk_seed = bytes.fromhex(state["pk_seed"])
    pk_root = bytes.fromhex(state["pk_root"])
    salt = bytes.fromhex(state["salt"])
    initcode = bytes.fromhex(state["initcode"])
    sk = keygen(seed32, lss.B, LEAN_S)  # deterministic regeneration from the seed
    assert sk.pk_seed == pk_seed and sk.pk_root == pk_root, "key regeneration mismatch"

    checks = {}
    result = {"chain": "ethrex", "rpc": rpc.RPC_URL, "chain_id": CHAIN_ID,
              "account": account, "recipient": recipient, "sponsor": OPEN_SPONSOR,
              "factory": FACTORY, "paymaster": paymaster, "operator": state.get("operator"),
              "verifier": VERIFIER, "frame_module": FRAME_MODULE, "value": VALUE,
              "funded_wei": int(state.get("account_funded_wei", 0)),
              "cold_faucet_used": bool(state.get("cold_faucet_used", False))}

    # pre-conditions the funding step must have satisfied (the orchestrator also gates) -----
    acct_bal0 = rpc.get_balance(account)
    checks["account funded before deploy (listener gate)"] = acct_bal0 >= ACCT_FUND
    if acct_bal0 < ACCT_FUND:
        raise SystemExit(f"execute called but account not funded ({acct_bal0} wei)")

    # NO-EOA SPONSORED DEPLOY (TX1): openSponsor is the sender and pays --------------------
    print(f"[ethrex execute] no-EOA sponsored deploy via openSponsor {OPEN_SPONSOR}")
    tx1 = build_deploy_tx(salt, initcode)
    sim1 = lss.simulate(tx1)
    ok1 = isinstance(sim1, dict) and sim1.get("valid") and sim1.get("executionStatus") == "success"
    print(f"  simulation: {str(sim1)[:180]}")
    if not ok1:
        raise SystemExit("deploy TX1 simulation failed; not sending (a failure is the signal)")

    sponsor_before = rpc.get_balance(OPEN_SPONSOR)
    dh = rpc.send_raw(tx1.encode_hex())
    print(f"  submitted TX1 {dh}")
    drc = stealth._wait(dh)
    if not drc:
        raise SystemExit("deploy TX1 not mined within the timeout")
    d_from = (drc.get("from") or "").lower()
    d_payer = (drc.get("payer") or "").lower()
    d_gas_cost = pm._gas_cost(drc)
    sponsor_after = rpc.get_balance(OPEN_SPONSOR)
    acct_code = rpc.get_code(account)
    acct_has_code = isinstance(acct_code, str) and len(acct_code) > 2
    acct_bal_after_deploy = rpc.get_balance(account)
    print(f"  status {drc.get('status')}  from {d_from}  payer {d_payer or '(not reported)'}  gasUsed {drc.get('gasUsed')}")
    print(f"  account code now {len(acct_code)//2-1 if acct_has_code else 0} B  balance {acct_bal_after_deploy/1e18:.4f} ETH")

    checks["deploy TX1 mined status 0x1"] = drc.get("status") in ("0x1", 1)
    checks["deploy TX1 sender is the SPONSOR CONTRACT (no EOA)"] = d_from == OPEN_SPONSOR.lower()
    checks["account now HAS code (deployed)"] = acct_has_code
    checks["account balance survived the deploy (CREATE2 kept the received ETH)"] = (
        acct_bal_after_deploy == acct_bal0)
    checks["SPONSOR paid the deploy gas (its balance dropped > 0)"] = sponsor_before > sponsor_after
    if d_gas_cost:
        checks["SPONSOR delta == gasUsed*effectiveGasPrice (sponsor paid ALL deploy gas)"] = (
            (sponsor_before - sponsor_after) == d_gas_cost)
    if d_payer:
        checks["deploy payer == the SPONSOR (not an EOA)"] = d_payer == OPEN_SPONSOR.lower()
    result.update({"deploy_tx": dh, "deploy_from": d_from, "deploy_payer": d_payer,
                   "deploy_status": drc.get("status"), "deploy_gas_used": drc.get("gasUsed")})

    # NEGATIVE A: tampered leanSphincs account witness -> rejected at validation -----------
    rneg1 = to_checksum_address("0x" + keccak(b"dual/neg-acct/" + os.urandom(8))[12:].hex())
    print(f"\n[negative A] tampered leanSphincs account witness, simulate only -> {rneg1}")
    txnegA = lpm.build_tx(account, paymaster, rneg1, VALUE)
    lpm.authorize(txnegA, sk, pk_seed, pk_root, operator_hex, good_operator=True)
    tamper_account_sig(txnegA)
    try:
        simA = lss.simulate(txnegA)
    except Exception as exc:
        simA = {"__error__": str(exc)}
    print(f"  bad-account-sig simulation: {str(simA)[:160]}")
    rejA = not (isinstance(simA, dict) and simA.get("valid") and simA.get("executionStatus") == "success")
    checks["NEG A: tampered account witness rejected (not sent)"] = rejA
    checks["NEG A: recipient got nothing"] = rpc.get_balance(rneg1) == 0

    # NEGATIVE B: tampered operator witness -> paymaster gate reverts, rejected -------------
    rneg2 = to_checksum_address("0x" + keccak(b"dual/neg-op/" + os.urandom(8))[12:].hex())
    print(f"[negative B] tampered operator witness, simulate only -> {rneg2}")
    txnegB = lpm.build_tx(account, paymaster, rneg2, VALUE)
    lpm.authorize(txnegB, sk, pk_seed, pk_root, operator_hex, good_operator=False)
    try:
        simB = lss.simulate(txnegB)
    except Exception as exc:
        simB = {"__error__": str(exc)}
    print(f"  bad-operator-sig simulation: {str(simB)[:160]}")
    rejB = not (isinstance(simB, dict) and simB.get("valid") and simB.get("executionStatus") == "success")
    checks["NEG B: tampered operator witness rejected (not sent)"] = rejB
    checks["NEG B: recipient got nothing"] = rpc.get_balance(rneg2) == 0

    # POSITIVE: paymaster-sponsored PQ send, account pays ZERO gas --------------------------
    print(f"\n[spend TX2] paymaster-sponsored leanSphincs send -> {recipient}")
    tx2 = lpm.build_tx(account, paymaster, recipient, VALUE)
    t0 = time.time()
    sig_hash = lpm.authorize(tx2, sk, pk_seed, pk_root, operator_hex, good_operator=True)
    print(f"  sig hash 0x{sig_hash.hex()}  leanSphincs witness {len(tx2.signatures[0].signature)} B  "
          f"operator witness {len(tx2.signatures[1].signature)} B  ({time.time()-t0:.2f}s)")
    sim2 = lss.simulate(tx2)
    ok2 = isinstance(sim2, dict) and sim2.get("valid") and sim2.get("executionStatus") == "success"
    print(f"  simulation: {str(sim2)[:180]}")
    if not ok2:
        raise SystemExit("spend TX2 simulation failed; not sending (a failure is the signal)")

    acct_before = rpc.get_balance(account)
    pm_before = rpc.get_balance(paymaster)
    recv_before = rpc.get_balance(recipient)
    sh = rpc.send_raw(tx2.encode_hex())
    print(f"  submitted TX2 {sh}")
    src = stealth._wait(sh)
    if not src:
        raise SystemExit("spend TX2 not mined within the timeout")
    gas_used = int(src.get("gasUsed", "0x0"), 16)
    gas_cost = pm._gas_cost(src)
    s_from = (src.get("from") or "").lower()
    s_payer = (src.get("payer") or "").lower()
    acct_after = rpc.get_balance(account)
    pm_after = rpc.get_balance(paymaster)
    recv_after = rpc.get_balance(recipient)
    acct_delta = acct_before - acct_after
    pm_delta = pm_before - pm_after
    recv_delta = recv_after - recv_before
    print(f"  status {src.get('status')}  from {s_from}  payer {s_payer or '(not reported)'}  gasUsed {gas_used}")
    print(f"  account   delta {acct_delta} wei  (value moved = {VALUE})")
    print(f"  paymaster delta {pm_delta} wei  (gasUsed*effGasPrice = {gas_cost})")
    print(f"  recipient received {recv_delta} wei")

    checks["POS: spend mined status 0x1"] = src.get("status") in ("0x1", 1)
    checks["POS: receipt sender is the ACCOUNT (not the paymaster)"] = s_from == account.lower()
    checks["POS: ACCOUNT paid ZERO gas (delta == exactly the value)"] = acct_delta == VALUE
    checks["POS: recipient received the full value (no gas loss)"] = recv_delta == VALUE
    checks["POS: PAYMASTER paid the gas (its balance dropped > 0)"] = pm_delta > 0
    if gas_cost:
        checks["POS: PAYMASTER delta == gasUsed*effectiveGasPrice (paid ALL send gas)"] = pm_delta == gas_cost
    if s_payer:
        checks["POS: spend payer == the PAYMASTER (not the account)"] = s_payer == paymaster.lower()

    result.update({"spend_tx": sh, "spend_from": s_from, "spend_payer": s_payer,
                   "spend_status": src.get("status"), "spend_gas_used": src.get("gasUsed"),
                   "account_delta": acct_delta, "paymaster_delta": pm_delta,
                   "recipient_received": recv_delta, "checks": checks,
                   "all_green": all(checks.values())})
    _save_result(result)

    print("\n== ethrex checks ==")
    for name, ok in checks.items():
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    if result["all_green"]:
        print("\nETHREX HALF GREEN: counterfactual -> fund -> no-EOA sponsored deploy -> "
              "paymaster-sponsored PQ send, all observed in receipts on rpc1.privacy.ethrex.xyz.")
    else:
        raise SystemExit("\nETHREX HALF FAILED: see the checks above (a failure is the signal).")
    return result


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode == "derive":
        derive()
    elif mode == "fund":
        fund()
    elif mode == "execute":
        execute()
    elif mode == "all":
        derive()
        fund()
        execute()
    else:
        raise SystemExit(f"unknown mode {mode!r}; use derive | fund | execute | all")


if __name__ == "__main__":
    main()
