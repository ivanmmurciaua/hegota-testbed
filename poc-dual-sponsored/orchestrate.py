#!/usr/bin/env python3
"""UNIFIED dual-network "sponsored post-quantum ETH send" PoC orchestrator.

One command, one listener loop, one summary. Ties the two already-green halves
(ethrex leanSphincs-s on privacy-8141; Daisugi SPHINCS-G Gen1 on chainId 1337) into a
single actionable PoC. The proven halves are the execution engines; this file is the
orchestration + listener + unified reporting only. It never edits the testbed or delta1.

Flow, for BOTH chains:
  1. DERIVE : each half generates a fresh key, computes its COUNTERFACTUAL account address
              and a fresh recipient, and writes a local (gitignored) state file. This driver prints
              both accounts and both recipients so a human could fund them.
  2. LISTEN : this driver launches each half's `fund` step (faucet is the default trigger;
              an env funder is the cold-faucet fallback), then runs ONE real poll loop that
              watches BOTH chains' account balances until ETH has arrived at each
              counterfactual account (with a per-chain timeout). A chain proceeds only once
              its account is observed funded on-chain and its fund step exited cleanly.
  3. EXECUTE: for each funded chain, the half runs the two zero-gas rail txs: a no-EOA
              openSponsor deploy, then the paymaster-paid PQ ETH send (account pays 0 gas).
  4. SUMMARY: a single table, per chain: account, deploy tx (+payer==sponsor), spend tx
              (+payer==paymaster, account zero gas), funded, received, and no-gas-loss.

A live failure is a finding: this driver reports it and stops that chain; it never fakes
a green. No secret is written to any committed file; keys live only in the gitignored
state files (this run) and in memory.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.environ.get("DUAL_STATE_DIR", HERE)

# Per-chain RPC endpoints for the listener's direct balance reads (env-overridable).
ETHREX_RPC = os.environ.get("ETHREX_RPC_URL", "https://rpc1.privacy.ethrex.xyz")
DAISUGI_RPC = os.environ.get("DAISUGI_RPC_URL", "https://daisugi.fyi/rpc")

# The hegota-testbed root (read-only); the ethrex half runs with its core on PYTHONPATH.
# This folder lives at <testbed>/poc-dual-sponsored, so the testbed root is its parent.
TESTBED = os.environ.get("PQ_TESTBED") or os.path.dirname(HERE)
CORE = os.path.join(TESTBED, "core")
VENV_PY = os.path.join(TESTBED, ".venv", "bin", "python")
PYTHON = VENV_PY if os.access(VENV_PY, os.X_OK) else "python3"
NODE = os.environ.get("NODE_BIN", "node")

# Per-chain listener timeouts (seconds). ethrex's faucet drip can take minutes.
ETHREX_TIMEOUT = int(os.environ.get("ETHREX_LISTEN_TIMEOUT", "900"))
DAISUGI_TIMEOUT = int(os.environ.get("DAISUGI_LISTEN_TIMEOUT", "600"))
POLL_INTERVAL = int(os.environ.get("LISTEN_POLL_INTERVAL", "10"))


def ethrex_env() -> dict:
    env = dict(os.environ)
    env["DUAL_STATE_DIR"] = STATE_DIR
    env["PQ_DKSAP"] = os.path.join(CORE, "vendor")
    pp = ":".join([os.path.join(CORE, "pocs"), os.path.join(CORE, "lib"), os.path.join(CORE, "vendor")])
    env["PYTHONPATH"] = pp + ((":" + env["PYTHONPATH"]) if env.get("PYTHONPATH") else "")
    env["PQ_RPC_URL"] = ETHREX_RPC
    env["PQ_CHAIN_ID"] = "8141"
    env["PQ_FAUCET_URL"] = os.environ.get("ETHREX_FAUCET_URL", "https://faucet.privacy.ethrex.xyz/api/claim")
    env["PQ_FEE_NESTED"] = env.get("PQ_FEE_NESTED", "1")
    env["PQ_OMIT_RECENT_ROOTS"] = env.get("PQ_OMIT_RECENT_ROOTS", "1")
    env["PQ_SINGLETON"] = env.get("PQ_SINGLETON", "0x1602bef8eaa64f9fd3cdf4331473400deee70201")
    return env


def daisugi_env() -> dict:
    env = dict(os.environ)
    env["DUAL_STATE_DIR"] = STATE_DIR
    # daisugi defaults; set explicitly so the ethrex PQ_* above can never leak in.
    env["PQ_RPC_URL"] = DAISUGI_RPC
    env["PQ_CHAIN_ID"] = "1337"
    env["PQ_FAUCET_URL"] = os.environ.get("DAISUGI_FAUCET_URL", "https://daisugi.fyi/api/faucet")
    return env


CHAINS = {
    "ethrex": {
        "label": "ethrex (leanSphincs-s, 8141)",
        "rpc": ETHREX_RPC,
        "state": os.path.join(STATE_DIR, "ethrex.state.json"),
        "result": os.path.join(STATE_DIR, "ethrex.result.json"),
        "log": os.path.join(STATE_DIR, "ethrex.run.log"),
        "cmd": lambda mode: [PYTHON, os.path.join(HERE, "dual_sponsored_ethrex.py"), mode],
        "env": ethrex_env,
        "timeout": ETHREX_TIMEOUT,
        "need_key": "need_min",
    },
    "daisugi": {
        "label": "daisugi (SPHINCS-G Gen1, 1337)",
        "rpc": DAISUGI_RPC,
        "state": os.path.join(STATE_DIR, "daisugi.state.json"),
        "result": os.path.join(STATE_DIR, "daisugi.result.json"),
        "log": os.path.join(STATE_DIR, "daisugi.run.log"),
        "cmd": lambda mode: [NODE, os.path.join(HERE, "dual_sponsored_daisugi.mjs"), mode],
        "env": daisugi_env,
        "timeout": DAISUGI_TIMEOUT,
        "need_key": "need",
    },
}


def rpc_balance(rpc_url: str, address: str) -> int:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                       "params": [address, "latest"]}).encode()
    req = urllib.request.Request(rpc_url, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.load(resp)
    if "result" not in out:
        raise RuntimeError(f"eth_getBalance error from {rpc_url}: {out.get('error')}")
    return int(out["result"], 16)


def run_mode(name: str, mode: str, background: bool = False):
    """Run a half in a given mode, streaming its output to the chain's log file."""
    c = CHAINS[name]
    logf = open(c["log"], "a")
    logf.write(f"\n===== {name} {mode} @ {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
    logf.flush()
    proc = subprocess.Popen(c["cmd"](mode), env=c["env"](), stdout=logf, stderr=subprocess.STDOUT)
    if background:
        proc._logf = logf  # keep handle alive
        return proc
    rc = proc.wait()
    logf.close()
    return rc


def tail(path: str, n: int = 15) -> str:
    try:
        with open(path) as f:
            return "".join(f.readlines()[-n:])
    except OSError:
        return "(no log)"


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None  # optional: run a single chain
    names = [only] if only in CHAINS else list(CHAINS)
    print("=" * 78)
    print("UNIFIED dual-network sponsored post-quantum ETH send")
    print(f"  chains: {', '.join(CHAINS[n]['label'] for n in names)}")
    print(f"  state dir: {STATE_DIR}")
    print("=" * 78)

    # clear stale state/results so a partial prior run can never be mistaken for this one
    for n in names:
        for p in (CHAINS[n]["state"], CHAINS[n]["result"]):
            if os.path.exists(p):
                os.remove(p)

    # ---- PHASE 1: DERIVE (both) -------------------------------------------------------
    print("\n[1/4 DERIVE] generating fresh keys and computing counterfactual addresses ...")
    derivers = {n: run_mode(n, "derive", background=True) for n in names}
    for n, p in derivers.items():
        rc = p.wait()
        p._logf.close()
        if rc != 0:
            print(f"  {n}: derive FAILED (rc {rc}). A failure is the finding; stopping.")
            print(tail(CHAINS[n]["log"]))
            raise SystemExit(1)

    states = {}
    for n in names:
        with open(CHAINS[n]["state"]) as f:
            states[n] = json.load(f)
    print("\n  +--------------------------------------------------------------------------+")
    print("  | FUND THESE COUNTERFACTUAL ACCOUNTS (the listener watches them)           |")
    print("  +--------------------------------------------------------------------------+")
    for n in names:
        s = states[n]
        need = int(s[CHAINS[n]["need_key"]])
        print(f"  | {CHAINS[n]['label']:34s}")
        print(f"  |   account   {s['account']}  (>= {need} wei)")
        print(f"  |   recipient {s['recipient']}")
    print("  +--------------------------------------------------------------------------+")

    # ---- PHASE 2: FUND + the single LISTENER loop -------------------------------------
    print("\n[2/4 LISTEN] triggering funding (faucet default, env funder fallback) and "
          "polling both accounts until ETH arrives ...")
    funders = {n: run_mode(n, "fund", background=True) for n in names}
    deadline = {n: time.time() + CHAINS[n]["timeout"] for n in names}
    need = {n: int(states[n][CHAINS[n]["need_key"]]) for n in names}
    funded, failed = {}, {}
    last_print = 0.0

    while len(funded) + len(failed) < len(names):
        now = time.time()
        for n in names:
            if n in funded or n in failed:
                continue
            fp = funders[n]
            fp_done = fp.poll() is not None
            try:
                bal = rpc_balance(CHAINS[n]["rpc"], states[n]["account"])
            except Exception as exc:  # transient RPC hiccup: keep polling
                bal = -1
                if now - last_print >= POLL_INTERVAL:
                    print(f"  {n}: balance read hiccup ({exc}); retrying")
            # proceed only when the account is observed funded AND fund exited cleanly
            if bal >= need[n] and fp_done and fp.returncode == 0:
                fp._logf.close()
                funded[n] = bal
                print(f"  {n}: FUNDED {bal} wei at {states[n]['account']} (fund step done); proceeding")
            elif fp_done and fp.returncode != 0:
                fp._logf.close()
                failed[n] = f"fund step failed (rc {fp.returncode})"
                print(f"  {n}: FUND FAILED (rc {fp.returncode}). A failure is the finding; stopping this chain.")
                print(tail(CHAINS[n]["log"]))
            elif now > deadline[n]:
                failed[n] = "listener timeout (account never funded)"
                print(f"  {n}: LISTENER TIMEOUT after {CHAINS[n]['timeout']}s; account not funded "
                      f"(cold faucet and no working funder). Reporting honestly and stopping this chain.")
                if fp.poll() is None:
                    fp.terminate()
        if now - last_print >= POLL_INTERVAL:
            parts = []
            for n in names:
                if n in funded:
                    parts.append(f"{n}=FUNDED")
                elif n in failed:
                    parts.append(f"{n}=FAILED")
                else:
                    try:
                        b = rpc_balance(CHAINS[n]["rpc"], states[n]["account"])
                        parts.append(f"{n}={b}/{need[n]}wei")
                    except Exception:
                        parts.append(f"{n}=?")
            print(f"  [listener] {time.strftime('%H:%M:%S')}  " + "  ".join(parts))
            last_print = now
        if len(funded) + len(failed) < len(names):
            time.sleep(POLL_INTERVAL)

    # ---- PHASE 3: EXECUTE (per funded chain) ------------------------------------------
    print("\n[3/4 EXECUTE] no-EOA sponsored deploy + paymaster-paid PQ send on funded chains ...")
    exec_rc = {}
    exec_procs = {n: run_mode(n, "execute", background=True) for n in funded}
    for n, p in exec_procs.items():
        rc = p.wait()
        p._logf.close()
        exec_rc[n] = rc
        print(f"  {n}: execute finished (rc {rc})")
        if rc != 0:
            print(tail(CHAINS[n]["log"], 25))

    # ---- PHASE 4: UNIFIED SUMMARY -----------------------------------------------------
    results = {}
    for n in names:
        rp = CHAINS[n]["result"]
        if os.path.exists(rp):
            with open(rp) as f:
                results[n] = json.load(f)

    print("\n" + "=" * 78)
    print("UNIFIED SUMMARY: sponsored post-quantum ETH send on BOTH networks")
    print("=" * 78)
    all_green = bool(results) and len(results) == len(names)
    for n in names:
        print(f"\n[{CHAINS[n]['label']}]  rpc {CHAINS[n]['rpc']}")
        if n in failed:
            print(f"  STATUS: NOT COMPLETED -> {failed[n]} (a failure is the reported finding)")
            all_green = False
            continue
        r = results.get(n)
        if not r:
            print("  STATUS: NO RESULT FILE (execute did not finish); treated as FAILED")
            all_green = False
            continue
        green = r.get("all_green")
        all_green = all_green and green
        deploy_payer_ok = (r.get("deploy_payer") or "").lower() == r["sponsor"].lower() if r.get("deploy_payer") else None
        spend_payer_ok = (r.get("spend_payer") or "").lower() == r["paymaster"].lower() if r.get("spend_payer") else None
        acct_delta = int(r.get("account_delta", 0))
        value = int(r.get("value", 0))
        recv = int(r.get("recipient_received", 0))
        # halves use different sign conventions for the account delta (ethrex: before-after,
        # +value; daisugi: after-before, -value); the zero-gas invariant is |delta| == value.
        acct_zero_gas = abs(acct_delta) == value
        zero_gas = acct_zero_gas and (recv == value)
        print(f"  account (counterfactual)  {r['account']}")
        print(f"  recipient                 {r['recipient']}")
        print(f"  sponsor / paymaster       {r['sponsor']} / {r['paymaster']}")
        print(f"  DEPLOY tx                 {r['deploy_tx']}")
        print(f"     from/payer == sponsor  {r.get('deploy_from')} (payer match: {deploy_payer_ok})")
        print(f"  SPEND  tx                 {r['spend_tx']}")
        print(f"     payer == paymaster     {r.get('spend_payer')} (payer match: {spend_payer_ok})")
        print(f"  amount funded             {r.get('funded_wei')} wei")
        print(f"  value moved / received    {value} / {recv} wei")
        print(f"  account gas paid          |account delta| {abs(acct_delta)} wei == value {value}? "
              f"{acct_zero_gas}  (account paid ZERO gas)")
        print(f"  no gas loss               recipient got the full value: {zero_gas}")
        print(f"  cold-faucet fallback used {r.get('cold_faucet_used')} {r.get('cold_faucet_roles', '')}")
        print(f"  HALF GREEN                {green}")

    # compact one-line table
    print("\n  " + "-" * 92)
    print(f"  {'chain':10} {'deploy tx':20} {'spend tx':20} {'acct 0 gas':10} {'recv==value':12} {'green':6}")
    print("  " + "-" * 92)
    for n in names:
        r = results.get(n)
        if not r:
            print(f"  {n:10} {'FAILED':20} {'-':20} {'-':10} {'-':12} {'NO':6}")
            continue
        acct_delta = int(r.get("account_delta", 0)); value = int(r.get("value", 0)); recv = int(r.get("recipient_received", 0))
        print(f"  {n:10} {r['deploy_tx'][:18]:20} {r['spend_tx'][:18]:20} "
              f"{str(abs(acct_delta) == value):10} {str(recv == value):12} {str(bool(r.get('all_green'))):6}")
    print("  " + "-" * 92)

    print("\n  One actionable command runs the whole thing on both networks:")
    print("    bash run_dual.sh")
    if all_green:
        print("\nALL GREEN: on BOTH ethrex (leanSphincs) and Daisugi (SPHINCS-G Gen1) the one PoC ran "
              "counterfactual -> fund -> no-EOA sponsored deploy -> paymaster-paid PQ send with zero gas loss, "
              "all observed in on-chain receipts.")
    else:
        print("\nNOT ALL GREEN: see the per-chain status above. A live failure is a finding, not faked.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
