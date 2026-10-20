"""Minimal JSON-RPC client + faucet for the ethrex Hegota privacy testnet."""
import json

import requests

from .config import FAUCET_URL, RPC_URL

class RpcError(Exception):
    pass

_id = 0

def rpc(method, params=None, url=RPC_URL):
    global _id
    _id += 1
    r = requests.post(
        url,
        json={"jsonrpc": "2.0", "id": _id, "method": method, "params": params or []},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RpcError(json.dumps(data["error"]))
    return data["result"]


def to_int(hexstr):
    return int(hexstr, 16)


def get_balance(addr):
    return to_int(rpc("eth_getBalance", [addr, "latest"]))


def get_nonce(addr):
    return to_int(rpc("eth_getTransactionCount", [addr, "latest"]))


def get_code(addr):
    return rpc("eth_getCode", [addr, "latest"])


def get_receipt(txhash):
    return rpc("eth_getTransactionReceipt", [txhash])


def send_raw(raw_hex):
    return rpc("eth_sendRawTransaction", [raw_hex])


def estimate_gas(call):
    return to_int(rpc("eth_estimateGas", [call]))


def gas_price():
    """The node's suggested gas price (base fee + a typical priority)."""
    return to_int(rpc("eth_gasPrice"))


def base_fee():
    """The latest block's base fee per gas (0 if the chain does not expose it)."""
    b = rpc("eth_getBlockByNumber", ["latest", False]).get("baseFeePerGas")
    return to_int(b) if b else 0


def max_priority_fee():
    """The node's suggested priority fee (often conservative / inflated)."""
    try:
        return to_int(rpc("eth_maxPriorityFeePerGas"))
    except RpcError:
        return 0


def recent_priority():
    """The priority fee recent blocks actually paid (50th-pct reward over the last
    few blocks), i.e. what it really takes to be included right now. 0 on an idle
    chain that mines at the base fee."""
    try:
        h = rpc("eth_feeHistory", ["0x5", "latest", [50]])
        rewards = [to_int(r[0]) for r in h.get("reward", []) if r]
        return max(rewards) if rewards else 0
    except (RpcError, KeyError, IndexError, ValueError):
        return 0


def eth_call(call, block="latest"):
    return rpc("eth_call", [call, block])


def faucet_claim(addr):
    r = requests.post(FAUCET_URL, json={"address": addr}, timeout=60)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text
