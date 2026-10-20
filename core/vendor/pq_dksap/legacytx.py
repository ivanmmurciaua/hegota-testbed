"""Minimal legacy (type-0, EIP-155) tx build + sign, using eth_keys only.

Just enough to deploy contracts on the ethrex Hegota testnet without web3/eth-account.
"""
import rlp
from eth_keys import keys
from eth_utils import keccak, to_canonical_address


def _addr(a):
    if a is None or a == b"" or a == "" or a == "0x":
        return b""
    if isinstance(a, (bytes, bytearray)):
        return bytes(a)
    return to_canonical_address(a)


def sign_legacy(private_key_hex, *, nonce, gas_price, gas_limit, to, value, data, chain_id):
    """Return (raw_hex, tx_hash) for a signed EIP-155 legacy transaction."""
    pk = keys.PrivateKey(bytes.fromhex(private_key_hex.removeprefix("0x")))
    to_b = _addr(to)
    data_b = data if isinstance(data, (bytes, bytearray)) else bytes.fromhex(data.removeprefix("0x"))
    unsigned = [nonce, gas_price, gas_limit, to_b, value, bytes(data_b), chain_id, 0, 0]
    h = keccak(rlp.encode(unsigned))
    sig = pk.sign_msg_hash(h)
    v = chain_id * 2 + 35 + sig.v
    signed = [nonce, gas_price, gas_limit, to_b, value, bytes(data_b), v, sig.r, sig.s]
    raw = rlp.encode(signed)
    return "0x" + raw.hex(), "0x" + keccak(raw).hex()


def create_address(sender_addr, nonce):
    """CREATE address: keccak(rlp([sender, nonce]))[12:]."""
    body = rlp.encode([to_canonical_address(sender_addr), nonce])
    return "0x" + keccak(body)[12:].hex()
