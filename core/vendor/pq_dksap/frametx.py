"""EIP-8141 Frame Transaction (type 0x06) encoding + canonical signature hash,
in the ethrex Hegota dialect (EIP-8141 + EIP-8250 keyed nonces + EIP-8272 recent roots).

  payload  = 0x06 || rlp([chain_id, nonce_keys, nonce_seq, sender, frames,
                          signatures, fees, blob_hashes, recent_root_references])
  frame    = [mode, flags, target, [execution, state], value, data]
  sig      = [scheme, signer, msg, signature]
  fees     = [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas]

We use the linear nonce domain (nonce_keys = [0]) and reference no recent roots.

The canonical sig_hash elides the `signature` bytes of any signature whose `msg`
is empty (matching ethrex's compute_sig_hash), so an ML-DSA signature can sign a
hash that commits to the whole transaction without a circular dependency.
"""
from dataclasses import dataclass, field
# from typing import List, Optional

import rlp
from eth_utils import keccak, to_canonical_address

FRAME_TX_TYPE = 0x06

MODE_DEFAULT = 0
MODE_VERIFY = 1
MODE_SENDER = 2

SCHEME_ARBITRARY = 0
SCHEME_SECP256K1 = 1
SCHEME_P256 = 2

FLAG_NONE = 0x0
FLAG_APPROVE_EXECUTION = 0x1
FLAG_APPROVE_PAYMENT = 0x2
FLAG_APPROVE_EXECUTION_AND_PAYMENT = 0x3
FLAG_ATOMIC_BATCH = 0x4


def _addr_bytes(a: str | None) -> bytes:
    if a is None or a == "" or a == "0x":
        return b""
    return to_canonical_address(a)


@dataclass
class Frame:
    mode: int
    flags: int
    target: str | None
    execution_gas: int
    state_gas: int
    value: int
    data: bytes = b""

    def to_list(self):
        return [
            self.mode,
            self.flags,
            _addr_bytes(self.target),
            [self.execution_gas, self.state_gas],
            self.value,
            self.data,
        ]


@dataclass
class Signature:
    scheme: int
    signer: str | None
    msg: bytes = b""
    signature: bytes = b""

    def to_list(self, canonical: bool):
        sig_bytes = b"" if (canonical and len(self.msg) == 0) else self.signature
        return [self.scheme, _addr_bytes(self.signer), self.msg, sig_bytes]


@dataclass
class FrameTx:
    chain_id: int
    nonce: int
    sender: str
    frames: list[Frame]
    signatures: list[Signature] = field(default_factory=list)
    max_priority_fee_per_gas: int = 10 ** 9
    max_fee_per_gas: int = 2 * 10 ** 9
    max_fee_per_blob_gas: int = 0
    blob_versioned_hashes: list = field(default_factory=list)

    def _fees(self):
        return [self.max_priority_fee_per_gas, self.max_fee_per_gas, self.max_fee_per_blob_gas]

    def _payload_list(self, canonical: bool):
        # Hegota envelope (EIP-8141 + EIP-8250 keyed nonces + EIP-8272 recent roots):
        #   [chain_id, nonce_keys, nonce_seq, sender, frames, signatures, fees,
        #    blob_hashes, recent_root_references]
        # We use the linear nonce domain (nonce_keys = [0], the single zero key)
        # and reference no recent roots (empty list).
        return [
            self.chain_id,
            [0],                                        # nonce_keys (linear domain)
            self.nonce,                                 # nonce_seq
            _addr_bytes(self.sender),
            [f.to_list() for f in self.frames],
            [s.to_list(canonical) for s in self.signatures],
            self._fees(),
            self.blob_versioned_hashes,
            [],                                         # recent_root_references
        ]

    def sig_hash(self) -> bytes:
        body = rlp.encode(self._payload_list(canonical=True))
        return keccak(bytes([FRAME_TX_TYPE]) + body)

    def encode(self) -> bytes:
        body = rlp.encode(self._payload_list(canonical=False))
        return bytes([FRAME_TX_TYPE]) + body

    def encode_hex(self) -> str:
        return "0x" + self.encode().hex()
