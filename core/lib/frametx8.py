"""8-field frame-tx envelope for the CURRENT Hegota build (re-genesis 2026-09-14).

The testnet moved recent_root_references OUT of the envelope (recent roots are now
a canonical VERIFY frame to 0x...8272), so the envelope is 8 fields, not pq-dksap's
9. pq-dksap stays untouched; this is the testbed's encoder matching the live build,
verified against the deployed source at commit 4738681 (RLPEncode + compute_sig_hash):

  payload = 0x06 || rlp([chain_id, nonce_keys, nonce_seq, sender, frames, signatures,
                         [max_priority_fee, max_fee, max_fee_per_blob_gas],
                         blob_versioned_hashes])

Frame and Signature encodings did NOT change, so they are reused from pq-dksap. The
canonical sig_hash elides the signature bytes of any signature whose msg is empty
(matching the build's compute_sig_hash), handled by Signature.to_list(canonical).
"""
import os
from dataclasses import dataclass, field

import rlp
from eth_utils import keccak

import _pqdksap  # noqa: F401
from pq_dksap.frametx import FRAME_TX_TYPE, Frame, Signature, _addr_bytes  # noqa: F401

# Fee layout is a Hegota migration variable. The privacy-8141 build used a nested
# 3-tuple; the hegota-3151908 build uses three FLAT u64 fields. Default flat (live);
# set PQ_FEE_NESTED=1 for the old nested layout.
FEE_NESTED = os.environ.get("PQ_FEE_NESTED") == "1"
# The privacy-8141 build (commit 4738681) has NO recent_root_references field in the
# envelope (recent roots moved to a VERIFY frame); the hegota-3151908 build re-added it.
OMIT_RECENT_ROOTS = os.environ.get("PQ_OMIT_RECENT_ROOTS") == "1"


@dataclass
class FrameTx8:
    chain_id: int
    nonce: int
    sender: str
    frames: list
    signatures: list = field(default_factory=list)
    nonce_keys: list = field(default_factory=lambda: [0])
    max_priority_fee_per_gas: int = 10 ** 9
    max_fee_per_gas: int = 2 * 10 ** 9
    max_fee_per_blob_gas: int = 0
    blob_versioned_hashes: list = field(default_factory=list)
    recent_root_references: list = field(default_factory=list)

    def _payload_list(self, canonical: bool):
        # No recent_root_references field. Fee layout per FEE_NESTED (migration var).
        head = [
            self.chain_id,
            self.nonce_keys,                                 # [0] = linear domain
            self.nonce,                                      # nonce_seq
            _addr_bytes(self.sender),
            [f.to_list() for f in self.frames],
            [s.to_list(canonical) for s in self.signatures],
        ]
        if FEE_NESTED:
            fees = [[self.max_priority_fee_per_gas, self.max_fee_per_gas, self.max_fee_per_blob_gas]]
        else:
            fees = [self.max_priority_fee_per_gas, self.max_fee_per_gas, self.max_fee_per_blob_gas]
        tail = [self.blob_versioned_hashes]
        if not OMIT_RECENT_ROOTS:
            tail.append(self.recent_root_references)
        return head + fees + tail

    def sig_hash(self) -> bytes:
        return keccak(bytes([FRAME_TX_TYPE]) + rlp.encode(self._payload_list(canonical=True)))

    def encode(self) -> bytes:
        return bytes([FRAME_TX_TYPE]) + rlp.encode(self._payload_list(canonical=False))

    def encode_hex(self) -> str:
        return "0x" + self.encode().hex()
