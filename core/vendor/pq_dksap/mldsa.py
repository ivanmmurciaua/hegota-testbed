"""ML-DSA-44 (Dilithium2), ETH-optimized variant (keccak-PRNG XOFs).

This is the signer that matches the deployed ZKNOX ETHDilithium verifier. It
wraps the ZKNox `dilithium_py` reference implementation (install: see README).

A stealth account is identified by a 32-byte seed. From it we derive:
  - `pk_deploy`: the expanded public key the onchain verifier consumes
                 (abi.encode(bytes A_hat, bytes tr, bytes t1)), passed inline
  - the ability to sign a 32-byte message (the frame tx's sig_hash)
"""
from eth_abi import encode as abi_encode

from dilithium_py.dilithium.default_parameters import Dilithium2 as D
from dilithium_py.keccak_prng.keccak_prng_wrapper import Keccak256PRNG

XOF = Keccak256PRNG
SIG_LEN = 2420


def keypair(seed: bytes):
    """Deterministically derive the ML-DSA keypair from a 32-byte seed."""
    return D.key_derive(seed, _xof=XOF, _xof2=XOF)


def expanded_pk(pk) -> bytes:
    """The deployment-ready expanded public key (A_hat || tr || t1), ABI-encoded."""
    rho, t1 = D._unpack_pk(pk)
    A_hat = D._expand_matrix_from_seed(rho, _xof=XOF)
    tr = D._h(pk, 64, _xof=XOF)
    t1n = t1.scale(1 << D.d).to_ntt()
    a = [[[int(v) for v in col] for col in row] for row in A_hat.compact_256(32)]
    t = [[int(v) for v in row[0]] for row in t1n.compact_256(32)]
    return abi_encode(
        ["bytes", "bytes", "bytes"],
        [abi_encode(["uint256[][][]"], [a]), tr, abi_encode(["uint256[][]"], [t])],
    )


def sign(sk, message: bytes) -> bytes:
    """Raw 2420-byte signature over `message` (deterministic)."""
    sig = D.sign(sk, message, deterministic=True, _xof=XOF, _xof2=XOF)
    assert len(sig) == SIG_LEN, f"unexpected signature length {len(sig)}"
    return sig


def verify(pk, message: bytes, signature: bytes) -> bool:
    return D.verify(pk, message, signature, _xof=XOF, _xof2=XOF)
