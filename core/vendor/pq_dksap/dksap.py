"""Dual-Key Stealth Address Protocol core (post-quantum), on the ZKNOX/Keccak
ML-DSA profile the deployed verifier speaks.

Blinded ML-DSA (additive blinding with a fresh error term, "construction A")
over an ML-KEM shared secret: the PAYER derives the stealth public key from the
recipient's published meta-address (public inputs only) and so can compute the
address but never spend; only the RECIPIENT, holding the spending secrets,
forms the blinded signing key. This is the key-agreement / derivation layer the
onchain spend engine in `stealth.py` carries.

The announcement transport (an onchain ERC-5564 Announcer, an ERC-6538
registry, or a scanner) is intentionally left to the caller: here the ML-KEM
ciphertext is handed to the recipient offchain. Registry + scanning are future
work, not discarded.

Credit: the blinded-ML-DSA construction is from the pq-sap project by Skas. This
module re-expresses it over the Keccak-PRNG XOFs (rather than SHAKE) so blinded
signatures verify under the same onchain verifier the rest of this repo uses.
"""
import hashlib
from dataclasses import dataclass

from eth_utils import keccak
from kyber_py.ml_kem import ML_KEM_512 as KEM

from . import mldsa
from .mldsa import D, XOF, expanded_pk

Q = 8380417
Q_BITS = 23
N = 256
META_VERSION = 0x01
T_BYTES = D.k * N * Q_BITS // 8       # full-precision t: k polys, 23-bit coeffs
KEM_EK_BYTES = 800                    # ML-KEM-512 encapsulation key
BETA_BLINDED = D.tau * 2 * D.eta      # widened rejection bound for blinded key
VIEW_TAG_BYTES = 1

_VIEW_KDF = b"pq-dksap/view/v1"
_BLIND_KDF = b"pq-dksap/blind/v1"
_SIGN_KDF = b"pq-dksap/sign-key/v1"


# --------------------------------------------------------------------------
# Fixed-width little-endian bit packing (FIPS 204 bit order)
# --------------------------------------------------------------------------
def _bit_pack(vals, bits):
    acc = abits = 0
    out = bytearray()
    for v in vals:
        acc |= v << abits
        abits += bits
        while abits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            abits -= 8
    if abits:
        out.append(acc & 0xFF)
    return bytes(out)


def _bit_unpack(data, bits, count):
    acc = abits = 0
    out = []
    it = iter(data)
    mask = (1 << bits) - 1
    while len(out) < count:
        while abits < bits:
            acc |= next(it) << abits
            abits += 8
        out.append(acc & mask)
        acc >>= bits
        abits -= bits
    return out


def _pack_t(t) -> bytes:
    return _bit_pack([c % Q for row in t._data for c in row[0].coeffs], Q_BITS)


def _unpack_t(data):
    coeffs = _bit_unpack(data, Q_BITS, D.k * N)
    return D.M.vector([D.R(coeffs[i * N:(i + 1) * N]) for i in range(D.k)])


# --------------------------------------------------------------------------
# Recipient meta-address (published) and secret (retained)
# --------------------------------------------------------------------------
@dataclass
class MetaPublic:
    rho: bytes
    t: object          # full-precision t = A*s1 + s2 (the sender needs it unrounded)
    kem_ek: bytes      # ML-KEM encapsulation (viewing) key

    def encode(self) -> bytes:
        out = bytes([META_VERSION]) + self.rho + _pack_t(self.t) + self.kem_ek
        return out

    @classmethod
    def decode(cls, data: bytes) -> "MetaPublic":
        if not data or data[0] != META_VERSION:
            raise ValueError("unsupported or malformed meta-address")
        rho = data[1:33]
        t = _unpack_t(data[33:33 + T_BYTES])
        kem_ek = data[33 + T_BYTES:]
        return cls(rho, t, kem_ek)


@dataclass
class MetaSecret:
    s1: object
    s2: object
    kem_dk: bytes      # ML-KEM decapsulation key = the VIEWING key


def gen_meta(seed: bytes):
    """Recipient key generation, deterministic in `seed` (keep it secret).
    Returns (MetaPublic to publish, MetaSecret to retain). Mirrors FIPS 204
    key expansion but keeps t at full precision for the sender's Power2Round."""
    h = D._h(seed + bytes([D.k, D.l]), 128, _xof=XOF)
    rho, rho_prime = h[:32], h[32:96]
    A_hat = D._expand_matrix_from_seed(rho, _xof=XOF)
    s1, s2 = D._expand_vector_from_seed(rho_prime, _xof=XOF)
    t = (A_hat @ s1.to_ntt()).from_ntt() + s2
    kd = hashlib.shake_256(_VIEW_KDF + seed).digest(64)
    kem_ek, kem_dk = KEM._keygen_internal(kd[:32], kd[32:])
    return MetaPublic(rho, t, kem_ek), MetaSecret(s1, s2, kem_dk)


# --------------------------------------------------------------------------
# Blinding: shared between sender and recipient, driven only by ss
# --------------------------------------------------------------------------
def _blinding(ss: bytes):
    return D._expand_vector_from_seed(hashlib.shake_256(_BLIND_KDF + ss).digest(64), _xof=XOF)


def _view_tag(ss: bytes) -> bytes:
    return hashlib.sha256(ss).digest()[:VIEW_TAG_BYTES]


def _derive_stealth_pk(meta_pub, ss):
    A_hat = D._expand_matrix_from_seed(meta_pub.rho, _xof=XOF)
    s_p, e_p = _blinding(ss)
    t_prime = (A_hat @ s_p.to_ntt()).from_ntt() + e_p + meta_pub.t
    t1, t0 = t_prime.power_2_round(D.d)
    return D._pack_pk(meta_pub.rho, t1), t0, s_p, e_p


# --------------------------------------------------------------------------
# Payer side: derive a fresh stealth address from public data only
# --------------------------------------------------------------------------
@dataclass
class StealthTarget:
    stealth_pk: bytes   # packed ML-DSA public key of the blinded key
    pk_deploy: bytes    # expanded pk the onchain verifier consumes
    commit: bytes       # keccak256(pk_deploy), the account's key commitment
    kem_ct: bytes       # the announcement to deliver to the recipient
    view_tag: bytes


def sender_derive(meta_pub) -> StealthTarget:
    ss, ct = KEM.encaps(meta_pub.kem_ek)
    pk, _t0, _s, _e = _derive_stealth_pk(meta_pub, ss)
    pkd = expanded_pk(pk)
    return StealthTarget(pk, pkd, keccak(pkd), ct, _view_tag(ss))


# --------------------------------------------------------------------------
# Recipient side: recover the blinded spending key from the ciphertext
# --------------------------------------------------------------------------
@dataclass
class BlindedKey:
    stealth_pk: bytes
    pk_deploy: bytes
    commit: bytes
    s1_b: object
    s2_b: object
    t0: object
    ss: bytes

    def sign(self, m: bytes, ctx: bytes = b"") -> bytes:
        return sign_blinded(self, m, ctx)


def recipient_recover(meta_pub, meta_sec, kem_ct, view_tag=None) -> BlindedKey:
    ss = KEM.decaps(meta_sec.kem_dk, kem_ct)
    if view_tag is not None and _view_tag(ss) != view_tag:
        raise ValueError("view tag mismatch: not this recipient's payment")
    pk, t0, s_p, e_p = _derive_stealth_pk(meta_pub, ss)
    pkd = expanded_pk(pk)
    return BlindedKey(pk, pkd, keccak(pkd),
                      meta_sec.s1 + s_p, meta_sec.s2 + e_p, t0, ss)


def sign_blinded(bkey, m: bytes, ctx: bytes = b"") -> bytes:
    """FIPS 204 signing over the widened-norm blinded key (s1+s', s2+e', t0'),
    on the Keccak profile. The rejection bounds use beta' = tau*2*eta; the
    verifier's bound is unchanged, so the signature is a standard ML-DSA
    signature accepted by the stock (and onchain) verifier."""
    pk = bkey.stealth_pk
    rho = D._unpack_pk(pk)[0]
    A_hat = D._expand_matrix_from_seed(rho, _xof=XOF)
    tr = D._h(pk, 64, _xof=XOF)
    m_prime = bytes([0, len(ctx)]) + ctx + m
    mu = D._h(tr + m_prime, 64, _xof=XOF)
    K = hashlib.shake_256(_SIGN_KDF + bkey.ss).digest(32)
    rho_p = D._h(K + bytes(32) + mu, 64, _xof=XOF)      # deterministic (rnd = 0^32)

    s1h, s2h, t0h = bkey.s1_b.to_ntt(), bkey.s2_b.to_ntt(), bkey.t0.to_ntt()
    beta = max(D.beta, BETA_BLINDED)
    kappa, alpha = 0, D.gamma_2 << 1
    while True:
        y = D._expand_mask_vector(rho_p, kappa, _xof=XOF)
        w = (A_hat @ y.to_ntt()).from_ntt()
        kappa += D.l
        w1 = w.high_bits(alpha)
        c_tilde = D._h(mu + w1.bit_pack_w(D.gamma_2), D.c_tilde_bytes, _xof=XOF)
        c_hat = D.R.sample_in_ball(c_tilde, D.tau, _xof=XOF).to_ntt()
        z = y + s1h.scale(c_hat).from_ntt()
        if z.check_norm_bound(D.gamma_1 - beta):
            continue
        c_s2 = s2h.scale(c_hat).from_ntt()
        if (w - c_s2).low_bits(alpha).check_norm_bound(D.gamma_2 - beta):
            continue
        c_t0 = t0h.scale(c_hat).from_ntt()
        if c_t0.check_norm_bound(D.gamma_2):
            continue
        h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
        if h.sum_hint() > D.omega:
            continue
        return D._pack_sig(c_tilde, z, h)


def authorize(tx, bkey) -> bytes:
    """Sign the frame-tx's canonical sig_hash with the blinded stealth key and
    place pk||sig inline in the ARBITRARY signature. Returns the signed hash."""
    h = tx.sig_hash()
    sig = bkey.sign(h)
    assert mldsa.verify(bkey.stealth_pk, h, sig), "blinded ML-DSA verify failed"
    tx.signatures[0].signature = bkey.pk_deploy + sig
    return h
