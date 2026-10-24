#!/usr/bin/env python3
"""
PQFS 2.0 - Post-Quantum File Sharing System
Authors: Pushkar Wagh & Vivaan Kriplani   (v1: AES-256-GCM + passphrase over raw TCP)

What is new in 2.0 (the six upgrades)
-------------------------------------
 1. MULTI-FAMILY HYBRID KEM   X25519 (elliptic curve) + ML-KEM (lattice, FIPS 203)
                              + HQC (code-based, NIST backup KEM). All shared
                              secrets are fed into one KDF, so an attacker must
                              break ALL families to recover a key.
 2. MULTIPATH SECRET SHARING  The random file key is Shamir-split (t-of-n, GF(256),
                              information-theoretic). Each share travels to a
                              different relay. Seeing fewer than t relays reveals
                              NOTHING about the key, even to an attacker who can
                              later break every KEM.
 3. CRYPTO-AGILITY            File encrypted once with a random data key (DEK).
                              Only the tiny key-wrap layer ("slot set", versioned
                              by epoch) is redone by `rewrap` when an algorithm is
                              deprecated. The sender's signed manifest carries a
                              minimum-suite floor + the epoch-1 suite hash, and
                              every epoch is bound into the KEM key derivation
                              and MACed, so downgrade / rollback attacks fail.
 4. SHELF-LIFE POLICY ENGINE  You say how long the secret must live; a transparent
                              heuristic scorer (lifetime + sensitivity of name and
                              content) picks tier T1/T2/T3 (suites, n, t). `audit`
                              finds wraps that no longer meet policy and `--fix`
                              upgrades them automatically. (Deterministic rules,
                              not a trained ML model.)
 5. THRESHOLD + TRANSPARENCY  t-of-n custodians must cooperate (`approve`) to open
                              a file. Every relay keeps an append-only RFC-6962
                              style Merkle log, tree heads signed with SLH-DSA
                              (hash-based). Receipts carry inclusion proofs;
                              `monitor` checks consistency (no history rewrite).
 6. METADATA PRIVACY          Filename, size, hashes and the sender's identity are
                              inside an AEAD-encrypted trailer; file size is
                              hidden with Padme padding; every chunk has equal
                              size; the relay link is a hybrid PQ channel with
                              forward secrecy where the client stays anonymous;
                              recipients are not named anywhere (trial decrypt).

Install (Python 3.9+)
---------------------
    pip install cryptography liboqs-python
    (liboqs itself must be present; liboqs-python builds it on first import if it
     can. HQC needs a reasonably recent liboqs. Run `python main.py info`.)

Quick tour
----------
    python main.py selftest                      # unit tests of the primitives
    python main.py demo                          # full end-to-end demo on localhost
    python main.py keygen alice ; python main.py keygen bob
    python main.py relay --port 5001 --store ./r1     # run 3 of these (5001-5003)
    python main.py send report.pdf --id alice.id --to bob.pub \\
        --relay 127.0.0.1:5001 --relay 127.0.0.1:5002 --relay 127.0.0.1:5003 --years 30
    python main.py trust alice.pub               # (bob) trust Alice's fingerprint
    python main.py receive <pkg>.ticket.json --id bob.id --outdir ./inbox

Honest limits (read these)
--------------------------
 * "Quantum-proof" here means: no known quantum attack. Nothing is proven. That is
   why everything is hybrid across independent math families.
 * HQC was selected by NIST in 2025 as a backup KEM; its final standard may still
   be pending. Lattice/code KEM and SLH-DSA come from liboqs, which its authors
   describe as research-grade. This project is educational and NOT audited.
 * `rewrap` protects future recordings. It cannot un-leak ciphertext/slots an
   attacker already harvested under an old suite.
 * Relays see IPs and timing. Fewer than t colluding relays learn nothing about
   the key, but t colluding relays + a break of the KEMs would.
 * Identity files are only as strong as their passphrase.
"""

from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import hmac
import itertools
import json
import math
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

try:  # liboqs python bindings (post-quantum algorithms)
    import oqs  # type: ignore
    _OQS_ERR = None
except Exception as _e:  # pragma: no cover
    oqs = None
    _OQS_ERR = _e

VERSION = "2.0"
MAGIC = b"PQFS2PKG"
CHUNK = 64 * 1024                 # plaintext bytes per AEAD chunk
MIN_PAD = 4096                    # smallest padded plaintext (hides tiny files)
MAX_CT = 2 * 1024 * 1024          # max size of one encrypted channel record
RANGE_MAX = 1 << 20               # max bytes served per PKG_RANGE
UPLOAD_REC = 256 * 1024
DEFAULT_PORT = 5001
MAX_SLOTS = 32
SLH_ALGS = ["SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s"]


class PQFSError(Exception):
    pass


def say(tag: str, msg: str) -> None:
    print(f"[{tag}] {msg}", flush=True)


# ============================================================ small utilities

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def cj(o) -> bytes:
    """Canonical JSON bytes (stable for hashing / signing / MACing)."""
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha3(*parts: bytes) -> bytes:
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes | None = None) -> bytes:
    return HKDF(algorithm=hashes.SHA3_256(), length=length, salt=salt, info=info).derive(ikm)


def now() -> int:
    return int(time.time())


def home() -> Path:
    p = Path(os.environ.get("PQFS_HOME") or (Path.home() / ".pqfs2"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_json(path: Path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return default


def save_json(path: Path, obj, private: bool = False) -> None:
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=1))
    if private:
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
    os.replace(tmp, path)


def fp_fmt(fp: str) -> str:
    return " ".join(fp[i:i + 8] for i in range(0, 32, 8))


# ================================================== algorithm registry (liboqs)

KEM_ALIASES = {
    "ML-KEM-768": ["ML-KEM-768", "Kyber768"],
    "ML-KEM-1024": ["ML-KEM-1024", "Kyber1024"],
    "HQC-192": ["HQC-3", "HQC-192"],
    "HQC-256": ["HQC-5", "HQC-256"],
}
SIG_ALIASES = {
    "ML-DSA-65": ["ML-DSA-65", "Dilithium3"],
    "SLH-DSA-SHA2-128f": ["SLH_DSA_PURE_SHA2_128F", "SPHINCS+-SHA2-128f-simple"],
    "SLH-DSA-SHA2-128s": ["SLH_DSA_PURE_SHA2_128S", "SPHINCS+-SHA2-128s-simple"],
}
# family, strength level (used to compare suites)
KEM_FAMILY = {
    "X25519": ("ecdh", 1),
    "ML-KEM-768": ("lattice", 2), "ML-KEM-1024": ("lattice", 3),
    "HQC-192": ("code", 2), "HQC-256": ("code", 3),
}


def _need_oqs() -> None:
    if oqs is None:
        raise PQFSError(
            "liboqs-python is required for post-quantum algorithms.\n"
            "  pip install liboqs-python   (and make sure liboqs is installed)\n"
            f"  import error: {_OQS_ERR}")


@functools.lru_cache(maxsize=None)
def _enabled(kind: str) -> frozenset:
    _need_oqs()
    return frozenset(oqs.get_enabled_kem_mechanisms() if kind == "kem"
                     else oqs.get_enabled_sig_mechanisms())


def _pick(kind: str, canon: str) -> str:
    table = KEM_ALIASES if kind == "kem" else SIG_ALIASES
    if canon not in table:
        raise PQFSError(f"unknown algorithm '{canon}'")
    for name in table[canon]:
        if name in _enabled(kind):
            return name
    raise PQFSError(f"{canon} is not enabled in your liboqs build "
                    f"(tried {table[canon]}). Upgrade liboqs.")


def have(kind: str, canon: str) -> bool:
    try:
        _pick(kind, canon)
        return True
    except PQFSError:
        return False


# ---- KEMs -------------------------------------------------------------------

def kem_generate(canon: str) -> tuple[bytes, bytes]:
    if canon == "X25519":
        sk = X25519PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()
    with oqs.KeyEncapsulation(_pick("kem", canon)) as k:
        pk = k.generate_keypair()
        return pk, k.export_secret_key()


def kem_encaps(canon: str, pk: bytes) -> tuple[bytes, bytes]:
    if canon == "X25519":
        e = X25519PrivateKey.generate()
        ss = e.exchange(X25519PublicKey.from_public_bytes(pk))
        return e.public_key().public_bytes_raw(), ss
    with oqs.KeyEncapsulation(_pick("kem", canon)) as k:
        ct, ss = k.encap_secret(pk)
        return ct, ss


def kem_decaps(canon: str, sk: bytes, ct: bytes) -> bytes:
    if canon == "X25519":
        return X25519PrivateKey.from_private_bytes(sk).exchange(
            X25519PublicKey.from_public_bytes(ct))
    with oqs.KeyEncapsulation(_pick("kem", canon), sk) as k:
        return k.decap_secret(ct)


# ---- signatures -------------------------------------------------------------

def sig_generate(canon: str) -> tuple[bytes, bytes]:
    if canon == "ed25519":
        sk = Ed25519PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()
    with oqs.Signature(_pick("sig", canon)) as s:
        pk = s.generate_keypair()
        return pk, s.export_secret_key()


def sig_sign(canon: str, sk: bytes, msg: bytes) -> bytes:
    if canon == "ed25519":
        return Ed25519PrivateKey.from_private_bytes(sk).sign(msg)
    with oqs.Signature(_pick("sig", canon), sk) as s:
        return s.sign(msg)


def sig_verify(canon: str, pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        if canon == "ed25519":
            Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
            return True
        with oqs.Signature(_pick("sig", canon)) as v:
            return bool(v.verify(msg, sig, pk))
    except Exception:
        return False


# ============================================ identities (hybrid key bundles)

KEM_ALL = ["ML-KEM-768", "ML-KEM-1024", "HQC-192", "HQC-256"]


def fp_of(public: dict) -> str:
    return sha3(b"PQFS2-fp", cj(public)).hex()


def new_identity(name: str) -> dict:
    """Generate ALL key types once so any tier can be used later."""
    secret = {"kem": {}, "sig": {}}
    public = {"kem": {}, "sig": {}}
    pk, sk = kem_generate("X25519")
    public["x25519"], secret["x25519"] = b64e(pk), b64e(sk)
    for k in KEM_ALL:
        if not have("kem", k):
            say("WARN", f"{k} unavailable in this liboqs build; identity will lack it")
            continue
        pk, sk = kem_generate(k)
        public["kem"][k], secret["kem"][k] = b64e(pk), b64e(sk)
    for s in ("ed25519", "ML-DSA-65"):
        pk, sk = sig_generate(s)
        public["sig"][s], secret["sig"][s] = b64e(pk), b64e(sk)
    return {"name": name, "public": public, "secret": secret, "fp": fp_of(public)}


def ask_pass(prompt: str, confirm: bool = False) -> str:
    env = os.environ.get("PQFS_PASSPHRASE")
    if env:
        return env
    p = getpass(prompt)
    if confirm and p != getpass("Confirm passphrase: "):
        raise PQFSError("passphrases do not match")
    if not p:
        raise PQFSError("empty passphrase")
    return p


def save_identity(path: Path, ident: dict, passphrase: str) -> None:
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())
    blob = AESGCM(key).encrypt(nonce, cj(ident["secret"]), b"PQFS2-identity")
    save_json(path, {"pqfs": 2, "type": "identity", "name": ident["name"],
                     "public": ident["public"], "fp": ident["fp"],
                     "kdf": {"alg": "scrypt", "n": 2 ** 15, "r": 8, "p": 1, "salt": b64e(salt)},
                     "nonce": b64e(nonce), "ct": b64e(blob)}, private=True)


def load_identity(path: str) -> dict:
    d = load_json(Path(path))
    if not d or d.get("type") != "identity":
        raise PQFSError(f"{path} is not a PQFS2 identity file")
    pw = ask_pass(f"Passphrase for identity '{d['name']}': ")
    k = d["kdf"]
    key = Scrypt(salt=b64d(k["salt"]), length=32, n=k["n"], r=k["r"], p=k["p"]).derive(pw.encode())
    try:
        secret = json.loads(AESGCM(key).decrypt(b64d(d["nonce"]), b64d(d["ct"]), b"PQFS2-identity"))
    except InvalidTag:
        raise PQFSError("wrong passphrase or corrupted identity file")
    if fp_of(d["public"]) != d["fp"]:
        raise PQFSError("identity public bundle does not match its fingerprint")
    return {"name": d["name"], "public": d["public"], "secret": secret, "fp": d["fp"]}


def load_public(path: str) -> dict:
    d = load_json(Path(path))
    if not d or d.get("type") not in ("public", "identity"):
        raise PQFSError(f"{path} is not a PQFS2 public bundle")
    if fp_of(d["public"]) != d["fp"]:
        raise PQFSError(f"{path}: fingerprint mismatch (file altered?)")
    return {"name": d["name"], "public": d["public"], "fp": d["fp"]}


def contacts() -> dict:
    return load_json(home() / "contacts.json", {})


def trust_contact(fp: str, name: str) -> None:
    c = contacts()
    c[fp] = {"name": name, "added": now()}
    save_json(home() / "contacts.json", c)


# ============================================= hybrid KEM combiner + hybrid sig

def kem_pk(public: dict, name: str) -> bytes:
    try:
        return b64d(public["x25519"]) if name == "X25519" else b64d(public["kem"][name])
    except KeyError:
        raise PQFSError(f"recipient bundle has no {name} key")


def kem_sk(secret: dict, name: str) -> bytes:
    return b64d(secret["x25519"]) if name == "X25519" else b64d(secret["kem"][name])


def kem_combine(names, pks, cts, sss, ctx: bytes) -> bytes:
    """Combiner: the key depends on EVERY shared secret, ciphertext and public
    key plus the context (which contains the suite descriptor hash)."""
    ikm = b"".join(struct.pack(">H", len(s)) + s for s in sss)
    info = b"PQFS2-combiner-v1" + sha3(ctx) + b"".join(
        sha3(n.encode(), pk, ct) for n, pk, ct in zip(names, pks, cts))
    return hkdf(ikm, info, 32)


def hybrid_encaps(public: dict, kems: list[str], ctx: bytes):
    cts, pks, sss, raw = {}, [], [], []
    for n in kems:
        pk = kem_pk(public, n)
        ct, ss = kem_encaps(n, pk)
        cts[n] = b64e(ct)
        pks.append(pk); sss.append(ss); raw.append(ct)
    return cts, kem_combine(kems, pks, raw, sss, ctx)


def hybrid_decaps(secret: dict, public: dict, kems, cts: dict, ctx: bytes) -> bytes:
    pks, sss, raw = [], [], []
    for n in kems:
        ct = b64d(cts[n])
        sss.append(kem_decaps(n, kem_sk(secret, n), ct))
        pks.append(kem_pk(public, n)); raw.append(ct)
    return kem_combine(kems, pks, raw, sss, ctx)


def hybrid_sign(secret: dict, msg: bytes) -> dict:
    return {s: b64e(sig_sign(s, b64d(secret["sig"][s]), msg)) for s in ("ed25519", "ML-DSA-65")}


def hybrid_verify(public: dict, msg: bytes, sig: dict) -> bool:
    try:
        return all(sig_verify(s, b64d(public["sig"][s]), msg, b64d(sig[s]))
                   for s in ("ed25519", "ML-DSA-65"))
    except Exception:
        return False


# ========================================= Shamir secret sharing over GF(2^8)

_EXP = [0] * 512
_LOG = [0] * 256


def _init_gf() -> None:
    x = 1
    for i in range(255):
        _EXP[i], _LOG[x] = x, i
        x2 = x << 1
        if x2 & 0x100:
            x2 ^= 0x11B
        x ^= x2                      # multiply by generator 3
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_gf()


def gmul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def gdiv(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _EXP[(_LOG[a] - _LOG[b]) % 255]


def shamir_split(secret: bytes, n: int, t: int) -> list[tuple[int, bytes]]:
    """t-of-n. Any t shares reconstruct; any t-1 shares are statistically
    independent of the secret (information-theoretic, no hardness assumption)."""
    if not (1 <= t <= n <= 255):
        raise ValueError("need 1 <= t <= n <= 255")
    coeffs = [os.urandom(t - 1) for _ in secret]
    out = []
    for x in range(1, n + 1):
        y = bytearray()
        for s, c in zip(secret, coeffs):
            acc = 0
            for coef in reversed(c):
                acc = gmul(acc, x) ^ coef
            y.append(gmul(acc, x) ^ s)
        out.append((x, bytes(y)))
    return out


def shamir_combine(shares: list[tuple[int, bytes]]) -> bytes:
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share index")
    lag = []
    for i, xi in enumerate(xs):
        num = den = 1
        for j, xj in enumerate(xs):
            if i != j:
                num = gmul(num, xj)
                den = gmul(den, xi ^ xj)
        lag.append(gdiv(num, den))
    out = bytearray()
    for k in range(len(shares[0][1])):
        acc = 0
        for (_, y), l in zip(shares, lag):
            acc ^= gmul(y[k], l)
        out.append(acc)
    return bytes(out)


# ============================================================== Padme padding

def padme(length: int) -> int:
    """Padme (Nikitin et al.): pads to a coarse grid with <=12% overhead, so the
    ciphertext size only leaks O(log log n) bits about the real size."""
    if length < 2:
        return length
    e = length.bit_length() - 1
    s = e.bit_length()
    mask = (1 << (e - s)) - 1
    return (length + mask) & ~mask


# ======================================================= tiers + policy engine

TIERS = {
    "T1": {"label": "T1-ephemeral", "kems": ["X25519", "ML-KEM-768"], "n": 1, "t": 1},
    "T2": {"label": "T2-standard", "kems": ["X25519", "ML-KEM-768", "HQC-192"], "n": 3, "t": 2},
    "T3": {"label": "T3-longterm", "kems": ["X25519", "ML-KEM-1024", "HQC-256"], "n": 5, "t": 3},
}
TIER_ORDER = ["T1", "T2", "T3"]


def load_deprecated() -> set:
    return set(load_json(home() / "deprecated.json", []))


def effective_kems(tier: str, deprecated: set) -> list[str]:
    """The tier's suite minus any algorithm the operator marked as broken."""
    kems = [k for k in TIERS[tier]["kems"] if k not in deprecated]
    if not any(k != "X25519" for k in kems):
        raise PQFSError(f"tier {tier} has no non-deprecated post-quantum KEM left; "
                        "add a new algorithm to TIERS")
    return kems


def suite_satisfies(kems, floor, deprecated=frozenset()) -> bool:
    """Does `kems` cover every algorithm family in `floor` at >= strength?
    Families entirely retired by the operator are ignored."""
    for fam in {KEM_FAMILY[k][0] for k in floor}:
        members = [k for k in KEM_FAMILY if KEM_FAMILY[k][0] == fam]
        if all(m in deprecated for m in members):
            continue
        need = max(KEM_FAMILY[k][1] for k in floor if KEM_FAMILY[k][0] == fam)
        got = [KEM_FAMILY[k][1] for k in kems
               if k in KEM_FAMILY and KEM_FAMILY[k][0] == fam and k not in deprecated]
        if not got or max(got) < need:
            return False
    return True


NAME_RULES = [
    (r"(id_rsa|id_ed25519|\.pem$|\.key$|\.p12$|\.pfx$|\.kdbx$|wallet|seed|mnemonic|secret|credential|\.env$)",
     25, "filename looks like key/credential material"),
    (r"(passport|aadhaar|ssn|tax|payroll|salary|medical|patient|diagnos|prescription|contract|nda|legal|bank|statement)",
     18, "filename suggests personal/financial/legal record"),
    (r"(backup|dump|export|archive|database|\.sql$|\.db$)", 10, "filename suggests bulk data/backup"),
]
CONTENT_RULES = [
    (rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", 30, "content contains a PEM private key"),
    (rb"AKIA[0-9A-Z]{16}", 25, "content contains an AWS-style access key"),
    (rb"(?i)password\s*[:=]", 12, "content contains 'password =' patterns"),
    (rb"\b\d{3}-\d{2}-\d{4}\b", 12, "content contains SSN-like numbers"),
    (rb"\b\d{4}\s?\d{4}\s?\d{4}\b", 8, "content contains 12-digit ID-like numbers"),
]


def tier_rank(t: str) -> int:
    return TIER_ORDER.index(t)


def tier_for_years(years: float) -> str:
    return "T3" if years >= 20 else "T2" if years >= 5 else "T1"


def assess(path: str, years: float) -> dict:
    """Transparent heuristic exposure score (0-100) -> tier. Everything that
    contributes is listed in `reasons`. Harvest-now-decrypt-later risk grows with
    how long the secret must stay secret and how valuable the content looks."""
    name = os.path.basename(path).lower()
    size = os.path.getsize(path)
    reasons = []
    life = min(55, round(14 * math.log2(1 + years)))
    score = life
    reasons.append(f"must stay secret {years:g} years -> +{life}")
    sens = 0
    for pat, pts, why in NAME_RULES:
        if re.search(pat, name):
            sens += pts; reasons.append(f"{why} -> +{pts}")
    try:
        with open(path, "rb") as f:
            sample = f.read(256 * 1024)
    except OSError:
        sample = b""
    for pat, pts, why in CONTENT_RULES:
        if re.search(pat, sample):
            sens += pts; reasons.append(f"{why} -> +{pts}")
    sens = min(sens, 45)
    score += sens
    if size > (1 << 30):
        score += 5; reasons.append("bulk data (>1 GiB) -> +5")
    score = min(score, 100)
    tier = "T1" if score < 35 else "T2" if score < 65 else "T3"
    floor = tier_for_years(years)
    if tier_rank(floor) > tier_rank(tier):
        reasons.append(f"lifetime floor raises tier {tier} -> {floor}")
        tier = floor
    return {"score": score, "tier": tier, "reasons": reasons}


# ================================================================ Merkle log
# RFC 6962 / RFC 9162 Merkle tree, SHA3-256.

def leaf_hash(data: bytes) -> bytes:
    return sha3(b"\x00", data)


def node_hash(l: bytes, r: bytes) -> bytes:
    return sha3(b"\x01", l, r)


def _split(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)      # largest power of two < n


def mth(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return sha3(b"")
    if n == 1:
        return leaves[0]
    k = _split(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def audit_path(m: int, leaves: list[bytes]) -> list[bytes]:
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if m < k:
        return audit_path(m, leaves[:k]) + [mth(leaves[k:])]
    return audit_path(m - k, leaves[k:]) + [mth(leaves[:k])]


def verify_inclusion(lh: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    if index >= size or size == 0:
        return False
    fn, sn, r = index, size - 1, lh
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    return sn == 0 and r == root


def consistency_proof(m: int, leaves: list[bytes]) -> list[bytes]:
    def sub(m, d, b):
        n = len(d)
        if m == n:
            return [] if b else [mth(d)]
        k = _split(n)
        if m <= k:
            return sub(m, d[:k], b) + [mth(d[k:])]
        return sub(m - k, d[k:], False) + [mth(d[:k])]
    if m == 0 or m == len(leaves):
        return []
    return sub(m, leaves, True)


def verify_consistency(first: int, second: int, fh: bytes, sh: bytes, proof: list[bytes]) -> bool:
    if first > second:
        return False
    if first == second:
        return fh == sh and not proof
    if first == 0:
        return True
    proof = list(proof)
    if first & (first - 1) == 0:
        proof.insert(0, fh)
    if not proof:
        return False
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1; sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1; sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1; sn >>= 1
    return fr == fh and sr == sh and sn == 0


class MerkleLog:
    """Append-only log persisted as JSON lines; leaves are canonical JSON."""

    def __init__(self, path: Path | None):
        self.path = path
        self.records: list[dict] = []
        self.leaves: list[bytes] = []
        if path and Path(path).exists():
            for line in Path(path).read_text().splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self.records.append(rec)
                    self.leaves.append(leaf_hash(cj(rec)))

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, rec: dict) -> int:
        self.records.append(rec)
        self.leaves.append(leaf_hash(cj(rec)))
        if self.path:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
        return len(self.leaves) - 1

    def root(self, size: int | None = None) -> bytes:
        return mth(self.leaves[:size])

    def proof(self, index: int, size: int) -> list[bytes]:
        return audit_path(index, self.leaves[:size])

    def consistency(self, first: int, second: int) -> list[bytes]:
        return consistency_proof(first, self.leaves[:second])


def verify_receipt(entry: dict) -> tuple[bool, str]:
    """Offline check of a relay receipt: inclusion proof + SLH-DSA tree-head sig."""
    try:
        rc, rl = entry["receipt"], entry["relay"]
        if rl["alg"] not in SLH_ALGS:
            return False, "unexpected relay signature algorithm"
        if sha3(rl["alg"].encode(), b64d(rl["pk"])).hex() != rl["fp"]:
            return False, "relay key does not match its fingerprint"
        sth = rc["sth"]
        if not sig_verify(rl["alg"], b64d(rl["pk"]), b"PQFS2-STH" + cj(sth), b64d(rc["sig"])):
            return False, "tree-head signature INVALID"
        ok = verify_inclusion(leaf_hash(cj(rc["leaf"])), rc["index"], sth["size"],
                              [bytes.fromhex(h) for h in rc["proof"]], bytes.fromhex(sth["root"]))
        return (True, "inclusion proof + signature valid") if ok else (False, "inclusion proof INVALID")
    except Exception as e:
        return False, f"malformed receipt: {e}"


# ============================================== encrypted channel (PQ hybrid)

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def _send_raw(sock, obj) -> None:
    b = cj(obj)
    sock.sendall(struct.pack(">I", len(b)) + b)


def _recv_raw(sock):
    (n,) = struct.unpack(">I", _recv_exact(sock, 4))
    if n > 1 << 20:
        raise PQFSError("oversized handshake message")
    return json.loads(_recv_exact(sock, n))


class Channel:
    """AES-256-GCM record layer. Nonces are per-direction counters."""

    def __init__(self, sock, k_send: bytes, k_recv: bytes):
        self.s, self.ks, self.kr = sock, AESGCM(k_send), AESGCM(k_recv)
        self.ns = self.nr = 0

    def send(self, data: bytes) -> None:
        nonce = b"\0\0\0\0" + self.ns.to_bytes(8, "big")
        self.ns += 1
        ct = self.ks.encrypt(nonce, data, b"PQFS2-rec")
        self.s.sendall(struct.pack(">I", len(ct)) + ct)

    def recv(self) -> bytes:
        (n,) = struct.unpack(">I", _recv_exact(self.s, 4))
        if n > MAX_CT:
            raise PQFSError("oversized record")
        ct = _recv_exact(self.s, n)
        nonce = b"\0\0\0\0" + self.nr.to_bytes(8, "big")
        self.nr += 1
        try:
            return self.kr.decrypt(nonce, ct, b"PQFS2-rec")
        except InvalidTag:
            raise PQFSError("channel record failed authentication")

    def send_json(self, o) -> None:
        self.send(cj(o))

    def recv_json(self):
        return json.loads(self.recv())


def server_handshake(sock, ident: dict) -> Channel:
    """Server authenticates with a hash-based signature (SLH-DSA) over the
    transcript; session keys come from ephemeral X25519 + ephemeral ML-KEM-768
    (forward secret). The client is anonymous."""
    ch = _recv_raw(sock)
    if ch.get("t") != "CH":
        raise PQFSError("bad client hello")
    ex = X25519PrivateKey.generate()
    kpk, ksk = kem_generate("ML-KEM-768")
    sh = {"t": "SH", "xpk": b64e(ex.public_key().public_bytes_raw()), "kpk": b64e(kpk),
          "n": b64e(os.urandom(32)), "alg": ident["alg"], "pk": ident["pk"]}
    transcript = cj(ch) + cj(sh)
    sig = sig_sign(ident["alg"], b64d(ident["sk"]), b"PQFS2-HS" + sha3(transcript))
    _send_raw(sock, dict(sh, sig=b64e(sig)))
    ck = _recv_raw(sock)
    ct = b64d(ck["ct"])
    ss_k = kem_decaps("ML-KEM-768", ksk, ct)
    ss_x = ex.exchange(X25519PublicKey.from_public_bytes(b64d(ch["xpk"])))
    keys = hkdf(ss_x + ss_k, b"PQFS2-chan" + sha3(transcript, ct), 64)
    return Channel(sock, keys[32:], keys[:32])


def client_handshake(sock) -> tuple[Channel, dict]:
    ex = X25519PrivateKey.generate()
    ch = {"t": "CH", "xpk": b64e(ex.public_key().public_bytes_raw()), "n": b64e(os.urandom(32))}
    _send_raw(sock, ch)
    full = _recv_raw(sock)
    sig = b64d(full.pop("sig"))
    sh = full
    if sh.get("t") != "SH" or sh.get("alg") not in SLH_ALGS:
        raise PQFSError("bad server hello")
    transcript = cj(ch) + cj(sh)
    pk = b64d(sh["pk"])
    if not sig_verify(sh["alg"], pk, b"PQFS2-HS" + sha3(transcript), sig):
        raise PQFSError("relay handshake signature INVALID")
    ct, ss_k = kem_encaps("ML-KEM-768", b64d(sh["kpk"]))
    ss_x = ex.exchange(X25519PublicKey.from_public_bytes(b64d(sh["xpk"])))
    _send_raw(sock, {"t": "CK", "ct": b64e(ct)})
    keys = hkdf(ss_x + ss_k, b"PQFS2-chan" + sha3(transcript, ct), 64)
    info = {"alg": sh["alg"], "pk": sh["pk"], "fp": sha3(sh["alg"].encode(), pk).hex()}
    return Channel(sock, keys[:32], keys[32:]), info


# ====================================================================== relay

def pick_slh() -> str:
    for a in SLH_ALGS:
        if have("sig", a):
            return a
    raise PQFSError("no SLH-DSA variant available in your liboqs build")


def load_or_create_relay_identity(store: Path) -> dict:
    p = store / "relay_id.json"
    d = load_json(p)
    if d is None:
        alg = pick_slh()
        pk, sk = sig_generate(alg)
        d = {"alg": alg, "pk": b64e(pk), "sk": b64e(sk)}
        save_json(p, d, private=True)
    d["fp"] = sha3(d["alg"].encode(), b64d(d["pk"])).hex()
    return d


PKG_RE = re.compile(r"[0-9a-f]{32}")


class Relay:
    """Store-and-forward drop node + append-only transparency log. It only ever
    holds ciphertext, hybrid-wrapped Shamir shares and the log."""

    def __init__(self, host: str, port: int, store: str, max_size: int = 2 << 30):
        self.store = Path(store)
        (self.store / "pkgs").mkdir(parents=True, exist_ok=True)
        (self.store / "slots").mkdir(parents=True, exist_ok=True)
        self.ident = load_or_create_relay_identity(self.store)
        self.log = MerkleLog(self.store / "log.jsonl")
        self.lock = threading.Lock()
        self.max_size = max_size
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.running = True

    # ---- lifecycle
    def serve_forever(self) -> None:
        while self.running:
            try:
                conn, addr = self.srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def start(self) -> "Relay":
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        self.running = False
        try:
            self.srv.close()
        except OSError:
            pass

    # ---- log helpers
    def _sth(self, size: int) -> tuple[dict, str]:
        sth = {"size": size, "root": self.log.root(size).hex(), "ts": now(), "relay": self.ident["fp"]}
        sig = sig_sign(self.ident["alg"], b64d(self.ident["sk"]), b"PQFS2-STH" + cj(sth))
        return sth, b64e(sig)

    def _commit(self, rec: dict) -> dict:
        with self.lock:
            idx = self.log.append(rec)
            size = len(self.log)
            sth, sig = self._sth(size)
            return {"leaf": rec, "index": idx, "sth": sth, "sig": sig,
                    "proof": [h.hex() for h in self.log.proof(idx, size)]}

    # ---- connection handler
    def _handle(self, conn, addr) -> None:
        conn.settimeout(120)
        try:
            with conn:
                ch = server_handshake(conn, self.ident)
                while True:
                    try:
                        req = ch.recv_json()
                    except (ConnectionError, socket.timeout):
                        break
                    op = req.get("op")
                    fn = {"PKG_PUT": self.op_pkg_put, "PKG_STAT": self.op_pkg_stat,
                          "PKG_RANGE": self.op_pkg_range, "SLOTS_PUT": self.op_slots_put,
                          "SLOTS_GET": self.op_slots_get, "LOG_HEAD": self.op_log_head,
                          "LOG_CONS": self.op_log_cons}.get(op)
                    if fn is None:
                        ch.send_json({"ok": False, "err": "unknown op"})
                        continue
                    try:
                        fn(ch, req)
                    except PQFSError as e:
                        ch.send_json({"ok": False, "err": str(e)})
        except Exception as e:  # keep the relay alive on any client error
            if self.running:
                say("RELAY", f"{addr[0]}: connection ended ({type(e).__name__}: {e})")

    def _pkg(self, req) -> str:
        pkg = str(req.get("pkg", ""))
        if not PKG_RE.fullmatch(pkg):
            raise PQFSError("bad package id")
        return pkg

    # ---- ops
    def op_pkg_put(self, ch, req) -> None:
        pkg = self._pkg(req)
        size = int(req.get("size", 0))
        path = self.store / "pkgs" / f"{pkg}.pq2pkg"
        if size <= 0 or size > self.max_size:
            raise PQFSError("bad size")
        if path.exists():
            raise PQFSError("package already exists (immutable)")
        ch.send_json({"ok": True, "ready": True})
        part = path.with_suffix(".part")
        h, got, err = hashlib.sha3_256(), 0, None
        try:
            with open(part, "wb") as f:
                while got < size:
                    blk = ch.recv()
                    got += len(blk)
                    if got > size:
                        err = "more data than announced"
                        break
                    f.write(blk); h.update(blk)
            if err is None:
                err = self._validate_pkg(part, pkg, size)
        except BaseException:
            part.unlink(missing_ok=True)      # client vanished mid-upload
            raise
        if err:
            part.unlink(missing_ok=True)
            raise PQFSError(err)
        os.replace(part, path)
        rc = self._commit({"op": "PKG_PUT", "pkg": pkg, "size": size, "digest": h.hexdigest(), "ts": now()})
        ch.send_json({"ok": True, "receipt": rc})

    @staticmethod
    def _validate_pkg(path: Path, pkg: str, size: int) -> str | None:
        try:
            with open(path, "rb") as f:
                head = f.read(12)
                if head[:8] != MAGIC:
                    return "not a PQFS2 package"
                hlen = struct.unpack(">I", head[8:12])[0]
                if hlen > 65536:
                    return "header too large"
                hd = json.loads(f.read(hlen))
            if hd.get("pkg") != pkg or hd.get("v") != 2:
                return "package id/version mismatch"
            if size < 12 + hlen + hd["pad"] + 16 * hd["n"] + 4 + 28:
                return "package too short"
        except Exception:
            return "malformed package"
        return None

    def op_pkg_stat(self, ch, req) -> None:
        path = self.store / "pkgs" / f"{self._pkg(req)}.pq2pkg"
        if not path.exists():
            raise PQFSError("not found")
        ch.send_json({"ok": True, "size": path.stat().st_size})

    def op_pkg_range(self, ch, req) -> None:
        path = self.store / "pkgs" / f"{self._pkg(req)}.pq2pkg"
        off, n = int(req.get("off", -1)), int(req.get("len", 0))
        if not path.exists():
            raise PQFSError("not found")
        if off < 0 or n < 1 or n > RANGE_MAX or off + n > path.stat().st_size:
            raise PQFSError("bad range")
        with open(path, "rb") as f:
            f.seek(off)
            data = f.read(n)
        ch.send_json({"ok": True, "len": len(data)})
        ch.send(data)

    def op_slots_put(self, ch, req) -> None:
        pkg = self._pkg(req)
        b = req.get("bundle")
        try:
            d = b["desc"]
            assert d["pkg"] == pkg and isinstance(d["epoch"], int) and d["epoch"] >= 1
            assert isinstance(b["slots"], list) and 0 < len(b["slots"]) <= MAX_SLOTS
        except Exception:
            raise PQFSError("malformed slot bundle")
        raw = cj(b)
        if len(raw) > 1_500_000:
            raise PQFSError("bundle too large")
        d_ = self.store / "slots" / pkg
        d_.mkdir(exist_ok=True)
        if len(list(d_.glob("*.json"))) >= 64:
            raise PQFSError("too many bundles for this package")
        digest = sha3(raw).hex()
        (d_ / f"{d['epoch']:06d}-{digest[:16]}.json").write_bytes(raw)
        rc = self._commit({"op": "SLOTS_PUT", "pkg": pkg, "epoch": d["epoch"],
                           "slots": len(b["slots"]), "digest": digest, "ts": now()})
        ch.send_json({"ok": True, "receipt": rc})

    def op_slots_get(self, ch, req) -> None:
        pkg = self._pkg(req)
        d_ = self.store / "slots" / pkg
        files = sorted(d_.glob("*.json")) if d_.exists() else []
        rc = self._commit({"op": "SLOTS_GET", "pkg": pkg, "count": len(files), "ts": now()})
        ch.send_json({"ok": True, "count": len(files), "receipt": rc})
        for f in files:
            ch.send(f.read_bytes())

    def op_log_head(self, ch, req) -> None:
        with self.lock:
            sth, sig = self._sth(len(self.log))
        ch.send_json({"ok": True, "sth": sth, "sig": sig})

    def op_log_cons(self, ch, req) -> None:
        a, b = int(req.get("first", 0)), int(req.get("second", 0))
        with self.lock:
            if not (0 <= a <= b <= len(self.log)):
                raise PQFSError("bad tree sizes")
            proof = [h.hex() for h in self.log.consistency(a, b)]
            ra, rb = self.log.root(a).hex(), self.log.root(b).hex()
        ch.send_json({"ok": True, "proof": proof, "first_root": ra, "second_root": rb})


# ================================================================ relay client

def parse_addr(s: str) -> tuple[str, int]:
    if ":" in s:
        h, p = s.rsplit(":", 1)
        return h, int(p)
    return s, DEFAULT_PORT


class RelayClient:
    """Connects, verifies the relay's hash-based signature, pins its key (TOFU or
    from the ticket) and speaks the encrypted relay protocol."""

    def __init__(self, addr: str, expect_fp: str | None = None):
        self.addr = addr
        host, port = parse_addr(addr)
        s = socket.create_connection((host, port), timeout=15)
        s.settimeout(120)
        self.sock = s
        try:
            self.ch, self.info = client_handshake(s)
            self.info["addr"] = addr
            self._pin(expect_fp)
        except Exception:
            s.close()
            raise

    def _pin(self, expect_fp: str | None) -> None:
        fp = self.info["fp"]
        if expect_fp and fp != expect_fp:
            raise PQFSError(f"relay {self.addr} key fingerprint differs from the ticket "
                            "(wrong relay or man-in-the-middle)")
        db = load_json(home() / "relays.json", {})
        rec = db.get(self.addr)
        if rec and rec["fp"] != fp:
            raise PQFSError(f"relay {self.addr} presented a NEW key (pinned {fp_fmt(rec['fp'])}, "
                            f"got {fp_fmt(fp)}). Possible MITM; delete the pin only if you trust the change.")
        if not rec:
            db[self.addr] = {"fp": fp, "alg": self.info["alg"], "pk": self.info["pk"]}
            save_json(home() / "relays.json", db)
            say("PIN", f"pinned relay {self.addr} key {fp_fmt(fp)} (verify out-of-band!)")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def req(self, **kw) -> dict:
        self.ch.send_json(kw)
        r = self.ch.recv_json()
        if not r.get("ok"):
            raise PQFSError(f"relay {self.addr}: {r.get('err', 'error')}")
        return r

    def entry(self, receipt: dict) -> dict:
        return {"relay": dict(self.info), "receipt": receipt}

    def pkg_put(self, pkg: str, path: str) -> dict:
        self.req(op="PKG_PUT", pkg=pkg, size=os.path.getsize(path))
        with open(path, "rb") as f:
            while True:
                blk = f.read(UPLOAD_REC)
                if not blk:
                    break
                self.ch.send(blk)
        r = self.ch.recv_json()
        if not r.get("ok"):
            raise PQFSError(f"relay {self.addr}: {r.get('err', 'upload failed')}")
        return self.entry(r["receipt"])

    def pkg_stat(self, pkg: str) -> int:
        return int(self.req(op="PKG_STAT", pkg=pkg)["size"])

    def pkg_range(self, pkg: str, off: int, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            step = min(RANGE_MAX, n - len(out))
            r = self.req(op="PKG_RANGE", pkg=pkg, off=off + len(out), len=step)
            data = self.ch.recv()
            if len(data) != r["len"] or len(data) != step:
                raise PQFSError("short range read")
            out.extend(data)
        return bytes(out)

    def slots_put(self, pkg: str, bundle: dict) -> dict:
        return self.entry(self.req(op="SLOTS_PUT", pkg=pkg, bundle=bundle)["receipt"])

    def slots_get(self, pkg: str) -> tuple[dict, list]:
        r = self.req(op="SLOTS_GET", pkg=pkg)
        bundles = [json.loads(self.ch.recv()) for _ in range(r["count"])]
        return self.entry(r["receipt"]), bundles

    def log_head(self) -> tuple[dict, bytes]:
        r = self.req(op="LOG_HEAD")
        return r["sth"], b64d(r["sig"])

    def log_cons(self, first: int, second: int) -> dict:
        return self.req(op="LOG_CONS", first=first, second=second)


class RelaySource:
    """Random-access view of a package stored on a relay."""

    def __init__(self, client: RelayClient, pkg: str, size: int):
        self.c, self.pkg, self.size = client, pkg, size

    def read(self, off: int, n: int) -> bytes:
        return self.c.pkg_range(self.pkg, off, n)

    def close(self) -> None:
        self.c.close()


# ===================================================== package (encrypted file)

def chunk_len(i: int, padded: int) -> int:
    return min(CHUNK, padded - i * CHUNK)


def chunk_nonce(i: int) -> bytes:
    return b"\0\0\0\0" + struct.pack(">Q", i)


def chunk_aad(hh: bytes, i: int, last: bool) -> bytes:
    # STREAM-style: index + "last" flag are authenticated => reorder/truncate/extend fail
    return b"PQFS2-chunk" + hh + struct.pack(">QB", i, 1 if last else 0)


def desc_hash(desc: dict) -> bytes:
    return sha3(cj(desc))


def build_package(path: str, out_path: str, dek: bytes, pkg_hex: str, sender: dict,
                  floor_tier: str, years: float, desc0: dict, progress=True) -> dict:
    """Streaming encrypt: [MAGIC][hlen][header][chunks...][trailer][tlen].
    The header is minimal; filename/size/hashes/sender live in the encrypted trailer."""
    real = os.path.getsize(path)
    padded = padme(max(real, MIN_PAD))
    n = (padded + CHUNK - 1) // CHUNK
    header = cj({"v": 2, "pkg": pkg_hex, "cipher": "AES-256-GCM-STREAM", "chunk": CHUNK,
                 "n": n, "pad": padded})
    hh = sha3(header)
    pkg = bytes.fromhex(pkg_hex)
    aes = AESGCM(hkdf(dek, b"PQFS2 file" + pkg))
    body_h, plain_h = hashlib.sha3_256(), hashlib.sha3_256()
    read_total = 0
    with open(path, "rb") as src, open(out_path, "wb") as out:
        out.write(MAGIC + struct.pack(">I", len(header)) + header)
        for i in range(n):
            want = chunk_len(i, padded)
            pt = src.read(want)
            read_total += len(pt)
            plain_h.update(pt)
            pt = pt + b"\0" * (want - len(pt))
            ct = aes.encrypt(chunk_nonce(i), pt, chunk_aad(hh, i, i == n - 1))
            body_h.update(ct)
            out.write(ct)
            if progress and (i + 1) % 200 == 0:
                say("SEND", f"encrypted chunk {i + 1}/{n}")
        if read_total != real or src.read(1):
            raise PQFSError("file changed while reading")
        manifest = {"pkg": pkg_hex, "header_sha3": hh.hex(), "body_sha3": body_h.hexdigest(),
                    "plain_sha3": plain_h.hexdigest(), "size": real,
                    "filename": os.path.basename(path), "created": now(), "years": years,
                    "floor": floor_tier, "desc0_sha3": desc_hash(desc0).hex()}
        meta = {"manifest": manifest,
                "sender": {"name": sender["name"], "public": sender["public"]},
                "sig": hybrid_sign(sender["secret"], b"PQFS2-manifest" + cj(manifest))}
        nonce = os.urandom(12)
        trailer = nonce + AESGCM(hkdf(dek, b"PQFS2 meta" + pkg)).encrypt(
            nonce, cj(meta), b"PQFS2-meta" + hh)
        out.write(trailer + struct.pack(">I", len(trailer)))
    return {"padded": padded, "chunks": n, "real": real}


def parse_pkg(src) -> dict:
    head = src.read(0, 12)
    if head[:8] != MAGIC:
        raise PQFSError("not a PQFS2 package")
    hlen = struct.unpack(">I", head[8:12])[0]
    if hlen > 65536:
        raise PQFSError("header too large")
    hb = src.read(12, hlen)
    header = json.loads(hb)
    tl = struct.unpack(">I", src.read(src.size - 4, 4))[0]
    t_off = src.size - 4 - tl
    body_off, body_len = 12 + hlen, header["pad"] + 16 * header["n"]
    if body_off + body_len != t_off:
        raise PQFSError("package layout inconsistent (truncated or extended?)")
    return {"header": header, "hh": sha3(hb), "body_off": body_off, "body_len": body_len,
            "trailer": src.read(t_off, tl)}


def open_trailer(dek: bytes, pf: dict) -> dict:
    pkg = bytes.fromhex(pf["header"]["pkg"])
    t = pf["trailer"]
    pt = AESGCM(hkdf(dek, b"PQFS2 meta" + pkg)).decrypt(t[:12], t[12:], b"PQFS2-meta" + pf["hh"])
    return json.loads(pt)


def verify_meta(meta: dict, pf: dict) -> str:
    man, sender = meta["manifest"], meta["sender"]
    if man["pkg"] != pf["header"]["pkg"] or man["header_sha3"] != pf["hh"].hex():
        raise PQFSError("manifest does not match package header")
    if not hybrid_verify(sender["public"], b"PQFS2-manifest" + cj(man), meta["sig"]):
        raise PQFSError("sender signature INVALID (Ed25519 + ML-DSA-65)")
    if man["floor"] not in TIERS or not (0 <= man["size"] <= pf["header"]["pad"]):
        raise PQFSError("manifest fields invalid")
    return fp_of(sender["public"])


def decrypt_body(src, pf: dict, dek: bytes, man: dict, out) -> None:
    header, hh = pf["header"], pf["hh"]
    n, padded = header["n"], header["pad"]
    aes = AESGCM(hkdf(dek, b"PQFS2 file" + bytes.fromhex(header["pkg"])))
    body_h, plain_h = hashlib.sha3_256(), hashlib.sha3_256()
    remaining, off, idx = man["size"], pf["body_off"], 0
    while idx < n:
        batch = min(16, n - idx)
        lens = [chunk_len(i, padded) + 16 for i in range(idx, idx + batch)]
        buf = src.read(off, sum(lens))
        off += len(buf)
        pos = 0
        for j, l in enumerate(lens):
            i = idx + j
            ct = buf[pos:pos + l]; pos += l
            try:
                pt = aes.decrypt(chunk_nonce(i), ct, chunk_aad(hh, i, i == n - 1))
            except InvalidTag:
                raise PQFSError(f"chunk {i + 1}/{n} failed authentication (tampered)")
            body_h.update(ct)
            take = min(len(pt), remaining)
            out.write(pt[:take]); plain_h.update(pt[:take])
            if any(pt[take:]):
                raise PQFSError("non-zero padding")
            remaining -= take
        idx += batch
        if idx % 160 == 0 or idx == n:
            say("RECV", f"decrypted chunk {idx}/{n}")
    if remaining != 0:
        raise PQFSError("file shorter than manifest size")
    if body_h.hexdigest() != man["body_sha3"]:
        raise PQFSError("ciphertext hash does not match signed manifest")
    if plain_h.hexdigest() != man["plain_sha3"]:
        raise PQFSError("plaintext hash does not match signed manifest")


# ================================================ key-wrap layer ("slot sets")

def make_desc(pkg: str, epoch: int, tier: str, kems: list, n: int, t: int, years: float) -> dict:
    return {"v": 2, "pkg": pkg, "epoch": epoch, "tier": tier, "kems": kems,
            "n": n, "t": t, "years": years, "created": now()}


def wrap_slot(public: dict, desc: dict, i: int, x: int, share: bytes) -> dict:
    ctx = b"PQFS2-slot" + desc_hash(desc) + struct.pack(">H", i)
    cts, key = hybrid_encaps(public, desc["kems"], ctx)
    nonce = os.urandom(12)
    w = AESGCM(key).encrypt(nonce, bytes([x]) + share, ctx)
    return {"i": i, "cts": cts, "nonce": b64e(nonce), "w": b64e(w)}


def unwrap_slot(ident: dict, desc: dict, slot: dict):
    """Trial decryption: returns (x, share) if this slot was wrapped to us."""
    try:
        ctx = b"PQFS2-slot" + desc_hash(desc) + struct.pack(">H", slot["i"])
        key = hybrid_decaps(ident["secret"], ident["public"], desc["kems"], slot["cts"], ctx)
        pt = AESGCM(key).decrypt(b64d(slot["nonce"]), b64d(slot["w"]), ctx)
        return pt[0], pt[1:]
    except Exception:
        return None


def desc_mac(dek: bytes, desc: dict) -> str:
    key = hkdf(dek, b"PQFS2 desc-mac" + bytes.fromhex(desc["pkg"]))
    return hmac.new(key, cj(desc), "sha3_256").hexdigest()


def issue_slotset(dek: bytes, desc: dict, holders: list[dict], n_relays: int) -> list[dict | None]:
    """Shamir-split the DEK, wrap each share to its holder with the hybrid KEM and
    spread the slots over relays (round robin). Returns one bundle per relay."""
    shares = shamir_split(dek, desc["n"], desc["t"])
    mac = desc_mac(dek, desc)
    per_relay: list[list] = [[] for _ in range(n_relays)]
    for idx, ((x, share), holder) in enumerate(zip(shares, holders)):
        per_relay[idx % n_relays].append(wrap_slot(holder["public"], desc, idx, x, share))
    return [{"v": 2, "desc": desc, "mac": mac, "slots": s} if s else None for s in per_relay]


def check_topology(n: int, t: int, r: int, allow_weak: bool) -> None:
    per = -(-n // r)
    if t > 1 and per >= t:
        msg = (f"topology too weak: {n} shares over {r} relay(s) puts up to {per} shares on one "
               f"relay, but the threshold is {t}. One compromised relay could then hold enough "
               f"shares. Use at least {-(-n // (t - 1))} relays, or pass --allow-weak-topology.")
        if not allow_weak:
            raise PQFSError(msg)
        say("WARN", msg)


# ---- releases (threshold decryption by several custodians) --------------------

def make_release(approver: dict, combiner_public: dict, desc: dict, x: int, share: bytes) -> dict:
    dh = desc_hash(desc)
    ctx = b"PQFS2-release" + dh
    cts, key = hybrid_encaps(combiner_public, desc["kems"], ctx)
    nonce = os.urandom(12)
    core = {"pkg": desc["pkg"], "epoch": desc["epoch"], "dh": dh.hex(), "cts": cts,
            "nonce": b64e(nonce), "w": b64e(AESGCM(key).encrypt(nonce, bytes([x]) + share, ctx))}
    return {"pqfs": 2, "type": "release", "core": core,
            "approver": {"name": approver["name"], "public": approver["public"]},
            "sig": hybrid_sign(approver["secret"], b"PQFS2-release" + cj(core))}


def open_release(ident: dict, rel: dict, desc: dict):
    try:
        core = rel["core"]
        if core["dh"] != desc_hash(desc).hex():
            return None
        if not hybrid_verify(rel["approver"]["public"], b"PQFS2-release" + cj(core), rel["sig"]):
            return None
        ctx = b"PQFS2-release" + desc_hash(desc)
        key = hybrid_decaps(ident["secret"], ident["public"], desc["kems"], core["cts"], ctx)
        pt = AESGCM(key).decrypt(b64d(core["nonce"]), b64d(core["w"]), ctx)
        return pt[0], pt[1:], fp_of(rel["approver"]["public"]), rel["approver"]["name"]
    except Exception:
        return None


# ================================================= recovering the data key

def group_bundles(bundles: list, pkg: str) -> dict:
    groups: dict = {}
    for b in bundles:
        try:
            d = b["desc"]
            if d["pkg"] != pkg or d["v"] != 2 or not isinstance(d["epoch"], int):
                continue
            g = groups.setdefault((d["epoch"], desc_hash(d).hex()),
                                  {"desc": d, "mac": b["mac"], "slots": []})
            g["slots"].extend(b["slots"])
        except (KeyError, TypeError):
            continue
    return groups


def recover(ident: dict, bundles: list, pf: dict, releases: list, min_tier=None,
            allow_deprecated=False) -> dict:
    """Find the newest slot-set epoch we can open (own slots + releases), rebuild the
    DEK by Shamir, authenticate it against the encrypted trailer, verify the sender's
    signed floor and the descriptor MAC. Fails closed."""
    pkg = pf["header"]["pkg"]
    dep = set() if allow_deprecated else load_deprecated()
    groups = group_bundles(bundles, pkg)
    if not groups:
        raise PQFSError("no key slots found on the relays for this package")
    notes = []
    for (epoch, dh), g in sorted(groups.items(), key=lambda kv: kv[0][0], reverse=True):
        desc = g["desc"]
        bad = [k for k in desc["kems"] if k in dep]
        if bad:
            notes.append(f"epoch {epoch}: uses deprecated {bad}")
            continue
        if min_tier and not suite_satisfies(desc["kems"], TIERS[min_tier]["kems"], dep):
            notes.append(f"epoch {epoch}: below --min-tier {min_tier}")
            continue
        shares, approvers = {}, []
        for s in g["slots"]:
            r = unwrap_slot(ident, desc, s)
            if r:
                shares[r[0]] = r[1]
        for rel in releases:
            r = open_release(ident, rel, desc)
            if r:
                shares[r[0]] = r[1]
                approvers.append((r[2], r[3]))
        if len(shares) < desc["t"]:
            notes.append(f"epoch {epoch}: have {len(shares)} share(s), need {desc['t']}")
            continue
        for combo in itertools.combinations(sorted(shares.items()), desc["t"]):
            dek = shamir_combine(list(combo))
            try:
                meta = open_trailer(dek, pf)
            except InvalidTag:
                continue                     # wrong/poisoned share combination
            sender_fp = verify_meta(meta, pf)
            man = meta["manifest"]
            if not suite_satisfies(desc["kems"], TIERS[man["floor"]]["kems"], dep):
                notes.append(f"epoch {epoch}: violates the sender's signed minimum suite ({man['floor']})")
                break
            if not hmac.compare_digest(g["mac"], desc_mac(dek, desc)):
                notes.append(f"epoch {epoch}: descriptor MAC invalid")
                break
            return {"dek": dek, "meta": meta, "desc": desc, "epoch": epoch, "sender_fp": sender_fp,
                    "approvers": approvers, "max_epoch": max(e for e, _ in groups)}
        else:
            notes.append(f"epoch {epoch}: shares did not authenticate")
    raise PQFSError("could not recover the key. " + "; ".join(notes))


def check_rollback(pkg: str, epoch: int, allow: bool) -> None:
    st = load_json(home() / "state.json", {})
    prev = st.get(pkg, {}).get("epoch", 0)
    if epoch < prev and not allow:
        raise PQFSError(f"ROLLBACK detected: you previously used epoch {prev} of this package but "
                        f"the relays now only offer epoch {epoch}. A relay may be replaying an old, "
                        "weaker key-wrap. Use --allow-rollback only if you know why.")
    st[pkg] = {"epoch": max(prev, epoch), "seen": now()}
    save_json(home() / "state.json", st)


# ======================================================= ticket-level helpers

def load_ticket(path: str) -> dict:
    t = load_json(Path(path))
    if not t or t.get("type") != "ticket":
        raise PQFSError(f"{path} is not a PQFS2 ticket")
    return t


def fetch_bundles(ticket: dict, quiet=False) -> list:
    bundles = []
    for r in ticket["relays"]:
        try:
            with RelayClient(r["addr"], r.get("fp")) as c:
                entry, bs = c.slots_get(ticket["pkg"])
                ok, why = verify_receipt(entry)
                if not ok:
                    say("WARN", f"{r['addr']}: access receipt invalid: {why}")
                bundles.extend(bs)
                if not quiet:
                    say("RECV", f"{r['addr']}: {len(bs)} slot bundle(s); access logged "
                                f"(log entry #{entry['receipt']['index']})")
        except (OSError, PQFSError) as e:
            say("WARN", f"relay {r['addr']} unreachable/refused: {e}")
    return bundles


def open_source(ticket: dict) -> RelaySource:
    last = None
    for r in ticket["relays"]:
        try:
            c = RelayClient(r["addr"], r.get("fp"))
            try:
                return RelaySource(c, ticket["pkg"], c.pkg_stat(ticket["pkg"]))
            except Exception:
                c.close(); raise
        except (OSError, PQFSError) as e:
            last = e
    raise PQFSError(f"package not available on any relay ({last})")


def relay_specs(addrs: list[str]) -> list[dict]:
    specs = []
    for a in addrs:
        with RelayClient(a) as c:
            specs.append({"addr": a, "fp": c.info["fp"]})
    return specs


def publish_bundles(specs, bundles, pkg, receipts) -> None:
    for spec, b in zip(specs, bundles):
        if b is None:
            continue
        with RelayClient(spec["addr"], spec["fp"]) as c:
            e = c.slots_put(pkg, b)
            receipts.append(e)
            say("SEND", f"{spec['addr']}: stored {len(b['slots'])} slot(s) epoch {b['desc']['epoch']} "
                        f"(log #{e['receipt']['index']})")


def save_receipts(ticket_path: Path, receipts: list) -> Path:
    p = ticket_path.with_name(ticket_path.name.replace(".ticket.json", "") + ".receipts.json")
    old = load_json(p, [])
    save_json(p, old + receipts)
    return p


def sender_trust(fp: str, name: str, ident: dict, allow_unknown: bool) -> None:
    if fp == ident["fp"]:
        return
    c = contacts()
    if fp in c:
        say("RECV", f"sender verified: {c[fp]['name']} ({fp_fmt(fp)})")
        return
    say("WARN", f"sender '{name}' fingerprint {fp_fmt(fp)} is NOT in your contacts")
    if allow_unknown:
        return
    if sys.stdin.isatty() and input("Accept this sender for this file? [y/N] ").strip().lower() == "y":
        return
    raise PQFSError("unknown sender rejected (use `trust <their.pub>` or --allow-unknown-sender)")


def safe_out_path(outdir: str, filename: str) -> str:
    name = os.path.basename(filename.replace("\\", "/")).replace("\0", "")
    if name in ("", ".", ".."):
        name = "received.bin"
    os.makedirs(outdir, exist_ok=True)
    base = os.path.join(outdir, name)
    root, ext = os.path.splitext(base)
    out, i = base, 1
    while os.path.exists(out):
        out = f"{root}_{i}{ext}"; i += 1
    return out


# =============================================================== CLI commands

def cmd_info(a) -> None:
    print(f"PQFS {VERSION}")
    print(f"liboqs-python: {'available' if oqs else 'MISSING (' + str(_OQS_ERR) + ')'}")
    if oqs:
        for k in KEM_ALIASES:
            print(f"  KEM  {k:12s} {'OK ' if have('kem', k) else 'MISSING'}")
        for s in SIG_ALIASES:
            print(f"  SIG  {s:18s} {'OK ' if have('sig', s) else 'MISSING'}")
    print("  KEM  X25519       OK (cryptography)")
    print(f"home: {home()}   deprecated: {sorted(load_deprecated()) or 'none'}")


def cmd_keygen(a) -> None:
    out = Path(a.outdir)
    idp, pubp = out / f"{a.name}.id", out / f"{a.name}.pub"
    if (idp.exists() or pubp.exists()) and not a.force:
        raise PQFSError(f"{idp} or {pubp} exists (use --force)")
    say("KEYGEN", "generating X25519 + ML-KEM-768/1024 + HQC-192/256 + Ed25519 + ML-DSA-65 ...")
    ident = new_identity(a.name)
    save_identity(idp, ident, ask_pass("New identity passphrase: ", confirm=True))
    save_json(pubp, {"pqfs": 2, "type": "public", "name": a.name,
                     "public": ident["public"], "fp": ident["fp"]})
    say("KEYGEN", f"private (encrypted): {idp}")
    say("KEYGEN", f"public bundle      : {pubp}   (share this)")
    say("KEYGEN", f"fingerprint        : {fp_fmt(ident['fp'])}   (compare out-of-band)")


def cmd_trust(a) -> None:
    for p in a.files:
        b = load_public(p)
        trust_contact(b["fp"], b["name"])
        say("TRUST", f"trusted {b['name']}  {fp_fmt(b['fp'])}")


def cmd_deprecate(a) -> None:
    dep = load_deprecated()
    if a.list:
        print(sorted(dep) or "none"); return
    if a.undo:
        dep.discard(a.alg)
    else:
        if a.alg not in KEM_FAMILY:
            raise PQFSError(f"unknown KEM; choose from {sorted(KEM_FAMILY)}")
        dep.add(a.alg)
    save_json(home() / "deprecated.json", sorted(dep))
    say("POLICY", f"deprecated set is now: {sorted(dep) or 'none'}")


def cmd_assess(a) -> None:
    r = assess(a.file, a.years)
    print(f"exposure score {r['score']}/100  ->  tier {r['tier']} ({TIERS[r['tier']]['label']})")
    for x in r["reasons"]:
        print("  -", x)
    t = TIERS[r["tier"]]
    print(f"suite {t['kems']}, default {t['t']}-of-{t['n']} shares")


def cmd_relay(a) -> None:
    r = Relay(a.host, a.port, a.store, a.max_size_mb << 20)
    say("RELAY", f"listening on {a.host}:{r.port}   store={a.store}")
    say("RELAY", f"log-signing key: {r.ident['alg']}  fingerprint {fp_fmt(r.ident['fp'])}")
    say("RELAY", f"transparency log has {len(r.log)} entries. Ctrl+C to stop.")
    try:
        r.serve_forever()
    except KeyboardInterrupt:
        say("RELAY", "stopped")


def cmd_send(a) -> None:
    ident = load_identity(a.id)
    holders = [load_public(p) for p in a.to]
    if not a.relay:
        raise PQFSError("give at least one --relay host:port")
    if not os.path.isfile(a.file):
        raise PQFSError(f"file not found: {a.file}")
    years = a.years
    ass = assess(a.file, years)
    tier = a.tier or ass["tier"]
    say("POLICY", f"exposure score {ass['score']}/100 -> policy tier {ass['tier']}")
    for r in ass["reasons"]:
        say("POLICY", "  " + r)
    if a.tier and tier_rank(a.tier) < tier_rank(ass["tier"]):
        say("WARN", f"--tier {a.tier} is BELOW the policy recommendation {ass['tier']}")
    dep = load_deprecated()
    kems = effective_kems(tier, dep)
    if len(holders) == 1:
        n = a.shares or TIERS[tier]["n"]
        t = a.threshold or min(TIERS[tier]["t"], n)
        holder_list = [holders[0]] * n
    else:
        n = len(holders)
        t = a.threshold or (n // 2 + 1)
        holder_list = holders
    if not (1 <= t <= n <= MAX_SLOTS):
        raise PQFSError(f"invalid threshold: need 1 <= t <= n <= {MAX_SLOTS} (t={t}, n={n})")
    for h in holders:
        for k in kems:
            kem_pk(h["public"], k)
    check_topology(n, t, len(a.relay), a.allow_weak_topology)
    specs = relay_specs(a.relay)
    say("SEND", f"suite {kems}; {t}-of-{n} shares over {len(specs)} relay(s); "
                f"custodian(s): {', '.join(h['name'] for h in holders)}")

    pkg = os.urandom(16).hex()
    dek = os.urandom(32)
    desc = make_desc(pkg, 1, tier, kems, n, t, years)
    tmpdir = tempfile.mkdtemp(prefix="pqfs2-")
    pkg_path = os.path.join(tmpdir, f"{pkg}.pq2pkg")
    try:
        info = build_package(a.file, pkg_path, dek, pkg, ident, tier, years, desc)
        say("SEND", f"file {info['real']} B padded to {info['padded']} B (Padme), {info['chunks']} equal chunks")
        receipts = []
        targets = range(len(specs)) if a.replicate else [0]
        for i in targets:
            with RelayClient(specs[i]["addr"], specs[i]["fp"]) as c:
                e = c.pkg_put(pkg, pkg_path)
                receipts.append(e)
                say("SEND", f"{specs[i]['addr']}: ciphertext stored (log #{e['receipt']['index']})")
        publish_bundles(specs, issue_slotset(dek, desc, holder_list, len(specs)), pkg, receipts)
    finally:
        try:
            os.remove(pkg_path); os.rmdir(tmpdir)
        except OSError:
            pass
    tpath = Path(a.out or f"{pkg[:12]}.ticket.json")
    save_json(tpath, {"pqfs": 2, "type": "ticket", "pkg": pkg, "created": now(),
                      "relays": specs, "note": "locations only - contains no secrets"})
    rp = save_receipts(tpath, receipts)
    bad = [verify_receipt(e) for e in receipts if not verify_receipt(e)[0]]
    say("SEND", f"ticket  : {tpath}   (send this to the recipient over any channel)")
    say("SEND", f"receipts: {rp}   ({len(receipts)} log receipts, "
                f"{'all valid' if not bad else 'SOME INVALID'})")
    say("SEND", f"security: < {t} relays learn nothing about the key (information-theoretic); "
                f"breaking every KEM would additionally need >= {t} relays' data.")


def cmd_receive(a) -> None:
    ident = load_identity(a.id)
    ticket = load_ticket(a.ticket)
    releases = []
    for p in a.release or []:
        d = load_json(Path(p))
        releases += d["releases"] if d.get("type") == "release-set" else [d]
    bundles = fetch_bundles(ticket)
    src = open_source(ticket)
    try:
        pf = parse_pkg(src)
        res = recover(ident, bundles, pf, releases, a.min_tier, a.allow_deprecated)
        check_rollback(ticket["pkg"], res["epoch"], a.allow_rollback)
        man = res["meta"]["manifest"]
        desc = res["desc"]
        say("RECV", f"key recovered: epoch {res['epoch']}, tier {desc['tier']}, suite {desc['kems']}, "
                    f"{desc['t']}-of-{desc['n']}" + (f", approvals from {[n for _, n in res['approvers']]}"
                                                     if res["approvers"] else ""))
        sender_trust(res["sender_fp"], res["meta"]["sender"]["name"], ident, a.allow_unknown_sender)
        if res["max_epoch"] > res["epoch"]:
            say("WARN", f"newer epoch {res['max_epoch']} exists but was not usable")
        say("RECV", f"file '{man['filename']}' {man['size']} bytes, signed by "
                    f"{res['meta']['sender']['name']} (Ed25519 + ML-DSA-65 valid)")
        out_path = safe_out_path(a.outdir, man["filename"])
        part = out_path + ".part"
        try:
            with open(part, "wb") as f:
                decrypt_body(src, pf, res["dek"], man, f)
            os.replace(part, out_path)
        except Exception:
            try:
                os.remove(part)
            except OSError:
                pass
            raise
        say("RECV", "INTEGRITY: every chunk authenticated, ciphertext + plaintext hashes match the signed manifest  \u2714")
        say("RECV", f"saved to {out_path}")
    finally:
        src.close()


def cmd_approve(a) -> None:
    ident = load_identity(a.id)
    combiner = load_public(a.for_)
    ticket = load_ticket(a.ticket)
    bundles = fetch_bundles(ticket)
    rels = []
    for (epoch, dh), g in group_bundles(bundles, ticket["pkg"]).items():
        for s in g["slots"]:
            r = unwrap_slot(ident, g["desc"], s)
            if r:
                rels.append(make_release(ident, combiner["public"], g["desc"], r[0], r[1]))
                say("APPROVE", f"released my share for epoch {epoch} to {combiner['name']}")
    if not rels:
        raise PQFSError("you hold no key slot for this package")
    save_json(Path(a.out), {"pqfs": 2, "type": "release-set", "releases": rels})
    say("APPROVE", f"wrote {a.out} (encrypted to {combiner['name']}, signed by {ident['name']})")


def cmd_rewrap(a, *, quiet_ident=None) -> None:
    ident = quiet_ident or load_identity(a.id)
    ticket = load_ticket(a.ticket)
    releases = []
    for p in getattr(a, "release", None) or []:
        d = load_json(Path(p))
        releases += d["releases"] if d.get("type") == "release-set" else [d]
    bundles = fetch_bundles(ticket, quiet=True)
    src = open_source(ticket)
    try:
        pf = parse_pkg(src)
    finally:
        src.close()
    res = recover(ident, bundles, pf, releases, None, True)
    man = res["meta"]["manifest"]
    years = a.years if getattr(a, "years", None) is not None else man["years"]
    dep = load_deprecated()
    ass_tier = tier_for_years(years)
    tier = getattr(a, "tier", None) or ass_tier
    tier = TIER_ORDER[max(tier_rank(tier), tier_rank(man["floor"]))]   # never below the signed floor
    # If the recovered tier's suite still contains deprecated algorithms, escalate.
    while True:
        kems = effective_kems(tier, dep)
        if suite_satisfies(kems, TIERS[man["floor"]]["kems"], dep) or tier == TIER_ORDER[-1]:
            break
        tier = TIER_ORDER[tier_rank(tier) + 1]
    holders = [load_public(p) for p in (getattr(a, "to", None) or [])]
    if len(holders) > 1:
        n, t = len(holders), getattr(a, "threshold", None) or (len(holders) // 2 + 1)
        holder_list = holders
    else:
        me = {"name": ident["name"], "public": ident["public"]}
        h = holders[0] if holders else me
        n = TIERS[tier]["n"]; t = getattr(a, "threshold", None) or min(TIERS[tier]["t"], n)
        holder_list = [h] * n
    extra = getattr(a, "relay", None) or []
    specs = list(ticket["relays"]) + [s for s in relay_specs(extra)
                                       if s["addr"] not in {r["addr"] for r in ticket["relays"]}]
    check_topology(n, t, len(specs), getattr(a, "allow_weak_topology", False))
    epoch = res["max_epoch"] + 1
    desc = make_desc(ticket["pkg"], epoch, tier, kems, n, t, years)
    receipts = []
    say("REWRAP", f"file key stays the same; new key-wrap epoch {epoch}: tier {tier}, suite {kems}, "
                  f"{t}-of-{n} over {len(specs)} relay(s). Ciphertext is NOT touched.")
    publish_bundles(specs, issue_slotset(res["dek"], desc, holder_list, len(specs)), ticket["pkg"], receipts)
    ticket["relays"] = specs
    save_json(Path(a.ticket), ticket)
    save_receipts(Path(a.ticket), receipts)
    check_rollback(ticket["pkg"], epoch, True)
    say("REWRAP", "done. Old-epoch slots remain on relays (they cannot be un-harvested).")


def cmd_audit(a) -> None:
    dep = load_deprecated()
    tickets = sorted(Path(a.tickets).glob("*.ticket.json"))
    if not tickets:
        say("AUDIT", f"no *.ticket.json in {a.tickets}"); return
    ident = None
    fixed = problems = 0
    for tp in tickets:
        t = load_json(tp)
        bundles = fetch_bundles(t, quiet=True)
        groups = group_bundles(bundles, t["pkg"])
        if not groups:
            say("AUDIT", f"{tp.name}: no slot bundles reachable"); continue
        (epoch, _), g = max(groups.items(), key=lambda kv: kv[0][0])
        d = g["desc"]
        issues = []
        if any(k in dep for k in d["kems"]):
            issues.append(f"uses deprecated {[k for k in d['kems'] if k in dep]}")
        if tier_rank(d["tier"]) < tier_rank(tier_for_years(d["years"])):
            issues.append(f"tier {d['tier']} below policy {tier_for_years(d['years'])} for {d['years']:g}y secrecy")
        if a.max_age_days and now() - d["created"] > a.max_age_days * 86400:
            issues.append(f"key-wrap older than {a.max_age_days} days")
        status = "OK" if not issues else "NEEDS UPGRADE: " + "; ".join(issues)
        say("AUDIT", f"{tp.name}: epoch {epoch}, {d['tier']}, {d['t']}-of-{d['n']}, {d['kems']} -> {status}")
        if issues:
            problems += 1
            if a.fix:
                if ident is None:
                    ident = load_identity(a.id)
                ns = argparse.Namespace(ticket=str(tp), id=a.id, years=None, tier=None, to=None,
                                        threshold=None, relay=None, release=None,
                                        allow_weak_topology=a.allow_weak_topology)
                try:
                    cmd_rewrap(ns, quiet_ident=ident); fixed += 1
                except PQFSError as e:
                    say("AUDIT", f"  could not auto-fix: {e}")
    say("AUDIT", f"{len(tickets)} ticket(s), {problems} need upgrade, {fixed} fixed")


def cmd_verify_receipt(a) -> None:
    entries = load_json(Path(a.file), [])
    pins = load_json(home() / "relays.json", {})
    bad = 0
    for e in entries:
        ok, why = verify_receipt(e)
        pin = pins.get(e["relay"]["addr"], {}).get("fp")
        pinned = "pinned" if pin == e["relay"]["fp"] else "NOT PINNED"
        leaf = e["receipt"]["leaf"]
        say("RECEIPT", f"{leaf['op']:9s} log#{e['receipt']['index']:<4d} relay {e['relay']['addr']} "
                       f"({pinned}): {'OK' if ok else 'FAIL'} - {why}")
        bad += not ok
    if bad:
        raise PQFSError(f"{bad} receipt(s) failed verification")


def cmd_monitor(a) -> None:
    with RelayClient(a.relay) as c:          # connecting also pins the relay key on first use
        db = load_json(home() / "relays.json", {})
        rec = db[a.relay]
        sth, sig = c.log_head()
        if not sig_verify(rec["alg"], b64d(rec["pk"]), b"PQFS2-STH" + cj(sth), sig):
            raise PQFSError("tree head signature INVALID")
        old = rec.get("head")
        if old:
            if sth["size"] < old["size"]:
                raise PQFSError(f"LOG SHRANK from {old['size']} to {sth['size']} entries: history was removed!")
            r = c.log_cons(old["size"], sth["size"])
            ok = verify_consistency(old["size"], sth["size"], bytes.fromhex(old["root"]),
                                    bytes.fromhex(sth["root"]), [bytes.fromhex(h) for h in r["proof"]])
            if not ok or r["first_root"] != old["root"]:
                raise PQFSError("LOG INCONSISTENT: the relay rewrote history!")
            say("MONITOR", f"append-only verified: {old['size']} -> {sth['size']} entries, "
                           "old tree is a prefix of the new one \u2714")
        else:
            say("MONITOR", f"first observation recorded: {sth['size']} entries, root {sth['root'][:16]}...")
        rec["head"] = {"size": sth["size"], "root": sth["root"], "ts": sth["ts"]}
        db[a.relay] = rec
        save_json(home() / "relays.json", db)


# ==================================================================== selftest

def cmd_selftest(a) -> None:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            raise PQFSError(f"selftest failed: {name}")
        ok += 1

    print("Selftest")
    secret = os.urandom(32)
    for n, t in [(1, 1), (3, 2), (5, 3), (7, 7)]:
        sh = shamir_split(secret, n, t)
        check(f"shamir {t}-of-{n} reconstructs", shamir_combine(sh[:t]) == secret
              and shamir_combine(sh[-t:]) == secret)
    sh = shamir_split(secret, 5, 3)
    check("shamir t-1 shares give a wrong key", shamir_combine(sh[:2]) != secret)
    check("padme never shrinks / <=12% overhead",
          all(L <= padme(L) <= L * 1.125 + 1 for L in [4096, 5000, 123456, 10 ** 7]))
    for size in [1, 2, 3, 5, 8, 13, 21, 50]:
        leaves = [leaf_hash(str(i).encode()) for i in range(size)]
        root = mth(leaves)
        good = all(verify_inclusion(leaves[i], i, size, audit_path(i, leaves), root) for i in range(size))
        good &= not verify_inclusion(leaves[0], 0, size, audit_path(0, leaves), sha3(b"x"))
        for m in range(1, size + 1):
            good &= verify_consistency(m, size, mth(leaves[:m]), root, consistency_proof(m, leaves))
        check(f"merkle inclusion + consistency (size {size})", good)
    leaves = [leaf_hash(str(i).encode()) for i in range(9)]
    forged = list(leaves); forged[2] = leaf_hash(b"evil")
    check("merkle detects rewritten history",
          not verify_consistency(5, 9, mth(leaves[:5]), mth(forged), consistency_proof(5, forged))
          and not verify_consistency(5, 9, mth(leaves[:5]), mth(forged), consistency_proof(5, leaves)))
    if oqs is None:
        raise PQFSError("liboqs missing: cannot run PQ selftests")
    ident = new_identity("t")
    for kems in (TIERS["T2"]["kems"], TIERS["T3"]["kems"]):
        if all(have("kem", k) or k == "X25519" for k in kems):
            cts, key = hybrid_encaps(ident["public"], kems, b"ctx")
            check(f"hybrid KEM roundtrip {kems}",
                  hybrid_decaps(ident["secret"], ident["public"], kems, cts, b"ctx") == key)
            bad = dict(cts); bad[kems[1]] = b64e(bytes(len(b64d(cts[kems[1]]))))
            check("tampered lattice ciphertext changes the key",
                  hybrid_decaps(ident["secret"], ident["public"], kems, bad, b"ctx") != key)
            check("different context/suite changes the key",
                  hybrid_decaps(ident["secret"], ident["public"], kems, cts, b"other") != key)
    sig = hybrid_sign(ident["secret"], b"m")
    check("hybrid signature ok", hybrid_verify(ident["public"], b"m", sig))
    check("hybrid signature rejects other message", not hybrid_verify(ident["public"], b"x", sig))
    alg = pick_slh(); pk, sk = sig_generate(alg)
    check(f"{alg} sign/verify", sig_verify(alg, pk, b"z", sig_sign(alg, sk, b"z")))
    print(f"Selftest OK ({ok} checks)")


# ======================================================================= demo

def cmd_demo(a) -> None:
    import shutil
    if oqs is None:
        raise PQFSError("liboqs missing")
    root = Path(tempfile.mkdtemp(prefix="pqfs2-demo-"))
    os.environ["PQFS_HOME"] = str(root / "home")
    os.environ["PQFS_PASSPHRASE"] = "demo-passphrase"
    relays = [Relay("127.0.0.1", 0, root / f"relay{i}").start() for i in range(3)]
    addrs = [f"127.0.0.1:{r.port}" for r in relays]
    rel = [x for ad in addrs for x in ("--relay", ad)]
    cwd = os.getcwd()
    os.chdir(root)

    def run(*argv):
        args = build_parser().parse_args(list(map(str, argv)))
        args.func(args)

    def title(s):
        print(f"\n===== {s} =====")

    try:
        title("Setup: 3 relays + identities (alice=sender, bob/carol/dave=custodians)")
        for n in ("alice", "bob", "carol", "dave"):
            run("keygen", n)
        run("trust", "alice.pub")
        # a "sensitive" file so the policy engine reacts
        (root / "wallet-backup.key").write_bytes(
            b"-----BEGIN PRIVATE KEY-----\n" + os.urandom(1_300_000) + b"\n-----END PRIVATE KEY-----\n")
        original = (root / "wallet-backup.key").read_bytes()

        title("Feature 4: shelf-life policy engine (dry run)")
        run("assess", "wallet-backup.key", "--years", 30)

        title("Features 1,2,5,6: send (hybrid X25519+ML-KEM+HQC, 3-of-5 shares over 3 relays)")
        run("send", "wallet-backup.key", "--id", "alice.id", "--to", "bob.pub", *rel,
            "--years", 30, "--out", "t30.ticket.json")
        title("Receive (bob), with verified access receipts")
        run("receive", "t30.ticket.json", "--id", "bob.id", "--outdir", "inbox")
        got = (root / "inbox" / "wallet-backup.key").read_bytes()
        assert got == original, "ROUNDTRIP MISMATCH"
        print("  -> byte-for-byte identical to the original")

        title("Feature 5: transparency-log receipts verify offline")
        run("verify-receipt", "t30.receipts.json")

        title("Metadata privacy: what a relay actually stores")
        pk = next((root / "relay0" / "pkgs").glob("*.pq2pkg"))
        raw = pk.read_bytes()
        print(f"  package on disk: {len(raw)} bytes for a {len(original)}-byte file (Padme-padded)")
        print(f"  filename visible in stored package? {b'wallet' in raw}   "
              f"sender name visible? {b'alice' in raw}")

        title("Tamper test: flip 1 byte of the stored ciphertext")
        blob = bytearray(raw); blob[len(blob) // 2] ^= 1
        pk.write_bytes(bytes(blob))
        try:
            run("receive", "t30.ticket.json", "--id", "bob.id", "--outdir", "inbox2")
            raise AssertionError("tampering NOT detected!")
        except PQFSError as e:
            print(f"  -> rejected as expected: {e}")
        pk.write_bytes(raw)
        assert not list((root / "inbox2").glob("*")) if (root / "inbox2").exists() else True

        title("Feature 2: the tool refuses a topology where one relay could hold t shares")
        try:
            run("send", "wallet-backup.key", "--id", "alice.id",
                "--to", "bob.pub", "--relay", addrs[0], "--tier", "T2", "--out", "weak.ticket.json")
            raise AssertionError("weak topology was NOT refused!")
        except PQFSError as e:
            print(f"  -> refused: {str(e)[:150]}...")

        title("Feature 3+4: crypto-agility. HQC-192 gets 'broken' -> audit -> auto rewrap")
        run("send", "wallet-backup.key", "--id", "alice.id", "--to", "alice.pub", *rel,
            "--years", 5, "--out", "t5.ticket.json", "--tier", "T2")
        run("deprecate", "HQC-192")
        run("audit", "--tickets", ".", "--id", "alice.id", "--fix")
        run("audit", "--tickets", ".", "--id", "alice.id")
        run("deprecate", "HQC-192", "--undo")

        title("Feature 3: rollback/downgrade attack - malicious relays hide the newer key-wrap epoch")
        pkgid = load_json(root / "t5.ticket.json")["pkg"]
        hidden = {}
        for f in root.glob(f"relay*/slots/{pkgid}/000002-*.json"):
            hidden[f] = f.read_bytes(); f.unlink()
        try:
            run("receive", "t5.ticket.json", "--id", "alice.id", "--outdir", "inbox4")
            raise AssertionError("rollback was NOT detected!")
        except PQFSError as e:
            print(f"  -> rejected: {str(e)[:150]}...")
        for f, b in hidden.items():
            f.write_bytes(b)

        title("Feature 5: threshold decryption. 2-of-3 custodians (bob, carol, dave)")
        (root / "board-minutes.txt").write_bytes(b"merger terms: confidential\n" * 500)
        run("trust", "bob.pub")
        run("send", "board-minutes.txt", "--id", "alice.id", "--to", "bob.pub", "--to", "carol.pub",
            "--to", "dave.pub", *rel, "--threshold", 2, "--years", 3, "--out", "tb.ticket.json")
        try:
            run("receive", "tb.ticket.json", "--id", "bob.id", "--outdir", "inbox3")
        except PQFSError as e:
            print(f"  -> bob alone cannot open it: {str(e)[:110]}...")
        run("approve", "tb.ticket.json", "--id", "carol.id", "--for", "bob.pub", "--out", "carol.rel")
        run("receive", "tb.ticket.json", "--id", "bob.id", "--release", "carol.rel", "--outdir", "inbox3")

        title("Feature 5: append-only log monitor (consistency proofs)")
        run("monitor", "--relay", addrs[0])
        run("receive", "t30.ticket.json", "--id", "bob.id", "--outdir", "inbox")
        run("monitor", "--relay", addrs[0])
        print("\nDEMO COMPLETE: all checks passed.")
    finally:
        os.chdir(cwd)
        for r in relays:
            r.stop()
        if not a.keep:
            shutil.rmtree(root, ignore_errors=True)
        else:
            print(f"demo files kept in {root}")


# ==================================================================== parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=f"PQFS {VERSION} - post-quantum file sharing")
    sp = p.add_subparsers(dest="cmd", required=True)

    def add(name, func, help_):
        s = sp.add_parser(name, help=help_)
        s.set_defaults(func=func)
        return s

    add("info", cmd_info, "show algorithm availability")
    add("selftest", cmd_selftest, "run unit tests")
    s = add("demo", cmd_demo, "end-to-end demo on localhost"); s.add_argument("--keep", action="store_true")
    s = add("keygen", cmd_keygen, "create an identity (NAME.id + NAME.pub)")
    s.add_argument("name"); s.add_argument("--outdir", default="."); s.add_argument("--force", action="store_true")
    s = add("trust", cmd_trust, "trust sender public bundles"); s.add_argument("files", nargs="+")
    s = add("deprecate", cmd_deprecate, "mark a KEM as broken (drives auto-upgrade)")
    s.add_argument("alg", nargs="?"); s.add_argument("--undo", action="store_true")
    s.add_argument("--list", action="store_true")
    s = add("assess", cmd_assess, "policy engine dry run")
    s.add_argument("file"); s.add_argument("--years", type=float, default=1.0)
    s = add("relay", cmd_relay, "run a relay + transparency-log node")
    s.add_argument("--host", default="0.0.0.0"); s.add_argument("--port", type=int, default=DEFAULT_PORT)
    s.add_argument("--store", default="./relay-store"); s.add_argument("--max-size-mb", type=int, default=2048)
    s = add("send", cmd_send, "encrypt + upload a file")
    s.add_argument("file"); s.add_argument("--id", required=True)
    s.add_argument("--to", action="append", required=True, help="recipient/custodian .pub (repeatable)")
    s.add_argument("--relay", action="append", help="host:port (repeatable)")
    s.add_argument("--years", type=float, default=1.0, help="how long it must stay secret")
    s.add_argument("--tier", choices=TIER_ORDER); s.add_argument("--threshold", type=int)
    s.add_argument("--shares", type=int); s.add_argument("--replicate", action="store_true")
    s.add_argument("--allow-weak-topology", action="store_true"); s.add_argument("--out")
    s = add("receive", cmd_receive, "download + decrypt a file")
    s.add_argument("ticket"); s.add_argument("--id", required=True); s.add_argument("--outdir", default=".")
    s.add_argument("--release", action="append"); s.add_argument("--min-tier", choices=TIER_ORDER)
    s.add_argument("--allow-unknown-sender", action="store_true")
    s.add_argument("--allow-rollback", action="store_true"); s.add_argument("--allow-deprecated", action="store_true")
    s = add("approve", cmd_approve, "custodian: release your share to a combiner")
    s.add_argument("ticket"); s.add_argument("--id", required=True)
    s.add_argument("--for", dest="for_", required=True, help="combiner's .pub"); s.add_argument("--out", required=True)
    s = add("rewrap", cmd_rewrap, "re-issue the key-wrap under the current policy (file untouched)")
    s.add_argument("ticket"); s.add_argument("--id", required=True); s.add_argument("--to", action="append")
    s.add_argument("--relay", action="append"); s.add_argument("--tier", choices=TIER_ORDER)
    s.add_argument("--years", type=float); s.add_argument("--threshold", type=int)
    s.add_argument("--release", action="append"); s.add_argument("--allow-weak-topology", action="store_true")
    s = add("audit", cmd_audit, "check tickets against policy / deprecations")
    s.add_argument("--tickets", default="."); s.add_argument("--id"); s.add_argument("--fix", action="store_true")
    s.add_argument("--max-age-days", type=int, default=0); s.add_argument("--allow-weak-topology", action="store_true")
    s = add("verify-receipt", cmd_verify_receipt, "verify log receipts offline"); s.add_argument("file")
    s = add("monitor", cmd_monitor, "check a relay's log is append-only"); s.add_argument("--relay", required=True)
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "audit" and args.fix and not args.id:
            raise PQFSError("--fix needs --id")
        if args.cmd == "deprecate" and not (args.list or args.alg):
            raise PQFSError("give an algorithm name or --list")
        args.func(args)
    except PQFSError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except (ConnectionError, OSError) as e:
        print(f"[ERROR] network/file problem: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
