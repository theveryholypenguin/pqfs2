"""Benchmarks for PQFS 2.0 (run: python bench.py). Writes results/bench.json"""
import json, os, sys, time, tempfile, statistics as st
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main as m

def timeit(f, n):
    ts = []
    for _ in range(n):
        t = time.perf_counter(); f(); ts.append((time.perf_counter() - t) * 1000)
    return round(st.mean(ts), 3)

out = {}
# 1. KEM primitives
kem = {}
for k in ["X25519", "ML-KEM-768", "ML-KEM-1024", "HQC-192", "HQC-256"]:
    pk, sk = m.kem_generate(k); ct, ss = m.kem_encaps(k, pk)
    kem[k] = {"pk_B": len(pk), "ct_B": len(ct),
              "keygen_ms": timeit(lambda: m.kem_generate(k), 20),
              "encaps_ms": timeit(lambda: m.kem_encaps(k, pk), 20),
              "decaps_ms": timeit(lambda: m.kem_decaps(k, sk, ct), 20)}
out["kem"] = kem
# 2. signatures
sig = {}
for s in ["ed25519", "ML-DSA-65", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s"]:
    if s != "ed25519" and not m.have("sig", s): continue
    pk, sk = m.sig_generate(s); sg = m.sig_sign(s, sk, b"x" * 256)
    n = 3 if "SLH" in s else 20
    sig[s] = {"pk_B": len(pk), "sig_B": len(sg),
              "sign_ms": timeit(lambda: m.sig_sign(s, sk, b"x" * 256), n),
              "verify_ms": timeit(lambda: m.sig_verify(s, pk, b"x" * 256, sg), n)}
out["sig"] = sig
# 3. hybrid KEM per tier
ident = m.new_identity("b")
tiers = {}
for t, v in m.TIERS.items():
    cts, key = m.hybrid_encaps(ident["public"], v["kems"], b"c")
    tiers[t] = {"suite": v["kems"], "n": v["n"], "t": v["t"],
                "ct_bytes": sum(len(m.b64d(c)) for c in cts.values()),
                "encaps_ms": timeit(lambda: m.hybrid_encaps(ident["public"], v["kems"], b"c"), 10),
                "decaps_ms": timeit(lambda: m.hybrid_decaps(ident["secret"], ident["public"], v["kems"], cts, b"c"), 10)}
out["tiers"] = tiers
# 4. file throughput + padding overhead
tp = []
for mb in [0.01, 0.1, 1, 10, 50]:
    size = int(mb * 1024 * 1024)
    d = tempfile.mkdtemp(); src = os.path.join(d, "f.bin"); open(src, "wb").write(os.urandom(size))
    dek = os.urandom(32); pkg = os.urandom(16).hex()
    desc = m.make_desc(pkg, 1, "T2", m.TIERS["T2"]["kems"], 3, 2, 5)
    po = os.path.join(d, "p.pkg")
    t0 = time.perf_counter(); info = m.build_package(src, po, dek, pkg, ident, "T2", 5, desc, progress=False)
    enc = time.perf_counter() - t0
    class S:
        def __init__(s, p): s.b = open(p, "rb").read(); s.size = len(s.b)
        def read(s, o, n): return s.b[o:o + n]
    s = S(po); pf = m.parse_pkg(s); meta = m.open_trailer(dek, pf)
    import io, contextlib
    buf = io.BytesIO()
    t0 = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        m.decrypt_body(s, pf, dek, meta["manifest"], buf)
    dec = time.perf_counter() - t0
    assert buf.getvalue() == open(src, "rb").read()
    tp.append({"size_B": size, "pkg_B": s.size, "overhead_pct": round((s.size - size) / size * 100, 2),
               "encrypt_s": round(enc, 3), "decrypt_s": round(dec, 3),
               "enc_MBps": round(size / 2**20 / enc, 1), "dec_MBps": round(size / 2**20 / dec, 1)})
out["throughput"] = tp
# 5. Shamir
sh = {}
for n, t in [(3, 2), (5, 3), (10, 6), (32, 16)]:
    sec = os.urandom(32); shs = m.shamir_split(sec, n, t)
    sh[f"{t}-of-{n}"] = {"split_ms": timeit(lambda: m.shamir_split(sec, n, t), 20),
                         "combine_ms": timeit(lambda: m.shamir_combine(shs[:t]), 20)}
out["shamir"] = sh
# 6. Merkle
mk = {}
for N in [16, 256, 4096]:
    leaves = [m.leaf_hash(str(i).encode()) for i in range(N)]
    mk[N] = {"proof_len": len(m.audit_path(N // 2, leaves)), "proof_B": 32 * len(m.audit_path(N // 2, leaves)),
             "root_ms": timeit(lambda: m.mth(leaves), 3), "cons_len": len(m.consistency_proof(N // 2, leaves))}
out["merkle"] = mk
# 7. end-to-end slot size
cts, key = m.hybrid_encaps(ident["public"], m.TIERS["T3"]["kems"], b"c")
out["slot_json_bytes_T3"] = len(m.cj(m.wrap_slot(ident["public"], m.make_desc("a" * 32, 1, "T3", m.TIERS["T3"]["kems"], 5, 3, 30), 0, 1, os.urandom(32))))
# 8. Padme
out["padme"] = [{"len": L, "padded": m.padme(L), "pct": round((m.padme(L) - L) / L * 100, 2)} for L in [4097, 10000, 100000, 1300055, 10**7, 10**8]]
os.makedirs("results", exist_ok=True)
json.dump(out, open("results/bench.json", "w"), indent=1)
print(json.dumps(out, indent=1))
