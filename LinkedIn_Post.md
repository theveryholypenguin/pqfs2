# LinkedIn post (copy-paste) - attach the A3 poster image/PDF

Repo link is already filled in below. Attach the poster, tag Dr. Reema Roychaudhary and SAII, then post. Keep the post URL handy to show the evaluator.

---

**Your encrypted files are being collected today so a quantum computer can read them tomorrow.** 🔐

For our Mini Project we built **PQFS 2.0, a Post-Quantum File Sharing System**, to answer one question: what if the cryptography protecting a file breaks, or some of the servers storing it are hostile?

**What it does**
🔸 **Hybrid key exchange across 3 independent math families**: X25519 + ML-KEM (lattice, NIST FIPS 203) + HQC (code-based). An attacker has to break all of them.
🔸 **Multipath secret sharing**: the file key is split with Shamir's scheme across several relay servers. Fewer than t servers learn nothing about the key, even with unlimited computing power.
🔸 **Crypto-agility**: if an algorithm is retired, one command re-wraps the key. The file is never re-encrypted.
🔸 **Shelf-life policy engine**: tell it how many years a secret must live, and it chooses the security tier and explains why.
🔸 **Threshold custody + transparency logs**: t-of-n people must approve to open a file; relays keep signed, append-only Merkle logs.
🔸 **Metadata privacy**: file name, sender and exact size are hidden from the servers.

**What we measured**
✅ 24/24 unit tests and a 12-scenario end-to-end demo pass (tampered byte rejected, rollback attack caught, 2-of-3 approval enforced)
✅ ~150-186 MiB/s streaming encryption on one CPU core
✅ Post-quantum key wrapping costs only milliseconds per key share

**What we learned**: post-quantum security is not "swap one algorithm". It is layered design, honest threat modelling and planning for the day an algorithm is retired. We also documented the limits: this is an educational prototype, not audited.

💻 Code: https://github.com/theveryholypenguin/pqfs2
📄 Full report and poster in the repo.

Thank you to our faculty for the guidance, and to the Open Quantum Safe project (liboqs) for the post-quantum implementations.

#PostQuantumCryptography #Cybersecurity #Cryptography #QuantumComputing #NIST #MLKEM #InformationSecurity #Python #OpenSource #MiniProject #Engineering

---

## Short version (if you want fewer words)

Built **PQFS 2.0**, a post-quantum file-sharing system: hybrid X25519 + ML-KEM + HQC key exchange, Shamir key splitting across relay servers, one-command algorithm upgrades without re-encrypting, and signed transparency logs. 24/24 tests pass. Code: https://github.com/theveryholypenguin/pqfs2 #PostQuantumCryptography #Cybersecurity #Python

## Poster description (alt text / caption under the image)

PQFS 2.0 poster: system architecture (sender, three relays, recipient), the six upgrades, security tiers T1-T3 and measured results.
