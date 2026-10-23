# ec_utils Roadmap

This document outlines planned enhancements, cryptographic extensions, and architectural improvements for `ec_utils`.

---

## 1. Batch Signature Verification (Ed25519)

- **Standard**: [RFC 8032 §5.1.7](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.7) / libsodium batch verification.
- **Goal**: Verify a batch of $M$ independent Ed25519 signatures simultaneously in a single multi-scalar multiplication rather than checking each signature individually.
- **Mechanism**:
  Sample independent 128-bit random weights $z_1, \dots, z_M$ and verify the joint linear relation:
  $$\left(-\sum_{i=1}^M z_i s_i \pmod L\right) \cdot B + \sum_{i=1}^M z_i \cdot R_i + \sum_{i=1}^M (z_i k_i \pmod L) \cdot A_i = 0$$
- **Algorithm**: Multi-scalar accumulation (Bos-Coster / Pippenger algorithm).
- **Expected Speedup**: ~2× to 3× higher throughput when verifying batches of 8–64 signatures.

---

## 2. BIP-340 Schnorr Signatures (secp256k1 / Bitcoin Taproot)

- **Standard**: [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) (64-byte Schnorr signatures for secp256k1).
- **Goal**: Support modern Bitcoin Taproot signatures alongside ECDSA.
- **Features**:
  - 32-byte $x$-only public keys (eliminating point decompression ambiguity).
  - Provably secure, non-malleable 64-byte $(r, s)$ signatures.
  - Tagged SHA-256 hashes (`BIP0340/challenge`, `BIP0340/aux`, `BIP0340/nonce`).
  - Foundation for multi-signatures (MuSig) and batch verification on secp256k1.

---

## 3. Diffie-Hellman Key Exchange (X25519 / RFC 7748)

- **Standard**: [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) (Curve25519 ECDH).
- **Goal**: Enable pure-Erlang key agreement and shared secret derivation.
- **Features**:
  - Point conversion between Ed25519 (twisted Edwards) and Curve25519 (Montgomery) via birational equivalence:
    $$u = \frac{1 + y}{1 - y}$$
  - Montgomery ladder scalar multiplication on the $u$-coordinate (constant number of field operations).
  - Interoperability with standard Curve25519 implementations (`enacl:box`, OpenSSL, and `crypto:compute_key`).

---

## 4. Side-Channel & Timing Mitigation (Exploratory)

While pure Erlang bignum arithmetic on the BEAM is fundamentally variable-time (reliant on runtime bignum routines), high-level algorithmic timing variances can be mitigated for defense-in-depth:
- **Branch-Free Scalar Loops**: Use uniform Montgomery ladder steps for scalar multiplication so the sequence of point operations is identical regardless of scalar bit values.
- **Constant-Time Table Lookups**: Replace secret-indexed tuple lookups (`element(W + 1, Table)`) with branchless bitwise selection across table entries.
- **Scalar & Coordinate Blinding**: Randomize Jacobian/projective coordinates ($(X \cdot r^2, Y \cdot r^3, Z \cdot r)$) and blind secret scalars ($k' = k + r \cdot N$) during signing to decorrelate execution timing from secret keys.

---

## 5. Packaging & Publishing Readiness

- **Hex.pm Packaging**: Metadata validation in `src/ec_utils.app.src` for publishing to Hex.pm.
- **Documentation**: Integration with `rebar3 ex_doc` for generating HexDocs.
- **Benchmarking CLI**: A lightweight escript or task for running and reporting automated performance regressions.
