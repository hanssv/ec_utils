# ec_utils Roadmap

This document outlines planned enhancements, cryptographic extensions, and architectural improvements for `ec_utils`.

---

## 1. Batch Signature Verification (Ed25519) `[Completed]`

- **Standard**: [RFC 8032 §5.1.7](https://datatracker.ietf.org/doc/html/rfc8032#section-5.1.7) / libsodium batch verification.
- **Implementation**:
  - `ecu_eddsa:sign_verify_batch/1`: Verifies a list of `{Sig, Msg, PK}` tuples in a single pass.
  - `ecu_ed25519:multi_scalar_mul/1`: Interleaved windowed Straus multi-scalar multiplication algorithm sharing group doublings across all batch points.
- **Mechanism**:
  Sample independent 128-bit random weights $z_1, \dots, z_M$ and verify the joint linear relation:
  $$8 \left( \sum_{i=1}^M z_i \cdot R_i + \sum_{i=1}^M (z_i k_i \pmod L) \cdot A_i - \left(\sum_{i=1}^M z_i s_i \pmod L\right) \cdot B \right) = \mathcal{O}$$
- **Measured Speedup**: **~2.3× higher throughput** for batches of 32 signatures (846 µs/sig $\rightarrow$ 368 µs/sig).

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

## 3. FROST: Flexible Round-Optimized Schnorr Threshold Signatures (RFC 9591)

- **Standard**: [RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) / Komlo & Goldberg (2020).
- **Goal**: Implement threshold multi-party signing ($t$-of-$n$) where any threshold subset of participants cooperatively produces standard BIP-340 or Ed25519 Schnorr signatures.
- **Features**:
  - **FROST(secp256k1, SHA-256)**: Produces standard BIP-340 signatures indistinguishable from a single signer.
  - **FROST(Ed25519, SHA-512)**: Produces standard Ed25519 signatures.
  - **Two-Round Signing**: Nonce commitment generation (Round 1) and signature share aggregation (Round 2) using binding factors to prevent ROS/forgery attacks.
  - **Key Generation & Resharing**: Distributed Key Generation (DKG) using Pedersen verifiable secret sharing (VSS) or trusted dealer setup.

---

## 4. Diffie-Hellman Key Exchange (X25519 / RFC 7748)

- **Standard**: [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) (Curve25519 ECDH).
- **Goal**: Enable pure-Erlang key agreement and shared secret derivation.
- **Features**:
  - Point conversion between Ed25519 (twisted Edwards) and Curve25519 (Montgomery) via birational equivalence:
    $$u = \frac{1 + y}{1 - y}$$
  - Montgomery ladder scalar multiplication on the $u$-coordinate (constant number of field operations).
  - Interoperability with standard Curve25519 implementations (`enacl:box`, OpenSSL, and `crypto:compute_key`).

---

## 5. Side-Channel & Timing Mitigation (Exploratory)

While pure Erlang bignum arithmetic on the BEAM is fundamentally variable-time (reliant on runtime bignum routines), high-level algorithmic timing variances can be mitigated for defense-in-depth:
- **Branch-Free Scalar Loops**: Use uniform Montgomery ladder steps for scalar multiplication so the sequence of point operations is identical regardless of scalar bit values.
- **Constant-Time Table Lookups**: Replace secret-indexed tuple lookups (`element(W + 1, Table)`) with branchless bitwise selection across table entries.
- **Scalar & Coordinate Blinding**: Randomize Jacobian/projective coordinates ($(X \cdot r^2, Y \cdot r^3, Z \cdot r)$) and blind secret scalars ($k' = k + r \cdot N$) during signing to decorrelate execution timing from secret keys.

---

## 6. Packaging & Publishing Readiness

- **Hex.pm Packaging**: Metadata validation in `src/ec_utils.app.src` for publishing to Hex.pm.
- **Documentation**: Integration with `rebar3 ex_doc` for generating HexDocs.
- **Benchmarking CLI**: A lightweight escript or task for running and reporting automated performance regressions.
