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

## 2. BIP-340 Schnorr Signatures (secp256k1 / Bitcoin Taproot) `[Completed]`

- **Standard**: [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) (64-byte Schnorr signatures for secp256k1).
- **Implementation**:
  - `ecu_schnorr`: Complete BIP-340 implementation (`sign_keypair/0`, `sign/2,3`, `verify/3`, `lift_x/1`, `tagged_hash/2`).
  - Tested against all 19 official [BIP-340 CSV test vectors](https://raw.githubusercontent.com/bitcoin/bips/master/bip-0340/test-vectors.csv).
- **Features**:
  - 32-byte $x$-only public keys (eliminating point decompression ambiguity).
  - Provably secure, non-malleable 64-byte $(r, s)$ signatures.
  - Tagged SHA-256 hashes (`BIP0340/challenge`, `BIP0340/aux`, `BIP0340/nonce`).
  - Foundation for multi-signatures (MuSig) and FROST threshold signatures on secp256k1.

---

## 3. FROST: Flexible Round-Optimized Schnorr Threshold Signatures (RFC 9591 & BIP-340) `[Completed for Ed25519, secp256k1, and Ed448]`

- **Standard**: [RFC 9591](https://datatracker.ietf.org/doc/html/rfc9591) / Komlo & Goldberg (2020) & [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
- **Goal**: Implement threshold multi-party signing ($t$-of-$n$) where any threshold subset of participants cooperatively produces standard Schnorr signatures indistinguishable from a single signer.
- **Ciphersuites**:
  - **Stage 1: `FROST(Ed25519, SHA-512)` `[Completed]`**: Produces standard 64-byte Ed25519 signatures verifiable with `ecu_eddsa`.
  - **Stage 2: `FROST(secp256k1, SHA-256)` & `bip340` `[Completed]`**: Produces standard RFC 9591 65-byte signatures and BIP-340 64-byte $x$-only Taproot signatures verifiable with `ecu_schnorr`.
  - **Stage 3: `FROST(Ed448, SHAKE256)` `[Completed]`**: Threshold signing for the Ed448 Goldilocks curve using SHAKE256 XOF, producing standard 114-byte signatures ($R \parallel z$) verifiable with `ecu_eddsa448`.
- **Protocol Features**:
  - Two-Round Signing: Nonce commitment generation (Round 1) and signature share aggregation (Round 2) using binding factors to prevent ROS/forgery attacks.
  - Two-Round Distributed Key Generation (DKG) with Schnorr Proof of Knowledge (PoK) and Feldman verifiable secret sharing (VSS).
  - Validated against official RFC 9591 Appendix E.1, E.2, and E.5 test vectors, plus BIP-340 threshold verification.

---

## 4. Diffie-Hellman Key Exchange (X25519, X448, secp256k1 / RFC 7748) `[Completed]`

- **Standard**: [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) (Curve25519 & Curve448 Diffie-Hellman) and SEC 1 §3.3.1 (secp256k1 ECDH).
- **Goal**: Enable pure-Erlang key agreement and shared secret derivation.
- **Features `[Completed]`**:
  - Point conversion between Ed25519 (twisted Edwards) and Curve25519 (Montgomery) via birational equivalence:
    $$u = \frac{1 + y}{1 - y}$$
  - Montgomery ladder scalar multiplication on the $u$-coordinate (constant number of field operations) for both X25519 and X448.
  - Interoperability with standard Curve25519 and Curve448 implementations (`crypto:compute_key` as an oracle).
  - RFC 7748 Section 6.1 (X25519) and Section 6.2 (X448) test vector compliance (Alice/Bob and 1,000-iteration tests).
  - secp256k1 ECDH with support for compressed, uncompressed, and affine point inputs.

---

## 5. Ed448 / Curve448 (Goldilocks Curve / RFC 7748 & RFC 8032) `[Completed]`

- **Standard**: [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748) (X448 key exchange) and [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) (Ed448 digital signatures).
- **Goal**: High-security (~224-bit security level) elliptic curve cryptography based on the Goldilocks prime $p = 2^{448} - 2^{224} - 1$.
- **Features**:
  - **Ed448 Signatures `[Completed]`**:
    - `ecu_ed448`: Projective Edwards curve arithmetic ($x^2 + y^2 = 1 + d x^2 y^2$, $d = -39081$), comb table base-point scalar multiplication (114 windows), windowed scalar multiplication, dual-base multiplication, and interleaved Straus multi-scalar multiplication (MSM).
    - `ecu_eddsa448`: Complete RFC 8032 Ed448 signing and verification with Keccak SHAKE256 XOF, context string support ($0 \le |C| \le 255$), and batch signature verification.
    - Verified against all RFC 8032 Section 7.4 test vectors and cross-checked against OTP `crypto` as an oracle.
  - **X448 Key Exchange `[Completed]`**: Montgomery ladder over Curve448 for X448 key agreement (`ecu_ecdh:x448/2`, `ecu_ecdh:compute_key/3`).
  - **FROST(Ed448, SHAKE256) `[Completed]`**: Threshold signing for Ed448.

---

## 6. Pure-Erlang Keccak-256 & SHA-3 (Zero External Dependencies)

- **Standard**: Keccak Sponge Function Family / FIPS 202 (SHA-3, SHAKE) & Ethereum Keccak-256.
- **Goal**: Implement pure-Erlang Keccak-f[1600] state permutations to eliminate the `erlang-sha3` C NIF dependency.
- **Features**:
  - `ecu_keccak`: Pure-Erlang Keccak-256 (pad `0x01` / Ethereum format) and NIST SHA3-224/256/384/512 (pad `0x06`).
  - Seamless zero-dependency address recovery in `ecu_crypto:eth_recover/2` and Ethereum signing.
  - Test vectors and differential testing against OTP `crypto` and `erlang-sha3`.

---

## 7. BIP-327: MuSig2 (Simple Two-Round Schnorr Multi-Signatures)

- **Standard**: [BIP-327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) (MuSig2 multi-signatures for BIP-340).
- **Goal**: Enable compact $n$-of-$n$ Schnorr multi-signatures aggregated into standard 64-byte BIP-340 signatures.
- **Features**:
  - Key aggregation algorithm ($\mathrm{KeyAgg}$) with rogue-key attack resistance.
  - Two-round signing protocol with nonces and partial signature aggregation.
  - Interoperability with `ecu_schnorr` and BIP-340 Taproot verifiers.
  - Verification against official BIP-327 test vectors.

---

## 8. Hierarchical Deterministic (HD) Wallets (BIP-32, BIP-44 & SLIP-0010)

- **Standard**: [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), and [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md).
- **Goal**: Pure-Erlang hierarchical deterministic wallet key derivation for secp256k1 and Ed25519.
- **Features**:
  - Extended keys (`xprv`, `xpub`) with Base58Check encoding.
  - Hardened and unhardened child key derivation (`CKDpriv`, `CKDpub`).
  - Standard derivation paths (`m/44'/60'/0'/0/0`, etc.).
  - SLIP-0010 master seed derivation for Ed25519 curves.

---

## 9. Hash-to-Curve (RFC 9380) & Verifiable Random Functions (VRF / RFC 9381)

- **Standard**: [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380) (Hashing to Elliptic Curves) and [RFC 9381](https://datatracker.ietf.org/doc/html/rfc9381) (Verifiable Random Functions).
- **Goal**: Map arbitrary byte strings deterministically to curve points and evaluate verifiable pseudorandom proofs.
- **Features**:
  - Simplified SWU (Shallue-van de Woestijne-Ulas) and Elligator2 point mapping.
  - ECVRF-EDWARDS25519-SHA512-ELL2 and ECVRF-SECP256K1-SHA256 evaluation and verification.

---

## 10. Zero-Knowledge Proofs & Pairing-Friendly Curves (BLS12-381)

- **Standard**: Pairing-friendly elliptic curves; [BLS Signatures RFC draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature); Ethereum / Filecoin / Zcash zk-SNARK primitives.
- **Goal**: Support pairing-based cryptography, short aggregate signatures, and zero-knowledge proof verification.
- **Features**:
  - Arithmetic in $\mathbb{G}_1$ (over $\mathbb{F}_q$) and $\mathbb{G}_2$ (over extension field $\mathbb{F}_{q^2}$) on the BLS12-381 curve.
  - Optimal Ate pairing $e: \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$ over field extension $\mathbb{F}_{q^{12}}$.
  - BLS threshold and aggregate signatures (non-interactive aggregation of $N$ signatures into a single group element).
  - Verifier building blocks for Groth16 / PLONK zk-SNARK proof verification.

---

## 11. Algorithmic Performance Optimizations (Deferred)

- **GLV Endomorphism Decomposition (secp256k1)**: Decomposing 256-bit scalars into 128-bit halves ($k \cdot P = k_1 \cdot P + k_2 \cdot \phi(P)$) to halve doubling chains.
- **wNAF Variable Scalar Multiplication**: Windowed Non-Adjacent Form ($w=4, 5$) to reduce point additions by 33–50%.
- **BIP-340 Batch Verification**: Batch verification of Taproot signatures using 128-bit random weights.

---

## 12. Packaging & Release Readiness

- **Hex.pm Packaging**: Metadata validation in `src/ec_utils.app.src` for publishing to Hex.pm.
- **Documentation**: Integration with `rebar3 ex_doc` for generating HexDocs.
- **Benchmarking CLI**: A lightweight escript or task for running and reporting automated performance regressions.
