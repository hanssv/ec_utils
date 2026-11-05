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

## 6. Pure-Erlang Keccak-256 & SHA-3 (Zero External Dependencies) `[Completed]`

- **Standard**: Keccak Sponge Function Family / FIPS 202 (SHA-3, SHAKE) & Ethereum Keccak-256.
- **Goal**: Implement pure-Erlang Keccak-f[1600] state permutations to eliminate the `erlang-sha3` C NIF dependency.
- **Features `[Completed]`**:
  - `ecu_keccak`: Pure-Erlang Keccak-256 (pad `0x01` / Ethereum format), NIST SHA3-224/256/384/512 (pad `0x06`), and SHAKE128/256 XOF.
  - Zero external production dependencies (`{deps, []}` in `rebar.config`).
  - Seamless zero-dependency address recovery in `ecu_crypto:eth_recover/2` and Ethereum signing.
  - Optimized direct binary padding, zero-bignum state pipeline, and fused 4-round permutation achieving ~80.7 µs/op.
  - Test vectors and differential testing against OTP `crypto` and `ecu_rustcrypto_nif`.

---

## 7. BIP-327: MuSig2 (Simple Two-Round Schnorr Multi-Signatures) `[Completed]`

- **Standard**: [BIP-327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki) (MuSig2 multi-signatures for BIP-340) and Ed25519 MuSig2.
- **Goal**: Enable compact $n$-of-$n$ Schnorr multi-signatures aggregated into standard 64-byte BIP-340 or Ed25519 signatures.
- **Features `[Completed]`**:
  - `ecu_musig2`: Pure-Erlang MuSig2 implementation supporting both `bip340` (secp256k1 default) and `ed25519`:
    - `key_agg/1,2`, `key_agg_pubkey/1,2`, `key_agg_coeff/2,3`: Key aggregation with rogue-key attack resistance, second-unique-key handling, and duplicate public key handling.
    - `nonce_gen/0,1,2`: Secure nonce generation (pair of secret/public nonces).
    - `nonce_agg/1,2`: Nonce aggregation into a combined public nonce.
    - `sign_partial/5,6`: Partial signing bound to aggregate key, aggregate nonce, and message.
    - `verify_partial/6,7`: Verification of individual partial signatures prior to aggregation.
    - `aggregate_partial/4,5`: Aggregation of partial signatures into standard 64-byte Schnorr signatures with optional tweak accumulator support.
  - Optional reference NIF `ecu_musig2_nif` wrapping the official Rust `musig2` crate (`make musig2_reference`).
  - Unit tests (`musig2_tests.erl`) and property-based differential tests (`musig2_eqc.erl`) cross-verifying pure Erlang vs Rust `musig2`.


---

## 8. Hierarchical Deterministic (HD) Wallets (BIP-32, BIP-44, SLIP-0010) & BIP-39 `[Completed]`

- **Standard**: [BIP-32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki), [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki), [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md), and [AEX-10](https://github.com/aeternity/AEXs/blob/master/AEXS/aex-10.md).
- **Goal**: Pure-Erlang hierarchical deterministic wallet key derivation and mnemonic seed generation for secp256k1 and Ed25519 with zero external dependencies.
- **Features `[Completed]`**:
  - `ecu_bip39`: Pure-Erlang BIP-39 mnemonic phrase generation, validation, and seed derivation:
    - Mnemonic generation from 128–256 bit entropy or 12–24 words (`generate_mnemonic/1,2`).
    - Bidirectional conversion between entropy and mnemonic phrases (`entropy_to_mnemonic/1,2`, `mnemonic_to_entropy/1,2`).
    - Structure, checksum, and dictionary validation (`validate_mnemonic/1,2`).
    - PBKDF2-HMAC-SHA512 seed derivation (2,048 rounds) with UTF-8 NFKD normalization (`mnemonic_to_seed/1,2`).
    - Direct bridge to HD master key (`mnemonic_to_master_key/2,3`).
  - `ecu_bip39_words`: Embedded official 2,048 English wordlist with $O(1)$ lookups and zero filesystem dependencies.
  - `ecu_base58`: High-performance pure-Erlang Base58 and Base58Check encoding and decoding using Radix-$58^{10}$ chunking (~3.5–3.6 µs/op encode/decode; ~5.5–6.0 µs/op Base58Check).
  - `ecu_hd`: Complete BIP-32 and SLIP-0010 implementation:
    - Master key derivation from seeds (`master_key/2`).
    - Private and public child key derivation (`ckd_priv/2`, `ckd_pub/2`) for secp256k1 (~172 µs/op priv, ~205 µs/op pub).
    - Hardened-only child derivation for Ed25519 per SLIP-0010 (~163 µs/op).
    - Extended key serialization (`xprv`, `xpub`) with Base58Check encoding (`to_base58/1,2`, `from_base58/1`).
    - Flexible derivation paths (`derive_path/2`, `derive_path_from_seed/3`), supporting `m/44'/0'/0'/0/0`, `m/44H/457H/0H`, and `M/0/1`.
    - BIP-44 shortcut (`derive_bip44/5,6`) and Aeternity AEX-10 shortcut (`derive_aex10/3,4`).
  - Unit tests (`hd_tests.erl`, `bip39_tests.erl`) covering official BIP-32 test vectors 1–4, SLIP-0010 vectors, AEX-10 test vectors, and all 24 Trezor BIP-39 test vectors.
  - Property tests (`hd_eqc.erl`, `bip39_eqc.erl`) verifying Base58 round-trips, mnemonic entropy round-trips, tamper resistance, and public vs private derivation equivalence.

---

## 9. Hash-to-Curve (RFC 9380) `[Completed]` & Verifiable Random Functions (VRF / RFC 9381)

- **Standard**: [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380) (Hashing to Elliptic Curves) and [RFC 9381](https://datatracker.ietf.org/doc/html/rfc9381) (Verifiable Random Functions).
- **Goal**: Map arbitrary byte strings deterministically to curve points and evaluate verifiable pseudorandom proofs.
- **Features**:
  - `ecu_h2c` `[Completed]`: Simplified SWU on 3-isogenous curve with rational map (secp256k1), Elligator 2 on Montgomery Curve25519 with cofactor clearing (edwards25519), and Elligator 2 on Montgomery Curve448 with degree-4 isogeny (edwards448).
  - ECVRF-EDWARDS25519-SHA512-ELL2 and ECVRF-SECP256K1-SHA256 evaluation and verification.

---

## 10. Post-Quantum Cryptography: ML-KEM (FIPS 203) & Hybrid Key Exchange `[Completed]`

- **Standard**: [NIST FIPS 203](https://doi.org/10.6028/NIST.FIPS.203) (Module-Lattice-Based Key-Encapsulation Mechanism Standard).
- **Goal**: Provide quantum-resistant key encapsulation and hybrid key exchange on the BEAM with zero native dependencies.
- **Features `[Completed]`**:
  - Full implementation of all three NIST security parameter sets: `ml_kem_512` (Category 1), `ml_kem_768` (Category 3), and `ml_kem_1024` (Category 5).
  - In-place Number Theoretic Transform (NTT), inverse NTT, and Barrett-reduced modular arithmetic modulo $q = 3329$.
  - Centered Binomial Distribution sampling ($\eta_1, \eta_2 \in \{2, 3\}$) and matrix sampling from SHAKE128/SHAKE256 sponge primitives.
  - Fujisaki-Okamoto transform with implicit rejection: corrupted or tampered ciphertexts return a pseudorandom key $J(z \parallel c)$ preventing chosen-ciphertext timing leaks.
  - Hybrid post-quantum key agreement (`x25519_mlkem768` in `ecu_ecdh`) combining classical X25519 ECDH and ML-KEM-768 into a 256-bit dual-secure shared secret.
  - 100% verified against official NIST ACVP intermediate test vectors and differentially tested against OTP 29 `crypto`.

---

## 11. Post-Quantum Digital Signatures: ML-DSA (FIPS 204) `[Completed]`

- **Standard**: [NIST FIPS 204](https://doi.org/10.6028/NIST.FIPS.204) (Module-Lattice-Based Digital Signature Standard).
- **Goal**: Implement pure-Erlang quantum-resistant digital signatures with zero native dependencies in `src/`.
- **Features `[Completed]`**:
  - Full support for all three NIST security parameter sets: `ml_dsa_44` (NIST Category 2), `ml_dsa_65` (NIST Category 3), and `ml_dsa_87` (NIST Category 5).
  - In-place Number Theoretic Transform (NTT), inverse NTT, and modular arithmetic modulo $q = 8{,}380{,}417$ ($\zeta = 1753$).
  - Power-of-two rounding (`power2round`), high/low bit decomposition (`decompose`), and hint generation/usage (`make_hint`, `use_hint`).
  - Uniform polynomial matrix rejection sampling (`expand_a`), bounded error polynomial sampling (`expand_s`), masking polynomial sampling (`expand_mask`), and challenge polynomial sampling (`sample_in_ball`).
  - Bit packing and unpacking for public keys, secret keys, hints, and signatures.
  - Randomized signing (recommended per FIPS 204 §5.3) and deterministic signing with optional user context strings ($0 \le |C| \le 255$).
  - 100% verified against official NIST ACVP test vectors and bidirectional differential testing with OTP 29 `crypto`.

---

## 12. Zero-Knowledge Proofs & Pairing-Friendly Curves (BLS12-381)

- **Standard**: Pairing-friendly elliptic curves; [BLS Signatures RFC draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature); Ethereum / Filecoin / Zcash zk-SNARK primitives.
- **Goal**: Support pairing-based cryptography, short aggregate signatures, and zero-knowledge proof verification.
- **Features**:
  - Arithmetic in $\mathbb{G}_1$ (over $\mathbb{F}_q$) and $\mathbb{G}_2$ (over extension field $\mathbb{F}_{q^2}$) on the BLS12-381 curve.
  - Optimal Ate pairing $e: \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$ over field extension $\mathbb{F}_{q^{12}}$.
  - BLS threshold and aggregate signatures (non-interactive aggregation of $N$ signatures into a single group element).
  - Verifier building blocks for Groth16 / PLONK zk-SNARK proof verification.

---

## 13. Algorithmic Performance Optimizations (Deferred)

- **GLV Endomorphism Decomposition (secp256k1)**: Decomposing 256-bit scalars into 128-bit halves ($k \cdot P = k_1 \cdot P + k_2 \cdot \phi(P)$) to halve doubling chains.
- **wNAF Variable Scalar Multiplication**: Windowed Non-Adjacent Form ($w=4, 5$) to reduce point additions by 33–50%.
- **BIP-340 Batch Verification**: Batch verification of Taproot signatures using 128-bit random weights.

---

## 14. Packaging & Release Readiness

- **Hex.pm Packaging**: Metadata validation in `src/ec_utils.app.src` for publishing to Hex.pm.
- **Documentation**: Integration with `rebar3 ex_doc` for generating HexDocs.
- **Benchmarking CLI `[Completed]`**: Standalone escript (`bin/bench`) and Makefile targets (`make bench`, `make bench-save`, `make bench-compare`) supporting calibrated execution, statistical percentiles (mean, median, p95), JSON export, Markdown tables, and automated regression detection.
