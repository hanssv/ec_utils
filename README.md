ec_utils
========

A pure Erlang library containing elliptic curve cryptography utilities for
**Ed25519** and **secp256k1**.

This library is intended for learning, experimentation, and as a portable
pure-Erlang fallback when native C/Rust NIFs (such as `libsodium`/`enacl` or
native `secp256k1` bindings) are unavailable.

Build & Verification
--------------------

```sh
# Compile
$ rebar3 compile

# EUnit test suite
$ rebar3 eunit

# Dialyzer static analysis
$ rebar3 dialyzer

# QuickCheck property-based testing
$ rebar3 as test eqc
```

### Type Checking (eqWAlizer)

Type specifications across all source modules are validated using [eqWAlizer](https://github.com/whatsapp/eqwalizer) via the [Erlang Language Platform (ELP)](https://github.com/whatsapp/erlang-language-platform):

```sh
# Type-check all source modules
$ elp eqwalize-all --as default

# Or using mise
$ mise run eqwalize

# Or type-check a specific module
$ elp eqwalize ecu_secp256k1
```

Quick Start
-----------

### Ed25519 & Batch Verification

```erlang
%% Keypair generation, signing, and detached verification
{SecretKey, PublicKey} = ecu_eddsa:sign_keypair(),
Signature = ecu_eddsa:sign_detached(<<"Hello, world!">>, SecretKey),
true = ecu_eddsa:sign_verify_detached(Signature, <<"Hello, world!">>, PublicKey).

%% Batch verification of multiple signatures in a single pass (RFC 8032 §5.1.7)
Items = [
    {Sig1, Msg1, PK1},
    {Sig2, Msg2, PK2},
    {Sig3, Msg3, PK3}
],
true = ecu_eddsa:sign_verify_batch(Items).
```

### BIP-340 Schnorr Signatures (Bitcoin Taproot)

```erlang
%% Generate keypair with 32-byte x-only public key
{SecretKey, PublicKey} = ecu_schnorr:sign_keypair(),
Msg = <<"Bitcoin Taproot transaction">>,

%% Sign and verify 64-byte signature
Signature = ecu_schnorr:sign(SecretKey, Msg),
true = ecu_schnorr:verify(Signature, Msg, PublicKey).
```

### FROST Threshold Signatures (RFC 9591 & BIP-340)

```erlang
%% Trusted dealer keygen for a 2-of-3 BIP-340 threshold group
{Shares, GroupPK, _VSS} = ecu_frost:trusted_dealer_keygen(bip340, 2, 3),
Msg = <<"Threshold signed payload">>,

%% Round 1: Any 2 participants commit nonces
[{1, S1}, {2, S2} | _] = Shares,
{N1, {HC1, BC1}} = ecu_frost:commit(bip340, S1),
{N2, {HC2, BC2}} = ecu_frost:commit(bip340, S2),
Commitments = [{1, HC1, BC1}, {2, HC2, BC2}],

%% Round 2: Participants compute partial signature shares
Z1 = ecu_frost:sign(bip340, 1, S1, GroupPK, N1, Msg, Commitments),
Z2 = ecu_frost:sign(bip340, 2, S2, GroupPK, N2, Msg, Commitments),

%% Aggregate shares into a standard 64-byte BIP-340 Taproot signature
Signature = ecu_frost:aggregate(bip340, Commitments, Msg, GroupPK, [Z1, Z2]),
true = ecu_schnorr:verify(Signature, Msg, GroupPK).
```

Supported Curves & API
----------------------

### Ed25519 / EdDSA

- `ecu_eddsa`: High-level Ed25519 digital signature API matching standard
  `libsodium` conventions:
  - `sign_keypair/0`: Generate a fresh `{secret, public}` keypair.
  - `sign_keypair_from_seed/1`: Deterministically derive a keypair from a
    32-byte seed.
  - `sign/2`, `sign_open/2`: Create and open combined signed messages.
  - `sign_detached/2`, `sign_verify_detached/3`: Create and verify detached
    signatures.
  - `sign_verify_batch/1`: Batch signature verification verifying a list of
    `{Sig, Msg, PK}` tuples in a single pass (RFC 8032 §5.1.7).
- `ecu_ed25519`: Curve point arithmetic and group operations using extended
  homogeneous coordinates (`{X, Y, Z, T}`):
  - Point addition (`p_add/2`), subtraction (`p_sub/2`), doubling (`p_dbl/1`),
    and negation (`p_neg/1`).
  - Base-point scalar multiplication (`scalar_mul_base/1`,
    `scalar_mul_base_noclamp/1`) using a precomputed comb table.
  - Variable-base scalar multiplication (`scalar_mul/2`, `scalar_mul_noclamp/2`)
    using a fixed 4-bit window method.
  - Dual-scalar multiplication (`scalar_mul_dual_base/3`) for verification.
  - Multi-scalar multiplication (`multi_scalar_mul/1`) using interleaved windowed
    Straus accumulation for accelerated batch operations.
  - Point compression (`compress/1`) and decompression (`decompress/1`) with
    canonical encoding checks and small-order point detection
    (`is_small_order/1`).

### secp256k1 / ECDSA

- `ecu_ecdsa`: ECDSA key derivation, signing, and verification on secp256k1:
  - `private_to_public/2`: Derive compressed public key from a private key with
    strict range checking (`1 <= Priv < N`).
  - `sign/3`: Sign message hash with a private key.
  - `verify/4`: Verify signature against message hash and public key.
- `ecu_secp256k1`: Curve arithmetic in prime field `P` and group order `N`:
  - Point operations internally accelerated using Jacobian coordinates
    (`{X, Y, Z}` with `x = X/Z^2, y = Y/Z^3`).
  - Scalar multiplication (`scalar_mul/2`, `scalar_mul_base/1`).
  - Double-scalar multiplication (`scalar_mul_dual/4`) using Shamir's trick.
  - Compressed point encoding (`compress/1`, `decompress/1`).
- `ecu_crypto`: High-level cryptocurrency utilities:
  - Ethereum message signing and address recovery (`eth_msg_sign/2`,
    `eth_msg_recover/2`, `ec_recover/2`).
  - Bitcoin address derivation (`private_to_short/2`).

### secp256k1 / BIP-340 Schnorr (Bitcoin Taproot)

- `ecu_schnorr`: Complete BIP-340 64-byte Schnorr signature implementation:
  - `sign_keypair/0`: Generate a fresh `{secret, public}` keypair with 32-byte $x$-only public key.
  - `sign_keypair_from_secret/1`: Derive 32-byte $x$-only public key from a 32-byte secret key (negating the scalar if $Y$ is odd).
  - `sign/2`, `sign/3`: Sign arbitrary-length message with deterministic or auxiliary randomness.
  - `verify/3`: Verify 64-byte signature against message and 32-byte $x$-only public key.
  - `lift_x/1`: Lift 32-byte $X$ coordinate to secp256k1 curve point with even $Y$.
  - `tagged_hash/2`: Compute BIP-340 tagged hashes (`BIP0340/challenge`, `BIP0340/aux`, `BIP0340/nonce`).

### FROST Threshold Signatures (RFC 9591 & BIP-340)

- `ecu_frost`: Two-round FROST threshold signature scheme supporting ciphersuites:
  - `ed25519`: `FROST(Ed25519, SHA-512)` (default) producing standard 64-byte Ed25519 signatures.
  - `secp256k1`: `FROST(secp256k1, SHA-256)` using RFC 9380 `expand_message_xmd` producing 65-byte signatures ($R \parallel z$).
  - `bip340`: BIP-340 Schnorr threshold signatures on secp256k1 producing 64-byte $x$-only signatures ($r \parallel s$) with tagged hashes, verified via `ecu_schnorr:verify/3`.
  - API functions accept an optional `ciphersuite()` prefix (`ed25519 | secp256k1 | bip340`), defaulting to `ed25519`:
    - `commit/1,2`: Round 1 preprocessing — generate hiding & binding nonces and commitments.
    - `sign/6,7`: Round 2 signing — compute partial signature share $z_i$ bound to group public key and message.
    - `verify_signature_share/7,8`: Coordinator verification of individual signature shares.
    - `aggregate/4,5`: Aggregate threshold signature shares into a group signature.
    - `verify/3,4`: Verify aggregated FROST signatures (detached Ed25519, secp256k1 prime-order verify, or BIP-340).
    - `trusted_dealer_keygen/2,3,4`: Trusted dealer key generation ($t$-of-$n$) with Feldman VSS commitments.
    - `vss_verify/3,4`: Verifiable Secret Sharing share verification.
    - `secret_share_combine/1,2`: Lagrange polynomial secret reconstruction from $t$ shares.
- `ecu_frost_dkg`: Two-round Distributed Key Generation (DKG):
  - `round1/3,4`, `round1_check/4,5`: Coefficient commitment and zero-knowledge Proof of Knowledge (PoK).
  - `round2/2,3`, `round2_check/3,4`: Share distribution and verification against public commitments.
  - `compute_private_sign_share/1,2,3`, `compute_public_verification_share/1,2,3`, `compute_public_key/1,2`: Joint key derivation.

Performance & Benchmarks
------------------------

Pure Erlang bignum arithmetic cannot match native assembly or C/Rust NIFs, but
the library incorporates key algorithmic optimizations:

1. **Jacobian projective coordinates (secp256k1):** Doubling and mixed additions
   require zero modular inversions; a single field inversion is computed at the
   end of scalar multiplication.
2. **Precomputed comb table (Ed25519 & secp256k1):** Base-point scalar multiplication uses a
   precomputed table of 1,024 points stored in `persistent_term` (loaded via
   `-on_load`), taking at most 64 additions and 0 doublings.
3. **Fixed 4-bit window (Ed25519):** Variable-base scalar multiplication
   processes nibbles left-to-right with binary pattern matching, cutting additions
   roughly in half.
4. **Shamir's trick / Straus double-scalar multiplication:** Verification and
   address recovery interleave two scalar multiplications into a single doubling
   chain, eliminating process spawning and message passing overhead.

### Measured Performance (`rebar3 eunit -m benchmark_tests`, Apple Silicon)

| Operation | Baseline | Optimized | Speedup | Reference (Native NIF) | vs Reference |
|:---|---:|---:|---:|---:|---:|
| **secp256k1 scalar mul base** | 5,377 µs | **166 µs** | **~32×** | — | — |
| **secp256k1 eth_recover** | 7,810 µs | **893 µs** | **~8.7×** | 54.1 µs (Rust NIF) | 16.5× |
| **secp256k1 bip340 sign** | — | **370 µs** | — | — | — |
| **secp256k1 bip340 verify** | — | **996 µs** | — | — | — |
| **ed25519 scalar mul base** | 746 µs | **122 µs** | **~6.1×** | 14.9 µs (enacl) | 8.2× |
| **ed25519 scalar mul** | 741 µs | **614 µs** | **~1.2×** | 71.8 µs (enacl) | 8.6× |
| **ed25519 sign** | 739 µs | **272 µs** | **~2.7×** | 16.1 µs (enacl) | 16.9× |
| **ed25519 verify** | 1,496 µs | **769 µs** | **~1.9×** | 44.2 µs (enacl) | 17.4× |
| **ed25519 verify (batch of 32)** | 846 µs/sig | **368 µs/sig** | **~2.3×** | — | — |
| **ed25519 point add** | 1.9 µs | **2.3 µs** | ~1.0× | 12.6 µs (enacl) | **5.6× faster** |
| **frost ed25519 commit** | — | **329 µs** | — | — | — |
| **frost ed25519 part sign** | — | **2.12 ms** | — | — | — |
| **frost ed25519 aggregate** | — | **2.32 ms** | — | — | — |
| **frost ed25519 verify** | — | **929 µs** | — | — | — |
| **frost secp256k1 commit** | — | **331 µs** | — | — | — |
| **frost secp256k1 part sign** | — | **2.50 ms** | — | — | — |
| **frost secp256k1 aggregate** | — | **2.64 ms** | — | — | — |
| **frost secp256k1 verify** | — | **1.02 ms** | — | — | — |
| **frost bip340 commit** | — | **351 µs** | — | — | — |
| **frost bip340 part sign** | — | **2.52 ms** | — | — | — |
| **frost bip340 aggregate** | — | **2.59 ms** | — | — | — |
| **frost bip340 verify** | — | **1.02 ms** | — | — | — |

*Note: Pure Erlang point addition is faster than `enacl` because calling the NIF
incurs marshalling and point decompression overhead.*

Roadmap
-------

See [ROADMAP.md](ROADMAP.md) for details on completed milestones and planned cryptographic extensions, including:
- **Diffie-Hellman Key Exchange (X25519 / RFC 7748)**: Pure-Erlang Montgomery ladder on Curve25519.
- **Ed448 Goldilocks Curve (RFC 8032 & RFC 7748)**: 448-bit Edwards curve arithmetic and SHAKE256.
- **Pairing-Friendly Cryptography (BLS12-381)**: Primitives for threshold BLS signatures and ZK-SNARK verifiers.

Security Considerations & Limitations
-------------------------------------

> **Warning: Not Constant-Time**
>
> All arithmetic in this library is implemented in pure Erlang on top of the
> BEAM virtual machine. Point operations and scalar multiplications branch on
> secret scalar bits, and BEAM bignum operations take time that depends on the
> magnitude and values of operands.
>
> **Do NOT use this library for signing with high-value secret keys in environments
> where an attacker can observe precise execution timing or side-channels.**
> In production environments handling sensitive private keys, use constant-time
> native implementations (such as `enacl` / `libsodium` or native `secp256k1`
> NIFs).
