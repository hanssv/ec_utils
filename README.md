ec_utils
========

A pure Erlang library containing elliptic curve cryptography utilities for
**Ed25519** and **secp256k1**.

This library is intended for learning, experimentation, and as a portable
pure-Erlang fallback when native C/Rust NIFs (such as `libsodium`/`enacl` or
native `secp256k1` bindings) are unavailable.

Build & Test
------------

```sh
$ rebar3 compile
$ rebar3 eunit
$ rebar3 eqc
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
- `ecu_ed25519`: Curve point arithmetic and group operations using extended
  homogeneous coordinates (`{X, Y, Z, T}`):
  - Point addition (`p_add/2`), subtraction (`p_sub/2`), doubling (`p_dbl/1`),
    and negation (`p_neg/1`).
  - Base-point scalar multiplication (`scalar_mul_base/1`,
    `scalar_mul_base_noclamp/1`) using a precomputed comb table.
  - Variable-base scalar multiplication (`scalar_mul/2`, `scalar_mul_noclamp/2`)
    using a fixed 4-bit window method.
  - Dual-scalar multiplication (`scalar_mul_dual_base/3`) for verification.
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
| **ed25519 scalar mul base** | 746 µs | **122 µs** | **~6.1×** | 14.9 µs (enacl) | 8.2× |
| **ed25519 scalar mul** | 741 µs | **614 µs** | **~1.2×** | 71.8 µs (enacl) | 8.6× |
| **ed25519 sign** | 739 µs | **272 µs** | **~2.7×** | 16.1 µs (enacl) | 16.9× |
| **ed25519 verify** | 1,496 µs | **769 µs** | **~1.9×** | 44.2 µs (enacl) | 17.4× |
| **ed25519 point add** | 1.9 µs | **2.3 µs** | ~1.0× | 12.6 µs (enacl) | **5.6× faster** |

*Note: Pure Erlang point addition is faster than `enacl` because calling the NIF
incurs marshalling and point decompression overhead.*

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
