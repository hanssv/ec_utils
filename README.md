ec_utils
========

A pure Erlang cryptographic library implementing elliptic curve arithmetic
(**Ed25519**, **Ed448**, **secp256k1**), digital signatures (ECDSA, EdDSA,
BIP-340 Schnorr), threshold signatures (FROST RFC 9591), multi-signatures
(MuSig2 BIP-327), key exchange (X25519, X448), Hash-to-Curve (RFC 9380),
hierarchical deterministic wallets (BIP-32, SLIP-0010, AEX-10), mnemonics (BIP-39),
and address encodings (Base58, Base58Check, Bech32, Bech32m).

This library has **zero external C or third-party dependencies** in production
and runs completely self-contained on the BEAM. Reference NIFs in `crates/`
exist purely as test oracles for differential fuzzing and cross-verification.

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

### Ed448 (RFC 8032 & SHAKE256)

```erlang
%% Keypair generation with 57-byte public key
{SecretKey, PublicKey} = ecu_eddsa448:sign_keypair(),
Msg = <<"High-security payload">>,

%% Sign and verify 114-byte signature with optional context string
Context = <<"custom-app-v1">>,
Signature = ecu_eddsa448:sign_detached(Msg, SecretKey, Context),
true = ecu_eddsa448:sign_verify_detached(Signature, Msg, PublicKey, Context).

%% Batch verification of multiple Ed448 signatures in a single pass
Batch = [
    {SigA, MsgA, PKA, ContextA},
    {SigB, MsgB, PKB, ContextB}
],
true = ecu_eddsa448:sign_verify_batch(Batch).
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

### MuSig2 Multi-Signatures (BIP-327)

```erlang
%% Key aggregation for 2 signers
SK1 = crypto:strong_rand_bytes(32),
SK2 = crypto:strong_rand_bytes(32),
PK1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK1)),
PK2 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK2)),
{ok, Ctx} = ecu_musig2:key_agg([PK1, PK2]),
AggPK = ecu_musig2:key_agg_pubkey(Ctx),
Msg = <<"Multi-party payment">>,

%% Round 1: Generate nonces and aggregate
{SecN1, PubN1} = ecu_musig2:nonce_gen(bip340, SK1),
{SecN2, PubN2} = ecu_musig2:nonce_gen(bip340, SK2),
{ok, AggN} = ecu_musig2:nonce_agg([PubN1, PubN2]),

%% Round 2: Partial signing and verification
{ok, Psig1} = ecu_musig2:sign_partial(Ctx, SK1, SecN1, AggN, Msg),
{ok, Psig2} = ecu_musig2:sign_partial(Ctx, SK2, SecN2, AggN, Msg),
true = ecu_musig2:verify_partial(Ctx, Psig1, PubN1, PK1, AggN, Msg),
true = ecu_musig2:verify_partial(Ctx, Psig2, PubN2, PK2, AggN, Msg),

%% Aggregate into a standard 64-byte BIP-340 Schnorr signature
{ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, [Psig1, Psig2]),
true = ecu_schnorr:verify(Sig, Msg, AggPK).
```

### Diffie-Hellman Key Exchange (X25519, X448, secp256k1)

```erlang
%% X25519 (RFC 7748)
{PubA, PrivA} = ecu_ecdh:keypair(x25519),
{PubB, PrivB} = ecu_ecdh:keypair(x25519),
SharedSecret = ecu_ecdh:compute_key(x25519, PubB, PrivA),
SharedSecret = ecu_ecdh:compute_key(x25519, PubA, PrivB).

%% X448 (RFC 7748 Goldilocks)
{PubA448, PrivA448} = ecu_ecdh:keypair(x448),
{PubB448, PrivB448} = ecu_ecdh:keypair(x448),
Shared448 = ecu_ecdh:compute_key(x448, PubB448, PrivA448).

%% Ed25519 to X25519 conversion (birational equivalence)
XPub = ecu_ecdh:ed25519_public_to_x25519(Ed25519PubKey),
XPriv = ecu_ecdh:ed25519_secret_to_x25519(Ed25519SecretKey).
```

### Hierarchical Deterministic (HD) Wallets (BIP-32 & SLIP-0010)

```erlang
%% Master key derivation from seed
Seed = crypto:strong_rand_bytes(32),
{ok, MasterKey} = ecu_hd:master_key(secp256k1, Seed),

%% Standard BIP-44 key derivation path (e.g. Ethereum: m/44'/60'/0'/0/0)
{ok, ChildKey} = ecu_hd:derive_path("m/44'/60'/0'/0/0", MasterKey),
{ok, PrivKey} = ecu_hd:private_key(ChildKey),
{ok, PubKey} = ecu_hd:public_key(ChildKey),

%% Base58Check extended keys (xprv / xpub)
XPub = ecu_hd:to_base58(public, ChildKey),
XPrv = ecu_hd:to_base58(private, ChildKey),

%% Ed25519 SLIP-0010 & AEX-10 (e.g. Aeternity: m/44H/457H/0H/0H/0H)
{ok, AexKey} = ecu_hd:derive_aex10(Seed, 0, 0).
```

### BIP-39 Mnemonic Seed Generation

```erlang
%% Generate 12-word or 24-word mnemonic phrases
Mnemonic12 = ecu_bip39:generate_mnemonic(12),
Mnemonic24 = ecu_bip39:generate_mnemonic(256),
ok = ecu_bip39:validate_mnemonic(Mnemonic12),

%% Derive 512-bit binary seed with optional passphrase (PBKDF2-HMAC-SHA512 with UTF-8 NFKD)
Seed = ecu_bip39:mnemonic_to_seed(Mnemonic12, "optional_passphrase"),

%% One-step derivation from mnemonic directly to HD master key
{ok, MasterKey} = ecu_bip39:mnemonic_to_master_key(secp256k1, Mnemonic12, "passphrase").
```

### Bech32 & Bech32m Address Encoding (BIP-173 & BIP-350)

```erlang
%% Encode a Bitcoin SegWit v0 P2WPKH address (20-byte pubkey hash)
PubKeyHash = crypto:hash(ripemd160, crypto:hash(sha256, PubKey)),
{ok, SegwitV0Addr} = ecu_bech32:encode_segwit_address(<<"bc">>, 0, PubKeyHash),

%% Encode a Bitcoin Taproot v1 P2TR address (32-byte x-only pubkey, automatically uses Bech32m)
{ok, TaprootAddr} = ecu_bech32:encode_segwit_address(<<"bc">>, 1, TaprootPubKey),

%% Decode and validate SegWit address with strict checksum variant enforcement
{ok, {WitnessVersion, Program}} = ecu_bech32:decode_segwit_address(<<"bc">>, TaprootAddr),

%% Generic Bech32/Bech32m encoding with 5-bit conversion
{ok, Bits5} = ecu_bech32:convert_bits(<<"payload">>, 8, 5, true),
{ok, Bech32Str} = ecu_bech32:encode(<<"custom">>, Bits5, bech32m).
```

### Hash-to-Curve & Encode-to-Curve (RFC 9380)

Deterministic, indifferentiable hashing and non-uniform encoding of arbitrary binary payloads to curve points across `secp256k1`, `edwards25519`, and `edwards448`:

```erlang
%% Hash to secp256k1 (Random Oracle, SSWU + 3-isogeny)
PtRO = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, <<"identity-payload">>),
true = ecu_secp256k1:on_curve(PtRO).

%% Encode to edwards25519 with custom domain separation tag (Elligator 2 + cofactor clearing)
CustomDST = <<"MY-APP-ED25519-V1">>,
PtNU = ecu_h2c:encode_to_curve(edwards25519_xmd_sha512_ell2_nu, <<"message">>, CustomDST),
true = ecu_ed25519:on_curve(PtNU).

%% Hash to edwards448 (SHAKE256 XOF + Elligator 2 + 4-isogeny)
Pt448 = ecu_h2c:hash_to_curve(edwards448_xof_shake256_ell2_ro, <<"high-security-payload">>),
true = ecu_ed448:on_curve(Pt448).
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

### Ed448 (Curve448 / Goldilocks)

- `ecu_eddsa448`: High-level Ed448 digital signature API (RFC 8032) using SHAKE256:
  - `sign_keypair/0`: Generate a fresh 57-byte `{secret, public}` keypair.
  - `sign_seed_keypair/1`: Deterministically derive a keypair from a 57-byte seed.
  - `sign/2,3`, `sign_open/2,3`: Create and open combined signed messages with optional context string ($0 \le |C| \le 255$).
  - `sign_detached/2,3`, `sign_verify_detached/3,4`: Create and verify 114-byte detached signatures with optional context string.
  - `sign_verify_batch/1,2`: Batch signature verification verifying a list of `{Sig, Msg, PK}` or `{Sig, Msg, PK, Context}` tuples in a single pass.
- `ecu_ed448`: Curve point arithmetic and group operations using projective coordinates (`{X, Y, Z}` with $x = X/Z, y = Y/Z$):
  - Point addition (`p_add/2`), subtraction (`p_sub/2`), doubling (`p_dbl/1`), and negation (`p_neg/1`) using complete Edwards formulas.
  - Base-point scalar multiplication (`scalar_mul_base/1`, `scalar_mul_base_noclamp/1`) using a 114-window precomputed comb table.
  - Variable-base scalar multiplication (`scalar_mul/2`, `scalar_mul_noclamp/2`) using a fixed 4-bit window method.
  - Dual-scalar multiplication (`scalar_mul_dual_base/3`) for signature verification.
  - Multi-scalar multiplication (`multi_scalar_mul/1`) using interleaved windowed Straus accumulation.
  - Point compression (`compress/1`) and decompression (`decompress/1`) with canonical encoding checks and small-order detection (`is_small_order/1`).

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
  - `ed448`: `FROST(Ed448, SHAKE256)` producing standard 114-byte Ed448 signatures ($R \parallel z$) verified with `ecu_eddsa448:sign_verify_detached/4`.
  - `secp256k1`: `FROST(secp256k1, SHA-256)` using RFC 9380 `expand_message_xmd` producing 65-byte signatures ($R \parallel z$).
  - `bip340`: BIP-340 Schnorr threshold signatures on secp256k1 producing 64-byte $x$-only signatures ($r \parallel s$) with tagged hashes, verified via `ecu_schnorr:verify/3`.
  - API functions accept an optional `ciphersuite()` prefix (`ed25519 | secp256k1 | bip340 | ed448`), defaulting to `ed25519`:
    - `commit/1,2`: Round 1 preprocessing — generate hiding & binding nonces and commitments.
    - `sign/6,7`: Round 2 signing — compute partial signature share $z_i$ bound to group public key and message.
    - `verify_signature_share/7,8`: Coordinator verification of individual signature shares.
    - `aggregate/4,5`: Aggregate threshold signature shares into a group signature.
    - `verify/3,4`: Verify aggregated FROST signatures (detached Ed25519, Ed448, secp256k1 prime-order verify, or BIP-340).
    - `trusted_dealer_keygen/2,3,4`: Trusted dealer key generation ($t$-of-$n$) with Feldman VSS commitments.
    - `vss_verify/3,4`: Verifiable Secret Sharing share verification.
    - `secret_share_combine/1,2`: Lagrange polynomial secret reconstruction from $t$ shares.
- `ecu_frost_dkg`: Two-round Distributed Key Generation (DKG):
  - `round1/3,4`, `round1_check/4,5`: Coefficient commitment and zero-knowledge Proof of Knowledge (PoK).
  - `round2/2,3`, `round2_check/3,4`: Share distribution and verification against public commitments.
  - `compute_private_sign_share/1,2,3`, `compute_public_verification_share/1,2,3`, `compute_public_key/1,2`: Joint key derivation.

### Diffie-Hellman / ECDH (X25519, X448, secp256k1)

- `ecu_ecdh`: Diffie-Hellman key exchange and Montgomery curve functions:
  - `keypair/1`: Fresh `{PublicKey, PrivateKey}` keypair generation (`x25519`, `x448`, `secp256k1`).
  - `keypair_from_seed/2`: Deterministic keypair generation from seed bytes.
  - `compute_key/3`: Key agreement returning shared secret binary (`32` bytes for X25519 and secp256k1, `56` bytes for X448).
  - `x25519/2`: RFC 7748 §5 scalar multiplication over Montgomery Curve25519 ($u$-coordinate).
  - `x448/2`: RFC 7748 §5 scalar multiplication over Montgomery Curve448 ($u$-coordinate).
  - `clamp/2`: RFC 7748 scalar pruning/clamping.
  - `ed25519_public_to_x25519/1`: Twisted Edwards public key conversion to Montgomery $u$-coordinate via birational map $u = (1 + y) / (1 - y) \pmod p$.
  - `ed25519_secret_to_x25519/1`: Ed25519 secret key conversion via SHA-512 and clamping.

### Pure-Erlang Keccak & SHA-3 (FIPS 202)

- `ecu_keccak`: High-speed unrolled 64-bit Keccak-f[1600] permutation and sponge construction (zero external C dependencies):
  - `keccak256/1`: Ethereum Keccak-256 hash function (zero padding delimiter).
  - `sha3_224/1`, `sha3_256/1`, `sha3_384/1`, `sha3_512/1`: Standard NIST FIPS 202 SHA-3 hash functions.
  - `shake128/2`, `shake256/2`: Keccak extendable-output functions (XOF).

> [!NOTE]
> `ecu_keccak` exists to keep `ec_utils` fully self-contained with zero external C dependencies for Ethereum message signing and recovery (`eth_msg_recover/2`), address derivation, and Ed448/SHAKE256.
> **Do not use this library for standalone hash functions alone!** If your application only requires high-throughput hashing or processes large volumes of data, use OTP's built-in `crypto:hash/2` (for NIST SHA-3) or a dedicated C/Rust NIF (such as `sha3`), which are ~40×–70× faster.

### MuSig2 Two-Round Multi-Signatures (BIP-327 & Ed25519)

- `ecu_musig2`: Two-round Schnorr multi-signature scheme producing standard 64-byte BIP-340 or Ed25519 signatures:
  - Supports both `bip340` (secp256k1 default) and `ed25519` ciphersuites.
  - `key_agg/1,2`: Aggregate individual signers' public keys with rogue-key attack defense ($L$-hash and second unique key optimization).
  - `key_agg_pubkey/1,2`: Extract the aggregated 32-byte $x$-only or compressed public key.
  - `key_agg_coeff/2,3`: Retrieve key aggregation coefficients for individual public keys (with duplicate key support).
  - `nonce_gen/0,1,2`: Generate secret and public nonce pairs.
  - `nonce_agg/1,2`: Aggregate participant public nonces into an aggregate nonce point.
  - `sign_partial/5,6`: Generate partial signatures bound to the group key, aggregate nonce, and message.
  - `verify_partial/6,7`: Verify individual partial signatures prior to aggregation.
  - `aggregate_partial/4,5`: Combine partial signatures into a standard 64-byte Schnorr signature with optional tweak accumulator support.

### Hierarchical Deterministic (HD) Wallets, BIP-39 & Base58

- `ecu_hd`: BIP-32 and SLIP-0010 hierarchical deterministic wallet key derivation:
  - `master_key/2`: Master key derivation from seed (`secp256k1` or `ed25519`).
  - `ckd_priv/2`, `ckd_pub/2`: Child key derivation (hardened and unhardened for secp256k1; hardened-only for Ed25519).
  - `derive_path/2`, `derive_path_from_seed/3`: Path evaluation (`"m/44'/60'/0'/0/0"`, `"M/0/1"`).
  - `derive_bip44/5,6`: Standard BIP-44 multi-account derivation.
  - `derive_aex10/3,4`, `derive_aex10_from_masterkey/3,4`: Aeternity AEX-10 account/address derivation.
  - `to_base58/1,2`, `from_base58/1`: Extended key serialization with Base58Check (`xprv`, `xpub`).
- `ecu_bip39`: BIP-39 mnemonic sentence generation, entropy round-trips, and seed derivation:
  - `generate_mnemonic/1,2`: Cryptographically secure mnemonic generation (12–24 words).
  - `entropy_to_mnemonic/1,2`: Convert 16–32 byte entropy to mnemonic words with SHA-256 checksums (~1.5 µs/op).
  - `mnemonic_to_entropy/1,2`: Validate and convert mnemonic back to entropy (~6.2 µs/op).
  - `validate_mnemonic/1,2`: Complete structure, dictionary, and checksum verification (~6.2 µs/op).
  - `mnemonic_to_seed/1,2`: PBKDF2-HMAC-SHA512 seed derivation (2,048 rounds) with UTF-8 NFKD normalization (~558 µs/op).
  - `mnemonic_to_master_key/2,3`: Direct bridge from mnemonic to validated HD master key.
- `ecu_bip39_words`: Embedded official 2,048 English wordlist for $O(1)$ indexed lookup with zero filesystem IO.
- `ecu_base58`: High-performance pure-Erlang Base58 and Base58Check encoding:
  - Optimized Radix-$58^{10}$ chunking (~3.5 µs/op encode/decode; ~5.5–6.0 µs/op Base58Check).
  - `encode/1`, `decode/1`: Raw Base58 with leading-zero preservation.
  - `encode_check/1`, `decode_check/1`: Base58Check with double SHA-256 checksums.

### Bech32 & Bech32m Address Encoding (BIP-173 & BIP-350)

- `ecu_bech32`: Pure-Erlang Bech32 and Bech32m base32 checksummed encoding:
  - `encode/3`: Encode human-readable part (HRP) and 5-bit payload using `bech32` ($M = 1$) or `bech32m` ($M = 0x2bc830a3$).
  - `decode/1`, `decode_lenient/1`: Parse and verify Bech32/Bech32m strings with strict casing and length verification.
  - `convert_bits/4`: Convert between arbitrary bit sizes (e.g. 8-bit to 5-bit) with strict padding error checks.
  - `encode_segwit_address/3`: Native Bitcoin SegWit address encoder, automatically selecting Bech32 for v0 and Bech32m for v1+ (Taproot) per BIP-350.
  - `decode_segwit_address/2`: Native Bitcoin SegWit address parser enforcing HRP match, witness version ($0..16$), program length ($2..40$ bytes), and checksum variant rules.

### Hash-to-Curve (RFC 9380)

- `ecu_h2c`: Pure-Erlang indifferentiable random oracle and non-uniform curve mapping (RFC 9380):
  - `hash_to_curve/2,3`: Indifferentiable hash-to-curve mapping ($Q_0 + Q_1$ with cofactor clearing) targeting:
    - `secp256k1_xmd_sha256_sswu_ro`: Simplified SWU on 3-isogenous curve with degree-3 rational map.
    - `edwards25519_xmd_sha512_ell2_ro`: Elligator 2 on Montgomery Curve25519 with birational map and $h_{\text{eff}} = 8$ cofactor clearing.
    - `edwards448_xof_shake256_ell2_ro`: Elligator 2 on Montgomery Curve448 with degree-4 rational isogeny and $h_{\text{eff}} = 4$ cofactor clearing.
  - `encode_to_curve/2,3`: Non-uniform encoding ($Q$ with cofactor clearing) for applications not requiring random oracle indifferentiability:
    - `secp256k1_xmd_sha256_sswu_nu`
    - `edwards25519_xmd_sha512_ell2_nu`
    - `edwards448_xof_shake256_ell2_nu`
  - `expand_message_xmd/4`: Merkle-Damgaard message expansion (SHA-256, SHA-512) with oversize DST hashing.
  - `expand_message_xof/3`: SHAKE256 extensible-output message expansion.
  - `hash_to_field/4`: Uniform pseudorandom field element generation with modulo reduction.
  - `map_to_curve/2`: Direct field-to-curve point mapping.
  - `clear_cofactor/2`: Curve-specific cofactor clearing ($h_{\text{eff}}$ scalar multiplication).

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

| Operation | Baseline | Optimized | Speedup | Reference (Native NIF / OpenSSL) | vs Reference |
|:---|---:|---:|---:|---:|---:|
| **secp256k1 scalar mul base** | 5,377 µs | **166 µs** | **~32×** | 225 µs (crypto / OpenSSL) | **1.35× faster** |
| **secp256k1 scalar mul** | — | **760 µs** | — | 243 µs (crypto / OpenSSL) | 3.1× |
| **secp256k1 eth_recover** | 7,810 µs | **893 µs** | **~8.7×** | 54.1 µs (Rust NIF) | 16.5× |
| **secp256k1 bip340 sign** | — | **370 µs** | — | 54.2 µs (k256 Rust NIF) | 6.8× |
| **secp256k1 bip340 verify** | — | **996 µs** | — | 49.6 µs (k256 Rust NIF) | 19.9× |
| **ed25519 scalar mul base** | 746 µs | **122 µs** | **~6.1×** | 14.9 µs (enacl) | 8.2× |
| **ed25519 scalar mul** | 741 µs | **614 µs** | **~1.2×** | 71.8 µs (enacl) | 8.6× |
| **ed25519 sign** | 739 µs | **272 µs** | **~2.7×** | 16.1 µs (enacl) | 16.9× |
| **ed25519 verify** | 1,496 µs | **769 µs** | **~1.9×** | 44.2 µs (enacl) | 17.4× |
| **ed25519 verify (batch of 32)** | 846 µs/sig | **368 µs/sig** | **~2.3×** | — | — |
| **ed25519 point add** | 1.9 µs | **2.3 µs** | ~1.0× | 12.6 µs (enacl) | **5.5× faster** |
| **ed448 scalar mul base** | — | **492 µs** | — | 61 µs (crypto / OpenSSL) | 8.1× |
| **ed448 scalar mul** | — | **1.80 ms** | — | — | — |
| **ed448 sign** | — | **1.06 ms** | — | 128 µs (crypto / OpenSSL) | 8.3× |
| **ed448 verify** | — | **2.46 ms** | — | 154 µs (crypto / OpenSSL) | 16.0× |
| **x25519 compute_key** | — | **575 µs** | — | 47.6 µs (enacl) / 63.2 µs (crypto) | 12.1× |
| **x448 compute_key** | — | **1.69 ms** | — | 205 µs (crypto / OpenSSL) | 8.2× |
| **frost ed25519 commit** | — | **329 µs** | — | 63.5 µs (frost-ed25519 Rust NIF) | 5.2× |
| **frost ed25519 part sign** | — | **2.12 ms** | — | 102 µs (frost-ed25519 Rust NIF) | 20.8× |
| **frost ed25519 aggregate** | — | **2.32 ms** | — | 183 µs (frost-ed25519 Rust NIF) | 12.7× |
| **frost ed25519 verify** | — | **929 µs** | — | 99.9 µs (frost-ed25519 Rust NIF) | 9.3× |
| **frost secp256k1 commit** | — | **331 µs** | — | 75.1 µs (frost-secp256k1 Rust NIF) | 4.4× |
| **frost secp256k1 part sign** | — | **2.50 ms** | — | 150 µs (frost-secp256k1 Rust NIF) | 16.7× |
| **frost secp256k1 aggregate** | — | **2.64 ms** | — | 245 µs (frost-secp256k1 Rust NIF) | 10.8× |
| **frost secp256k1 verify** | — | **1.02 ms** | — | 117 µs (frost-secp256k1 Rust NIF) | 8.7× |
| **frost bip340 commit** | — | **351 µs** | — | 75.7 µs (frost-secp256k1-tr Rust NIF) | 4.6× |
| **frost bip340 part sign** | — | **2.52 ms** | — | 165 µs (frost-secp256k1-tr Rust NIF) | 15.3× |
| **frost bip340 aggregate** | — | **2.59 ms** | — | 262 µs (frost-secp256k1-tr Rust NIF) | 9.9× |
| **frost bip340 verify** | — | **1.02 ms** | — | 133 µs (frost-secp256k1-tr Rust NIF) | 7.7× |
| **frost ed448 commit** | — | **1.11 ms** | — | 441 µs (frost-ed448 Rust NIF) | 2.5× |
| **frost ed448 part sign** | — | **5.95 ms** | — | 560 µs (frost-ed448 Rust NIF) | 10.6× |
| **frost ed448 aggregate** | — | **6.00 ms** | — | 1.10 ms (frost-ed448 Rust NIF) | 5.5× |
| **frost ed448 verify** | — | **2.38 ms** | — | 691 µs (frost-ed448 Rust NIF) | 3.4× |
| **keccak256 (Ethereum)** | — | **81.9 µs** | — | 0.35 µs (rustcrypto NIF) | 234× |
| **sha3_256 (NIST)** | — | **81.5 µs** | — | 0.44 µs (crypto / OpenSSL) | 185× |
| **musig2 bip327 key_agg** | — | **1.62 ms** | — | 73.4 µs (musig2 Rust NIF) | 22.1× |
| **musig2 bip327 nonce_gen** | — | **320 µs** | — | 51.5 µs (musig2 Rust NIF) | 6.2× |
| **musig2 bip327 nonce_agg** | — | **145 µs** | — | 30.7 µs (musig2 Rust NIF) | 4.7× |
| **musig2 bip327 sign_part** | — | **1.00 ms** | — | 67.3 µs (musig2 Rust NIF) | 14.9× |
| **musig2 bip327 verify_part** | — | **2.64 ms** | — | 190 µs (musig2 Rust NIF) | 13.9× |
| **musig2 bip327 aggregate** | — | **1.83 ms** | — | 159 µs (musig2 Rust NIF) | 11.5× |
| **base58 encode (78B)** | — | **3.6 µs** | — | — | — |
| **base58 decode (78B)** | — | **3.5 µs** | — | — | — |
| **base58check encode (78B)** | — | **5.6 µs** | — | — | — |
| **base58check decode (78B)** | — | **6.0 µs** | — | — | — |
| **bip32 ckd_priv (secp256k1)** | — | **172 µs** | — | — | — |
| **bip32 ckd_pub (secp256k1)** | — | **205 µs** | — | — | — |
| **slip10 ckd_priv (ed25519)** | — | **163 µs** | — | — | — |
| **bip39 generate_mnemonic (12w)** | — | **1.9 µs** | — | — | — |
| **bip39 entropy_to_mnemonic (16B)** | — | **1.5 µs** | — | — | — |
| **bip39 mnemonic_to_entropy (12w)** | — | **6.2 µs** | — | — | — |
| **bip39 validate_mnemonic (12w)** | — | **6.2 µs** | — | — | — |
| **bip39 mnemonic_to_seed (2048 iters)** | — | **558 µs** | — | — | — |
| **segwit v1 encode (Taproot 32B)** | — | **10.8 µs** | — | 0.42 µs (bech32 NIF) | 25.5× |
| **segwit v1 decode (Taproot 32B)** | — | **15.3 µs** | — | 0.75 µs (bech32 NIF) | 20.5× |
| **secp256k1 hash_to_curve (RO)** | — | **166 µs** | — | 56.2 µs (RustCrypto NIF) | 2.95× |
| **secp256k1 encode_to_curve (NU)** | — | **63 µs** | — | 31.2 µs (RustCrypto NIF) | 2.02× |
| **edwards25519 hash_to_curve (RO)** | — | **382 µs** | — | — | — |
| **edwards25519 encode_to_curve (NU)** | — | **285 µs** | — | — | — |
| **edwards448 hash_to_curve (RO)** | — | **1.05 ms** | — | — | — |
| **edwards448 encode_to_curve (NU)** | — | **760 µs** | — | — | — |

*Notes:*
- *Pure Erlang point addition is faster than `enacl` because calling the NIF incurs marshalling and point decompression overhead.*
- *Pure Erlang `secp256k1` base-point scalar multiplication is faster than OpenSSL due to the precomputed 1,024-entry comb table.*
- *BIP-340 Schnorr, Keccak-256, and Hash-to-Curve reference benchmarks use an optional test NIF (`k256`, `sha3`, `hash2curve`) buildable via `make rustcrypto_reference`.*
- *FROST threshold reference benchmarks use optional RFC 9591 test NIFs (Zcash Foundation `frost-core` crates) buildable via `make frost_reference`.*
- *MuSig2 reference benchmarks use the official BIP-327 Rust crate buildable via `make musig2_reference`.*
- *All reference NIFs can be built together using `make reference_nifs`.*


Roadmap
-------

See [ROADMAP.md](ROADMAP.md) for details on completed milestones and planned cryptographic extensions, including:
- **Diffie-Hellman Key Exchange (X25519 / RFC 7748)**: Pure-Erlang Montgomery ladder on Curve25519.
- **Ed448 Goldilocks Curve (RFC 8032 & RFC 7748)**: 448-bit Edwards curve arithmetic and SHAKE256 `[Completed]`.
- **FROST(Ed448, SHAKE256)**: Threshold signing for Ed448 `[Completed]`.
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
