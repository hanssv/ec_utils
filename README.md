ec_utils
========

A pure Erlang cryptographic library implementing elliptic curve arithmetic
(**Ed25519**, **Ed448**, **secp256k1**, **BN254 / alt_bn128**), digital signatures (ECDSA, EdDSA,
BIP-340 Schnorr, **ML-DSA / FIPS 204**, **SLH-DSA / FIPS 205**), threshold signatures (FROST RFC 9591), multi-signatures
(MuSig2 BIP-327), key exchange (X25519, X448), quantum-resistant key encapsulation
(ML-KEM / FIPS 203), hybrid post-quantum key exchange (X25519 + ML-KEM-768),
pairing-friendly cryptography & zero-knowledge proof verification (**BLS12-381**, **BN254**, **Groth16**, **PLONK**, **BabyJubjub**, **Jubjub**, **Pedersen**, **KZG / EIP-4844**, **Circom / ZoKrates R1CS & WTNS**),
Hash-to-Curve (RFC 9380), Verifiable Random Functions (VRF / RFC 9381),
hierarchical deterministic wallets (BIP-32, SLIP-0010, AEX-10),
mnemonics (BIP-39), and address encodings (Base58, Base58Check, Bech32, Bech32m).

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

### Verifiable Random Functions (VRF / RFC 9381)

Pure-Erlang implementation of Elliptic Curve Verifiable Random Functions (ECVRF) supporting both Ed25519 (Elligator 2 and Try-and-Increment) and secp256k1 (Try-and-Increment and Simplified SWU):

```erlang
%% ECVRF-EDWARDS25519-SHA512-ELL2 (RFC 9381 Suite 0x04)
{PK, SK} = ecu_vrf:keypair(edwards25519_sha512_ell2),
Alpha = <<"entropy-seed-for-leader-election">>,

%% Prover generates deterministic proof Pi
{ok, Proof} = ecu_vrf:prove(edwards25519_sha512_ell2, SK, Alpha),

%% Verifier verifies proof and extracts deterministic VRF output hash Beta
{ok, Beta} = ecu_vrf:verify(edwards25519_sha512_ell2, PK, Proof, Alpha),

%% Deterministic VRF hash can also be evaluated directly from proof
{ok, Beta} = ecu_vrf:proof_to_hash(edwards25519_sha512_ell2, Proof).

%% ECVRF-SECP256K1-SHA256-TAI (Suite 0xFE, RFC 6979 deterministic nonces)
{SecpPK, SecpSK} = ecu_vrf:keypair(secp256k1_sha256_tai),
{ok, SecpProof} = ecu_vrf:prove(secp256k1_sha256_tai, SecpSK, Alpha),
{ok, SecpBeta} = ecu_vrf:verify(secp256k1_sha256_tai, SecpPK, SecpProof, Alpha).
```

### Quantum-Resistant Key Encapsulation (ML-KEM / FIPS 203) & Hybrid Key Exchange

Pure-Erlang implementation of the NIST Post-Quantum Cryptography Standard FIPS 203 (ML-KEM-512, ML-KEM-768, ML-KEM-1024), plus hybrid classical/post-quantum key exchange combining X25519 with ML-KEM-768:

```erlang
%% ML-KEM-768 keypair generation, encapsulation, and decapsulation
{PublicKey, SecretKey} = ecu_ml_kem:keypair(ml_kem_768),
{SharedSecret, Ciphertext} = ecu_ml_kem:encaps(PublicKey),
SharedSecret = ecu_ml_kem:decaps(SecretKey, Ciphertext).

%% Deterministic derivation from NIST test vector seeds (d, z) and message seed m
{PK, SK} = ecu_ml_kem:keypair_from_seed(ml_kem_512, SeedD, SeedZ),
{SS, CT} = ecu_ml_kem:encaps(PK, SeedM),
SS = ecu_ml_kem:decaps(SK, CT).

%% Hybrid X25519 + ML-KEM-768 post-quantum key exchange (dual security)
{HybridPub, HybridPriv} = ecu_ecdh:hybrid_keypair(x25519_mlkem768),
{SharedKey, HybridCT} = ecu_ecdh:hybrid_encaps(HybridPub),
SharedKey = ecu_ecdh:hybrid_decaps(HybridPriv, HybridCT).
```

### Quantum-Resistant Digital Signatures (ML-DSA / FIPS 204)

Pure-Erlang implementation of the NIST Module-Lattice-Based Digital Signature Standard FIPS 204 (ML-DSA-44, ML-DSA-65, ML-DSA-87):

```erlang
%% Keypair generation, signing, and verification
#{public := PublicKey, secret := SecretKey} = ecu_ml_dsa:keypair(ml_dsa_65),
Msg = <<"Quantum-resistant signed payload">>,
Signature = ecu_ml_dsa:sign(Msg, SecretKey),
true = ecu_ml_dsa:verify(Msg, Signature, PublicKey).

%% Deterministic signing with optional context string (0 to 255 bytes)
Context = <<"custom-context">>,
DetSig = ecu_ml_dsa:sign_deterministic(Msg, SecretKey, Context),
true = ecu_ml_dsa:verify(Msg, DetSig, PublicKey, Context).

%% Deterministic keypair derivation from 32-byte seed
#{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ml_dsa_44, Seed32).
```

### Stateless Hash-Based Signatures (SLH-DSA / FIPS 205)

Pure-Erlang implementation of the NIST Stateless Hash-Based Digital Signature Standard FIPS 205 (formerly SPHINCS+), covering all 12 SHA-2 and SHAKE parameter sets:

```erlang
%% Fast Category 1 keypair generation, signing, and verification (SHA-2 recommended for Erlang)
#{public := PublicKey, secret := SecretKey} = ecu_slh_dsa:keypair(slh_dsa_sha2_128f),
Msg = <<"Stateless hash-based signature">>,
Signature = ecu_slh_dsa:sign(Msg, SecretKey),
true = ecu_slh_dsa:verify(Msg, Signature, PublicKey).

%% Deterministic signing with optional context string (0 to 255 bytes)
Context = <<"app-auth-v1">>,
DetSig = ecu_slh_dsa:sign_deterministic(Msg, SecretKey, Context),
true = ecu_slh_dsa:verify(Msg, DetSig, PublicKey, Context).

%% Deterministic keypair derivation from seeds (SK.seed, SK.prf, PK.seed)
#{public := PK, secret := SK} = ecu_slh_dsa:keypair_from_seeds(slh_dsa_sha2_128f, SKSeed, SKPrf, PKSeed).
```

### BN254 (alt_bn128) & Optimal Ate Pairing

Pure-Erlang arithmetic and pairing over the BN254 curve (alt_bn128 / Ethereum EVM precompiles / Circom):

```erlang
%% Point arithmetic on G1 (Fp) and G2 (Fp2)
P1 = ecu_bn254:g1_generator(),
P2 = ecu_bn254:g2_generator(),
Q1 = ecu_bn254:g1_mul(P1, 42),
Q2 = ecu_bn254:g2_mul(P2, 42),

%% Optimal Ate pairing e: G1 x G2 -> GT over Fp12
GT = ecu_bn254_pairing:pairing(P1, P2),

%% Multi-pairing check: e(P1, Q2) * e(-Q1, P2) == 1
true = ecu_bn254_pairing:pairing_check([
    {P1, Q2},
    {ecu_bn254:g1_neg(Q1), P2}
]).
```

### Groth16 zk-SNARK Proof Verification (BLS12-381 & BN254)

Pure-Erlang verification of Groth16 zero-knowledge proofs over BLS12-381 and BN254 (alt_bn128 / Ethereum EVM / Circom / SnarkJS):

```erlang
%% Single proof verification (default bls12_381, or explicit bn254)
Proof = #{a => ProofA, b => ProofB, c => ProofC},
VK = #{alpha_g1 => Alpha, beta_g2 => Beta, gamma_g2 => Gamma, delta_g2 => Delta, ic => [IC0, IC1]},
PublicInputs = [12345],

%% Verify over BLS12-381
true = ecu_groth16:verify(VK, PublicInputs, Proof),

%% Verify over BN254 (compatible with SnarkJS / Circom / EVM test vectors)
true = ecu_groth16:verify(bn254, VK, PublicInputs, Proof).

%% Randomized batch verification of multiple Groth16 proofs in a single multi-Miller loop
Batch = [
    {Inputs1, Proof1},
    {Inputs2, Proof2}
],
true = ecu_groth16:verify_batch(bn254, VK, Batch).
```

### PLONK Universal zk-SNARK Verification (BN254 & BLS12-381)

Pure-Erlang universal zero-knowledge proof verification based on the PLONK protocol (Gabizon et al., 2019) supporting both BN254 (Ethereum EVM / SnarkJS) and BLS12-381:

```erlang
%% Single proof verification from JSON files (SnarkJS / Circom)
{ok, VKJson} = file:read_file("verification_key.json"),
{ok, ProofJson} = file:read_file("proof.json"),
{ok, PubJson} = file:read_file("public.json"),

%% Verify directly from JSON binaries
true = ecu_plonk:verify(VKJson, PubJson, ProofJson),

%% Or parse into strongly typed records (#plonk_vk{}, #plonk_proof{})
{ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
{ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),
{ok, Pub} = ecu_plonk:parse_public_inputs(PubJson, bn254),

%% Verify over BN254 or BLS12-381
true = ecu_plonk:verify(bn254, VK, Pub, Proof),
true = ecu_plonk:verify(bls12_381, BLS12_VK, BLS12_Pub, BLS12_Proof).
```

### Poseidon Algebraic Hash Function (BLS12-381 & BN254)

Pure-Erlang Poseidon algebraic hashing for ZK circuits and smart contract platforms:

```erlang
%% BLS12-381 2-to-1 hashing (compatible with Aeternity FATE VM / Sophia Crypto.poseidon)
Hash = ecu_poseidon:hash3(1, 2).

%% BN254 2-to-1 hashing (compatible with Circomlib / Ethereum / Tornado Cash)
HashBN = ecu_poseidon:hash3(bn254, 1, 2).

%% Multi-element hashing (t in 2..9)
MultiHash = ecu_poseidon:hash(bls12_381, [1, 2, 3, 4]).

%% 32-byte big-endian binary inputs
BinHash = ecu_poseidon:hash_binary(bn254, [<<1:256>>, <<2:256>>]).
```

### BabyJubjub & Circom EdDSA (Poseidon)

Pure-Erlang BabyJubjub twisted Edwards curve arithmetic (EIP-2494) and Circom-compatible EdDSA signatures with Poseidon:

```erlang
%% Key generation (random or from 32-byte seed)
{SecretSeed, PublicKey} = ecu_babyjubjub:keypair(),

%% Circom-compatible EdDSA signing with Poseidon
Msg = 123456789,
Signature = ecu_babyjubjub:sign(SecretSeed, Msg),

%% Verification (compatible with Circom EdDSAPoseidonVerifier.circom and circomlibjs)
true = ecu_babyjubjub:verify(PublicKey, Signature, Msg).

%% Curve operations
Base8 = ecu_babyjubjub:base8(),
P2 = ecu_babyjubjub:double(Base8),
Compressed = ecu_babyjubjub:compress(P2),
{ok, P2} = ecu_babyjubjub:decompress(Compressed).

%% Montgomery ladder scalar multiplication (u-only constant-time)
MBase8 = ecu_babyjubjub:edwards_to_montgomery(Base8),
URes = ecu_babyjubjub:montgomery_ladder(123456789, element(1, MBase8)).

%% Circomlib-compatible Pedersen Hash & Commitments
MsgBin = <<"state commitment data">>,
HashPt = ecu_babyjubjub_pedersen:hash(MsgBin),
HashComp = ecu_babyjubjub_pedersen:hash_compressed(MsgBin),
Commitment = ecu_babyjubjub_pedersen:commit(MsgBin, 123456789).

### Jubjub Curve over BLS12-381 (Zcash ZIP 216 / ZIP 243)

Pure-Erlang Jubjub twisted Edwards curve arithmetic over the scalar field of BLS12-381:

```erlang
Gen = ecu_jubjub:generator(),
DoubleGen = ecu_jubjub:double(Gen),
P_mul = ecu_jubjub:mul(Gen, 123456789),

%% ZIP 216 point compression and decompression
Comp = ecu_jubjub:compress(P_mul),
{ok, P_mul} = ecu_jubjub:decompress(Comp),

%% Montgomery ladder on Jubjub
MGen = ecu_jubjub:edwards_to_montgomery(Gen),
UK = ecu_jubjub:montgomery_ladder(123456789, element(1, MGen)).
```
```

### KZG Polynomial Commitments & EIP-4844 (BLS12-381)

Pure-Erlang constant-sized KZG polynomial commitments, evaluation proofs, and Ethereum EIP-4844 point evaluation precompile:

```erlang
%% Structured Reference String (SRS / Powers of Tau)
SRS = ecu_kzg:setup(16, 1234567890987654321),

%% Commit to polynomial P(x) = 5 + 3x + 7x^2
Poly = [5, 3, 7],
Commitment = ecu_kzg:commit(SRS, Poly),

%% Create opening proof for P(42) = Y
Z = 42,
{Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),

%% Verify proof in a single 2-pair Miller loop and final exponentiation
true = ecu_kzg:verify(SRS, Commitment, Z, Y, Proof),

%% Randomized batch verification of N proofs in a single 2-pairing check
true = ecu_kzg:verify_batch(SRS, [{Commitment, Z, Y, Proof}]),

%% EIP-4844 Point Evaluation Precompile (192-byte standard consensus format)
{ok, <<4096:256/big, _Modulus:256/big>>} = ecu_kzg:point_evaluation(SRS, Input192Bytes).
```

### Circom 2 & ZoKrates Circuit Tooling (R1CS & WTNS)

Pure-Erlang binary parsing, serialization, constraint satisfaction checking, and Groth16 public input extraction for Circom `.r1cs` and `.wtns` files:

```erlang
%% Parse Circom 2 .r1cs and .wtns witness files
{ok, R1CS} = ecu_circom:parse_r1cs("circuit.r1cs"),
{ok, WTNS} = ecu_circom:parse_wtns("witness.wtns"),

%% Validate constraint satisfaction: (A * W) * (B * W) = (C * W) (mod q)
ok = ecu_circom:check_constraints(R1CS, WTNS),
true = ecu_circom:is_satisfied(R1CS, WTNS),

%% Extract public inputs vector formatted directly for ecu_groth16:verify/3,4
PublicInputs = ecu_circom:extract_public_inputs(WTNS, R1CS),
true = ecu_groth16:verify(bn254, VK, PublicInputs, Proof).
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

### Verifiable Random Functions (RFC 9381)

- `ecu_vrf`: Pure-Erlang Elliptic Curve Verifiable Random Functions (RFC 9381):
  - Supported Ciphersuites:
    - `edwards25519_sha512_ell2`: RFC 9381 Suite 0x04 using RFC 9380 Elligator 2 mapping and RFC 8032 nonces.
    - `edwards25519_sha512_tai`: RFC 9381 Suite 0x03 using Try-and-Increment point hunting.
    - `secp256k1_sha256_tai`: Suite 0xFE with Try-and-Increment and RFC 6979 deterministic nonces.
    - `secp256k1_sha256_sswu`: Suite 0xFE with Simplified SWU mapping and RFC 6979 deterministic nonces.
  - `keypair/1`: Generate fresh public/secret keypair for a given suite.
  - `derive_public_key/2`: Deterministically derive public key point string from secret key.
  - `prove/3,4`: Generate deterministic VRF proof $\pi$ for input message $\alpha$ (with optional custom salt).
  - `verify/4,5`: Cryptographically verify proof $\pi$ against public key and input message, returning `{ok, Beta}` or `{error, Reason}` (supports optional public key validation bypass).
  - `proof_to_hash/2`: Deterministically extract VRF hash output $\beta$ directly from proof $\pi$.

### ML-KEM (FIPS 203) & Hybrid Post-Quantum Key Exchange

- `ecu_ml_kem`: Pure-Erlang implementation of the NIST Module-Lattice-Based Key-Encapsulation Mechanism Standard (FIPS 203):
  - `keypair/1`: Generate fresh public/secret keypair for `ml_kem_512`, `ml_kem_768`, or `ml_kem_1024`.
  - `keypair_from_seed/3`: Deterministically derive keypair from seeds `d` and `z` ($32$ bytes each) per FIPS 203 Algorithm 19.
  - `encaps/1,2`: Encapsulate a shared secret against a public key (using strong random seed or explicit $32$-byte message seed `m`).
  - `decaps/2`: Decapsulate ciphertext with secret key. Features implicit rejection: invalid or tampered ciphertexts return a pseudorandom key $J(z \ || \ c)$ rather than failing.
  - `parameter_set/1`: Determine parameter set from public key length ($800$, $1184$, or $1568$ bytes).
- `ecu_ecdh` (Hybrid Extension):
  - `hybrid_keypair(x25519_mlkem768)`: Generate composite public key ($32 + 1184 = 1216$ bytes) and private key ($32 + 2400 = 2432$ bytes).
  - `hybrid_encaps/1`: Produce combined dual-layer shared secret and hybrid ciphertext ($32 + 1088 = 1120$ bytes).
  - `hybrid_decaps/2`: Decapsulate and combine X25519 ECDH and ML-KEM-768 shared secrets via SHA3-256.

### ML-DSA (FIPS 204) Digital Signatures

- `ecu_ml_dsa`: Pure-Erlang implementation of the NIST Module-Lattice-Based Digital Signature Standard (FIPS 204):
  - Full support for `ml_dsa_44` (NIST Category 2), `ml_dsa_65` (NIST Category 3), and `ml_dsa_87` (NIST Category 5).
  - `keypair/1`: Fresh `#{public => PK, secret => SK}` keypair generation using strong random bytes.
  - `keypair_from_seed/2`: Deterministic keypair generation from a 32-byte seed $\xi$ per FIPS 204 Algorithm 1.
  - `sign/2,3`: Randomized digital signature generation (recommended per FIPS 204 §5.3) with optional context string ($0 \le |C| \le 255$).
  - `sign_deterministic/2,3`: Deterministic digital signature generation with optional context string.
  - `verify/3,4`: Signature verification with optional context string.
  - `parameter_set/1`: Identify parameter set (`ml_dsa_44 | ml_dsa_65 | ml_dsa_87`) from public key, secret key, or signature binary size.

### SLH-DSA (FIPS 205) Stateless Hash-Based Signatures

- `ecu_slh_dsa`: Pure-Erlang implementation of the NIST Stateless Hash-Based Digital Signature Standard (FIPS 205):
  - Full support for all 12 FIPS 205 parameter sets:
    - SHA-2 family: `slh_dsa_sha2_128s`, `slh_dsa_sha2_128f`, `slh_dsa_sha2_192s`, `slh_dsa_sha2_192f`, `slh_dsa_sha2_256s`, `slh_dsa_sha2_256f`.
    - SHAKE family: `slh_dsa_shake_128s`, `slh_dsa_shake_128f`, `slh_dsa_shake_192s`, `slh_dsa_shake_192f`, `slh_dsa_shake_256s`, `slh_dsa_shake_256f`.
  - `keypair/1`: Fresh `#{public => PK, secret => SK}` keypair generation using strong random bytes.
  - `keypair_from_seed/2`, `keypair_from_seeds/4`: Deterministic keypair generation from seed binaries per FIPS 205 Algorithm 16.
  - `sign/2,3,4`: Randomized digital signature generation (hedged per FIPS 205 Algorithm 17) with optional context string ($0 \le |C| \le 255$) and optional auxiliary randomness.
  - `sign_deterministic/2,3,4`: Deterministic digital signature generation with optional context string.
  - `verify/3,4,5`: Signature verification per FIPS 205 Algorithm 19 with optional context string.
  - `parameter_set/1`: Identify parameter set from public key, secret key, or signature binary size.
  - Performance: SHA-2 parameter sets (`slh_dsa_sha2_128f` ~346 ms) execute ~24× faster on the BEAM than SHAKE parameter sets due to 64-bit bignum representation in Keccak; SHA-2 is recommended for pure-Erlang environments.

### Pairing-Friendly Cryptography: BLS12-381

- `ecu_bls12_381`: Group arithmetic in $\mathbb{G}_1$ (over $\mathbb{F}_q$) and $\mathbb{G}_2$ (over $\mathbb{F}_{q^2}$) with Jacobian projective coordinates, point compression, and subgroup validation.
- `ecu_bls12_381_fp`: Pure-Erlang arithmetic across tower fields $\mathbb{F}_q, \mathbb{F}_{q^2}, \mathbb{F}_{q^6}, \mathbb{F}_{q^{12}}$.
- `ecu_bls12_381_pairing`: Optimal Ate pairing $e: \mathbb{G}_1 \times \mathbb{G}_2 \rightarrow \mathbb{G}_T$ and multi-Miller loop accumulation over field extension $\mathbb{F}_{q^{12}}$.
- `ecu_bls12_381_sig`: BLS signature generation, non-interactive aggregation, and verification (`min_pk` and `min_sig` ciphersuites per draft-irtf-cfrg-bls-signature).

### Pairing-Friendly Cryptography: BN254 (alt_bn128)

- `ecu_bn254`: Group arithmetic in $\mathbb{G}_1$ (over $\mathbb{F}_p$) and $\mathbb{G}_2$ (over extension field $\mathbb{F}_{p^2}$ with $u^2 + 1 = 0$):
  - $\mathbb{G}_1$ arithmetic: Point addition (`g1_add/2`), doubling (`g1_double/1`), scalar multiplication (`g1_mul/2`), multi-scalar multiplication (`g1_msm/2`), and negation (`g1_neg/1`) using Jacobian coordinates.
  - $\mathbb{G}_2$ arithmetic: Point addition (`g2_add/2`), doubling (`g2_double/1`), scalar multiplication (`g2_mul/2`), multi-scalar multiplication (`g2_msm/2`), and negation (`g2_neg/1`) using Jacobian coordinates over $\mathbb{F}_{p^2}$ with $D$-type twist curve $y^2 = x^3 + 3/(u + 9)$.
  - Point compression and serialization: 32-byte $\mathbb{G}_1$ compressed (`g1_compress/1`, `g1_decompress/1`) and 64-byte $\mathbb{G}_2$ compressed (`g2_compress/1`, `g2_decompress/1`), plus 64-byte $\mathbb{G}_1$ and 128-byte $\mathbb{G}_2$ uncompressed formats matching Ethereum EVM precompiles (`0x06`, `0x07`, `0x08` / EIP-196 & EIP-197).
  - Validation: Complete curve equation validation (`g1_on_curve/1`, `g2_on_curve/1`), subgroup membership testing (`g1_in_subgroup/1`, `g2_in_subgroup/1`), and identity checks.
- `ecu_bn254_fp`: Pure-Erlang arithmetic across tower extension fields:
  - Base field $\mathbb{F}_p$ ($p = 21888242871839275222246405745257275088548364400416034343698204186575808495617$).
  - Quadratic extension $\mathbb{F}_{p^2} = \mathbb{F}_p[u] / (u^2 + 1)$ with Karatsuba multiplication and complex squaring.
  - Sextic extension $\mathbb{F}_{p^6} = \mathbb{F}_{p^2}[v] / (v^3 - \xi)$ where $\xi = u + 9$, utilizing Chung-Hasan SQR3 squaring.
  - Dodecic extension $\mathbb{F}_{p^{12}} = \mathbb{F}_{p^6}[w] / (w^2 - v)$.
  - Frobenius endomorphisms $\pi, \pi^2, \pi^3$ precomputed for fast line evaluation and final exponentiation.
- `ecu_bn254_pairing`: Optimal Ate pairing over BN254:
  - `pairing/2`: Compute optimal Ate pairing $e(P, Q) \in \mathbb{G}_T$ where $P \in \mathbb{G}_1, Q \in \mathbb{G}_2$.
  - `miller_loop/2`: Miller loop with 65-iteration loop based on BN parameter $t = 4965661362426376488$ ($6t + 2$), with non-zero line evaluations in projective coordinates and Frobenius endomorphism addition steps.
  - `final_exponentiation/1`: Fast final exponentiation $(p^{12} - 1) / r$ decomposed into easy part $((p^6 - 1)(p^2 + 1))$ and hard part via cyclotomic squaring and Frobenius automorphisms.
  - `pairing_check/1`: Multi-pairing check $\prod_{i=1}^k e(P_i, Q_i) == 1$ accumulating all pairs in a single multi-Miller loop prior to a single final exponentiation.

### Groth16 zk-SNARK Proof Verification (BLS12-381 & BN254)

- `ecu_groth16`: Pure-Erlang Groth16 zero-knowledge proof verifier supporting both BLS12-381 and BN254 (alt_bn128):
  - `verify/3,4`: Verify Groth16 proof against verification key and public inputs using a 4-pair multi-Miller loop and single final exponentiation. Accepts optional `Curve` parameter (`bls12_381` [default] or `bn254`).
  - `verify_batch/2,3`: Randomized batch verification aggregating $N$ proofs into $N + 3$ pairings via 128-bit random weights (~2.5×–2.9× higher throughput).
  - Flexible point codecs supporting records (`#groth16_proof{}`, `#groth16_vk{}`), maps, tuples, compressed points (48B/96B for BLS12-381; 32B/64B for BN254), and uncompressed points (96B/192B for BLS12-381; 64B/128B EVM format for BN254).
  - Full EVM / SnarkJS / Circom compatibility: Public inputs, verification keys, and proofs exported from SnarkJS can be verified directly without conversion.
  - Strict validation: Rejects points not on curve, points not in prime subgroup, points at infinity, and out-of-range scalars.
- `ecu_poseidon`: Pure-Erlang implementation of the Poseidon algebraic hash function and Hades permutation:
  - `hash3/2`: Hash two elements over BLS12-381 ($t=3$, $R_F=8, R_P=57$, total 65 rounds: 4 full, 57 partial, 4 full). 100% compatible with Aeternity FATE VM opcode and `aeu_poseidon:hash3/2`.
  - `hash3/3`: Hash two elements specifying curve (`bls12_381` or `bn254`).
  - `hash/1,2`: Hash arbitrary $N \in [1, 8]$ field elements ($t \in [2, 9]$) using the Hades permutation with element-wise round constant addition and Cauchy MDS matrix mixing.
  - `hash_binary/1,2`: Big-endian 32-byte binary hashing with strict canonical boundary validation ($< q$).
  - `permute/2`: Evaluate the Hades permutation on full state vectors.
  - Optimized implementation: Unrolled constants table, register-allocated tail-recursive loop, zero heap allocations for `hash3/2,3` (~90 µs/hash, >10,800 hashes/sec in pure Erlang).
- `ecu_poseidon_constants`: Precomputed round constants and MDS matrices for BLS12-381 (from canonical Grain LFSR) and BN254 (matching Circomlib).
- `ecu_babyjubjub`: Pure-Erlang implementation of the BabyJubjub twisted Edwards curve (EIP-2494) and Poseidon EdDSA signatures:
  - `add/2`, `double/1`, `neg/1`, `mul/2`, `mul_base8/1`: Complete twisted Edwards arithmetic in projective coordinates over the scalar field of BN254.
  - `compress/1`, `decompress/1`: 32-byte point compression and decompression with Tonelli-Shanks modular square root.
  - `is_on_curve/1`, `is_in_subgroup/1`: Curve equation validation and prime-order subgroup membership checks.
  - `edwards_to_montgomery/1`, `montgomery_to_edwards/1`, `montgomery_ladder/2`: Birational Montgomery mapping and constant-time $u$-only Montgomery ladder.
  - `keypair/0,1`, `derive_public_key/1`: Key generation and derivation matching Circom / SnarkJS conventions.
  - `sign/2`, `verify/3`: Circom-compatible EdDSA signing and verification with Poseidon hash (`EdDSAPoseidonVerifier.circom`).
- `ecu_babyjubjub_pedersen`: Pure-Erlang Circomlib-compatible Pedersen Hash and Commitments over BabyJubjub:
  - `base/1`, `bases/0`: The 10 canonical generator base points defined in `pedersen.circom`.
  - `hash/1,2`, `hash_compressed/1`: 4-bit window Pedersen hashing supporting affine `{X, Y}`, 32-byte compressed, or `x_only` field element outputs up to 2000 bits (10 segments).
  - `commit/2,3`: Pedersen vector/scalar commitments with default or custom blinding generators.
- `ecu_jubjub`: Pure-Erlang implementation of the Jubjub twisted Edwards curve over BLS12-381 $\mathbb{F}_q$ (Zcash ZIP 216 / ZIP 243):
  - `add/2`, `double/1`, `neg/1`, `mul/2`, `mul_base8/1`: Complete twisted Edwards group operations with $a = -1, d = -(10240/10241) \pmod q$.
  - `compress/1`, `decompress/1`: ZIP 216 strict canonical point compression and decompression with Tonelli-Shanks square root.
  - `edwards_to_montgomery/1`, `montgomery_to_edwards/1`, `montgomery_ladder/2`: Montgomery birational equivalence ($A=40962, B=-40964$) and $u$-only ladder scalar multiplication.
- `ecu_blake512`: Pure-Erlang implementation of the BLAKE-512 cryptographic hash function used for BabyJubjub key expansion and nonces.
- `ecu_poly`: Finite field polynomial arithmetic over prime fields (defaulting to BLS12-381 $r$):
  - `eval/2,3`: Horner's method polynomial evaluation in $O(d)$.
  - `add/2,3`, `sub/2,3`, `mul_scalar/2,3`, `mul/2,3`: Dense polynomial arithmetic and convolution.
  - `divide_by_linear/2,3`: Ruffini's rule / synthetic division computing $Q(x) = \frac{P(x) - y}{x - z}$ in $O(d)$.
- `ecu_kzg`: Pure-Erlang Kate-Zaverucha-Goldberg (KZG) polynomial commitment scheme and EIP-4844 point evaluation:
  - `setup/2`: Structured Reference String (SRS / Powers of Tau) generator in $\mathbb{G}_1$ and $\mathbb{G}_2$.
  - `commit/2`, `commit_compressed/2`: Linear-combination polynomial commitment $C = [P(\tau)]_1 \in \mathbb{G}_1$ using windowed Straus multi-scalar multiplication.
  - `create_proof/3`, `create_proof_compressed/3`: Evaluation opening proof $\pi = [Q(\tau)]_1$ showing $P(z) = y$.
  - `verify/5`, `verify_compressed/5`: Single evaluation proof verification via 2-pair Miller loop: $e(C - [y]_1, [1]_2) = e(\pi, [\tau]_2 - [z]_2)$.
  - `verify_batch/2`: Randomized batch verification aggregating $N$ proofs into a single 2-pairing check using 128-bit random weights.
  - `point_evaluation/2`: Ethereum EIP-4844 Point Evaluation Precompile interface (address `0x0A`, 192-byte input).
- `ecu_circom`: Pure-Erlang Circom 2 and ZoKrates R1CS & Witness Tooling:
  - `parse_r1cs/1`, `serialize_r1cs/1`: Parse and serialize Circom 2 `.r1cs` binary format (header, constraints, wire-to-label map, custom sections).
  - `parse_wtns/1`, `serialize_wtns/1,2,3`: Parse and serialize Circom `.wtns` witness binary format.
  - `check_constraints/2`, `is_satisfied/2`: Verify witness vectors against all R1CS constraints with $O(1)$ wire lookups: $(A \cdot W) \times (B \cdot W) \equiv (C \cdot W) \pmod q$.
  - `eval_lc/3`: Modular evaluation of linear combinations.
  - `extract_public_inputs/2`, `extract_public_inputs_map/2`: Extract public inputs and outputs formatted directly for `ecu_groth16:verify/3,4`.
  - `new_r1cs/2,3`, `new_wtns/2,3`: Programmatic constructors for circuits and witnesses.
  - `default_prime/0,1`: Circuit field modulus accessors for BN254 and BLS12-381 scalar fields.
- `ecu_plonk`: Pure-Erlang Universal PLONK zk-SNARK verifier:
  - `verify/3,4`: Universal proof verification over BN254 and BLS12-381.
  - `parse_vk/1,2`, `parse_proof/1,2`, `parse_public_inputs/1,2`: Parsers supporting records, JSON maps, and binaries.
  - Strict subgroup validation on all G1 commitments and G2 SRS key $X_2$.
  - Keccak-256 Fiat-Shamir transcript generation, Lagrange and public input evaluations, linearized polynomial accumulation, and single 2-pairing check.

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

### Measured Performance (`make bench`, Apple Silicon)

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
| **ml_kem_512 keypair** | — | **1.11 ms** | — | — | — |
| **ml_kem_512 encaps** | — | **1.30 ms** | — | — | — |
| **ml_kem_512 decaps** | — | **1.91 ms** | — | — | — |
| **ml_kem_768 keypair** | — | **1.87 ms** | — | 42.1 µs (crypto / OpenSSL) | 44.4× |
| **ml_kem_768 encaps** | — | **1.95 ms** | — | 36.8 µs (crypto / OpenSSL) | 53.0× |
| **ml_kem_768 decaps** | — | **2.76 ms** | — | 108 µs (crypto / OpenSSL) | 25.5× |
| **x25519_mlkem768 hybrid keypair** | — | **2.45 ms** | — | — | — |
| **x25519_mlkem768 hybrid encaps** | — | **3.20 ms** | — | — | — |
| **x25519_mlkem768 hybrid decaps** | — | **3.28 ms** | — | — | — |
| **ml_dsa_44 keypair** | — | **3.84 ms** | — | — | — |
| **ml_dsa_44 sign** | — | **26.95 ms** | — | — | — |
| **ml_dsa_44 verify** | — | **3.65 ms** | — | — | — |
| **ml_dsa_65 keypair** | — | **5.68 ms** | — | 244 µs (crypto / OpenSSL) | 23.3× |
| **ml_dsa_65 sign** | — | **45.21 ms** | — | 2.32 ms (crypto / OpenSSL) | 19.5× |
| **ml_dsa_65 verify** | — | **5.28 ms** | — | 449 µs (crypto / OpenSSL) | 11.8× |
| **slh_dsa_sha2_128f keypair** | — | **17.3 ms** | — | 446 µs (crypto / OpenSSL) | 38.9× |
| **slh_dsa_sha2_128f sign** | — | **346 ms** | — | 9.87 ms (crypto / OpenSSL) | 35.1× |
| **slh_dsa_sha2_128f verify** | — | **20.9 ms** | — | 563 µs (crypto / OpenSSL) | 37.1× |
| **slh_dsa_shake_128f keypair** | 712 ms | **355 ms** | **2.00×** | 12.5 ms (crypto / OpenSSL) | 28.4× |
| **slh_dsa_shake_128f sign** | 16.37 s | **8.20 s** | **2.00×** | 27.2 ms (crypto / OpenSSL) | 301× |
| **slh_dsa_shake_128f verify** | 968 ms | **470 ms** | **2.06×** | 1.74 ms (crypto / OpenSSL) | 270× |
| **groth16 verify (BLS12-381)** | — | **25.2 ms** | — | — | — |
| **groth16 batch verify (4 proofs, BLS12-381)** | — | **9.9 ms/proof** | **~2.5×** | — | — |
| **bn254 G1 point add** | — | **3.10 µs** | — | 3.44 µs (Arkworks Rust NIF) | **1.11× faster** |
| **bn254 G1 scalar mul** | — | **1.03 ms** | — | 51.0 µs (Arkworks Rust NIF) | 20.1× |
| **bn254 G2 point add** | — | **22.2 µs** | — | 204 µs (Arkworks Rust NIF) | **9.2× faster** |
| **bn254 G2 scalar mul** | — | **3.08 ms** | — | 335 µs (Arkworks Rust NIF) | 9.2× |
| **bn254 optimal ate pairing** | — | **18.4 ms** | — | 679 µs (Arkworks Rust NIF) | 27.0× |
| **groth16 verify (BN254)** | — | **26.2 ms** | — | 1.59 ms (Arkworks Rust NIF) | 16.5× |
| **groth16 batch verify (4 proofs, BN254)** | — | **9.1 ms/proof** | **~2.9×** | — | — |
| **poseidon hash3 (BN254)** | — | **115 µs** | — | 21.2 µs (light-poseidon Rust NIF) | 5.4× |
| **babyjubjub point add** | — | **14.5 µs** | — | 1.31 ms (babyjubjub-rs Rust NIF)* | **90× faster** |
| **babyjubjub scalar mul** | — | **259 µs** | — | 684 µs (babyjubjub-rs Rust NIF) | **2.64× faster** |
| **babyjubjub point compress** | — | **0.09 µs** | — | — | — |
| **babyjubjub point decompress** | — | **137 µs** | — | 645 µs (babyjubjub-rs Rust NIF) | **4.71× faster** |
| **babyjubjub eddsa sign (Poseidon)** | — | **2.64 ms** | — | 276 µs (babyjubjub-rs Rust NIF) | 9.57× |
| **babyjubjub eddsa verify (Poseidon)** | — | **2.74 ms** | — | 1.56 ms (babyjubjub-rs Rust NIF) | 1.76× |
| **poly eval (deg 16, Horner)** | — | **1.41 µs** | — | — | — |
| **poly synthetic division (deg 16, Ruffini)** | — | **1.49 µs** | — | — | — |
| **kzg commit (deg 16, G1)** | — | **213 µs** | — | 502 µs (blst Rust NIF)* | **2.36× faster** |
| **kzg create proof (deg 16)** | — | **3.93 ms** | — | 479 µs (blst Rust NIF) | 8.21× |
| **kzg verify proof (BLS12-381)** | — | **21.7 ms** | — | 948 µs (blst Rust NIF) | 22.9× |
| **kzg batch verify (4 proofs, BLS12-381)** | — | **8.83 ms/proof** | **~2.45×** | 524 µs/proof (blst Rust NIF) | 16.9× |
| **kzg eip4844 point evaluation (192B)** | — | **21.8 ms** | — | 951 µs (blst Rust NIF) | 22.9× |
| **circom r1cs parse (100 constraints)** | — | **29.8 µs** | — | 14.8 µs (r1cs-file Rust NIF) | 2.01× |
| **circom r1cs serialize (100 constraints)** | — | **29.1 µs** | — | 17.3 µs (r1cs-file Rust NIF) | 1.68× |
| **circom wtns parse (104 wires)** | — | **5.82 µs** | — | 0.68 µs (wtns-file Rust NIF) | 8.56× |
| **circom wtns serialize (104 wires)** | — | **3.96 µs** | — | 1.32 µs (wtns-file Rust NIF) | 3.00× |
| **circom check constraints (100 constraints)** | — | **29.9 µs** | — | 94.0 µs (Rust NIF) | **3.14× faster** |
| **plonk verify (BN254)** | — | **40.3 ms** | — | 1.92 ms (arkworks Rust NIF) | 20.96× |
| **vrf prove (Ed25519 Elligator 2)** | — | **1.88 ms** | — | 111 µs (vrf-rfc9381 Rust NIF) | 16.9× |
| **vrf verify (Ed25519 Elligator 2)** | — | **2.12 ms** | — | 137 µs (vrf-rfc9381 Rust NIF) | 15.5× |
| **vrf prove (secp256k1 TAI)** | — | **933 µs** | — | 179 µs (vrf_fun Rust NIF) | 5.2× |
| **vrf verify (secp256k1 TAI)** | — | **1.72 ms** | — | 144 µs (vrf_fun Rust NIF) | 12.0× |
| **vrf prove (secp256k1 SSWU)** | — | **926 µs** | — | — | — |
| **vrf verify (secp256k1 SSWU)** | — | **1.73 ms** | — | — | — |

*Notes:*
- *Pure Erlang point addition is faster than `enacl` because calling the NIF incurs marshalling and point decompression overhead.*
- *Pure Erlang `secp256k1` base-point scalar multiplication is faster than OpenSSL due to the precomputed 1,024-entry comb table.*
- *BIP-340 Schnorr, Keccak-256, and Hash-to-Curve reference benchmarks use an optional test NIF (`k256`, `sha3`, `hash2curve`) buildable via `make rustcrypto_reference`.*
- *FROST threshold reference benchmarks use optional RFC 9591 test NIFs (Zcash Foundation `frost-core` crates) buildable via `make frost_reference`.*
- *MuSig2 reference benchmarks use the official BIP-327 Rust crate buildable via `make musig2_reference`.*
- *BN254 elliptic curve and Groth16 reference benchmarks use an optional Arkworks test NIF (`crates/bn254_nif`) buildable via `make reference_nifs`.*
- *BabyJubjub and Circom EdDSA reference benchmarks use an optional Rust test NIF (`crates/babyjubjub_nif`) wrapping `babyjubjub-rs`, buildable via `make babyjubjub_reference`.*
- *KZG polynomial commitment reference benchmarks use an optional test NIF (`crates/bls12_381_nif`) wrapping Supranational `blst`, buildable via `make bls12_381_reference`.*
- *Circom R1CS and WTNS reference benchmarks use an optional test NIF (`crates/circom_nif`) wrapping official `r1cs-file` and `wtns-file` crates, buildable via `make circom_reference`.*
- *PLONK universal zk-SNARK reference benchmarks use an optional Arkworks test NIF (`crates/plonk_nif`) buildable via `make plonk_reference`.*
- *VRF (RFC 9381) reference benchmarks use an optional Rust test NIF (`crates/vrf_nif`) wrapping `vrf-rfc9381` and `vrf_fun`, buildable via `make vrf_reference`.*
- *Pure Erlang SLH-DSA signing executes ~80,000 hash operations. SHA-2 parameter sets (`slh_dsa_sha2_128f` at 346 ms) are ~24× faster than SHAKE parameter sets (`slh_dsa_shake_128f` at 8.20 s) because Keccak-f[1600] operates on 64-bit uints that exceed BEAM's 60-bit `smallint` range and lack SIMD vectorization. In contrast, native OpenSSL uses multi-buffer SIMD (AVX2/AVX-512) to compute 4–8 Keccak states concurrently, reaching 27.2 ms.*
- *All reference NIFs can be built together using `make reference_nifs`.*

### Automated Benchmarking CLI

`ec_utils` includes a dedicated benchmarking tool (`bin/bench` / `make bench`) for performance profiling and regression detection:

```bash
# Run all benchmarks with default duration (250 ms/op)
make bench

# Filter by cryptographic group or pattern
./bin/bench ed25519
./bin/bench ml_dsa
./bin/bench secp256k1

# Save baseline snapshot
make bench-save        # writes baseline.json

# Compare current performance against baseline
make bench-compare     # compares against baseline.json with regression alerts
```


Roadmap
-------

See [ROADMAP.md](ROADMAP.md) for details on completed milestones and planned cryptographic extensions, including:
- **Quantum-Resistant Cryptography**: ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) `[Completed]`.
- **Multi-Party & Threshold Signatures**: FROST (RFC 9591 on Ed25519, Ed448, secp256k1, BIP-340) and MuSig2 (BIP-327) `[Completed]`.
- **Hash-to-Curve & Verifiable Random Functions**: RFC 9380 curve hashing & RFC 9381 ECVRF on Ed25519 and secp256k1 `[Completed]`.
- **HD Wallets & Mnemonics**: BIP-32, SLIP-0010, AEX-10, and BIP-39 `[Completed]`.
- **Native Cryptographic Independence**: 100% pure-Erlang fallback for hashing, HMAC, and CSPRNG entropy via `ecu_compat` and `ecu_entropy` `[Completed]`.
- **Pairing-Friendly Cryptography, zk-SNARKs & Poseidon (BLS12-381 & BN254)**: BLS signatures, BN254 / BLS12-381 curve arithmetic & optimal Ate pairings, Groth16 proof verification, and Poseidon algebraic hashing `[Completed]`.

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
