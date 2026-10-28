%%% File        : ecdh_eqc.erl
%%% Description : QuickCheck properties for ecu_ecdh (cross-checked with OTP crypto)
-module(ecdh_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_secp256k1.hrl").

%% --- Generators

gen_x25519_seed() ->
  noshrink(binary(32)).

gen_x448_seed() ->
  noshrink(binary(56)).

gen_secp256k1_privkey() ->
  ?LET(X, choose(1, ?N - 1), <<X:256>>).

%% --- Properties

%% X25519 Diffie-Hellman symmetry: ECDH(Alice_Pub, Bob_Priv) == ECDH(Bob_Pub, Alice_Priv)
prop_x25519_symmetry() ->
  ?FORALL({SeedA, SeedB}, {gen_x25519_seed(), gen_x25519_seed()},
  begin
    {PubA, PrivA} = ecu_ecdh:keypair_from_seed(x25519, SeedA),
    {PubB, PrivB} = ecu_ecdh:keypair_from_seed(x25519, SeedB),
    SecA = ecu_ecdh:compute_key(x25519, PubB, PrivA),
    SecB = ecu_ecdh:compute_key(x25519, PubA, PrivB),
    equals(SecA, SecB)
  end).

%% X25519 matches OTP crypto:compute_key oracle
prop_x25519_matches_crypto() ->
  ?FORALL({SeedA, SeedB}, {gen_x25519_seed(), gen_x25519_seed()},
  begin
    {_PubA, PrivA} = ecu_ecdh:keypair_from_seed(x25519, SeedA),
    {PubB, _PrivB} = ecu_ecdh:keypair_from_seed(x25519, SeedB),
    OurSec = ecu_ecdh:compute_key(x25519, PubB, PrivA),
    CryptoSec = crypto:compute_key(ecdh, PubB, PrivA, x25519),
    equals(OurSec, CryptoSec)
  end).

%% X448 Diffie-Hellman symmetry
prop_x448_symmetry() ->
  ?FORALL({SeedA, SeedB}, {gen_x448_seed(), gen_x448_seed()},
  begin
    {PubA, PrivA} = ecu_ecdh:keypair_from_seed(x448, SeedA),
    {PubB, PrivB} = ecu_ecdh:keypair_from_seed(x448, SeedB),
    SecA = ecu_ecdh:compute_key(x448, PubB, PrivA),
    SecB = ecu_ecdh:compute_key(x448, PubA, PrivB),
    equals(SecA, SecB)
  end).

%% X448 matches OTP crypto:compute_key oracle
prop_x448_matches_crypto() ->
  ?FORALL({SeedA, SeedB}, {gen_x448_seed(), gen_x448_seed()},
  begin
    {_PubA, PrivA} = ecu_ecdh:keypair_from_seed(x448, SeedA),
    {PubB, _PrivB} = ecu_ecdh:keypair_from_seed(x448, SeedB),
    OurSec = ecu_ecdh:compute_key(x448, PubB, PrivA),
    CryptoSec = crypto:compute_key(ecdh, PubB, PrivA, x448),
    equals(OurSec, CryptoSec)
  end).

%% secp256k1 Diffie-Hellman symmetry
prop_secp256k1_symmetry() ->
  ?FORALL({PrivA, PrivB}, {gen_secp256k1_privkey(), gen_secp256k1_privkey()},
  begin
    PubA = ecu_ecdsa:private_to_public(secp256k1, PrivA),
    PubB = ecu_ecdsa:private_to_public(secp256k1, PrivB),
    SecA = ecu_ecdh:compute_key(secp256k1, PubB, PrivA),
    SecB = ecu_ecdh:compute_key(secp256k1, PubA, PrivB),
    equals(SecA, SecB)
  end).

%% secp256k1 matches OTP crypto:compute_key oracle (with both compressed and uncompressed peer pubkeys)
prop_secp256k1_matches_crypto() ->
  ?FORALL({PrivA, PrivB}, {gen_secp256k1_privkey(), gen_secp256k1_privkey()},
  begin
    PubB = ecu_ecdsa:private_to_public(secp256k1, PrivB),
    OurSec = ecu_ecdh:compute_key(secp256k1, PubB, PrivA),
    CryptoSec = crypto:compute_key(ecdh, PubB, PrivA, secp256k1),

    {XB, YB} = ecu_secp256k1:decompress(PubB),
    UncompressedB = <<4:8, XB:256, YB:256>>,
    OurSecUncompressed = ecu_ecdh:compute_key(secp256k1, UncompressedB, PrivA),

    conjunction([
      {matches_crypto, equals(OurSec, CryptoSec)},
      {matches_uncompressed, equals(OurSec, OurSecUncompressed)}
    ])
  end).

%% Birational equivalence: Ed25519 keypair converted to X25519 produces valid matching shared secret
prop_ed25519_birational() ->
  ?FORALL({SeedA, SeedB}, {gen_x25519_seed(), gen_x25519_seed()},
  begin
    KPA = ecu_eddsa:sign_seed_keypair(SeedA),
    KPB = ecu_eddsa:sign_seed_keypair(SeedB),

    XPubA = ecu_ecdh:ed25519_public_to_x25519(maps:get(public, KPA)),
    XPrivA = ecu_ecdh:ed25519_secret_to_x25519(maps:get(secret, KPA)),

    XPubB = ecu_ecdh:ed25519_public_to_x25519(maps:get(public, KPB)),
    XPrivB = ecu_ecdh:ed25519_secret_to_x25519(maps:get(secret, KPB)),

    SecA = ecu_ecdh:compute_key(x25519, XPubB, XPrivA),
    SecB = ecu_ecdh:compute_key(x25519, XPubA, XPrivB),

    equals(SecA, SecB)
  end).
