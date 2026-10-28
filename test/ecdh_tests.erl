%%% File        : ecdh_tests.erl
%%% Author      : Hans Svensson
%%% Description : Unit tests and RFC 7748 test vectors for ecu_ecdh
%%% Created     : 28 Oct 2026 by Hans Svensson
-module(ecdh_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

%% --- RFC 7748 Section 6.1 (X25519 Test Vectors)

rfc7748_x25519_alice_bob_test() ->
  PrivA = ecu_misc:hex_to_bin("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
  ExpPubA = ecu_misc:hex_to_bin("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
  PubA = ecu_ecdh:x25519(PrivA, <<9:256/little>>),
  ?assertEqual(ExpPubA, PubA),

  PrivB = ecu_misc:hex_to_bin("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
  ExpPubB = ecu_misc:hex_to_bin("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
  PubB = ecu_ecdh:x25519(PrivB, <<9:256/little>>),
  ?assertEqual(ExpPubB, PubB),

  ExpShared = ecu_misc:hex_to_bin("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
  SharedA = ecu_ecdh:compute_key(x25519, PubB, PrivA),
  SharedB = ecu_ecdh:compute_key(x25519, PubA, PrivB),
  ?assertEqual(ExpShared, SharedA),
  ?assertEqual(ExpShared, SharedB),
  ?assertEqual(SharedA, SharedB).

rfc7748_x25519_iterative_test() ->
  KInit = <<9:256/little>>,
  UInit = <<9:256/little>>,
  Loop = fun F(0, K, _U) -> K;
             F(N, K, U) ->
               NextK = ecu_ecdh:x25519(K, U),
               F(N - 1, NextK, K)
         end,

  %% After 1 iteration
  Res1 = Loop(1, KInit, UInit),
  Exp1 = ecu_misc:hex_to_bin("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"),
  ?assertEqual(Exp1, Res1),

  %% After 1,000 iterations
  Res1000 = Loop(1000, KInit, UInit),
  Exp1000 = ecu_misc:hex_to_bin("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"),
  ?assertEqual(Exp1000, Res1000).

%% --- RFC 7748 Section 6.2 (X448 Test Vectors)

rfc7748_x448_alice_bob_test() ->
  PrivA = ecu_misc:hex_to_bin("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf5"
                             "74a9419744897391006382a6f127ab1d9ac2d8c0a598726b"),
  ExpPubA = ecu_misc:hex_to_bin("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
                               "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"),
  PubA = ecu_ecdh:x448(PrivA, <<5:448/little>>),
  ?assertEqual(ExpPubA, PubA),

  PrivB = ecu_misc:hex_to_bin("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
                             "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"),
  ExpPubB = ecu_misc:hex_to_bin("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
                               "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"),
  PubB = ecu_ecdh:x448(PrivB, <<5:448/little>>),
  ?assertEqual(ExpPubB, PubB),

  ExpShared = ecu_misc:hex_to_bin("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
                                 "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"),
  SharedA = ecu_ecdh:compute_key(x448, PubB, PrivA),
  SharedB = ecu_ecdh:compute_key(x448, PubA, PrivB),
  ?assertEqual(ExpShared, SharedA),
  ?assertEqual(ExpShared, SharedB),
  ?assertEqual(SharedA, SharedB).

rfc7748_x448_iterative_test() ->
  KInit = <<5:448/little>>,
  UInit = <<5:448/little>>,
  Loop = fun F(0, K, _U) -> K;
             F(N, K, U) ->
               NextK = ecu_ecdh:x448(K, U),
               F(N - 1, NextK, K)
         end,

  %% After 1 iteration
  Res1 = Loop(1, KInit, UInit),
  Exp1 = ecu_misc:hex_to_bin("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a"
                             "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"),
  ?assertEqual(Exp1, Res1),

  %% After 1,000 iterations
  Res1000 = Loop(1000, KInit, UInit),
  Exp1000 = ecu_misc:hex_to_bin("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4"
                               "af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"),
  ?assertEqual(Exp1000, Res1000).

%% --- secp256k1 ECDH Tests

secp256k1_ecdh_test() ->
  {PubA, PrivA} = ecu_ecdh:keypair(secp256k1),
  {PubB, PrivB} = ecu_ecdh:keypair(secp256k1),

  SecretA = ecu_ecdh:compute_key(secp256k1, PubB, PrivA),
  SecretB = ecu_ecdh:compute_key(secp256k1, PubA, PrivB),
  ?assertEqual(SecretA, SecretB),
  ?assertEqual(32, byte_size(SecretA)),

  %% Cross-check with OTP crypto
  CryptoSecA = crypto:compute_key(ecdh, PubB, PrivA, secp256k1),
  ?assertEqual(CryptoSecA, SecretA).

secp256k1_uncompressed_pubkey_test() ->
  {PubA, PrivA} = ecu_ecdh:keypair(secp256k1),
  {PubB, PrivB} = ecu_ecdh:keypair(secp256k1),

  {XB, YB} = ecu_secp256k1:decompress(PubB),
  UncompressedB = <<4:8, XB:256, YB:256>>,

  SecretA = ecu_ecdh:compute_key(secp256k1, UncompressedB, PrivA),
  SecretB = ecu_ecdh:compute_key(secp256k1, PubA, PrivB),
  ?assertEqual(SecretA, SecretB).

%% --- Birational Equivalence Tests (Ed25519 to X25519)

ed25519_to_x25519_conversion_test() ->
  Seed = crypto:strong_rand_bytes(32),
  KP = ecu_eddsa:sign_seed_keypair(Seed),
  EdPK = maps:get(public, KP),
  EdSK = maps:get(secret, KP),

  XPub = ecu_ecdh:ed25519_public_to_x25519(EdPK),
  XPriv = ecu_ecdh:ed25519_secret_to_x25519(EdSK),

  %% Derived public key from converted private key must match converted public key
  DerivedXPub = ecu_ecdh:x25519(XPriv, <<9:256/little>>),
  ?assertEqual(XPub, DerivedXPub),

  %% Key exchange between two converted keypairs must match
  Seed2 = crypto:strong_rand_bytes(32),
  KP2 = ecu_eddsa:sign_seed_keypair(Seed2),
  XPub2 = ecu_ecdh:ed25519_public_to_x25519(maps:get(public, KP2)),
  XPriv2 = ecu_ecdh:ed25519_secret_to_x25519(maps:get(secret, KP2)),

  Secret1 = ecu_ecdh:compute_key(x25519, XPub2, XPriv),
  Secret2 = ecu_ecdh:compute_key(x25519, XPub, XPriv2),
  ?assertEqual(Secret1, Secret2).

%% --- Keypair Generation and Seed Tests

keypair_generation_test() ->
  lists:foreach(fun(Curve) ->
    {Pub1, Priv1} = ecu_ecdh:keypair(Curve),
    {Pub2, Priv2} = ecu_ecdh:keypair(Curve),
    ?assertNotEqual(Priv1, Priv2),
    ?assertNotEqual(Pub1, Pub2),
    Sec1 = ecu_ecdh:compute_key(Curve, Pub2, Priv1),
    Sec2 = ecu_ecdh:compute_key(Curve, Pub1, Priv2),
    ?assertEqual(Sec1, Sec2)
  end, [x25519, x448, secp256k1]).

keypair_from_seed_deterministic_test() ->
  Seed256 = crypto:strong_rand_bytes(32),
  {PubA1, PrivA1} = ecu_ecdh:keypair_from_seed(x25519, Seed256),
  {PubA2, PrivA2} = ecu_ecdh:keypair_from_seed(x25519, Seed256),
  ?assertEqual(PubA1, PubA2),
  ?assertEqual(PrivA1, PrivA2),

  Seed448 = crypto:strong_rand_bytes(56),
  {PubB1, PrivB1} = ecu_ecdh:keypair_from_seed(x448, Seed448),
  {PubB2, PrivB2} = ecu_ecdh:keypair_from_seed(x448, Seed448),
  ?assertEqual(PubB1, PubB2),
  ?assertEqual(PrivB1, PrivB2).

%% --- Error Handling & Boundary Tests

ecdh_error_handling_test() ->
  ?assertError(badarg, apply(ecu_ecdh, compute_key, [unknown_curve, <<0:256>>, <<0:256>>])),
  ?assertError(badarg, ecu_ecdh:compute_key(x25519, <<1, 2, 3>>, <<0:256>>)),
  ?assertError(badarg, ecu_ecdh:compute_key(x448, <<0:256>>, <<0:448>>)),
  ?assertError(badarg, ecu_ecdh:compute_key(secp256k1, <<0:256>>, <<0:256>>)),
  ?assertError(badarg, ecu_ecdh:x25519(<<1, 2>>, <<9:256/little>>)),
  ?assertError(badarg, ecu_ecdh:x448(<<1, 2>>, <<5:448/little>>)),
  ?assertError(badarg, ecu_ecdh:clamp(x25519, <<1, 2>>)),
  ?assertError(badarg, ecu_ecdh:clamp(x448, <<1, 2>>)),
  ?assertError(badarg, ecu_ecdh:ed25519_public_to_x25519(<<1, 2, 3>>)),
  ?assertError(badarg, ecu_ecdh:ed25519_secret_to_x25519(<<1, 2, 3>>)).
