-module(ed25519_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

point_encode_test() ->
  CompressedP = enacl:crypto_ed25519_scalarmult_base(<<123:256>>),
  D = ecu_ed25519:decompress(CompressedP),
  ?assertEqual(CompressedP, ecu_ed25519:compress(D)).

exp_mod_zero_test() ->
  %% 0^B mod P should be 0 when B > 0
  ?assertEqual(0, ecu_misc:exp_mod(0, 5, 7)).

decompress_identity_test() ->
  %% Identity point y = 1, x = 0 encoded as <<1:8, 0:248>>
  Ident = <<1:8, 0:248>>,
  %% This calls xrecover(1) -> exp_mod(0, ...), which previously went into infinite recursion / OOM
  ?assertEqual({0, 1, 1, 0}, ecu_ed25519:decompress(Ident)).

-include("ecu_ed25519.hrl").

malleable_s_test() ->
  #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
  Msg = <<"test message">>,
  Sig = ecu_eddsa:sign_detached(Msg, Priv),
  <<R:32/binary, S:256/little-unsigned-integer>> = Sig,
  S1 = S + ?N,
  ?assert(S1 < (1 bsl 256)),
  MalleableSig = <<R:32/binary, S1:256/little-unsigned-integer>>,
  %% enacl rejects S >= N (malleable signature)
  ?assertEqual(false, enacl:sign_verify_detached(MalleableSig, Msg, Pub)),
  %% ecu_eddsa should also reject S >= N
  ?assertEqual(false, ecu_eddsa:sign_verify_detached(MalleableSig, Msg, Pub)),
  SignedMsg = <<MalleableSig/binary, Msg/binary>>,
  ?assertEqual({error, failed_verification}, enacl:sign_open(SignedMsg, Pub)),
  ?assertEqual({error, failed_verification}, ecu_eddsa:sign_open(SignedMsg, Pub)).

small_order_pubkey_test() ->
  %% Order-4 point y = 0
  WeakA = <<0:256>>,
  Msg = <<"1">>,
  Sig = <<0:512>>,
  ?assertEqual(false, enacl:sign_verify_detached(Sig, Msg, WeakA)),
  ?assertEqual(false, ecu_eddsa:sign_verify_detached(Sig, Msg, WeakA)),
  ?assertEqual({error, failed_verification}, enacl:sign_open(<<Sig/binary, Msg/binary>>, WeakA)),
  ?assertEqual({error, failed_verification}, ecu_eddsa:sign_open(<<Sig/binary, Msg/binary>>, WeakA)).

decompress_canonical_test() ->
  %% y >= P is non-canonical
  NonCanonicalY = <<(?P + 1):256/little-unsigned-integer>>,
  ?assertError(badarg, ecu_ed25519:decompress(NonCanonicalY)),
  %% x = 0 with high bit (sign bit) set is non-canonical
  SignBitX0 = <<1:8, 0:30/unit:8, 128:8>>,
  ?assertError(badarg, ecu_ed25519:decompress(SignBitX0)),
  %% y not on curve (quadratic non-residue)
  NotOnCurve = <<2:256/little-unsigned-integer>>,
  ?assertError(badarg, ecu_ed25519:decompress(NotOnCurve)).

invalid_pubkey_no_crash_test() ->
  %% Point not on curve passed as public key
  BadPK = <<2:256/little-unsigned-integer>>,
  Msg = <<"test message">>,
  Sig = <<0:512>>,
  ?assertEqual(false, ecu_eddsa:sign_verify_detached(Sig, Msg, BadPK)),
  ?assertEqual({error, failed_verification}, ecu_eddsa:sign_open(<<Sig/binary, Msg/binary>>, BadPK)).

