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

