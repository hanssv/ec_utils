%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 19 Jan 2022 by Hans Svensson
-module(eddsa_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% Let's use enacl/libsodium as the oracle
-define(N, 16#1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED).

-define(KP, #{public => <<161,254,128,151,126,253,139,99,47,29,229,140,67,224,50,78,70,156,225,182,242,171,89,114,47,163,254,192,59,35,148,234>>, secret => <<102,73,74,74,245,130,53,139,149,247,67,138,211,86,72,227,20,43,6,39,134,133,215,10,3,159,123,152,144,208,176,138,161,254,128,151,126,253,139,99,47,29,229,140,67,224,50,78,70,156,225,182,242,171,89,114,47,163,254,192,59,35,148,234>>}).


gen_large_n() ->
  ?LET(<<X:512>>, binary(64), 1 + (X rem (?N - 1))).

gen_scalar() ->
  ?LET(N, gen_large_n(), <<N:256/little>>).

gen_point() ->
  ?LET(S, gen_scalar(), enacl:crypto_ed25519_scalarmult_base_noclamp(S)).

prop_keypair_seed() ->
  ?FORALL(Seed, binary(32),
  begin
    KP1 = enacl:sign_seed_keypair(Seed),
    KP2 = ecu_eddsa:sign_seed_keypair(Seed),
    equals(KP1, KP2)
  end).

prop_sign() ->
  ?FORALL({Priv, Msg}, {binary(32), binary(48)},
  begin
    #{secret := SK} = enacl:sign_seed_keypair(Priv),
    Sig1 = enacl:sign(Msg, SK),
    Sig2 = ecu_eddsa:sign(Msg, SK),
    equals(Sig1, Sig2)
  end).

prop_sign_open() ->
  ?FORALL({Priv, Msg}, {noshrink(binary(32)), noshrink(binary(48))},
  begin
    #{secret := SK, public := Pub} = enacl:sign_seed_keypair(Priv),
    Sig = enacl:sign(Msg, SK),
    Res1 = enacl:sign_open(Sig, Pub),
    Res2 = ecu_eddsa:sign_open(Sig, Pub),
    equals(Res1, Res2)
  end).

prop_sign_detached() ->
  ?FORALL({Priv, Msg}, {binary(32), binary(48)},
  begin
    #{secret := SK} = enacl:sign_seed_keypair(Priv),
    Sig1 = enacl:sign_detached(Msg, SK),
    Sig2 = ecu_eddsa:sign_detached(Msg, SK),
    equals(Sig1, Sig2)
  end).

prop_sign_verify_detached() ->
  ?FORALL({Priv, Msg}, {noshrink(binary(32)), noshrink(binary(48))},
  begin
    #{secret := SK, public := Pub} = enacl:sign_seed_keypair(Priv),
    Sig = enacl:sign_detached(Msg, SK),
    Res1 = enacl:sign_verify_detached(Sig, Msg, Pub),
    Res2 = ecu_eddsa:sign_verify_detached(Sig, Msg, Pub),
    equals(Res1, Res2)
  end).

