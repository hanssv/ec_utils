%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 19 Jan 2022 by Hans Svensson
-module(eddsa_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% Let's use enacl/libsodium as the oracle
-include("ecu_ed25519.hrl").

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

prop_malleable_s() ->
  ?FORALL({Priv, Msg, K}, {binary(32), binary(48), choose(1, 14)},
  begin
    #{secret := SK, public := Pub} = enacl:sign_seed_keypair(Priv),
    Sig = ecu_eddsa:sign_detached(Msg, SK),
    <<R:32/binary, S:256/little-unsigned-integer>> = Sig,
    S1 = S + K * ?N,
    MalleableSig = <<R:32/binary, S1:256/little-unsigned-integer>>,
    ResEnacl = enacl:sign_verify_detached(MalleableSig, Msg, Pub),
    ResEcu   = ecu_eddsa:sign_verify_detached(MalleableSig, Msg, Pub),
    equals({ResEnacl, false}, {ResEcu, ResEnacl})
  end).

prop_sign_open_malleable_s() ->
  ?FORALL({Priv, Msg, K}, {binary(32), binary(48), choose(1, 14)},
  begin
    #{secret := SK, public := Pub} = enacl:sign_seed_keypair(Priv),
    Sig = ecu_eddsa:sign_detached(Msg, SK),
    <<R:32/binary, S:256/little-unsigned-integer>> = Sig,
    S1 = S + K * ?N,
    MalleableMsg = <<R:32/binary, S1:256/little-unsigned-integer, Msg/binary>>,
    ResEnacl = enacl:sign_open(MalleableMsg, Pub),
    ResEcu   = ecu_eddsa:sign_open(MalleableMsg, Pub),
    equals({ResEnacl, {error, failed_verification}}, {ResEcu, ResEnacl})
  end).

prop_sign_verify_detached_arbitrary() ->
  ?FORALL({Sig, Msg, PK}, {noshrink(binary(64)), noshrink(binary(48)), noshrink(binary(32))},
  begin
    ResEnacl = enacl:sign_verify_detached(Sig, Msg, PK),
    ResEcu = try ecu_eddsa:sign_verify_detached(Sig, Msg, PK)
             catch _:_ -> crash
             end,
    equals(ResEnacl, ResEcu)
  end).

prop_sign_open_arbitrary() ->
  ?FORALL({Sig, Msg, PK}, {noshrink(binary(64)), noshrink(binary(48)), noshrink(binary(32))},
  begin
    SMsg = <<Sig/binary, Msg/binary>>,
    ResEnacl = enacl:sign_open(SMsg, PK),
    ResEcu = try ecu_eddsa:sign_open(SMsg, PK)
             catch _:_ -> crash
             end,
    equals(ResEnacl, ResEcu)
  end).

prop_sign_detached_mismatched_pub() ->
  ?FORALL({Seed, FakePub, Msg}, {binary(32), binary(32), binary(48)},
  begin
    #{secret := <<Sec:32/binary, RealPub:32/binary>>} = enacl:sign_seed_keypair(Seed),
    case FakePub == RealPub of
      true  -> true;
      false ->
        BadSK = <<Sec/binary, FakePub/binary>>,
        try ecu_eddsa:sign_detached(Msg, BadSK) of
          _ -> false
        catch
          error:badarg -> true
        end
    end
  end).

prop_multi_scalar_mul() ->
  ?FORALL(Pairs, non_empty(list({gen_large_n(), gen_point()})),
  begin
    Expected = lists:foldl(
      fun({K, Pt}, Acc) ->
        ecu_ed25519:p_add(Acc, ecu_ed25519:scalar_mul_noclamp(K, Pt))
      end,
      {0, 1, 1, 0},
      Pairs
    ),
    Actual = ecu_ed25519:multi_scalar_mul(Pairs),
    ecu_ed25519:pt_eq(Expected, Actual)
  end).

prop_batch_verify() ->
  ?FORALL(Items, non_empty(list({binary(32), binary(32)})),
  begin
    Batch = [ begin
                #{secret := SK, public := PK} = ecu_eddsa:sign_seed_keypair(Seed),
                Sig = ecu_eddsa:sign_detached(Msg, SK),
                {Sig, Msg, PK}
              end || {Seed, Msg} <- Items ],
    ecu_eddsa:sign_verify_batch(Batch)
  end).

prop_batch_verify_tampered() ->
  ?FORALL({Items, TamperIdx, TamperChoice},
          {non_empty(list({binary(32), binary(32)})), choose(1, 100), elements([sig, msg, pk])},
  begin
    Batch = [ begin
                #{secret := SK, public := PK} = ecu_eddsa:sign_seed_keypair(Seed),
                Sig = ecu_eddsa:sign_detached(Msg, SK),
                {Sig, Msg, PK}
              end || {Seed, Msg} <- Items ],
    Idx = ((TamperIdx - 1) rem length(Batch)) + 1,
    {Sig, Msg, PK} = lists:nth(Idx, Batch),
    TamperedItem =
      case TamperChoice of
        sig ->
          <<R:32/binary, S:256/little-unsigned-integer>> = Sig,
          {<<R/binary, ((S + 1) rem ?N):256/little>>, Msg, PK};
        msg ->
          {Sig, <<Msg/binary, 1>>, PK};
        pk ->
          #{public := OtherPK} = ecu_eddsa:sign_keypair(),
          {Sig, Msg, OtherPK}
      end,
    TamperedBatch = lists:sublist(Batch, Idx - 1) ++ [TamperedItem] ++ lists:nthtail(Idx, Batch),
    case TamperedItem == {Sig, Msg, PK} of
      true  -> true;
      false -> not ecu_eddsa:sign_verify_batch(TamperedBatch)
    end
  end).
