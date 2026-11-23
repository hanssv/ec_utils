%%%-------------------------------------------------------------------
%%% @doc
%%% Unit tests and NIF differential tests for Jubjub elliptic curve (BLS12-381).
%%% @end
%%%-------------------------------------------------------------------
-module(jubjub_tests).

-include_lib("eunit/include/eunit.hrl").

parameters_test() ->
  Q = ecu_jubjub:q(),
  A = ecu_jubjub:a(),
  D = ecu_jubjub:d(),
  Suborder = ecu_jubjub:suborder(),
  Cofactor = ecu_jubjub:cofactor(),
  Gen = ecu_jubjub:generator(),
  Base8 = ecu_jubjub:base8(),
  Id = ecu_jubjub:identity(),

  ?assertEqual(16#73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001, Q),
  ?assertEqual(Q - 1, A),
  ?assertEqual(19257038036680949359750312669786877991949435402254120286184196891950884077233, D),
  ?assertEqual(16#0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7, Suborder),
  ?assertEqual(8, Cofactor),
  ?assertEqual({0, 1}, Id),
  ?assertEqual(Gen, Base8),

  ?assert(ecu_jubjub:is_on_curve(Gen)),
  ?assert(ecu_jubjub:is_on_curve(Id)),
  ?assert(ecu_jubjub:is_in_subgroup(Gen)),
  ?assert(ecu_jubjub:is_in_subgroup(Id)),
  ?assertEqual(Id, ecu_jubjub:mul(Gen, Suborder)).

group_laws_test() ->
  P = ecu_jubjub:generator(),
  Id = ecu_jubjub:identity(),

  ?assertEqual(P, ecu_jubjub:add(P, Id)),
  ?assertEqual(P, ecu_jubjub:add(Id, P)),
  ?assertEqual(Id, ecu_jubjub:add(P, ecu_jubjub:neg(P))),

  P2 = ecu_jubjub:double(P),
  ?assertEqual(P2, ecu_jubjub:add(P, P)),
  ?assertEqual(P2, ecu_jubjub:mul(P, 2)),

  P3 = ecu_jubjub:add(P2, P),
  ?assertEqual(P3, ecu_jubjub:mul(P, 3)),

  ?assertEqual(ecu_jubjub:add(P, P2), ecu_jubjub:add(P2, P)),
  P5 = ecu_jubjub:add(P2, P3),
  ?assertEqual(P5, ecu_jubjub:mul(P, 5)),

  %% Negation and subtraction
  P_neg = ecu_jubjub:neg(P),
  ?assert(ecu_jubjub:is_on_curve(P_neg)),
  ?assertEqual(P2, ecu_jubjub:add(P3, P_neg)).

compression_roundtrip_test() ->
  Gen = ecu_jubjub:generator(),
  CompGen = ecu_jubjub:compress(Gen),
  ?assertEqual(32, byte_size(CompGen)),
  ?assertEqual({ok, Gen}, ecu_jubjub:decompress(CompGen)),

  %% Multiples roundtrip
  lists:foreach(
    fun(K) ->
      PK = ecu_jubjub:mul(Gen, K),
      CompPK = ecu_jubjub:compress(PK),
      ?assertEqual({ok, PK}, ecu_jubjub:decompress(CompPK))
    end,
    [1, 2, 3, 7, 100, 123456789]
  ).

zip216_canonical_rejection_test() ->
  Id = ecu_jubjub:identity(),
  CompId = ecu_jubjub:compress(Id),
  ?assertEqual({ok, Id}, ecu_jubjub:decompress(CompId)),

  %% Non-canonical encoding with sign bit = 1 on identity (u = 0)
  <<Id0:31/binary, LastByte:8>> = CompId,
  BadSignId = <<Id0/binary, (LastByte bor 16#80):8>>,
  ?assertEqual({error, non_canonical}, ecu_jubjub:decompress(BadSignId)),

  %% Non-canonical encoding with sign bit = 1 on (0, q-1)
  Q = ecu_jubjub:q(),
  P_order2 = {0, Q - 1},
  ?assert(ecu_jubjub:is_on_curve(P_order2)),
  CompOrder2 = ecu_jubjub:compress(P_order2),
  ?assertEqual({ok, P_order2}, ecu_jubjub:decompress(CompOrder2)),
  <<O2_0:31/binary, O2_Last:8>> = CompOrder2,
  BadSignO2 = <<O2_0/binary, (O2_Last bor 16#80):8>>,
  ?assertEqual({error, non_canonical}, ecu_jubjub:decompress(BadSignO2)).

montgomery_conversion_and_ladder_test() ->
  ?assertEqual(40962, ecu_jubjub:montgomery_a()),

  Id = ecu_jubjub:identity(),
  ?assertEqual(infinity, ecu_jubjub:edwards_to_montgomery(Id)),
  ?assertEqual(Id, ecu_jubjub:montgomery_to_edwards(infinity)),
  ?assert(ecu_jubjub:is_on_montgomery(infinity)),

  Q = ecu_jubjub:q(),
  P_0_minus1 = {0, Q - 1},
  ?assertEqual({0, 0}, ecu_jubjub:edwards_to_montgomery(P_0_minus1)),
  ?assertEqual(P_0_minus1, ecu_jubjub:montgomery_to_edwards({0, 0})),
  ?assert(ecu_jubjub:is_on_montgomery({0, 0})),

  Gen = ecu_jubjub:generator(),
  MGen = ecu_jubjub:edwards_to_montgomery(Gen),
  ?assert(ecu_jubjub:is_on_montgomery(MGen)),
  ?assertEqual(Gen, ecu_jubjub:montgomery_to_edwards(MGen)),

  %% Montgomery ladder consistency
  {UGen, _} = MGen,
  lists:foreach(
    fun(K) ->
      EdK = ecu_jubjub:mul(Gen, K),
      case ecu_jubjub:edwards_to_montgomery(EdK) of
        infinity ->
          ?assertEqual(0, ecu_jubjub:montgomery_ladder(K, UGen));
        {UK, _VK} ->
          ?assertEqual(UK, ecu_jubjub:montgomery_ladder(K, UGen))
      end
    end,
    [1, 2, 3, 5, 7, 16, 100, 123456789]
  ),

  %% Binary ladder encoding
  K_bin = <<123456789:256/little>>,
  U_bin = <<UGen:256/little>>,
  ResBin =
    case ecu_jubjub:montgomery_ladder(K_bin, U_bin) of
      B when is_binary(B) -> B
    end,
  ?assertEqual(32, byte_size(ResBin)),
  <<ResInt:256/little>> = ResBin,
  ?assertEqual(ecu_jubjub:montgomery_ladder(123456789, UGen), ResInt).

nif_differential_test() ->
  case ecu_jubjub_nif:is_available() of
    true ->
      Gen = ecu_jubjub:generator(),
      ErlCompGen = ecu_jubjub:compress(Gen),
      {ok, NifCompGen} = ecu_jubjub_nif:generator(),
      ?assertEqual(ErlCompGen, NifCompGen),

      ?assert(ecu_jubjub_nif:is_on_curve(ErlCompGen)),
      ?assert(ecu_jubjub_nif:is_in_subgroup(ErlCompGen)),

      %% Decompress point differential
      {ok, {ErlU_le, ErlV_le}} = ecu_jubjub_nif:decompress_point(ErlCompGen),
      {GenU, GenV} = Gen,
      ?assertEqual(<<GenU:256/little>>, ErlU_le),
      ?assertEqual(<<GenV:256/little>>, ErlV_le),

      %% Compress point differential
      {ok, NifRecompressed} = ecu_jubjub_nif:compress_point(ErlU_le, ErlV_le),
      ?assertEqual(ErlCompGen, NifRecompressed),

      %% Point doubling differential
      P2 = ecu_jubjub:double(Gen),
      ErlCompP2 = ecu_jubjub:compress(P2),
      {ok, NifCompP2} = ecu_jubjub_nif:point_double(ErlCompGen),
      ?assertEqual(ErlCompP2, NifCompP2),

      %% Point addition differential
      P3 = ecu_jubjub:add(P2, Gen),
      ErlCompP3 = ecu_jubjub:compress(P3),
      {ok, NifCompP3} = ecu_jubjub_nif:point_add(ErlCompP2, ErlCompGen),
      ?assertEqual(ErlCompP3, NifCompP3),

      %% Scalar multiplication differential
      lists:foreach(
        fun(S) ->
          SLE = <<S:256/little>>,
          P_s = ecu_jubjub:mul(Gen, S),
          Comp_s = ecu_jubjub:compress(P_s),
          {ok, NifComp_s} = ecu_jubjub_nif:point_mul(ErlCompGen, SLE),
          ?assertEqual(Comp_s, NifComp_s)
        end,
        [
          1,
          2,
          3,
          5,
          7,
          16,
          255,
          65535,
          123456789,
          16#0123456789abcdef0123456789abcdef,
          16#0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb6
        ]
      ),

      %% Montgomery ladder differential
      MGen = ecu_jubjub:edwards_to_montgomery(Gen),
      {UGen, _} = MGen,
      UGen_bin = <<UGen:256/little>>,
      lists:foreach(
        fun(S) ->
          SLE = <<S:256/little>>,
          LadderPure = ecu_jubjub:montgomery_ladder(SLE, UGen_bin),
          {ok, LadderNif} = ecu_jubjub_nif:montgomery_ladder(SLE, UGen_bin),
          ?assertEqual(LadderPure, LadderNif)
        end,
        [1, 2, 3, 5, 123456789]
      );
    false ->
      ok
  end.
