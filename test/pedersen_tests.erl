%%%-------------------------------------------------------------------
%%% @doc
%%% Unit tests for Circomlib-compatible Pedersen Hash and Commitments.
%%% @end
%%%-------------------------------------------------------------------
-module(pedersen_tests).

-include_lib("eunit/include/eunit.hrl").

bases_test() ->
  Bases = ecu_babyjubjub_pedersen:bases(),
  ?assertEqual(10, length(Bases)),

  lists:foreach(
    fun(Idx) ->
      Pt = ecu_babyjubjub_pedersen:base(Idx),
      ?assertEqual(lists:nth(Idx + 1, Bases), Pt),
      ?assert(ecu_babyjubjub:is_on_curve(Pt)),
      ?assert(ecu_babyjubjub:is_in_subgroup(Pt))
    end,
    lists:seq(0, 9)
  ),

  ?assertError(badarg, ecu_babyjubjub_pedersen:base(10)),
  ?assertError(badarg, ecu_babyjubjub_pedersen:base(-1)).

empty_hash_test() ->
  Id = ecu_babyjubjub:identity(),
  ?assertEqual(Id, ecu_babyjubjub_pedersen:hash(<<>>)),
  ?assertEqual(Id, ecu_babyjubjub_pedersen:hash(<<>>, affine)),
  ?assertEqual(0, ecu_babyjubjub_pedersen:hash(<<>>, x_only)),
  ?assertEqual(ecu_babyjubjub:compress(Id), ecu_babyjubjub_pedersen:hash(<<>>, compressed)),
  ?assertEqual(ecu_babyjubjub:compress(Id), ecu_babyjubjub_pedersen:hash_compressed(<<>>)).

single_byte_vector_test() ->
  %% Single zero byte <<0>>: 2 windows {0,0,0,0} -> scalar 1 + 16 = 17 on BASE[0]
  Base0 = ecu_babyjubjub_pedersen:base(0),
  ExpectedPt = ecu_babyjubjub:mul(Base0, 17),
  ExpectedX = 20122239225827662391862762159149847031375956973594213405841844209746264471448,
  ExpectedY = 14157172923413575889356720908798107199581766035967383707727097972522317120482,
  ?assertEqual({ExpectedX, ExpectedY}, ExpectedPt),

  Pt = ecu_babyjubjub_pedersen:hash(<<0>>),
  ?assertEqual({ExpectedX, ExpectedY}, Pt),
  ?assertEqual(ExpectedX, ecu_babyjubjub_pedersen:hash(<<0>>, x_only)),

  Comp = ecu_babyjubjub_pedersen:hash_compressed(<<0>>),
  ?assertEqual(ecu_babyjubjub:compress(Pt), Comp).

formats_test() ->
  Data = <<"test data for pedersen hash">>,
  Pt = ecu_babyjubjub_pedersen:hash(Data),
  ?assert(ecu_babyjubjub:is_on_curve(Pt)),
  ?assert(ecu_babyjubjub:is_in_subgroup(Pt)),

  {X, _Y} = Pt,
  ?assertEqual(X, ecu_babyjubjub_pedersen:hash(Data, x_only)),
  ?assertEqual(ecu_babyjubjub:compress(Pt), ecu_babyjubjub_pedersen:hash(Data, compressed)),
  ?assertEqual(ecu_babyjubjub:compress(Pt), ecu_babyjubjub_pedersen:hash_compressed(Data)).

multi_segment_test() ->
  %% 200 bits = 25 bytes (1 segment exactly)
  Data200 = <<0:200>>,
  Pt200 = ecu_babyjubjub_pedersen:hash(Data200),
  ?assert(ecu_babyjubjub:is_on_curve(Pt200)),
  ?assert(ecu_babyjubjub:is_in_subgroup(Pt200)),

  %% 248 bits = 31 bytes (standard Circom field element input: 2 segments)
  Data248 = <<16#1234567890abcdef:248/little>>,
  Pt248 = ecu_babyjubjub_pedersen:hash(Data248),
  ?assert(ecu_babyjubjub:is_on_curve(Pt248)),
  ?assert(ecu_babyjubjub:is_in_subgroup(Pt248)),

  %% 512 bits = 64 bytes (3 segments)
  Data512 = crypto:strong_rand_bytes(64),
  Pt512 = ecu_babyjubjub_pedersen:hash(Data512),
  ?assert(ecu_babyjubjub:is_on_curve(Pt512)),
  ?assert(ecu_babyjubjub:is_in_subgroup(Pt512)),

  %% 2000 bits = 250 bytes (exactly 10 segments, max capacity)
  Data2000 = crypto:strong_rand_bytes(250),
  Pt2000 = ecu_babyjubjub_pedersen:hash(Data2000),
  ?assert(ecu_babyjubjub:is_on_curve(Pt2000)),
  ?assert(ecu_babyjubjub:is_in_subgroup(Pt2000)),

  %% 2001 bits exceeds limit
  Data2001 = <<Data2000/binary, 1:1>>,
  ?assertError(input_too_large, ecu_babyjubjub_pedersen:hash(Data2001)).

commitments_test() ->
  Msg = <<"secret message for commitment">>,
  Blinding1 = 12345678901234567890,
  Blinding2 = 98765432109876543210,

  C1 = ecu_babyjubjub_pedersen:commit(Msg, Blinding1),
  C2 = ecu_babyjubjub_pedersen:commit(Msg, Blinding2),

  ?assert(ecu_babyjubjub:is_on_curve(C1)),
  ?assert(ecu_babyjubjub:is_on_curve(C2)),
  ?assert(ecu_babyjubjub:is_in_subgroup(C1)),
  ?assert(ecu_babyjubjub:is_in_subgroup(C2)),
  %% Hiding property: different blinding yields different commitments
  ?assertNotEqual(C1, C2),

  %% Zero blinding gives raw hash
  HashPt = ecu_babyjubjub_pedersen:hash(Msg),
  C_zero = ecu_babyjubjub_pedersen:commit(Msg, 0),
  ?assertEqual(HashPt, C_zero),

  %% 32-byte LE binary scalar blinding
  BlindingBin = <<Blinding1:256/little>>,
  C1_bin = ecu_babyjubjub_pedersen:commit(Msg, BlindingBin),
  ?assertEqual(C1, C1_bin),

  %% Custom blinding base
  CustomBase = ecu_babyjubjub_pedersen:base(8),
  C_custom = ecu_babyjubjub_pedersen:commit(Msg, Blinding1, CustomBase),
  ?assert(ecu_babyjubjub:is_on_curve(C_custom)),
  ?assertNotEqual(C1, C_custom),

  %% Invalid blinding base rejected
  ?assertError(badarg, ecu_babyjubjub_pedersen:commit(Msg, Blinding1, {123, 456})).

homomorphic_commitment_test() ->
  %% Test additive homomorphic property of Pedersen commitment:
  %% C(M, R1) + C(M, R2) = 2*Hash(M) + (R1 + R2)*H
  Msg = <<"homomorphic test">>,
  R1 = 1000,
  R2 = 2500,
  H = ecu_babyjubjub_pedersen:base(9),

  C1 = ecu_babyjubjub_pedersen:commit(Msg, R1, H),
  C2 = ecu_babyjubjub_pedersen:commit(Msg, R2, H),
  SumC = ecu_babyjubjub:add(C1, C2),

  HashPt = ecu_babyjubjub_pedersen:hash(Msg),
  TwoHashPt = ecu_babyjubjub:double(HashPt),
  BlindingCombined = ecu_babyjubjub:mul(H, R1 + R2),
  ExpectedSum = ecu_babyjubjub:add(TwoHashPt, BlindingCombined),

  ?assertEqual(ExpectedSum, SumC).

nif_differential_test() ->
  case ecu_babyjubjub_nif:is_available() of
    true ->
      %% Pedersen hash differential
      lists:foreach(
        fun(Data) ->
          PureComp = ecu_babyjubjub_pedersen:hash_compressed(Data),
          {ok, NifComp} = ecu_babyjubjub_nif:pedersen_hash(Data),
          ?assertEqual(PureComp, NifComp)
        end,
        [
          <<>>,
          <<0>>,
          <<"Hello, world!">>,
          <<16#1234567890abcdef:248/little>>,
          crypto:strong_rand_bytes(64)
        ]
      ),

      %% Pedersen commit differential
      Msg = <<"secret differential message">>,
      BlindingInt = 12345678901234567890,
      BlindingLE = <<BlindingInt:256/little>>,
      PureCommit = ecu_babyjubjub:compress(ecu_babyjubjub_pedersen:commit(Msg, BlindingInt)),
      {ok, NifCommit} = ecu_babyjubjub_nif:pedersen_commit(Msg, BlindingLE),
      ?assertEqual(PureCommit, NifCommit);
    false ->
      ok
  end.
