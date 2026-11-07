%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for pure-Erlang BLS12-381 G1 and G2 curve arithmetic and codecs.
%%% Includes differential cross-testing against the Rust reference NIF (blst).
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_tests).

-include_lib("eunit/include/eunit.hrl").

-define(BLS, ecu_bls12_381).
-define(NIF, ecu_bls12_381_nif).

g1_generator_test() ->
  G1 = ?BLS:g1_generator(),
  ?assert(?BLS:g1_on_curve(G1)),
  ?assertNot(?BLS:g1_is_zero(G1)),

  %% Subgroup check: r * G1 = infinity
  ?assert(?BLS:g1_is_in_subgroup(G1)),

  %% Check compressed encoding matches reference Rust NIF generator
  G1Comp = ?BLS:g1_compress(G1),
  ?assertEqual(48, byte_size(G1Comp)),
  case ?NIF:is_loaded() of
    true ->
      ?assertEqual(?NIF:g1_generator(), G1Comp);
    false ->
      ok
  end,

  %% Decompress roundtrip
  ?assertEqual({ok, G1}, ?BLS:g1_decompress(G1Comp)).

g1_arithmetic_test() ->
  G1 = ?BLS:g1_generator(),
  Inf = ?BLS:g1_infinity(),

  ?assert(?BLS:g1_is_zero(Inf)),
  ?assert(?BLS:g1_on_curve(Inf)),
  ?assert(?BLS:g1_is_in_subgroup(Inf)),

  %% P + Inf = P
  ?assertEqual(G1, ?BLS:g1_add(G1, Inf)),
  ?assertEqual(G1, ?BLS:g1_add(Inf, G1)),

  %% P + (-P) = Inf
  NegG1 = ?BLS:g1_neg(G1),
  ?assertEqual(Inf, ?BLS:g1_add(G1, NegG1)),
  ?assertEqual(Inf, ?BLS:g1_sub(G1, G1)),

  %% 2 * P = P + P = double(P)
  DoubleG1 = ?BLS:g1_double(G1),
  AddG1 = ?BLS:g1_add(G1, G1),
  Mul2G1 = ?BLS:g1_scalar_mul(G1, 2),
  ?assertEqual(DoubleG1, AddG1),
  ?assertEqual(DoubleG1, Mul2G1),

  %% 3 * P = 2 * P + P
  Mul3G1 = ?BLS:g1_scalar_mul(G1, 3),
  ?assertEqual(Mul3G1, ?BLS:g1_add(DoubleG1, G1)),

  %% Cross-check with Rust NIF oracle
  case ?NIF:is_loaded() of
    true ->
      G1Comp = ?BLS:g1_compress(G1),
      {ok, NifMul2} = ?NIF:g1_mult(G1Comp, <<2:256/little>>),
      ?assertEqual(NifMul2, ?BLS:g1_compress(DoubleG1)),

      {ok, NifMul3} = ?NIF:g1_mult(G1Comp, <<3:256/little>>),
      ?assertEqual(NifMul3, ?BLS:g1_compress(Mul3G1)),

      {ok, NifAdd} = ?NIF:g1_add(G1Comp, G1Comp),
      ?assertEqual(NifAdd, ?BLS:g1_compress(DoubleG1));
    false ->
      ok
  end.

g1_compression_infinity_test() ->
  Inf = ?BLS:g1_infinity(),
  InfComp = ?BLS:g1_compress(Inf),
  ?assertEqual(<<16#C0, 0:376>>, InfComp),
  ?assertEqual({ok, Inf}, ?BLS:g1_decompress(InfComp)),

  %% Uncompressed infinity
  InfUncomp = ?BLS:g1_serialize_uncompressed(Inf),
  ?assertEqual(<<16#40, 0:760>>, InfUncomp),
  ?assertEqual({ok, Inf}, ?BLS:g1_deserialize_uncompressed(InfUncomp)).

g1_uncompressed_roundtrip_test() ->
  G1 = ?BLS:g1_generator(),
  Uncomp = ?BLS:g1_serialize_uncompressed(G1),
  ?assertEqual(96, byte_size(Uncomp)),
  ?assertEqual({ok, G1}, ?BLS:g1_deserialize_uncompressed(Uncomp)).

g2_generator_test() ->
  G2 = ?BLS:g2_generator(),
  ?assert(?BLS:g2_on_curve(G2)),
  ?assertNot(?BLS:g2_is_zero(G2)),

  %% Subgroup check: r * G2 = infinity
  ?assert(?BLS:g2_is_in_subgroup(G2)),

  %% Check compressed encoding matches reference Rust NIF generator
  G2Comp = ?BLS:g2_compress(G2),
  ?assertEqual(96, byte_size(G2Comp)),
  case ?NIF:is_loaded() of
    true ->
      ?assertEqual(?NIF:g2_generator(), G2Comp);
    false ->
      ok
  end,

  %% Decompress roundtrip
  ?assertEqual({ok, G2}, ?BLS:g2_decompress(G2Comp)).

g2_arithmetic_test() ->
  G2 = ?BLS:g2_generator(),
  Inf = ?BLS:g2_infinity(),

  ?assert(?BLS:g2_is_zero(Inf)),
  ?assert(?BLS:g2_on_curve(Inf)),
  ?assert(?BLS:g2_is_in_subgroup(Inf)),

  %% P + Inf = P
  ?assertEqual(G2, ?BLS:g2_add(G2, Inf)),
  ?assertEqual(G2, ?BLS:g2_add(Inf, G2)),

  %% P + (-P) = Inf
  NegG2 = ?BLS:g2_neg(G2),
  ?assertEqual(Inf, ?BLS:g2_add(G2, NegG2)),
  ?assertEqual(Inf, ?BLS:g2_sub(G2, G2)),

  %% 2 * P = P + P = double(P)
  DoubleG2 = ?BLS:g2_double(G2),
  AddG2 = ?BLS:g2_add(G2, G2),
  Mul2G2 = ?BLS:g2_scalar_mul(G2, 2),
  ?assertEqual(DoubleG2, AddG2),
  ?assertEqual(DoubleG2, Mul2G2),

  %% 3 * P = 2 * P + P
  Mul3G2 = ?BLS:g2_scalar_mul(G2, 3),
  ?assertEqual(Mul3G2, ?BLS:g2_add(DoubleG2, G2)),

  %% Cross-check with Rust NIF oracle
  case ?NIF:is_loaded() of
    true ->
      G2Comp = ?BLS:g2_compress(G2),
      {ok, NifMul2} = ?NIF:g2_mult(G2Comp, <<2:256/little>>),
      ?assertEqual(NifMul2, ?BLS:g2_compress(DoubleG2)),

      {ok, NifMul3} = ?NIF:g2_mult(G2Comp, <<3:256/little>>),
      ?assertEqual(NifMul3, ?BLS:g2_compress(Mul3G2)),

      {ok, NifAdd} = ?NIF:g2_add(G2Comp, G2Comp),
      ?assertEqual(NifAdd, ?BLS:g2_compress(DoubleG2));
    false ->
      ok
  end.

g2_compression_infinity_test() ->
  Inf = ?BLS:g2_infinity(),
  InfComp = ?BLS:g2_compress(Inf),
  ?assertEqual(<<16#C0, 0:760>>, InfComp),
  ?assertEqual({ok, Inf}, ?BLS:g2_decompress(InfComp)),

  %% Uncompressed infinity
  InfUncomp = ?BLS:g2_serialize_uncompressed(Inf),
  ?assertEqual(<<16#40, 0:1528>>, InfUncomp),
  ?assertEqual({ok, Inf}, ?BLS:g2_deserialize_uncompressed(InfUncomp)).

g2_uncompressed_roundtrip_test() ->
  G2 = ?BLS:g2_generator(),
  Uncomp = ?BLS:g2_serialize_uncompressed(G2),
  ?assertEqual(192, byte_size(Uncomp)),
  ?assertEqual({ok, G2}, ?BLS:g2_deserialize_uncompressed(Uncomp)).

random_scalar_differential_test() ->
  case ?NIF:is_loaded() of
    true ->
      G1 = ?BLS:g1_generator(),
      G2 = ?BLS:g2_generator(),
      G1Comp = ?BLS:g1_compress(G1),
      G2Comp = ?BLS:g2_compress(G2),
      Scalars = [7, 42, 10007, 16#123456789abcdef0],
      lists:foreach(
        fun(K) ->
          KBinLittle = <<K:256/little>>,
          %% G1
          PureG1 = ?BLS:g1_scalar_mul(G1, K),
          PureG1Comp = ?BLS:g1_compress(PureG1),
          {ok, NifG1Comp} = ?NIF:g1_mult(G1Comp, KBinLittle),
          ?assertEqual(NifG1Comp, PureG1Comp),
          ?assertEqual({ok, PureG1}, ?BLS:g1_decompress(PureG1Comp)),

          %% G2
          PureG2 = ?BLS:g2_scalar_mul(G2, K),
          PureG2Comp = ?BLS:g2_compress(PureG2),
          {ok, NifG2Comp} = ?NIF:g2_mult(G2Comp, KBinLittle),
          ?assertEqual(NifG2Comp, PureG2Comp),
          ?assertEqual({ok, PureG2}, ?BLS:g2_decompress(PureG2Comp))
        end,
        Scalars
      );
    false ->
      ok
  end.

scalar_edge_cases_test() ->
  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),
  Inf = ?BLS:g1_infinity(),
  Inf2 = ?BLS:g2_infinity(),
  R = ecu_bls12_381_fp:r(),

  %% 0 * P = Inf
  ?assertEqual(Inf, ?BLS:g1_scalar_mul(G1, 0)),
  ?assertEqual(Inf2, ?BLS:g2_scalar_mul(G2, 0)),

  %% r * P = Inf
  ?assertEqual(Inf, ?BLS:g1_scalar_mul(G1, R)),
  ?assertEqual(Inf2, ?BLS:g2_scalar_mul(G2, R)),

  %% -1 * P = neg(P)
  ?assertEqual(?BLS:g1_neg(G1), ?BLS:g1_scalar_mul(G1, -1)),
  ?assertEqual(?BLS:g2_neg(G2), ?BLS:g2_scalar_mul(G2, -1)),

  %% Binary scalar
  ?assertEqual(?BLS:g1_double(G1), ?BLS:g1_scalar_mul(G1, <<2:256>>)),
  ?assertEqual(?BLS:g2_double(G2), ?BLS:g2_scalar_mul(G2, <<2:256>>)),

  %% scalar_mul_base
  ?assertEqual(?BLS:g1_scalar_mul(G1, 5), ?BLS:g1_scalar_mul_base(5)),
  ?assertEqual(?BLS:g2_scalar_mul(G2, 5), ?BLS:g2_scalar_mul_base(5)).

invalid_decompression_test() ->
  %% G1: invalid compressed bit
  ?assertEqual({error, not_compressed}, ?BLS:g1_decompress(<<0:384>>)),
  %% G1: invalid infinity (non-zero payload)
  ?assertEqual({error, invalid_infinity_encoding}, ?BLS:g1_decompress(<<16#C0, 1:376>>)),
  %% G1: coordinate out of range (top 5 bits set to 16#1F makes X > p)
  ?assertEqual(
    {error, coordinate_out_of_range},
    ?BLS:g1_decompress(<<(16#80 bor 16#1F):8, 0:376>>)
  ),

  %% G2: invalid compressed bit
  ?assertEqual({error, not_compressed}, ?BLS:g2_decompress(<<0:768>>)),
  %% G2: invalid infinity
  ?assertEqual({error, invalid_infinity_encoding}, ?BLS:g2_decompress(<<16#C0, 1:760>>)),
  %% G2: coordinate out of range
  ?assertEqual(
    {error, coordinate_out_of_range},
    ?BLS:g2_decompress(<<(16#80 bor 16#1F):8, 0:760>>)
  ).
