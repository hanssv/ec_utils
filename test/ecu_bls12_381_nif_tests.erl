%%%-------------------------------------------------------------------
%%% @doc
%%% Tests for ecu_bls12_381_nif reference oracle wrapper.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_nif_tests).

-include_lib("eunit/include/eunit.hrl").

nif_availability_test() ->
  case ecu_bls12_381_nif:is_available() of
    true ->
      ?assert(ecu_bls12_381_nif:is_loaded());
    false ->
      ok
  end.

g1_g2_point_ops_test() ->
  case ecu_bls12_381_nif:is_available() of
    true ->
      G1 = ecu_bls12_381_nif:g1_generator(),
      ?assertEqual(48, byte_size(G1)),
      G2 = ecu_bls12_381_nif:g2_generator(),
      ?assertEqual(96, byte_size(G2)),

      Scalar2 = <<2:256/little>>,
      {ok, G1_Double} = ecu_bls12_381_nif:g1_mult(G1, Scalar2),
      {ok, G1_Add} = ecu_bls12_381_nif:g1_add(G1, G1),
      ?assertEqual(G1_Double, G1_Add),

      {ok, G2_Double} = ecu_bls12_381_nif:g2_mult(G2, Scalar2),
      {ok, G2_Add} = ecu_bls12_381_nif:g2_add(G2, G2),
      ?assertEqual(G2_Double, G2_Add);
    false ->
      ok
  end.

pairing_bilinearity_test() ->
  case ecu_bls12_381_nif:is_available() of
    true ->
      G1 = ecu_bls12_381_nif:g1_generator(),
      G2 = ecu_bls12_381_nif:g2_generator(),

      Scalar2 = <<2:256/little>>,
      {ok, G1_x2} = ecu_bls12_381_nif:g1_mult(G1, Scalar2),
      {ok, G2_x2} = ecu_bls12_381_nif:g2_mult(G2, Scalar2),

      %% e(2*G1, G2) == e(G1, 2*G2)
      {ok, Pair1} = ecu_bls12_381_nif:pairing(G1_x2, G2),
      {ok, Pair2} = ecu_bls12_381_nif:pairing(G1, G2_x2),
      ?assertEqual(Pair1, Pair2),
      ?assertEqual(576, byte_size(Pair1));
    false ->
      ok
  end.

min_pk_sign_verify_test() ->
  case ecu_bls12_381_nif:is_available() of
    true ->
      IKM = crypto:strong_rand_bytes(32),
      {ok, {PK, SK}} = ecu_bls12_381_nif:min_pk_keygen(IKM),
      ?assertEqual(48, byte_size(PK)),
      ?assertEqual(32, byte_size(SK)),

      Msg = <<"Hello BLS12-381 from ec_utils!">>,
      DST = <<"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_">>,
      {ok, Sig} = ecu_bls12_381_nif:min_pk_sign(SK, Msg, DST),
      ?assertEqual(96, byte_size(Sig)),

      ?assert(ecu_bls12_381_nif:min_pk_verify(PK, Msg, Sig, DST)),
      ?assertNot(ecu_bls12_381_nif:min_pk_verify(PK, <<"Tampered">>, Sig, DST));
    false ->
      ok
  end.

min_pk_aggregation_test() ->
  case ecu_bls12_381_nif:is_available() of
    true ->
      Msg = <<"Aggregated message payload">>,
      DST = <<"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_">>,

      KeysAndSigs = [
        begin
          IKM = crypto:strong_rand_bytes(32),
          {ok, {PK, SK}} = ecu_bls12_381_nif:min_pk_keygen(IKM),
          {ok, Sig} = ecu_bls12_381_nif:min_pk_sign(SK, Msg, DST),
          {PK, Sig}
        end
       || _ <- lists:seq(1, 3)
      ],
      PKs = [P || {P, _} <- KeysAndSigs],
      Sigs = [S || {_, S} <- KeysAndSigs],

      {ok, AggSig} = ecu_bls12_381_nif:min_pk_aggregate(Sigs),
      ?assertEqual(96, byte_size(AggSig)),

      ?assert(ecu_bls12_381_nif:min_pk_fast_aggregate_verify(PKs, Msg, AggSig, DST)),
      ?assertNot(ecu_bls12_381_nif:min_pk_fast_aggregate_verify(PKs, <<"Wrong">>, AggSig, DST));
    false ->
      ok
  end.

min_sig_sign_verify_test() ->
  case ecu_bls12_381_nif:is_available() of
    true ->
      IKM = crypto:strong_rand_bytes(32),
      {ok, {PK, SK}} = ecu_bls12_381_nif:min_sig_keygen(IKM),
      ?assertEqual(96, byte_size(PK)),
      ?assertEqual(32, byte_size(SK)),

      Msg = <<"Minimal signature variant message">>,
      DST = <<"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_">>,
      {ok, Sig} = ecu_bls12_381_nif:min_sig_sign(SK, Msg, DST),
      ?assertEqual(48, byte_size(Sig)),

      ?assert(ecu_bls12_381_nif:min_sig_verify(PK, Msg, Sig, DST)),
      ?assertNot(ecu_bls12_381_nif:min_sig_verify(PK, <<"Wrong">>, Sig, DST));
    false ->
      ok
  end.
