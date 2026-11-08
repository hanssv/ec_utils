%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for pure-Erlang BLS12-381 optimal Ate pairing and pairing checks.
%%% Cross-verified against the Rust reference NIF (blst).
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_pairing_tests).

-include_lib("eunit/include/eunit.hrl").

-define(FP, ecu_bls12_381_fp).
-define(BLS, ecu_bls12_381).
-define(PAIRING, ecu_bls12_381_pairing).
-define(NIF, ecu_bls12_381_nif).

pairing_infinity_test() ->
  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),
  Inf1 = ?BLS:g1_infinity(),
  Inf2 = ?BLS:g2_infinity(),
  One = ?FP:fp12_one(),

  ?assertEqual(One, ?PAIRING:pairing(Inf1, G2)),
  ?assertEqual(One, ?PAIRING:pairing(G1, Inf2)),
  ?assertEqual(One, ?PAIRING:pairing(Inf1, Inf2)),
  ?assert(?PAIRING:pairing_check([])),
  ?assert(?PAIRING:pairing_check([{Inf1, G2}])).

pairing_non_degeneracy_test() ->
  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),
  One = ?FP:fp12_one(),

  Pair = ?PAIRING:pairing(G1, G2),
  ?assertNotEqual(One, Pair),

  %% Order of pairing value in G_T: Pair^r == 1
  R = ?FP:r(),
  ?assertEqual(One, ?FP:fp12_pow(Pair, R)).

pairing_bilinearity_test() ->
  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),

  G1_2 = ?BLS:g1_double(G1),
  G2_2 = ?BLS:g2_double(G2),

  %% e(2P, Q) == e(P, 2Q)
  Pair_2P_Q = ?PAIRING:pairing(G1_2, G2),
  Pair_P_2Q = ?PAIRING:pairing(G1, G2_2),
  ?assertEqual(Pair_2P_Q, Pair_P_2Q),

  %% e(2P, Q) == e(P, Q)^2
  Pair_P_Q = ?PAIRING:pairing(G1, G2),
  Pair_Sq = ?FP:fp12_sqr(Pair_P_Q),
  ?assertEqual(Pair_2P_Q, Pair_Sq),

  %% e(3P, Q) == e(P, Q)^3
  G1_3 = ?BLS:g1_scalar_mul(G1, 3),
  Pair_3P_Q = ?PAIRING:pairing(G1_3, G2),
  Pair_Cu = ?FP:fp12_pow(Pair_P_Q, 3),
  ?assertEqual(Pair_3P_Q, Pair_Cu).

pairing_check_test() ->
  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),

  %% e(P, Q) * e(-P, Q) == 1
  NegG1 = ?BLS:g1_neg(G1),
  ?assert(?PAIRING:pairing_check([{G1, G2}, {NegG1, G2}])),

  %% e(2P, Q) * e(P, -2Q) == 1
  G1_2 = ?BLS:g1_double(G1),
  NegG2_2 = ?BLS:g2_neg(?BLS:g2_double(G2)),
  ?assert(?PAIRING:pairing_check([{G1_2, G2}, {G1, NegG2_2}])),

  %% Not equal pairs should fail
  ?assertNot(?PAIRING:pairing_check([{G1, G2}, {G1, G2}])),

  %% Cross-check with Rust NIF oracle
  case ?NIF:is_loaded() of
    true ->
      G1Comp = ?BLS:g1_compress(G1_2),
      G2Comp = ?BLS:g2_compress(G2),
      NegG1Comp = ?BLS:g1_compress(?BLS:g1_neg(G1)),
      G2_2Comp = ?BLS:g2_compress(?BLS:g2_double(G2)),
      %% Verify pairing_check on Rust oracle
      ?assertEqual(
        true,
        ?NIF:pairing_check([{G1Comp, G2Comp}, {NegG1Comp, G2_2Comp}])
      ),
      %% Verify pure Erlang matches
      ?assert(
        ?PAIRING:pairing_check([
          {G1_2, G2},
          {?BLS:g1_neg(G1), ?BLS:g2_double(G2)}
        ])
      );
    false ->
      ok
  end.

multi_pairing_random_differential_test() ->
  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),
  A = 7,
  B = 13,
  G1_A = ?BLS:g1_scalar_mul(G1, A),
  G2_B = ?BLS:g2_scalar_mul(G2, B),
  G1_AB = ?BLS:g1_scalar_mul(G1, A * B),
  NegG1_AB = ?BLS:g1_neg(G1_AB),

  %% e(aP, bQ) * e(-(ab)P, Q) == 1
  Pairs = [{G1_A, G2_B}, {NegG1_AB, G2}],
  ?assert(?PAIRING:pairing_check(Pairs)),

  case ?NIF:is_loaded() of
    true ->
      NifPairs = [
        {?BLS:g1_compress(P), ?BLS:g2_compress(Q)}
       || {P, Q} <- Pairs
      ],
      ?assertEqual(true, ?NIF:pairing_check(NifPairs));
    false ->
      ok
  end.
