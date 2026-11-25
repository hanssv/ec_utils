%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for pure-Erlang BN254 (alt_bn128) curve arithmetic, field towers,
%%% optimal Ate pairing, and differential cross-verification with Rust reference NIF.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bn254_tests).

-include_lib("eunit/include/eunit.hrl").
-include("ecu_bn254.hrl").

-define(FP, ecu_bn254_fp).
-define(BN, ecu_bn254).
-define(PAIRING, ecu_bn254_pairing).
-define(NIF, ecu_bn254_nif).

nif_availability_test() ->
  case ?NIF:is_available() of
    true ->
      ?assert(?NIF:is_loaded());
    false ->
      ok
  end.

field_towers_test() ->
  %% Fp
  P = ?BN254_P,
  A = 1234567891011121314151617181920 rem P,
  B = 9876543211011121314151617181920 rem P,
  ?assertEqual((A + B) rem P, ?FP:fp_add(A, B)),
  ?assertEqual((A - B + P) rem P, ?FP:fp_sub(A, B)),
  ?assertEqual((A * B) rem P, ?FP:fp_mul(A, B)),
  ?assertEqual((A * A) rem P, ?FP:fp_sqr(A)),
  InvA = ?FP:fp_inv(A),
  ?assertEqual(1, ?FP:fp_mul(A, InvA)),

  %% Fp2
  A2 = {A, (A * 2) rem P},
  B2 = {B, (B * 3) rem P},
  InvA2 = ?FP:fp2_inv(A2),
  ?assertEqual(?FP:fp2_one(), ?FP:fp2_mul(A2, InvA2)),
  ?assertEqual(?FP:fp2_mul(A2, A2), ?FP:fp2_sqr(A2)),

  %% Fp6
  A6 = {A2, B2, ?FP:fp2_add(A2, B2)},
  InvA6 = ?FP:fp6_inv(A6),
  ?assertEqual(?FP:fp6_one(), ?FP:fp6_mul(A6, InvA6)),
  ?assertEqual(?FP:fp6_mul(A6, A6), ?FP:fp6_sqr(A6)),

  %% Fp12
  B6 = {?FP:fp2_sub(B2, A2), ?FP:fp2_mul(A2, B2), A2},
  A12 = {A6, B6},
  InvA12 = ?FP:fp12_inv(A12),
  ?assertEqual(?FP:fp12_one(), ?FP:fp12_mul(A12, InvA12)),
  ?assertEqual(?FP:fp12_mul(A12, A12), ?FP:fp12_sqr(A12)),

  %% Cyclotomic squaring for unitary elements
  %% A unitary element satisfying a^(p^6) = a^(-1)
  %% A12^(p^6 - 1) is unitary
  A12_p6 = ?FP:fp12_frobenius_p6(A12),
  Unitary = ?FP:fp12_mul(A12_p6, InvA12),
  ?assertEqual(?FP:fp12_sqr(Unitary), ?FP:fp12_cyclotomic_sqr(Unitary)).

g1_generator_and_arithmetic_test() ->
  G1 = ?BN:g1_generator(),
  ?assert(?BN:g1_on_curve(G1)),
  ?assertNot(?BN:g1_is_zero(G1)),
  ?assert(?BN:g1_is_in_subgroup(G1)),

  Inf = ?BN:g1_infinity(),
  ?assert(?BN:g1_is_zero(Inf)),
  ?assert(?BN:g1_on_curve(Inf)),
  ?assert(?BN:g1_is_in_subgroup(Inf)),

  %% P + Inf = P
  ?assertEqual(G1, ?BN:g1_add(G1, Inf)),
  ?assertEqual(G1, ?BN:g1_add(Inf, G1)),

  %% P + (-P) = Inf
  NegG1 = ?BN:g1_neg(G1),
  ?assertEqual(Inf, ?BN:g1_add(G1, NegG1)),
  ?assertEqual(Inf, ?BN:g1_sub(G1, G1)),

  %% 2*P == P + P
  G1_Double = ?BN:g1_double(G1),
  G1_Add = ?BN:g1_add(G1, G1),
  ?assertEqual(G1_Double, G1_Add),

  %% Scalar multiplication: 0*P, 1*P, 2*P, r*P
  ?assertEqual(Inf, ?BN:g1_scalar_mul(G1, 0)),
  ?assertEqual(G1, ?BN:g1_scalar_mul(G1, 1)),
  ?assertEqual(G1_Double, ?BN:g1_scalar_mul(G1, 2)),
  ?assertEqual(Inf, ?BN:g1_scalar_mul(G1, ?BN254_R)),

  %% Jacobian conversion
  J1 = ?BN:g1_to_jacobian(G1),
  ?assertEqual(G1, ?BN:g1_from_jacobian(J1)),
  J_Dbl = ?BN:g1_j_double(J1),
  ?assertEqual(G1_Double, ?BN:g1_from_jacobian(J_Dbl)),
  J_Add = ?BN:g1_j_add(J1, J1),
  ?assertEqual(G1_Double, ?BN:g1_from_jacobian(J_Add)),
  J_AddAff = ?BN:g1_j_add_affine(J1, G1),
  ?assertEqual(G1_Double, ?BN:g1_from_jacobian(J_AddAff)).

g1_serialization_test() ->
  G1 = ?BN:g1_generator(),
  G1Uncomp = ?BN:g1_to_uncompressed(G1),
  ?assertEqual(64, byte_size(G1Uncomp)),
  ?assertEqual({ok, G1}, ?BN:g1_from_uncompressed(G1Uncomp)),

  %% Infinity serialization
  Inf = ?BN:g1_infinity(),
  InfUncomp = ?BN:g1_to_uncompressed(Inf),
  ?assertEqual(<<0:512>>, InfUncomp),
  ?assertEqual({ok, Inf}, ?BN:g1_from_uncompressed(InfUncomp)),

  %% Compressed serialization
  G1Comp = ?BN:g1_compress(G1),
  ?assertEqual(32, byte_size(G1Comp)),
  ?assertEqual({ok, G1}, ?BN:g1_decompress(G1Comp)),

  InfComp = ?BN:g1_compress(Inf),
  ?assertEqual(<<0:256>>, InfComp),
  ?assertEqual({ok, Inf}, ?BN:g1_decompress(InfComp)),

  %% Cross-check with reference Rust NIF if loaded
  case ?NIF:is_loaded() of
    true ->
      NifGen = ?NIF:g1_generator(),
      ?assertEqual(G1Uncomp, NifGen),
      Scalar2 = <<2:256/big>>,
      {ok, NifDouble} = ?NIF:g1_mult(G1Uncomp, Scalar2),
      G1DoubleUncomp = ?BN:g1_to_uncompressed(?BN:g1_double(G1)),
      ?assertEqual(G1DoubleUncomp, NifDouble),
      {ok, NifAdd} = ?NIF:g1_add(G1Uncomp, G1Uncomp),
      ?assertEqual(G1DoubleUncomp, NifAdd);
    false ->
      ok
  end.

g2_generator_and_arithmetic_test() ->
  G2 = ?BN:g2_generator(),
  ?assert(?BN:g2_on_curve(G2)),
  ?assertNot(?BN:g2_is_zero(G2)),
  ?assert(?BN:g2_is_in_subgroup(G2)),

  Inf = ?BN:g2_infinity(),
  ?assert(?BN:g2_is_zero(Inf)),
  ?assert(?BN:g2_on_curve(Inf)),
  ?assert(?BN:g2_is_in_subgroup(Inf)),

  %% Q + Inf = Q
  ?assertEqual(G2, ?BN:g2_add(G2, Inf)),
  ?assertEqual(G2, ?BN:g2_add(Inf, G2)),

  %% Q + (-Q) = Inf
  NegG2 = ?BN:g2_neg(G2),
  ?assertEqual(Inf, ?BN:g2_add(G2, NegG2)),
  ?assertEqual(Inf, ?BN:g2_sub(G2, G2)),

  %% 2*Q == Q + Q
  G2_Double = ?BN:g2_double(G2),
  G2_Add = ?BN:g2_add(G2, G2),
  ?assertEqual(G2_Double, G2_Add),

  %% Scalar multiplication: 0*Q, 1*Q, 2*Q, r*Q
  ?assertEqual(Inf, ?BN:g2_scalar_mul(G2, 0)),
  ?assertEqual(G2, ?BN:g2_scalar_mul(G2, 1)),
  ?assertEqual(G2_Double, ?BN:g2_scalar_mul(G2, 2)),
  ?assertEqual(Inf, ?BN:g2_scalar_mul(G2, ?BN254_R)),

  %% Jacobian conversion
  J2 = ?BN:g2_to_jacobian(G2),
  ?assertEqual(G2, ?BN:g2_from_jacobian(J2)),
  J_Dbl = ?BN:g2_j_double(J2),
  ?assertEqual(G2_Double, ?BN:g2_from_jacobian(J_Dbl)),
  J_Add = ?BN:g2_j_add(J2, J2),
  ?assertEqual(G2_Double, ?BN:g2_from_jacobian(J_Add)),
  J_AddAff = ?BN:g2_j_add_affine(J2, G2),
  ?assertEqual(G2_Double, ?BN:g2_from_jacobian(J_AddAff)).

g2_serialization_test() ->
  G2 = ?BN:g2_generator(),
  G2Uncomp = ?BN:g2_to_uncompressed(G2),
  ?assertEqual(128, byte_size(G2Uncomp)),
  ?assertEqual({ok, G2}, ?BN:g2_from_uncompressed(G2Uncomp)),

  %% Infinity serialization
  Inf = ?BN:g2_infinity(),
  InfUncomp = ?BN:g2_to_uncompressed(Inf),
  ?assertEqual(<<0:1024>>, InfUncomp),
  ?assertEqual({ok, Inf}, ?BN:g2_from_uncompressed(InfUncomp)),

  %% Compressed serialization
  G2Comp = ?BN:g2_compress(G2),
  ?assertEqual(64, byte_size(G2Comp)),
  ?assertEqual({ok, G2}, ?BN:g2_decompress(G2Comp)),

  InfComp = ?BN:g2_compress(Inf),
  ?assertEqual(<<0:512>>, InfComp),
  ?assertEqual({ok, Inf}, ?BN:g2_decompress(InfComp)),

  %% Cross-check with reference Rust NIF if loaded
  case ?NIF:is_loaded() of
    true ->
      NifGen = ?NIF:g2_generator(),
      ?assertEqual(G2Uncomp, NifGen),
      Scalar2 = <<2:256/big>>,
      {ok, NifDouble} = ?NIF:g2_mult(G2Uncomp, Scalar2),
      G2DoubleUncomp = ?BN:g2_to_uncompressed(?BN:g2_double(G2)),
      ?assertEqual(G2DoubleUncomp, NifDouble),
      {ok, NifAdd} = ?NIF:g2_add(G2Uncomp, G2Uncomp),
      ?assertEqual(G2DoubleUncomp, NifAdd);
    false ->
      ok
  end.

pairing_infinity_and_non_degeneracy_test() ->
  G1 = ?BN:g1_generator(),
  G2 = ?BN:g2_generator(),
  Inf1 = ?BN:g1_infinity(),
  Inf2 = ?BN:g2_infinity(),
  One = ?FP:fp12_one(),

  ?assertEqual(One, ?PAIRING:pairing(Inf1, G2)),
  ?assertEqual(One, ?PAIRING:pairing(G1, Inf2)),
  ?assertEqual(One, ?PAIRING:pairing(Inf1, Inf2)),
  ?assert(?PAIRING:pairing_check([])),
  ?assert(?PAIRING:pairing_check([{Inf1, G2}])),

  %% Non-degeneracy: e(G1, G2) != 1
  Pair = ?PAIRING:pairing(G1, G2),
  ?assertNotEqual(One, Pair),

  %% Order of pairing in G_T: Pair^r == 1
  ?assertEqual(One, ?FP:fp12_pow(Pair, ?BN254_R)),

  %% Cross-check with NIF
  case ?NIF:is_loaded() of
    true ->
      G1Bin = ?BN:g1_to_uncompressed(G1),
      G2Bin = ?BN:g2_to_uncompressed(G2),
      ?assertEqual({ok, true}, ?NIF:pairing(G1Bin, G2Bin));
    false ->
      ok
  end.

pairing_bilinearity_test() ->
  G1 = ?BN:g1_generator(),
  G2 = ?BN:g2_generator(),

  G1_2 = ?BN:g1_double(G1),
  G2_2 = ?BN:g2_double(G2),

  %% e(2P, Q) == e(P, 2Q)
  Pair_2P_Q = ?PAIRING:pairing(G1_2, G2),
  Pair_P_2Q = ?PAIRING:pairing(G1, G2_2),
  ?assertEqual(Pair_2P_Q, Pair_P_2Q),

  %% e(2P, Q) == e(P, Q)^2
  Pair_P_Q = ?PAIRING:pairing(G1, G2),
  Pair_Sq = ?FP:fp12_sqr(Pair_P_Q),
  ?assertEqual(Pair_2P_Q, Pair_Sq),

  %% e(3P, Q) == e(P, Q)^3
  G1_3 = ?BN:g1_scalar_mul(G1, 3),
  Pair_3P_Q = ?PAIRING:pairing(G1_3, G2),
  Pair_Cube = ?FP:fp12_mul(Pair_Sq, Pair_P_Q),
  ?assertEqual(Pair_3P_Q, Pair_Cube),

  %% e(-P, Q) == e(P, -Q) == e(P, Q)^(-1)
  NegG1 = ?BN:g1_neg(G1),
  NegG2 = ?BN:g2_neg(G2),
  Pair_NegP_Q = ?PAIRING:pairing(NegG1, G2),
  Pair_P_NegQ = ?PAIRING:pairing(G1, NegG2),
  Pair_Inv = ?FP:fp12_inv(Pair_P_Q),
  ?assertEqual(Pair_NegP_Q, Pair_P_NegQ),
  ?assertEqual(Pair_NegP_Q, Pair_Inv).

pairing_check_test() ->
  G1 = ?BN:g1_generator(),
  G2 = ?BN:g2_generator(),
  NegG1 = ?BN:g1_neg(G1),

  %% e(G1, G2) * e(-G1, G2) == 1
  ?assert(?PAIRING:pairing_check(G1, G2, NegG1, G2)),
  ?assert(?PAIRING:pairing_check([{G1, G2}, {NegG1, G2}])),

  %% e(-2*G1, G2) * e(G1, 2*G2) == 1
  G1_2 = ?BN:g1_double(G1),
  G2_2 = ?BN:g2_double(G2),
  NegG1_2 = ?BN:g1_neg(G1_2),
  ?assert(?PAIRING:pairing_check(NegG1_2, G2, G1, G2_2)),

  %% Invalid pairing check: e(G1, G2) * e(G1, G2) != 1
  ?assertNot(?PAIRING:pairing_check(G1, G2, G1, G2)),

  %% Cross-check with NIF
  case ?NIF:is_loaded() of
    true ->
      G1Bin = ?BN:g1_to_uncompressed(G1),
      G2Bin = ?BN:g2_to_uncompressed(G2),
      NegG1Bin = ?BN:g1_to_uncompressed(NegG1),
      ?assert(?NIF:pairing_check([{G1Bin, G2Bin}, {NegG1Bin, G2Bin}]));
    false ->
      ok
  end.

eip196_vectors_test() ->
  %% EIP-196 test vector 1: Addition of generator with itself
  G1 = ?BN:g1_generator(),
  {X, Y} = ?BN:g1_add(G1, G1),
  ?assertEqual(
    1368015179489954701390400359078579693043519447331113978918064868415326638035,
    X
  ),
  ?assertEqual(
    9918110051302171585080402603319702774565515993150576347155970296011118125764,
    Y
  ),
  %% EIP-196 test vector 2: Scalar mul with 2
  ?assertEqual({X, Y}, ?BN:g1_scalar_mul(G1, 2)).

subgroup_and_curve_validation_test() ->
  %% Invalid point not on curve
  BadG1 = {1, 3},
  ?assertNot(?BN:g1_on_curve(BadG1)),
  ?assertEqual(error, ?BN:g1_from_uncompressed(<<1:256, 3:256>>)),

  %% G2 invalid point
  BadG2 = {{1, 0}, {3, 0}},
  ?assertNot(?BN:g2_on_curve(BadG2)),
  ?assertEqual(error, ?BN:g2_from_uncompressed(<<0:256, 1:256, 0:256, 3:256>>)),

  %% G2 point on twist curve but NOT in prime subgroup G2 (F-12, F-13, F-14)
  %% Find X0 such that X={X0, 0} has a square root on the twist curve
  TwistB = {
    16#2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5,
    16#9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2
  },
  X = {1, 0},
  Rhs = ecu_bn254_fp:fp2_add(
    ecu_bn254_fp:fp2_mul(ecu_bn254_fp:fp2_sqr(X), X),
    TwistB
  ),
  {ok, Y} = ecu_bn254_fp:fp2_sqrt(Rhs),
  TwistPt = {X, Y},
  ?assert(?BN:g2_on_curve(TwistPt)),
  ?assertNot(?BN:g2_is_in_subgroup(TwistPt)),
  ?assertEqual(error, ?BN:g2_from_uncompressed(?BN:g2_to_uncompressed(TwistPt))),
  ?assertEqual(error, ?BN:g2_decompress(?BN:g2_compress(TwistPt))),
  ?assertNot(?PAIRING:pairing_check([{?BN:g1_generator(), TwistPt}])).
