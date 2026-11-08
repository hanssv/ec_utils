%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for pure-Erlang BLS12-381 finite field towers (Fp, Fp2, Fp6, Fp12).
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_fp_tests).

-include_lib("eunit/include/eunit.hrl").

-define(FP, ecu_bls12_381_fp).

fp_basic_arithmetic_test() ->
  Zero = ?FP:fp_zero(),
  One = ?FP:fp_one(),
  ?assert(?FP:fp_is_zero(Zero)),
  ?assert(?FP:fp_is_one(One)),
  ?assertNot(?FP:fp_is_zero(One)),

  A = 123456789012345678901234567890,
  B = 987654321098765432109876543210,

  %% Addition / Subtraction / Negation
  ?assertEqual(A, ?FP:fp_add(A, Zero)),
  ?assertEqual(A, ?FP:fp_sub(A, Zero)),
  ?assertEqual(Zero, ?FP:fp_add(A, ?FP:fp_neg(A))),
  ?assertEqual(Zero, ?FP:fp_sub(A, A)),
  ?assertEqual(?FP:fp_add(A, B), ?FP:fp_add(B, A)),

  %% Multiplication / Squaring
  ?assertEqual(Zero, ?FP:fp_mul(A, Zero)),
  ?assertEqual(A, ?FP:fp_mul(A, One)),
  ?assertEqual(?FP:fp_sqr(A), ?FP:fp_mul(A, A)),
  ?assertEqual(?FP:fp_mul(A, B), ?FP:fp_mul(B, A)),

  %% Inversion
  InvA = ?FP:fp_inv(A),
  ?assertEqual(One, ?FP:fp_mul(A, InvA)),

  %% Exponentiation
  ?assertEqual(One, ?FP:fp_pow(A, 0)),
  ?assertEqual(A, ?FP:fp_pow(A, 1)),
  ?assertEqual(?FP:fp_sqr(A), ?FP:fp_pow(A, 2)),
  ?assertEqual(InvA, ?FP:fp_pow(A, ?FP:p() - 2)),

  %% Serialization
  BinA = ?FP:fp_to_bin(A),
  ?assertEqual(48, byte_size(BinA)),
  ?assertEqual(A, ?FP:fp_from_bin(BinA)),
  ?assertError(badarg, ?FP:fp_from_bin(<<(-1):384>>)),
  ?assertError(badarg, ?FP:fp_from_bin(<<1:380>>)).

fp_sqrt_test() ->
  %% 0 is its own square root
  ?assertEqual({ok, 0}, ?FP:fp_sqrt(0)),

  %% Square a random element and verify sqrt recovers it
  A = 1234567891011121314151617181920,
  SqrA = ?FP:fp_sqr(A),
  {ok, Root} = ?FP:fp_sqrt(SqrA),
  ?assert(Root =:= A orelse Root =:= ?FP:fp_neg(A)),
  ?assertEqual(SqrA, ?FP:fp_sqr(Root)),

  %% In Fp (p = 3 mod 4), -1 is a quadratic non-residue
  Neg1 = ?FP:fp_neg(1),
  ?assertEqual(error, ?FP:fp_sqrt(Neg1)).

fp2_arithmetic_test() ->
  Zero = ?FP:fp2_zero(),
  One = ?FP:fp2_one(),
  ?assert(?FP:fp2_is_zero(Zero)),
  ?assert(?FP:fp2_is_one(One)),

  A = {111222333444555, 666777888999000},
  B = {999888777666555, 444333222111000},

  %% Add / Sub / Neg
  ?assertEqual(A, ?FP:fp2_add(A, Zero)),
  ?assertEqual(Zero, ?FP:fp2_add(A, ?FP:fp2_neg(A))),
  ?assertEqual(Zero, ?FP:fp2_sub(A, A)),
  ?assertEqual(?FP:fp2_add(A, B), ?FP:fp2_add(B, A)),

  %% Mul / Sqr
  ?assertEqual(Zero, ?FP:fp2_mul(A, Zero)),
  ?assertEqual(A, ?FP:fp2_mul(A, One)),
  ?assertEqual(?FP:fp2_sqr(A), ?FP:fp2_mul(A, A)),
  ?assertEqual(?FP:fp2_mul(A, B), ?FP:fp2_mul(B, A)),

  %% u^2 = -1 in Fp2
  U = {0, 1},
  ?assertEqual({?FP:fp_neg(1), 0}, ?FP:fp2_sqr(U)),

  %% Inversion
  InvA = ?FP:fp2_inv(A),
  ?assertEqual(One, ?FP:fp2_mul(A, InvA)),

  %% Frobenius: pi(A) = conj(A)
  ?assertEqual(?FP:fp2_conj(A), ?FP:fp2_frobenius(A)),
  ?assertEqual(A, ?FP:fp2_frobenius(?FP:fp2_frobenius(A))),

  %% Serialization
  BinA = ?FP:fp2_to_bin(A),
  ?assertEqual(96, byte_size(BinA)),
  ?assertEqual(A, ?FP:fp2_from_bin(BinA)).

fp2_sqrt_test() ->
  Zero = ?FP:fp2_zero(),
  ?assertEqual({ok, Zero}, ?FP:fp2_sqrt(Zero)),

  A = {987654321, 123456789},
  SqrA = ?FP:fp2_sqr(A),
  {ok, Root} = ?FP:fp2_sqrt(SqrA),
  ?assertEqual(SqrA, ?FP:fp2_sqr(Root)),

  %% Square root of -1 in Fp2 is u = {0, 1}
  NegOne = {?FP:fp_neg(1), 0},
  {ok, RootNegOne} = ?FP:fp2_sqrt(NegOne),
  ?assertEqual(NegOne, ?FP:fp2_sqr(RootNegOne)),
  ?assert(RootNegOne =:= {0, 1} orelse RootNegOne =:= {0, ?FP:fp_neg(1)}).

fp6_arithmetic_test() ->
  Zero = ?FP:fp6_zero(),
  One = ?FP:fp6_one(),
  ?assert(?FP:fp6_is_zero(Zero)),
  ?assert(?FP:fp6_is_one(One)),

  A = {{1, 2}, {3, 4}, {5, 6}},
  B = {{7, 8}, {9, 10}, {11, 12}},

  %% Add / Sub / Neg
  ?assertEqual(A, ?FP:fp6_add(A, Zero)),
  ?assertEqual(Zero, ?FP:fp6_add(A, ?FP:fp6_neg(A))),
  ?assertEqual(Zero, ?FP:fp6_sub(A, A)),
  ?assertEqual(?FP:fp6_add(A, B), ?FP:fp6_add(B, A)),

  %% Mul / Sqr
  ?assertEqual(Zero, ?FP:fp6_mul(A, Zero)),
  ?assertEqual(A, ?FP:fp6_mul(A, One)),
  ?assertEqual(?FP:fp6_sqr(A), ?FP:fp6_mul(A, A)),
  ?assertEqual(?FP:fp6_mul(A, B), ?FP:fp6_mul(B, A)),

  %% v^3 = 1 + u = xi in Fp6
  V = {?FP:fp2_zero(), ?FP:fp2_one(), ?FP:fp2_zero()},
  V3 = ?FP:fp6_mul(?FP:fp6_sqr(V), V),
  ?assertEqual({{1, 1}, ?FP:fp2_zero(), ?FP:fp2_zero()}, V3),

  %% Inversion
  InvA = ?FP:fp6_inv(A),
  ?assertEqual(One, ?FP:fp6_mul(A, InvA)),

  %% Frobenius order: pi^6(A) = A
  Pi1 = ?FP:fp6_frobenius(A),
  Pi2 = ?FP:fp6_frobenius2(A),
  ?assertEqual(Pi2, ?FP:fp6_frobenius(Pi1)),
  Pi6 = ?FP:fp6_frobenius2(?FP:fp6_frobenius2(Pi2)),
  ?assertEqual(A, Pi6).

fp12_arithmetic_test() ->
  Zero = ?FP:fp12_zero(),
  One = ?FP:fp12_one(),
  ?assert(?FP:fp12_is_zero(Zero)),
  ?assert(?FP:fp12_is_one(One)),

  A0 = {{12, 34}, {56, 78}, {90, 12}},
  A1 = {{34, 56}, {78, 90}, {12, 34}},
  A = {A0, A1},

  B0 = {{98, 76}, {54, 32}, {10, 98}},
  B1 = {{76, 54}, {32, 10}, {98, 76}},
  B = {B0, B1},

  %% Add / Sub / Neg
  ?assertEqual(A, ?FP:fp12_add(A, Zero)),
  ?assertEqual(Zero, ?FP:fp12_add(A, ?FP:fp12_neg(A))),
  ?assertEqual(Zero, ?FP:fp12_sub(A, A)),
  ?assertEqual(?FP:fp12_add(A, B), ?FP:fp12_add(B, A)),

  %% Mul / Sqr
  ?assertEqual(Zero, ?FP:fp12_mul(A, Zero)),
  ?assertEqual(A, ?FP:fp12_mul(A, One)),
  ?assertEqual(?FP:fp12_sqr(A), ?FP:fp12_mul(A, A)),
  ?assertEqual(?FP:fp12_mul(A, B), ?FP:fp12_mul(B, A)),

  %% w^2 = v in Fp12
  W = {?FP:fp6_zero(), ?FP:fp6_one()},
  W2 = ?FP:fp12_sqr(W),
  ExpectedV = {{?FP:fp2_zero(), ?FP:fp2_one(), ?FP:fp2_zero()}, ?FP:fp6_zero()},
  ?assertEqual(ExpectedV, W2),

  %% Inversion
  InvA = ?FP:fp12_inv(A),
  ?assertEqual(One, ?FP:fp12_mul(A, InvA)),

  %% Exponentiation
  ?assertEqual(One, ?FP:fp12_pow(A, 0)),
  ?assertEqual(A, ?FP:fp12_pow(A, 1)),
  ?assertEqual(?FP:fp12_sqr(A), ?FP:fp12_pow(A, 2)),

  %% Frobenius order: pi^12(A) = A
  Pi1 = ?FP:fp12_frobenius(A),
  Pi2 = ?FP:fp12_frobenius2(A),
  Pi3 = ?FP:fp12_frobenius3(A),
  ?assertEqual(Pi2, ?FP:fp12_frobenius(Pi1)),
  ?assertEqual(Pi3, ?FP:fp12_frobenius(Pi2)),
  Pi6 = ?FP:fp12_frobenius3(Pi3),
  Pi12 = ?FP:fp12_frobenius3(?FP:fp12_frobenius3(Pi6)),
  ?assertEqual(A, Pi12),

  %% Serialization
  BinA = ?FP:fp12_to_bin(A),
  ?assertEqual(576, byte_size(BinA)),
  ?assertEqual(A, ?FP:fp12_from_bin(BinA)).
