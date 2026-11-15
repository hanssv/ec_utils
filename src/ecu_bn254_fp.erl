%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang finite field arithmetic for BN254 (alt_bn128) field extension towers:
%%%   - Base field Fp (254 bits)
%%%   - Quadratic extension Fp2 = Fp[u] / (u^2 + 1)
%%%   - Sextic extension Fp6 = Fp2[v] / (v^3 - (9 + u))
%%%   - Dodecic extension Fp12 = Fp6[w] / (w^2 - v)
%%%
%%% Reference:
%%%   - EIP-196 / EIP-197 specifications (Ethereum)
%%%   - Barreto, Naehrig: "Pairing-Friendly Elliptic Curves of Prime Order" (2005)
%%%   - arkworks ark-bn254
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bn254_fp).

-typing([eqwalizer]).

-include("ecu_bn254.hrl").

-export_type([fp/0, fp2/0, fp6/0, fp12/0]).

-type fp() :: non_neg_integer().
-type fp2() :: {fp(), fp()}.
-type fp6() :: {fp2(), fp2(), fp2()}.
-type fp12() :: {fp6(), fp6()}.

%% Curve & field parameters
-export([
  p/0,
  r/0,
  x/0
]).

%% Fp base field operations
-export([
  fp_zero/0,
  fp_one/0,
  fp_is_zero/1,
  fp_is_one/1,
  fp_add/2,
  fp_sub/2,
  fp_neg/1,
  fp_mul/2,
  fp_sqr/1,
  fp_inv/1,
  fp_pow/2,
  fp_sqrt/1,
  fp_to_bin/1,
  fp_from_bin/1
]).

%% Fp2 quadratic extension operations
-export([
  fp2_zero/0,
  fp2_one/0,
  fp2_is_zero/1,
  fp2_is_one/1,
  fp2_add/2,
  fp2_sub/2,
  fp2_neg/1,
  fp2_mul/2,
  fp2_sqr/1,
  fp2_mul_fp/2,
  fp2_mul_xi/1,
  fp2_inv/1,
  fp2_conj/1,
  fp2_frobenius/1,
  fp2_pow/2,
  fp2_sqrt/1,
  fp2_sgn0/1,
  fp2_to_bin/1,
  fp2_from_bin/1
]).

%% Fp6 cubic-over-quadratic extension operations
-export([
  fp6_zero/0,
  fp6_one/0,
  fp6_is_zero/1,
  fp6_is_one/1,
  fp6_add/2,
  fp6_sub/2,
  fp6_neg/1,
  fp6_mul/2,
  fp6_sqr/1,
  fp6_mul_fp2/2,
  fp6_mul_v/1,
  fp6_inv/1,
  fp6_frobenius/1,
  fp6_frobenius2/1
]).

%% Fp12 quadratic-over-sextic extension operations
-export([
  fp12_zero/0,
  fp12_one/0,
  fp12_is_zero/1,
  fp12_is_one/1,
  fp12_add/2,
  fp12_sub/2,
  fp12_neg/1,
  fp12_mul/2,
  fp12_sqr/1,
  fp12_mul_fp6/2,
  fp12_inv/1,
  fp12_conj/1,
  fp12_frobenius_p6/1,
  fp12_cyclotomic_sqr/1,
  fp12_pow/2,
  fp12_frobenius/1,
  fp12_frobenius2/1,
  fp12_frobenius3/1,
  fp12_to_bin/1,
  fp12_from_bin/1
]).

%% Helper for Frobenius constants
-export([
  gamma_11/0,
  gamma_12/0,
  gamma_1w/0,
  gamma_21/0,
  gamma_22/0,
  gamma_2w/0,
  gamma_3w/0
]).

%%%-------------------------------------------------------------------
%%% Constants
%%%-------------------------------------------------------------------

-spec p() -> pos_integer().
p() -> ?BN254_P.

-spec r() -> pos_integer().
r() -> ?BN254_R.

-spec x() -> pos_integer().
x() -> ?BN254_X.

%%%-------------------------------------------------------------------
%%% Fp: Base Field Arithmetic modulo P (254 bits)
%%%-------------------------------------------------------------------

-spec fp_zero() -> fp().
fp_zero() -> 0.

-spec fp_one() -> fp().
fp_one() -> 1.

-spec fp_is_zero(fp()) -> boolean().
fp_is_zero(0) -> true;
fp_is_zero(_) -> false.

-spec fp_is_one(fp()) -> boolean().
fp_is_one(1) -> true;
fp_is_one(_) -> false.

-spec fp_add(fp(), fp()) -> fp().
fp_add(A, B) ->
  S = A + B,
  P = ?BN254_P,
  if
    S >= P -> S - P;
    true -> S
  end.

-spec fp_sub(fp(), fp()) -> fp().
fp_sub(A, B) ->
  D = A - B,
  if
    D < 0 -> D + ?BN254_P;
    true -> D
  end.

-spec fp_neg(fp()) -> fp().
fp_neg(0) -> 0;
fp_neg(A) -> ?BN254_P - A.

-spec fp_mul(fp(), fp()) -> fp().
fp_mul(A, B) ->
  (A * B) rem ?BN254_P.

-spec fp_sqr(fp()) -> fp().
fp_sqr(A) ->
  (A * A) rem ?BN254_P.

-spec fp_inv(fp()) -> fp().
fp_inv(0) ->
  error(badarg);
fp_inv(A) ->
  case ecu_misc:eea(A, ?BN254_P) of
    {1, S, _} ->
      case S < 0 of
        true -> S + ?BN254_P;
        false -> S
      end;
    _ ->
      error(badarg)
  end.

-spec fp_pow(fp(), non_neg_integer()) -> fp().
fp_pow(_A, 0) ->
  1;
fp_pow(0, _) ->
  0;
fp_pow(A, 1) ->
  A;
fp_pow(A, Exp) when Exp > 1 ->
  ecu_misc:exp_mod(A, Exp, ?BN254_P).

%% Square root via Tonelli-Shanks for p = 3 mod 4: a^((p+1)/4)
-spec fp_sqrt(fp()) -> {ok, fp()} | error.
fp_sqrt(0) ->
  {ok, 0};
fp_sqrt(A) ->
  Root = fp_pow(A, (?BN254_P + 1) div 4),
  case fp_sqr(Root) =:= A of
    true -> {ok, Root};
    false -> error
  end.

-spec fp_to_bin(fp()) -> <<_:256>>.
fp_to_bin(A) when A >= 0, A < ?BN254_P ->
  <<A:256/big>>;
fp_to_bin(_) ->
  error(badarg).

-spec fp_from_bin(binary()) -> fp().
fp_from_bin(<<A:256/big>>) when A < ?BN254_P ->
  A;
fp_from_bin(_) ->
  error(badarg).

%%%-------------------------------------------------------------------
%%% Fp2: Quadratic Extension Fp[u] / (u^2 + 1)
%%% Element {C0, C1} represents C0 + C1 * u.
%%%-------------------------------------------------------------------

-spec fp2_zero() -> fp2().
fp2_zero() -> {0, 0}.

-spec fp2_one() -> fp2().
fp2_one() -> {1, 0}.

-spec fp2_is_zero(fp2()) -> boolean().
fp2_is_zero({0, 0}) -> true;
fp2_is_zero(_) -> false.

-spec fp2_is_one(fp2()) -> boolean().
fp2_is_one({1, 0}) -> true;
fp2_is_one(_) -> false.

-spec fp2_add(fp2(), fp2()) -> fp2().
fp2_add({A0, A1}, {B0, B1}) ->
  {fp_add(A0, B0), fp_add(A1, B1)}.

-spec fp2_sub(fp2(), fp2()) -> fp2().
fp2_sub({A0, A1}, {B0, B1}) ->
  {fp_sub(A0, B0), fp_sub(A1, B1)}.

-spec fp2_neg(fp2()) -> fp2().
fp2_neg({A0, A1}) ->
  {fp_neg(A0), fp_neg(A1)}.

-spec fp2_mul(fp2(), fp2()) -> fp2().
fp2_mul({A0, A1}, {B0, B1}) ->
  %% Karatsuba multiplication in Fp2:
  %% (A0 + A1*u)(B0 + B1*u) = (A0*B0 - A1*B1) + (A0*B1 + A1*B0)*u
  V0 = fp_mul(A0, B0),
  V1 = fp_mul(A1, B1),
  C0 = fp_sub(V0, V1),
  C1 = fp_sub(fp_sub(fp_mul(fp_add(A0, A1), fp_add(B0, B1)), V0), V1),
  {C0, C1}.

-spec fp2_sqr(fp2()) -> fp2().
fp2_sqr({A0, A1}) ->
  %% (A0 + A1*u)^2 = (A0 - A1)(A0 + A1) + 2*A0*A1*u
  C0 = fp_mul(fp_sub(A0, A1), fp_add(A0, A1)),
  C1 = fp_mul(fp_add(A0, A0), A1),
  {C0, C1}.

-spec fp2_mul_fp(fp2(), fp()) -> fp2().
fp2_mul_fp({A0, A1}, S) ->
  {fp_mul(A0, S), fp_mul(A1, S)}.

%% Multiplication by xi = 9 + u:
%% (A0 + A1*u)(9 + u) = (9*A0 - A1) + (A0 + 9*A1)*u
-spec fp2_mul_xi(fp2()) -> fp2().
fp2_mul_xi({A0, A1}) ->
  P = ?BN254_P,
  C0 = ((9 * A0 - A1) rem P + P) rem P,
  C1 = (A0 + 9 * A1) rem P,
  {C0, C1}.

-spec fp2_inv(fp2()) -> fp2().
fp2_inv({0, 0}) ->
  error(badarg);
fp2_inv({A0, A1}) ->
  %% (A0 + A1*u)^-1 = (A0 - A1*u) / (A0^2 + A1^2)
  Norm = fp_add(fp_sqr(A0), fp_sqr(A1)),
  InvNorm = fp_inv(Norm),
  {fp_mul(A0, InvNorm), fp_neg(fp_mul(A1, InvNorm))}.

-spec fp2_conj(fp2()) -> fp2().
fp2_conj({A0, A1}) ->
  {A0, fp_neg(A1)}.

-spec fp2_frobenius(fp2()) -> fp2().
fp2_frobenius(A) ->
  %% In Fp2, u^p = -u because p = 3 mod 4. Thus pi(A) = conj(A).
  fp2_conj(A).

-spec fp2_pow(fp2(), non_neg_integer()) -> fp2().
fp2_pow(_A, 0) -> fp2_one();
fp2_pow(A, 1) -> A;
fp2_pow(A, Exp) -> fp2_pow_acc(A, Exp, fp2_one()).

-spec fp2_pow_acc(fp2(), non_neg_integer(), fp2()) -> fp2().
fp2_pow_acc(_A, 0, Acc) ->
  Acc;
fp2_pow_acc(A, Exp, Acc) when Exp rem 2 =:= 1 ->
  fp2_pow_acc(fp2_sqr(A), Exp div 2, fp2_mul(Acc, A));
fp2_pow_acc(A, Exp, Acc) ->
  fp2_pow_acc(fp2_sqr(A), Exp div 2, Acc).

%% Square root in Fp2:
-spec fp2_sqrt(fp2()) -> {ok, fp2()} | error.
fp2_sqrt({0, 0}) ->
  {ok, {0, 0}};
fp2_sqrt({A0, 0}) ->
  case fp_sqrt(A0) of
    {ok, R0} ->
      {ok, {R0, 0}};
    error ->
      %% If A0 is a quadratic non-residue in Fp, its sqrt in Fp2 is sqrt(-A0)*u
      case fp_sqrt(fp_neg(A0)) of
        {ok, R1} -> {ok, {0, R1}};
        error -> error
      end
  end;
fp2_sqrt({A0, A1}) ->
  %% General square root for z = A0 + A1*u:
  %% alpha = sqrt(A0^2 + A1^2)
  Norm = fp_add(fp_sqr(A0), fp_sqr(A1)),
  case fp_sqrt(Norm) of
    error ->
      error;
    {ok, Alpha} ->
      %% Try delta = (A0 + Alpha) / 2
      Inv2 = (?BN254_P + 1) div 2,
      Delta1 = fp_mul(fp_add(A0, Alpha), Inv2),
      case fp_sqrt(Delta1) of
        {ok, C0} ->
          Inv2C0 = fp_inv(fp_add(C0, C0)),
          C1 = fp_mul(A1, Inv2C0),
          {ok, {C0, C1}};
        error ->
          Delta2 = fp_mul(fp_sub(A0, Alpha), Inv2),
          case fp_sqrt(Delta2) of
            {ok, C0} ->
              Inv2C0 = fp_inv(fp_add(C0, C0)),
              C1 = fp_mul(A1, Inv2C0),
              {ok, {C0, C1}};
            error ->
              error
          end
      end
  end.

%% sgn0 helper per RFC 9380 §4.1 for Fp2
-spec fp2_sgn0(fp2()) -> 0 | 1.
fp2_sgn0({C0, C1}) ->
  Sign0 = C0 rem 2,
  Zero0 = C0 =:= 0,
  Sign1 = C1 rem 2,
  case Sign0 =:= 1 orelse (Zero0 andalso Sign1 =:= 1) of
    true -> 1;
    false -> 0
  end.

%% Byte serialization: EIP-197 format puts C1 first, then C0 (64 bytes total).
-spec fp2_to_bin(fp2()) -> <<_:512>>.
fp2_to_bin({C0, C1}) ->
  B1 = fp_to_bin(C1),
  B0 = fp_to_bin(C0),
  <<B1/binary, B0/binary>>.

-spec fp2_from_bin(binary()) -> fp2().
fp2_from_bin(<<B1:32/binary, B0:32/binary>>) ->
  C1 = fp_from_bin(B1),
  C0 = fp_from_bin(B0),
  {C0, C1};
fp2_from_bin(_) ->
  error(badarg).

%%%-------------------------------------------------------------------
%%% Fp6: Cubic Extension over Fp2: Fp2[v] / (v^3 - (9 + u))
%%% Element {C0, C1, C2} represents C0 + C1 * v + C2 * v^2.
%%%-------------------------------------------------------------------

-spec fp6_zero() -> fp6().
fp6_zero() -> {fp2_zero(), fp2_zero(), fp2_zero()}.

-spec fp6_one() -> fp6().
fp6_one() -> {fp2_one(), fp2_zero(), fp2_zero()}.

-spec fp6_is_zero(fp6()) -> boolean().
fp6_is_zero({C0, C1, C2}) ->
  fp2_is_zero(C0) andalso fp2_is_zero(C1) andalso fp2_is_zero(C2).

-spec fp6_is_one(fp6()) -> boolean().
fp6_is_one({C0, C1, C2}) ->
  fp2_is_one(C0) andalso fp2_is_zero(C1) andalso fp2_is_zero(C2).

-spec fp6_add(fp6(), fp6()) -> fp6().
fp6_add({A0, A1, A2}, {B0, B1, B2}) ->
  {fp2_add(A0, B0), fp2_add(A1, B1), fp2_add(A2, B2)}.

-spec fp6_sub(fp6(), fp6()) -> fp6().
fp6_sub({A0, A1, A2}, {B0, B1, B2}) ->
  {fp2_sub(A0, B0), fp2_sub(A1, B1), fp2_sub(A2, B2)}.

-spec fp6_neg(fp6()) -> fp6().
fp6_neg({A0, A1, A2}) ->
  {fp2_neg(A0), fp2_neg(A1), fp2_neg(A2)}.

-spec fp6_mul(fp6(), fp6()) -> fp6().
fp6_mul({A0, A1, A2}, {B0, B1, B2}) ->
  %% Toom-Cook / Karatsuba multiplication in Fp6:
  V0 = fp2_mul(A0, B0),
  V1 = fp2_mul(A1, B1),
  V2 = fp2_mul(A2, B2),
  %% c0 = v0 + xi * ((a1 + a2)(b1 + b2) - v1 - v2)
  T0 = fp2_sub(fp2_sub(fp2_mul(fp2_add(A1, A2), fp2_add(B1, B2)), V1), V2),
  C0 = fp2_add(V0, fp2_mul_xi(T0)),
  %% c1 = (a0 + a1)(b0 + b1) - v0 - v1 + xi * v2
  T1 = fp2_sub(fp2_sub(fp2_mul(fp2_add(A0, A1), fp2_add(B0, B1)), V0), V1),
  C1 = fp2_add(T1, fp2_mul_xi(V2)),
  %% c2 = (a0 + a2)(b0 + b2) - v0 - v2 + v1
  T2 = fp2_sub(fp2_sub(fp2_mul(fp2_add(A0, A2), fp2_add(B0, B2)), V0), V2),
  C2 = fp2_add(T2, V1),
  {C0, C1, C2}.

-spec fp6_sqr(fp6()) -> fp6().
fp6_sqr({A0, A1, A2}) ->
  %% Chung-Hasan SQR3 for cubic extensions:
  S0 = fp2_sqr(A0),
  Ab = fp2_mul(A0, A1),
  S1 = fp2_add(Ab, Ab),
  S2 = fp2_sqr(fp2_sub(fp2_add(A0, A2), A1)),
  Bc = fp2_mul(A1, A2),
  S3 = fp2_add(Bc, Bc),
  S4 = fp2_sqr(A2),
  C0 = fp2_add(S0, fp2_mul_xi(S3)),
  C1 = fp2_add(S1, fp2_mul_xi(S4)),
  C2 = fp2_sub(fp2_sub(fp2_add(fp2_add(S1, S2), S3), S0), S4),
  {C0, C1, C2}.

-spec fp6_mul_fp2(fp6(), fp2()) -> fp6().
fp6_mul_fp2({A0, A1, A2}, S) ->
  {fp2_mul(A0, S), fp2_mul(A1, S), fp2_mul(A2, S)}.

-spec fp6_mul_v(fp6()) -> fp6().
fp6_mul_v({A0, A1, A2}) ->
  {fp2_mul_xi(A2), A0, A1}.

-spec fp6_inv(fp6()) -> fp6().
fp6_inv({A0, A1, A2}) ->
  %% Inversion using cofactor norm to Fp2:
  D0 = fp2_sub(fp2_sqr(A0), fp2_mul_xi(fp2_mul(A1, A2))),
  D1 = fp2_sub(fp2_mul_xi(fp2_sqr(A2)), fp2_mul(A0, A1)),
  D2 = fp2_sub(fp2_sqr(A1), fp2_mul(A0, A2)),
  %% Norm F = a0 * d0 + xi * (a2 * d1 + a1 * d2)
  T = fp2_add(fp2_mul(A2, D1), fp2_mul(A1, D2)),
  F = fp2_add(fp2_mul(A0, D0), fp2_mul_xi(T)),
  InvF = fp2_inv(F),
  {fp2_mul(D0, InvF), fp2_mul(D1, InvF), fp2_mul(D2, InvF)}.

-spec fp6_frobenius(fp6()) -> fp6().
fp6_frobenius({C0, C1, C2}) ->
  {
    fp2_frobenius(C0),
    fp2_mul(fp2_frobenius(C1), gamma_11()),
    fp2_mul(fp2_frobenius(C2), gamma_12())
  }.

-spec fp6_frobenius2(fp6()) -> fp6().
fp6_frobenius2({C0, C1, C2}) ->
  {
    C0,
    fp2_mul(C1, gamma_21()),
    fp2_mul(C2, gamma_22())
  }.

%%%-------------------------------------------------------------------
%%% Fp12: Quadratic Extension over Fp6: Fp6[w] / (w^2 - v)
%%% Element {C0, C1} represents C0 + C1 * w.
%%%-------------------------------------------------------------------

-spec fp12_zero() -> fp12().
fp12_zero() -> {fp6_zero(), fp6_zero()}.

-spec fp12_one() -> fp12().
fp12_one() -> {fp6_one(), fp6_zero()}.

-spec fp12_is_zero(fp12()) -> boolean().
fp12_is_zero({C0, C1}) ->
  fp6_is_zero(C0) andalso fp6_is_zero(C1).

-spec fp12_is_one(fp12()) -> boolean().
fp12_is_one({C0, C1}) ->
  fp6_is_one(C0) andalso fp6_is_zero(C1).

-spec fp12_add(fp12(), fp12()) -> fp12().
fp12_add({A0, A1}, {B0, B1}) ->
  {fp6_add(A0, B0), fp6_add(A1, B1)}.

-spec fp12_sub(fp12(), fp12()) -> fp12().
fp12_sub({A0, A1}, {B0, B1}) ->
  {fp6_sub(A0, B0), fp6_sub(A1, B1)}.

-spec fp12_neg(fp12()) -> fp12().
fp12_neg({A0, A1}) ->
  {fp6_neg(A0), fp6_neg(A1)}.

-spec fp12_mul(fp12(), fp12()) -> fp12().
fp12_mul({A0, A1}, {B0, B1}) ->
  %% Karatsuba multiplication in Fp12:
  V0 = fp6_mul(A0, B0),
  V1 = fp6_mul(A1, B1),
  C0 = fp6_add(V0, fp6_mul_v(V1)),
  C1 = fp6_sub(fp6_sub(fp6_mul(fp6_add(A0, A1), fp6_add(B0, B1)), V0), V1),
  {C0, C1}.

-spec fp12_sqr(fp12()) -> fp12().
fp12_sqr({A0, A1}) ->
  %% Complex-style squaring in Fp12:
  %% (A0 + A1*w)^2 = (A0^2 + A1^2*v) + 2*A0*A1*w
  V0 = fp6_sqr(A0),
  V1 = fp6_sqr(A1),
  C0 = fp6_add(V0, fp6_mul_v(V1)),
  C1 = fp6_sub(fp6_sub(fp6_sqr(fp6_add(A0, A1)), V0), V1),
  {C0, C1}.

-spec fp12_mul_fp6(fp12(), fp6()) -> fp12().
fp12_mul_fp6({A0, A1}, S) ->
  {fp6_mul(A0, S), fp6_mul(A1, S)}.

-spec fp12_inv(fp12()) -> fp12().
fp12_inv({A0, A1}) ->
  %% Inversion using norm to Fp6: N = A0^2 - A1^2 * v
  Norm = fp6_sub(fp6_sqr(A0), fp6_mul_v(fp6_sqr(A1))),
  InvNorm = fp6_inv(Norm),
  {fp6_mul(A0, InvNorm), fp6_neg(fp6_mul(A1, InvNorm))}.

-spec fp12_conj(fp12()) -> fp12().
fp12_conj({A0, A1}) ->
  {A0, fp6_neg(A1)}.

-spec fp12_frobenius_p6(fp12()) -> fp12().
fp12_frobenius_p6(A) ->
  fp12_conj(A).

%% Cyclotomic squaring for elements in the cyclotomic subgroup G_T
-spec fp12_cyclotomic_sqr(fp12()) -> fp12().
fp12_cyclotomic_sqr(A) ->
  fp12_sqr(A).

-spec fp12_pow(fp12(), non_neg_integer()) -> fp12().
fp12_pow(_A, 0) -> fp12_one();
fp12_pow(A, 1) -> A;
fp12_pow(A, Exp) -> fp12_pow_acc(A, Exp, fp12_one()).

-spec fp12_pow_acc(fp12(), non_neg_integer(), fp12()) -> fp12().
fp12_pow_acc(_A, 0, Acc) ->
  Acc;
fp12_pow_acc(A, Exp, Acc) when Exp rem 2 =:= 1 ->
  fp12_pow_acc(fp12_sqr(A), Exp div 2, fp12_mul(Acc, A));
fp12_pow_acc(A, Exp, Acc) ->
  fp12_pow_acc(fp12_sqr(A), Exp div 2, Acc).

-spec fp12_frobenius(fp12()) -> fp12().
fp12_frobenius({C0, C1}) ->
  {
    fp6_frobenius(C0),
    fp6_mul_fp2(fp6_frobenius(C1), gamma_1w())
  }.

-spec fp12_frobenius2(fp12()) -> fp12().
fp12_frobenius2({C0, C1}) ->
  {
    fp6_frobenius2(C0),
    fp6_mul_fp2(fp6_frobenius2(C1), gamma_2w())
  }.

-spec fp12_frobenius3(fp12()) -> fp12().
fp12_frobenius3({C0, C1}) ->
  {
    fp6_frobenius(fp6_frobenius2(C0)),
    fp6_mul_fp2(fp6_frobenius(fp6_frobenius2(C1)), gamma_3w())
  }.

%% Binary serialization for Fp12 (384 bytes: 12 * 32 bytes)
-spec fp12_to_bin(fp12()) -> <<_:3072>>.
fp12_to_bin({{{C00, C01}, {C10, C11}, {C20, C21}}, {{C30, C31}, {C40, C41}, {C50, C51}}}) ->
  <<
    (fp_to_bin(C01))/binary,
    (fp_to_bin(C00))/binary,
    (fp_to_bin(C11))/binary,
    (fp_to_bin(C10))/binary,
    (fp_to_bin(C21))/binary,
    (fp_to_bin(C20))/binary,
    (fp_to_bin(C31))/binary,
    (fp_to_bin(C30))/binary,
    (fp_to_bin(C41))/binary,
    (fp_to_bin(C40))/binary,
    (fp_to_bin(C51))/binary,
    (fp_to_bin(C50))/binary
  >>.

-spec fp12_from_bin(binary()) -> fp12().
fp12_from_bin(
  <<
    B01:32/binary,
    B00:32/binary,
    B11:32/binary,
    B10:32/binary,
    B21:32/binary,
    B20:32/binary,
    B31:32/binary,
    B30:32/binary,
    B41:32/binary,
    B40:32/binary,
    B51:32/binary,
    B50:32/binary
  >>
) ->
  {
    {
      {fp_from_bin(B00), fp_from_bin(B01)},
      {fp_from_bin(B10), fp_from_bin(B11)},
      {fp_from_bin(B20), fp_from_bin(B21)}
    },
    {
      {fp_from_bin(B30), fp_from_bin(B31)},
      {fp_from_bin(B40), fp_from_bin(B41)},
      {fp_from_bin(B50), fp_from_bin(B51)}
    }
  };
fp12_from_bin(_) ->
  error(badarg).

%%%-------------------------------------------------------------------
%%% Frobenius Constants for BN254
%%% xi = 9 + u
%%% gamma_1w = xi^((p - 1) / 6)
%%% gamma_11 = xi^((p - 1) / 3) = gamma_1w^2
%%% gamma_12 = xi^(2*(p - 1) / 3) = gamma_11^2
%%% gamma_2w = xi^((p^2 - 1) / 6)
%%% gamma_21 = xi^((p^2 - 1) / 3) = gamma_2w^2
%%% gamma_22 = xi^(2*(p^2 - 1) / 3) = gamma_21^2
%%% gamma_3w = xi^((p^3 - 1) / 6)
%%%-------------------------------------------------------------------

-spec gamma_1w() -> fp2().
gamma_1w() ->
  %% xi^((p - 1)/6)
  P = ?BN254_P,
  fp2_pow({9, 1}, (P - 1) div 6).

-spec gamma_11() -> fp2().
gamma_11() ->
  fp2_sqr(gamma_1w()).

-spec gamma_12() -> fp2().
gamma_12() ->
  fp2_sqr(gamma_11()).

-spec gamma_2w() -> fp2().
gamma_2w() ->
  P = ?BN254_P,
  fp2_pow({9, 1}, (P * P - 1) div 6).

-spec gamma_21() -> fp2().
gamma_21() ->
  fp2_sqr(gamma_2w()).

-spec gamma_22() -> fp2().
gamma_22() ->
  fp2_sqr(gamma_21()).

-spec gamma_3w() -> fp2().
gamma_3w() ->
  fp2_mul(gamma_1w(), gamma_2w()).
