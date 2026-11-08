%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang finite field arithmetic for BLS12-381 field extension towers:
%%%   - Base field Fp (381 bits)
%%%   - Quadratic extension Fp2 = Fp[u] / (u^2 + 1)
%%%   - Sextic extension Fp6 = Fp2[v] / (v^3 - (1 + u))
%%%   - Dodecic extension Fp12 = Fp6[w] / (w^2 - v)
%%%
%%% Reference:
%%%   - RFC 9380: https://www.rfc-editor.org/rfc/rfc9380.html
%%%   - draft-irtf-cfrg-pairing-friendly-curves:
%%%     https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves
%%%   - Zcash BLS12-381 specification:
%%%     https://github.com/zkcrypto/bls12_381
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_fp).

-typing([eqwalizer]).

-include("ecu_bls12_381.hrl").

-export_type([fp/0, fp2/0, fp6/0, fp12/0]).

-type fp() :: non_neg_integer().
-type fp2() :: {fp(), fp()}.
-type fp6() :: {fp2(), fp2(), fp2()}.
-type fp12() :: {fp6(), fp6()}.

%% Curve & field parameters
-export([
  p/0,
  r/0,
  x/0,
  abs_x/0
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
p() -> ?BLS12_381_P.

-spec r() -> pos_integer().
r() -> ?BLS12_381_R.

-spec x() -> integer().
x() -> ?BLS12_381_X.

-spec abs_x() -> pos_integer().
abs_x() -> ?BLS12_381_ABS_X.

%%%-------------------------------------------------------------------
%%% Fp: Base Field Arithmetic
%%%-------------------------------------------------------------------

-spec fp_zero() -> fp().
fp_zero() -> 0.

-spec fp_one() -> fp().
fp_one() -> 1.

-spec fp_is_zero(fp()) -> boolean().
fp_is_zero(A) -> A =:= 0.

-spec fp_is_one(fp()) -> boolean().
fp_is_one(A) -> A =:= 1.

-spec fp_add(fp(), fp()) -> fp().
fp_add(A, B) ->
  S = A + B,
  case S >= ?BLS12_381_P of
    true -> S - ?BLS12_381_P;
    false -> S
  end.

-spec fp_sub(fp(), fp()) -> fp().
fp_sub(A, B) ->
  case A >= B of
    true -> A - B;
    false -> A - B + ?BLS12_381_P
  end.

-spec fp_neg(fp()) -> fp().
fp_neg(0) -> 0;
fp_neg(A) -> ?BLS12_381_P - A.

-spec fp_mul(fp(), fp()) -> fp().
fp_mul(A, B) -> (A * B) rem ?BLS12_381_P.

-spec fp_sqr(fp()) -> fp().
fp_sqr(A) -> (A * A) rem ?BLS12_381_P.

-spec fp_inv(fp()) -> fp().
fp_inv(0) ->
  error(badarg);
fp_inv(A) ->
  case ecu_misc:eea(A, ?BLS12_381_P) of
    {1, S, _} ->
      case S < 0 of
        true -> S + ?BLS12_381_P;
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
  ecu_misc:exp_mod(A, Exp, ?BLS12_381_P).

%% Square root in Fp using p = 3 mod 4:
%% If A is a QR, sqrt(A) = A^((p + 1) / 4) mod p.
-spec fp_sqrt(fp()) -> {ok, fp()} | error.
fp_sqrt(0) ->
  {ok, 0};
fp_sqrt(A) ->
  Candidate = fp_pow(A, (?BLS12_381_P + 1) div 4),
  case fp_sqr(Candidate) =:= A of
    true -> {ok, Candidate};
    false -> error
  end.

-spec fp_to_bin(fp()) -> <<_:384>>.
fp_to_bin(A) when is_integer(A), A >= 0, A < ?BLS12_381_P ->
  <<A:384>>.

-spec fp_from_bin(binary()) -> fp().
fp_from_bin(<<A:384>>) when A < ?BLS12_381_P ->
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
  %% v0 = A0 * B0, v1 = A1 * B1
  %% c0 = v0 - v1
  %% c1 = (A0 + A1)(B0 + B1) - v0 - v1
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

%% Multiplication by xi = 1 + u:
%% (A0 + A1*u)(1 + u) = (A0 - A1) + (A0 + A1)*u
-spec fp2_mul_xi(fp2()) -> fp2().
fp2_mul_xi({A0, A1}) ->
  {fp_sub(A0, A1), fp_add(A0, A1)}.

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
    {ok, S} ->
      {ok, {S, 0}};
    error ->
      %% Since -1 is non-square in Fp, A0 = u^2 * (-A0), so -A0 is a square
      case fp_sqrt(fp_neg(A0)) of
        {ok, S} -> {ok, {0, S}};
        error -> error
      end
  end;
fp2_sqrt({A0, A1}) ->
  Norm = fp_add(fp_sqr(A0), fp_sqr(A1)),
  case fp_sqrt(Norm) of
    error ->
      error;
    {ok, D} ->
      Inv2 = (?BLS12_381_P + 1) div 2,
      T1 = fp_mul(fp_add(A0, D), Inv2),
      case fp_sqrt(T1) of
        {ok, X0} ->
          X1 = fp_mul(A1, fp_inv(fp_add(X0, X0))),
          {ok, {X0, X1}};
        error ->
          T2 = fp_mul(fp_sub(A0, D), Inv2),
          case fp_sqrt(T2) of
            {ok, X0} ->
              X1 = fp_mul(A1, fp_inv(fp_add(X0, X0))),
              {ok, {X0, X1}};
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

%% Byte serialization: RFC 9380 / Zcash format puts C1 first, then C0.
-spec fp2_to_bin(fp2()) -> <<_:768>>.
fp2_to_bin({C0, C1}) ->
  B1 = fp_to_bin(C1),
  B0 = fp_to_bin(C0),
  <<B1/binary, B0/binary>>.

-spec fp2_from_bin(binary()) -> fp2().
fp2_from_bin(<<B1:48/binary, B0:48/binary>>) ->
  C1 = fp_from_bin(B1),
  C0 = fp_from_bin(B0),
  {C0, C1};
fp2_from_bin(_) ->
  error(badarg).

%%%-------------------------------------------------------------------
%%% Fp6: Cubic Extension over Fp2: Fp2[v] / (v^3 - (1 + u))
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
  %% Karatsuba multiplication in Fp6 (Toom-Cook / Karatsuba):
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
  %% Chung-Hasan SQR3 squaring:
  S0 = fp2_sqr(A0),
  S1 = fp2_mul(fp2_add(A0, A0), A1),
  S2 = fp2_sqr(fp2_add(fp2_sub(A0, A1), A2)),
  S3 = fp2_mul(fp2_add(A1, A1), A2),
  S4 = fp2_sqr(A2),
  C0 = fp2_add(S0, fp2_mul_xi(S3)),
  C1 = fp2_add(S1, fp2_mul_xi(S4)),
  C2 = fp2_sub(fp2_add(fp2_add(S1, S2), S3), fp2_add(S0, S4)),
  {C0, C1, C2}.

-spec fp6_mul_fp2(fp6(), fp2()) -> fp6().
fp6_mul_fp2({A0, A1, A2}, S) ->
  {fp2_mul(A0, S), fp2_mul(A1, S), fp2_mul(A2, S)}.

%% Multiplication by v: (A0 + A1*v + A2*v^2)*v = xi*A2 + A0*v + A1*v^2
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

%% Cyclotomic squaring for elements in the cyclotomic subgroup G_T
-spec fp12_cyclotomic_sqr(fp12()) -> fp12().
fp12_cyclotomic_sqr(A) ->
  %% In cyclotomic subgroup, general squaring is sound and exact
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
  %% pi^3(A) = pi(pi^2(A))
  {
    fp6_frobenius(fp6_frobenius2(C0)),
    fp6_mul_fp2(fp6_frobenius(fp6_frobenius2(C1)), gamma_3w())
  }.

%% Binary serialization for Fp12 (576 bytes: 12 * 48 bytes)
-spec fp12_to_bin(fp12()) -> <<_:4608>>.
fp12_to_bin({{{C00, C01}, {C10, C11}, {C20, C21}}, {{C30, C31}, {C40, C41}, {C50, C51}}}) ->
  <<
    (fp_to_bin(C00))/binary,
    (fp_to_bin(C01))/binary,
    (fp_to_bin(C10))/binary,
    (fp_to_bin(C11))/binary,
    (fp_to_bin(C20))/binary,
    (fp_to_bin(C21))/binary,
    (fp_to_bin(C30))/binary,
    (fp_to_bin(C31))/binary,
    (fp_to_bin(C40))/binary,
    (fp_to_bin(C41))/binary,
    (fp_to_bin(C50))/binary,
    (fp_to_bin(C51))/binary
  >>.

-spec fp12_from_bin(binary()) -> fp12().
fp12_from_bin(
  <<B00:48/binary, B01:48/binary, B10:48/binary, B11:48/binary, B20:48/binary, B21:48/binary,
    B30:48/binary, B31:48/binary, B40:48/binary, B41:48/binary, B50:48/binary, B51:48/binary>>
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
%%% Precomputed Frobenius Constants
%%%
%%% xi = 1 + u in Fp2.
%%% gamma_1w = xi^((p - 1) / 6)
%%% gamma_11 = gamma_1w^2 = xi^((p - 1) / 3)
%%% gamma_12 = gamma_1w^4 = xi^(2(p - 1) / 3)
%%%
%%% gamma_2w = xi^((p^2 - 1) / 6) = pi(gamma_1w) * gamma_1w
%%% gamma_21 = gamma_2w^2
%%% gamma_22 = gamma_2w^4
%%%
%%% gamma_3w = xi^((p^3 - 1) / 6) = gamma_2w * gamma_1w
%%%-------------------------------------------------------------------

-spec gamma_1w() -> fp2().
gamma_1w() ->
  %% xi^((p - 1) / 6)
  fp2_pow({1, 1}, (?BLS12_381_P - 1) div 6).

-spec gamma_11() -> fp2().
gamma_11() ->
  %% xi^((p - 1) / 3) = gamma_1w^2
  fp2_sqr(gamma_1w()).

-spec gamma_12() -> fp2().
gamma_12() ->
  %% xi^(2*(p - 1) / 3) = gamma_11^2
  fp2_sqr(gamma_11()).

-spec gamma_2w() -> fp2().
gamma_2w() ->
  %% xi^((p^2 - 1) / 6) = pi(gamma_1w) * gamma_1w
  G1w = gamma_1w(),
  fp2_mul(fp2_frobenius(G1w), G1w).

-spec gamma_21() -> fp2().
gamma_21() ->
  %% xi^((p^2 - 1) / 3) = gamma_2w^2
  fp2_sqr(gamma_2w()).

-spec gamma_22() -> fp2().
gamma_22() ->
  %% xi^(2*(p^2 - 1) / 3) = gamma_21^2
  fp2_sqr(gamma_21()).

-spec gamma_3w() -> fp2().
gamma_3w() ->
  %% xi^((p^3 - 1) / 6) = gamma_2w * gamma_1w
  fp2_mul(gamma_2w(), gamma_1w()).
