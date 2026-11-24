%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang polynomial arithmetic over finite fields (defaulting to
%%% the BLS12-381 scalar field Fr).
%%%
%%% Polynomials are represented in dense form as lists of coefficients in
%%% ascending degree order:
%%%   `[c0, c1, c2, ..., cd]` corresponds to `c0 + c1*x + c2*x^2 + ... + cd*x^d`.
%%%
%%% Includes:
%%%   - Horner's method evaluation in O(d)
%%%   - Addition, subtraction, scalar multiplication, and polynomial convolution
%%%   - Synthetic division (Ruffini's rule) dividing P(x) by (x - z) in O(d)
%%%   - Canonical trimming and degree calculation
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_poly).

-typing([eqwalizer]).

-include("ecu_bls12_381.hrl").

-type poly() :: [non_neg_integer()].

-export_type([poly/0]).

-export([
  zero/0,
  is_zero/1,
  degree/1,
  trim/1,
  normalize/1,
  normalize/2,
  eval/2,
  eval/3,
  add/2,
  add/3,
  sub/2,
  sub/3,
  mul_scalar/2,
  mul_scalar/3,
  mul/2,
  mul/3,
  divide_by_linear/2,
  divide_by_linear/3
]).

-define(DEFAULT_MOD, ?BLS12_381_R).

%%%-------------------------------------------------------------------
%%% API
%%%-------------------------------------------------------------------

%% @doc Returns the zero polynomial [0].
-spec zero() -> poly().
zero() ->
  [0].

%% @doc Returns true if the polynomial is identically zero.
-spec is_zero(poly()) -> boolean().
is_zero(P) ->
  trim(P) =:= [0].

%% @doc Returns the degree of the polynomial (-1 for zero polynomial).
-spec degree(poly()) -> integer().
degree(P) ->
  case trim(P) of
    [0] -> -1;
    Trimmed -> length(Trimmed) - 1
  end.

%% @doc Strip trailing zeroes from high-degree coefficients.
-spec trim(poly()) -> poly().
trim([]) ->
  [0];
trim(P) ->
  trim_rev(lists:reverse(P)).

-spec trim_rev(poly()) -> poly().
trim_rev([]) ->
  [0];
trim_rev([0]) ->
  [0];
trim_rev([0 | Rest]) ->
  trim_rev(Rest);
trim_rev(Reversed) ->
  lists:reverse(Reversed).

%% @doc Normalize polynomial coefficients modulo BLS12-381 r and trim trailing zeroes.
-spec normalize(poly()) -> poly().
normalize(P) ->
  normalize(P, ?DEFAULT_MOD).

%% @doc Normalize polynomial coefficients modulo Mod and trim trailing zeroes.
-spec normalize(poly(), pos_integer()) -> poly().
normalize(P, Mod) when is_list(P), is_integer(Mod), Mod > 1 ->
  trim([((C rem Mod) + Mod) rem Mod || C <- P, is_integer(C)]).

%% @doc Evaluate polynomial at X modulo BLS12-381 scalar field modulus r.
-spec eval(poly(), integer()) -> non_neg_integer().
eval(P, X) ->
  eval(P, X, ?DEFAULT_MOD).

%% @doc Evaluate polynomial at X modulo Mod using Horner's method.
-spec eval(poly(), integer(), pos_integer()) -> non_neg_integer().
eval([], _X, _Mod) ->
  0;
eval(P, X, Mod) ->
  NormX = ((X rem Mod) + Mod) rem Mod,
  Rev = lists:reverse(P),
  eval_horner(Rev, NormX, Mod, 0).

-spec eval_horner(poly(), non_neg_integer(), pos_integer(), non_neg_integer()) ->
  non_neg_integer().
eval_horner([], _X, _Mod, Acc) ->
  Acc;
eval_horner([C | Rest], X, Mod, Acc) ->
  NormC = ((C rem Mod) + Mod) rem Mod,
  NewAcc = (Acc * X + NormC) rem Mod,
  eval_horner(Rest, X, Mod, NewAcc).

%% @doc Add two polynomials modulo BLS12-381 r.
-spec add(poly(), poly()) -> poly().
add(P1, P2) ->
  add(P1, P2, ?DEFAULT_MOD).

%% @doc Add two polynomials modulo Mod.
-spec add(poly(), poly(), pos_integer()) -> poly().
add(P1, P2, Mod) ->
  trim(add_coeffs(P1, P2, Mod, [])).

-spec add_coeffs(poly(), poly(), pos_integer(), poly()) -> poly().
add_coeffs([], [], _Mod, Acc) ->
  lists:reverse(Acc);
add_coeffs([C1 | R1], [], Mod, Acc) ->
  Norm = ((C1 rem Mod) + Mod) rem Mod,
  add_coeffs(R1, [], Mod, [Norm | Acc]);
add_coeffs([], [C2 | R2], Mod, Acc) ->
  Norm = ((C2 rem Mod) + Mod) rem Mod,
  add_coeffs([], R2, Mod, [Norm | Acc]);
add_coeffs([C1 | R1], [C2 | R2], Mod, Acc) ->
  Sum = (((C1 + C2) rem Mod) + Mod) rem Mod,
  add_coeffs(R1, R2, Mod, [Sum | Acc]).

%% @doc Subtract polynomial P2 from P1 modulo BLS12-381 r.
-spec sub(poly(), poly()) -> poly().
sub(P1, P2) ->
  sub(P1, P2, ?DEFAULT_MOD).

%% @doc Subtract polynomial P2 from P1 modulo Mod.
-spec sub(poly(), poly(), pos_integer()) -> poly().
sub(P1, P2, Mod) ->
  trim(sub_coeffs(P1, P2, Mod, [])).

-spec sub_coeffs(poly(), poly(), pos_integer(), poly()) -> poly().
sub_coeffs([], [], _Mod, Acc) ->
  lists:reverse(Acc);
sub_coeffs([C1 | R1], [], Mod, Acc) ->
  Norm = ((C1 rem Mod) + Mod) rem Mod,
  sub_coeffs(R1, [], Mod, [Norm | Acc]);
sub_coeffs([], [C2 | R2], Mod, Acc) ->
  Norm = (((-C2) rem Mod) + Mod) rem Mod,
  sub_coeffs([], R2, Mod, [Norm | Acc]);
sub_coeffs([C1 | R1], [C2 | R2], Mod, Acc) ->
  Diff = (((C1 - C2) rem Mod) + Mod) rem Mod,
  sub_coeffs(R1, R2, Mod, [Diff | Acc]).

%% @doc Multiply polynomial by scalar modulo BLS12-381 r.
-spec mul_scalar(poly(), integer()) -> poly().
mul_scalar(P, Scalar) ->
  mul_scalar(P, Scalar, ?DEFAULT_MOD).

%% @doc Multiply polynomial by scalar modulo Mod.
-spec mul_scalar(poly(), integer(), pos_integer()) -> poly().
mul_scalar(P, Scalar, Mod) ->
  NormS = ((Scalar rem Mod) + Mod) rem Mod,
  case NormS of
    0 -> [0];
    _ -> trim([(((C * NormS) rem Mod) + Mod) rem Mod || C <- P])
  end.

%% @doc Multiply two polynomials modulo BLS12-381 r.
-spec mul(poly(), poly()) -> poly().
mul(P1, P2) ->
  mul(P1, P2, ?DEFAULT_MOD).

%% @doc Multiply two polynomials modulo Mod via standard convolution.
-spec mul(poly(), poly(), pos_integer()) -> poly().
mul(P1, P2, Mod) ->
  T1 = trim(P1),
  T2 = trim(P2),
  case T1 =:= [0] orelse T2 =:= [0] of
    true ->
      [0];
    false ->
      Len = length(T1) + length(T2) - 1,
      ProdArr = lists:duplicate(Len, 0),
      trim(poly_conv(T1, 0, T2, Mod, ProdArr))
  end.

-spec poly_conv(poly(), non_neg_integer(), poly(), pos_integer(), [non_neg_integer()]) ->
  [non_neg_integer()].
poly_conv([], _I, _P2, _Mod, Acc) ->
  Acc;
poly_conv([C1 | Rest1], I, P2, Mod, Acc) ->
  Acc1 = add_shifted_scalar(P2, I, C1, Mod, Acc),
  poly_conv(Rest1, I + 1, P2, Mod, Acc1).

-spec add_shifted_scalar(
  poly(), non_neg_integer(), non_neg_integer(), pos_integer(), [non_neg_integer()]
) -> [non_neg_integer()].
add_shifted_scalar(P2, Shift, C, Mod, Acc) ->
  {Prefix, Target} = lists:split(Shift, Acc),
  Merged = add_scaled_list(P2, C, Mod, Target),
  Prefix ++ Merged.

-spec add_scaled_list(poly(), non_neg_integer(), pos_integer(), [non_neg_integer()]) ->
  [non_neg_integer()].
add_scaled_list([], _C, _Mod, Rest) ->
  Rest;
add_scaled_list([C2 | R2], C, Mod, [A | RA]) ->
  Val = (A + C2 * C) rem Mod,
  [Val | add_scaled_list(R2, C, Mod, RA)];
add_scaled_list([C2 | R2], C, Mod, []) ->
  Val = (C2 * C) rem Mod,
  [Val | add_scaled_list(R2, C, Mod, [])].

%% @doc Divide polynomial P(x) by (x - Z) modulo BLS12-381 r using Ruffini's rule.
%% Returns {Q, Remainder} such that P(x) = Q(x)*(x - Z) + Remainder.
-spec divide_by_linear(poly(), integer()) -> {poly(), non_neg_integer()}.
divide_by_linear(P, Z) ->
  divide_by_linear(P, Z, ?DEFAULT_MOD).

%% @doc Divide polynomial P(x) by (x - Z) modulo Mod using Ruffini's rule / synthetic division.
%% Returns {Q, Remainder} where P(x) = Q(x)*(x - Z) + Remainder.
-spec divide_by_linear(poly(), integer(), pos_integer()) -> {poly(), non_neg_integer()}.
divide_by_linear(P, Z, Mod) when is_list(P), is_integer(Z), is_integer(Mod), Mod > 1 ->
  NormP = [((C rem Mod) + Mod) rem Mod || C <- P, is_integer(C)],
  Trimmed = trim(NormP),
  NormZ = ((Z rem Mod) + Mod) rem Mod,
  case Trimmed of
    [C0] ->
      {[0], C0};
    _ ->
      Rev = lists:reverse(Trimmed),
      [Cd | Rest] = Rev,
      synthetic_division(Rest, NormZ, Mod, Cd, [Cd])
  end.

-spec synthetic_division(
  poly(), non_neg_integer(), pos_integer(), non_neg_integer(), [non_neg_integer()]
) -> {poly(), non_neg_integer()}.
synthetic_division([C0], Z, Mod, PrevQ, QAcc) ->
  NormC0 = ((C0 rem Mod) + Mod) rem Mod,
  Remainder = (NormC0 + Z * PrevQ) rem Mod,
  %% QAcc contains [q_{d-1}, q_{d-2}, ..., q_1] in descending order
  %% When reversed, it is [q_0, q_1, ..., q_{d-1}]
  %% But wait: synthetic division has q_{i-1} = c_i + z * q_i
  %% Let's trace carefully:
  %% [c_d, c_{d-1}, ..., c_1, c_0]
  %% q_{d-1} = c_d
  %% q_{d-2} = c_{d-1} + z * q_{d-1}
  %% ...
  %% q_0 = c_1 + z * q_1
  %% R = c_0 + z * q_0
  {trim(QAcc), Remainder};
synthetic_division([Ci | Rest], Z, Mod, PrevQ, QAcc) ->
  NormCi = ((Ci rem Mod) + Mod) rem Mod,
  Qi = (NormCi + Z * PrevQ) rem Mod,
  synthetic_division(Rest, Z, Mod, Qi, [Qi | QAcc]).
