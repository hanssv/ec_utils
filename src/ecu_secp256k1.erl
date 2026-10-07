%%% File        : ecu_secp256k1.erl
%%% Author      : Hans Svensson
%%% Description : Trying to whip together a pure Erlang secp256k1
%%%               Just for usage when speed isn't crucial...
%%% Created     : 22 Dec 2021 by Hans Svensson
-module(ecu_secp256k1).

-include("ecu_secp256k1.hrl").

-define(ADD(A, B), ((A + B) rem ?P)).
-define(MUL(A, B), ((A * B) rem ?P)).
-define(SUB(A, B), ((A - B + ?P) rem ?P)).
-define(DIV(A, B), f_div(A, B)).

-export([on_curve/1, p/0, n/0,
         scalar_mul/2, scalar_mul_base/1, p_add/2, p_neg/1,
         compress/1, decompress/1,
         f_add/2, f_mul/2, f_sub/2, f_div/2, f_inv/1,
         s_add/2, s_mul/2, s_sub/2, s_div/2, s_inv/1]).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

on_curve({X, Y}) ->
  %% y^2 = x^3 + 7
  X3 = ?MUL(?MUL(X, X), X),
  Y2 = ?MUL(Y, Y),
  Y2 == ?ADD(X3, ?B).

p() -> ?P.

n() -> ?N.

scalar_mul_base(<<K:256>>) ->
  scalar_mul(K, {?X, ?Y});
scalar_mul_base(K) ->
  scalar_mul(K, {?X, ?Y}).

scalar_mul(<<K:256>>, P) ->
  scalar_mul(K, P);
scalar_mul(K, _P) when K =< 0 ->
  {0, 0};
scalar_mul(_K, {0, 0}) ->
  {0, 0};
scalar_mul(1, {X, Y}) ->
  {X rem ?P, Y rem ?P};
scalar_mul(K, {X, Y}) ->
  AffP = {X rem ?P, Y rem ?P},
  from_jacobian(scalar_mul_loop(K, AffP)).

scalar_mul_loop(K, AffP) ->
  [_MSB | RestBits] = integer_to_list(K, 2),
  lists:foldl(fun
    ($0, Acc) -> j_double(Acc);
    ($1, Acc) -> j_add_affine(j_double(Acc), AffP)
  end, to_jacobian(AffP), RestBits).

to_jacobian({0, 0}) -> {1, 1, 0};
to_jacobian({X, Y}) -> {X rem ?P, Y rem ?P, 1}.

from_jacobian({_, _, 0}) -> {0, 0};
from_jacobian({X, Y, 1}) -> {X, Y};
from_jacobian({X, Y, Z}) ->
  Zinv = f_inv(Z),
  Zinv2 = ?MUL(Zinv, Zinv),
  Zinv3 = ?MUL(Zinv2, Zinv),
  {?MUL(X, Zinv2), ?MUL(Y, Zinv3)}.

j_double({_, _, 0}) -> {1, 1, 0};
j_double({_X, 0, _Z}) -> {1, 1, 0};
j_double({X, Y, Z}) ->
  Y2 = ?MUL(Y, Y),
  S  = ?MUL(4, ?MUL(X, Y2)),
  M  = ?MUL(3, ?MUL(X, X)),
  X3 = ?SUB(?MUL(M, M), ?MUL(2, S)),
  Y4 = ?MUL(Y2, Y2),
  Y3 = ?SUB(?MUL(M, ?SUB(S, X3)), ?MUL(8, Y4)),
  Z3 = ?MUL(2, ?MUL(Y, Z)),
  {X3, Y3, Z3}.

j_add_affine({_, _, 0}, {X2, Y2}) ->
  to_jacobian({X2, Y2});
j_add_affine(J1, {0, 0}) ->
  J1;
j_add_affine({X1, Y1, Z1}, {X2, Y2}) ->
  RX2 = X2 rem ?P,
  RY2 = Y2 rem ?P,
  Z1_2 = ?MUL(Z1, Z1),
  Z1_3 = ?MUL(Z1_2, Z1),
  U2 = ?MUL(RX2, Z1_2),
  S2 = ?MUL(RY2, Z1_3),
  if
    X1 == U2 ->
      if
        Y1 == S2 -> j_double({X1, Y1, Z1});
        true     -> {1, 1, 0}
      end;
    true ->
      H  = ?SUB(U2, X1),
      R  = ?SUB(S2, Y1),
      H2 = ?MUL(H, H),
      H3 = ?MUL(H2, H),
      V  = ?MUL(X1, H2),
      X3 = ?SUB(?SUB(?MUL(R, R), H3), ?MUL(2, V)),
      Y3 = ?SUB(?MUL(R, ?SUB(V, X3)), ?MUL(Y1, H3)),
      Z3 = ?MUL(Z1, H),
      {X3, Y3, Z3}
  end.


compress({X, Y}) when Y rem 2 == 0 -> <<2:8, X:256>>;
compress({X, _})                   -> <<3:8, X:256>>;
compress(<<4:8, X:256, Y:256>>)    -> compress({X, Y}).

decompress(<<N:8, X:256>>) when (N == 2 orelse N == 3), X < ?P ->
  Y0 = ?ADD(?B, ?MUL(X, ?MUL(X, X))),
  Y1 = pow(Y0, (?P + 1) div 4),
  case ?MUL(Y1, Y1) == Y0 of
    true ->
      case Y1 rem 2 == N rem 2 of
        true  -> {X, Y1};
        false -> {X, ?P - Y1}
      end;
    false ->
      error(badarg)
  end.

p_neg({X, Y}) -> {X, ?P - Y}.

p_add(P1, {0, 0}) -> P1;
p_add({0, 0}, P2) -> P2;
p_add({X1, Y1}, {X2, Y2}) ->
  RX1 = X1 rem ?P,
  RY1 = Y1 rem ?P,
  RX2 = X2 rem ?P,
  RY2 = Y2 rem ?P,
  if
    RX1 == RX2, (RY1 + RY2) rem ?P == 0 ->
      {0, 0};
    RX1 == RX2, RY1 == RY2 ->
      M  = ?DIV(?MUL(3, ?MUL(RX1, RX1)), ?MUL(2, RY1)),
      X3 = ?SUB(?MUL(M, M), ?MUL(2, RX1)),
      Y3 = ?SUB(?MUL(M, ?SUB(RX1, X3)), RY1),
      {X3, Y3};
    true ->
      M  = ?DIV(?SUB(RY2, RY1), ?SUB(RX2, RX1)),
      X3 = ?SUB(?MUL(M, M), ?ADD(RX1, RX2)),
      Y3 = ?SUB(?MUL(M, ?SUB(RX1, X3)), RY1),
      {X3, Y3}
  end.

pow(A, B) -> ecu_misc:exp_mod(A, B, ?P).

%% Arithmetics in prime field P
f_add(A, B) -> (A + B) rem ?P.
f_mul(A, B) -> (A * B) rem ?P.
f_sub(A, B) -> (A - B + ?P) rem ?P.
f_div(A, B) -> f_mul(A, f_inv(B)).

f_inv(A) ->
  pow(A, ?P - 2).

%% Arithmetics in curve group order N
s_add(A, B) -> (A + B) rem ?N.
s_mul(A, B) -> (A * B) rem ?N.
s_sub(A, B) -> (A - B + ?N) rem ?N.
s_div(A, B) -> s_mul(A, s_inv(B)).

s_inv(A) ->
  {1, S, _T} = ecu_misc:eea(A, ?N),
  (S + ?N) rem ?N.

%% curve() ->
%%   #{ p => 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
%%      a => 16#00, b => 16#07,
%%      x => 16#79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
%%      y => 16#483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
%%      n => 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
%%      e => 16#7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
%%    }.
