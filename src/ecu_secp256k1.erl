%%% File        : ecu_secp256k1.erl
%%% Author      : Hans Svensson
%%% Description : Trying to whip together a pure Erlang secp256k1
%%%               Just for usage when speed isn't crucial...
%%% Created     : 22 Dec 2021 by Hans Svensson
-module(ecu_secp256k1).

-typing([eqwalizer]).

-include("ecu_secp256k1.hrl").

-type pt_affine() :: {non_neg_integer(), non_neg_integer()}.
-type pt_jacobian() :: {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
-type pt() :: pt_affine().
-type pt_compressed() :: <<_:264>>.
-type pt_uncompressed() :: <<_:520>>.
-type scalar() :: non_neg_integer() | <<_:256>>.
-type field_elem() :: non_neg_integer().

-export_type([pt/0, pt_affine/0, pt_compressed/0, pt_uncompressed/0, scalar/0]).

-define(ADD(A, B), ((A + B) rem ?P)).
-define(MUL(A, B), ((A * B) rem ?P)).
-define(SUB(A, B), ((A - B + ?P) rem ?P)).
-define(DIV(A, B), f_div(A, B)).

-export([on_curve/1, p/0, n/0,
         scalar_mul/2, scalar_mul_base/1, scalar_mul_dual/4,
         p_add/2, p_neg/1,
         compress/1, decompress/1,
         f_add/2, f_mul/2, f_sub/2, f_div/2, f_inv/1,
         s_add/2, s_mul/2, s_sub/2, s_div/2, s_inv/1]).

-on_load(init/0).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-spec on_curve(pt_affine()) -> boolean().
on_curve({X, Y}) when is_integer(X), is_integer(Y) ->
  %% y^2 = x^3 + 7
  X3 = ?MUL(?MUL(X, X), X),
  Y2 = ?MUL(Y, Y),
  Y2 == ?ADD(X3, ?B).

-spec p() -> pos_integer().
p() -> ?P.

-spec n() -> pos_integer().
n() -> ?N.

-spec scalar_mul_base(scalar()) -> pt_affine().
scalar_mul_base(<<K:256>>) ->
  scalar_mul_base(K);
scalar_mul_base(K) when is_integer(K), K =< 0 ->
  {0, 0};
scalar_mul_base(K) when is_integer(K) ->
  case K rem ?N of
    0 -> {0, 0};
    RedK ->
      Table = get_base_comb(),
      Acc = mul_comb(RedK, 1, Table, {1, 1, 0}),
      from_jacobian(Acc)
  end.

-spec scalar_mul(scalar(), pt_affine()) -> pt_affine().
scalar_mul(<<K:256>>, P) ->
  scalar_mul(K, P);
scalar_mul(K, _P) when is_integer(K), K =< 0 ->
  {0, 0};
scalar_mul(_K, {0, 0}) ->
  {0, 0};
scalar_mul(1, {X, Y}) when is_integer(X), is_integer(Y) ->
  {X rem ?P, Y rem ?P};
scalar_mul(K, {X, Y}) when is_integer(K), is_integer(X), is_integer(Y) ->
  AffP = {X rem ?P, Y rem ?P},
  from_jacobian(scalar_mul_loop(K, AffP)).

-spec scalar_mul_loop(pos_integer(), pt_affine()) -> pt_jacobian().
scalar_mul_loop(K, AffP) when is_integer(K), K > 0 ->
  [_MSB | RestBits] = integer_to_list(K, 2),
  scalar_mul_loop_bits(RestBits, AffP, to_jacobian(AffP)).

-spec scalar_mul_loop_bits(string(), pt_affine(), pt_jacobian()) -> pt_jacobian().
scalar_mul_loop_bits([], _AffP, Acc) ->
  Acc;
scalar_mul_loop_bits([$0 | Rest], AffP, Acc) ->
  scalar_mul_loop_bits(Rest, AffP, j_double(Acc));
scalar_mul_loop_bits([$1 | Rest], AffP, Acc) ->
  scalar_mul_loop_bits(Rest, AffP, j_add_affine(j_double(Acc), AffP));
scalar_mul_loop_bits([_ | Rest], AffP, Acc) ->
  scalar_mul_loop_bits(Rest, AffP, Acc).

-spec scalar_mul_dual(scalar(), pt_affine(), scalar(), pt_affine()) -> pt_affine().
scalar_mul_dual(K1, P1, K2, P2) ->
  Aff1 = to_affine(P1),
  Aff2 = to_affine(P2),
  case {Aff1, Aff2} of
    {{0, 0}, _} -> scalar_mul(K2, Aff2);
    {_, {0, 0}} -> scalar_mul(K1, Aff1);
    _ ->
      P11 = p_add(Aff1, Aff2),
      Bits1 = integer_to_bitstring(K1),
      Bits2 = integer_to_bitstring(K2),
      from_jacobian(dual_loop(Bits1, Bits2, Aff1, Aff2, P11, {1, 1, 0}))
  end.

-spec to_affine(pt_affine()) -> pt_affine().
to_affine({X, Y}) when is_integer(X), is_integer(Y) ->
  {X rem ?P, Y rem ?P}.

-spec integer_to_bitstring(scalar()) -> <<_:256>>.
integer_to_bitstring(<<K:256>>) ->
  <<K:256>>;
integer_to_bitstring(K) when is_integer(K) ->
  <<K:256>>.

-spec dual_loop(bitstring(), bitstring(), pt_affine(), pt_affine(), pt_affine(), pt_jacobian()) ->
    pt_jacobian().
dual_loop(<<>>, <<>>, _P1, _P2, _P11, Acc) ->
  Acc;
dual_loop(<<B1:1, R1/bitstring>>, <<B2:1, R2/bitstring>>, P1, P2, P11, Acc) ->
  D = j_double(Acc),
  NewAcc =
    case {B1, B2} of
      {0, 0} -> D;
      {1, 0} -> j_add_affine(D, P1);
      {0, 1} -> j_add_affine(D, P2);
      {1, 1} -> j_add_affine(D, P11)
    end,
  dual_loop(R1, R2, P1, P2, P11, NewAcc).

-spec to_jacobian(pt_affine()) -> pt_jacobian().
to_jacobian({0, 0}) -> {1, 1, 0};
to_jacobian({X, Y}) when is_integer(X), is_integer(Y) ->
  {X rem ?P, Y rem ?P, 1}.

-spec from_jacobian(pt_jacobian()) -> pt_affine().
from_jacobian({_, _, 0}) -> {0, 0};
from_jacobian({X, Y, 1}) -> {X, Y};
from_jacobian({X, Y, Z}) ->
  Zinv = f_inv(Z),
  Zinv2 = ?MUL(Zinv, Zinv),
  Zinv3 = ?MUL(Zinv2, Zinv),
  {?MUL(X, Zinv2), ?MUL(Y, Zinv3)}.

-spec j_double(pt_jacobian()) -> pt_jacobian().
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

-spec j_add_affine(pt_jacobian(), pt_affine()) -> pt_jacobian().
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

-spec compress(pt_affine() | pt_uncompressed()) -> pt_compressed().
compress({X, Y}) when is_integer(X), is_integer(Y), Y rem 2 == 0 ->
  <<2:8, (X rem ?P):256>>;
compress({X, Y}) when is_integer(X), is_integer(Y) ->
  <<3:8, (X rem ?P):256>>;
compress(<<4:8, X:256, Y:256>>) ->
  compress({X, Y}).

-spec decompress(pt_compressed()) -> pt_affine().
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

-spec p_neg(pt_affine()) -> pt_affine().
p_neg({X, Y}) when is_integer(X), is_integer(Y) ->
  {X rem ?P, (?P - (Y rem ?P)) rem ?P}.

-spec p_add(pt_affine(), pt_affine()) -> pt_affine().
p_add(P1, {0, 0}) -> P1;
p_add({0, 0}, P2) -> P2;
p_add({X1, Y1}, {X2, Y2}) when is_integer(X1), is_integer(Y1),
                               is_integer(X2), is_integer(Y2) ->
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

-spec pow(integer(), non_neg_integer()) -> non_neg_integer().
pow(A, B) when is_integer(A), is_integer(B), B >= 0 ->
  ecu_misc:exp_mod(A, B, ?P).

%% Arithmetics in prime field P
-spec f_add(integer(), integer()) -> field_elem().
f_add(A, B) when is_integer(A), is_integer(B) ->
  (A + B) rem ?P.

-spec f_mul(integer(), integer()) -> field_elem().
f_mul(A, B) when is_integer(A), is_integer(B) ->
  (A * B) rem ?P.

-spec f_sub(integer(), integer()) -> field_elem().
f_sub(A, B) when is_integer(A), is_integer(B) ->
  (A - B + ?P) rem ?P.

-spec f_div(integer(), integer()) -> field_elem().
f_div(A, B) when is_integer(A), is_integer(B) ->
  f_mul(A, f_inv(B)).

-spec f_inv(integer()) -> field_elem().
f_inv(A) when is_integer(A) ->
  pow(A, ?P - 2).

%% Arithmetics in curve group order N
-spec s_add(integer(), integer()) -> non_neg_integer().
s_add(A, B) when is_integer(A), is_integer(B) ->
  (A + B) rem ?N.

-spec s_mul(integer(), integer()) -> non_neg_integer().
s_mul(A, B) when is_integer(A), is_integer(B) ->
  (A * B) rem ?N.

-spec s_sub(integer(), integer()) -> non_neg_integer().
s_sub(A, B) when is_integer(A), is_integer(B) ->
  (A - B + ?N) rem ?N.

-spec s_div(integer(), integer()) -> non_neg_integer().
s_div(A, B) when is_integer(A), is_integer(B) ->
  s_mul(A, s_inv(B)).

-spec s_inv(integer()) -> non_neg_integer().
s_inv(A) when is_integer(A) ->
  case ecu_misc:eea(A, ?N) of
    {1, S, _T} -> (S + ?N) rem ?N;
    _          -> error(badarg)
  end.

mul_comb(0, _I, _Table, Acc) ->
  Acc;
mul_comb(K, I, Table, Acc) ->
  W = K band 15,
  NextK = K bsr 4,
  NextAcc =
    case W of
      0 -> Acc;
      _ ->
        Pt = element(W + 1, element(I, Table)),
        case Acc of
          {_, _, 0} -> to_jacobian(Pt);
          _         -> j_add_affine(Acc, Pt)
        end
    end,
  mul_comb(NextK, I + 1, Table, NextAcc).

-spec init() -> ok.
init() ->
  Table = build_base_comb(),
  persistent_term:put({?MODULE, base_comb}, Table),
  ok.

-spec get_base_comb() -> tuple().
get_base_comb() ->
  persistent_term:get({?MODULE, base_comb}).

-spec build_base_comb() -> tuple().
build_base_comb() ->
  %% 64 windows, each with 16 multiples (0..15) of 16^i * G
  list_to_tuple(build_windows(0, {?X, ?Y})).

build_windows(64, _Cur) -> [];
build_windows(I, Cur) ->
  Mults = list_to_tuple(build_multiples(0, Cur, {1, 1, 0})),
  NextCur = from_jacobian(dbl4(to_jacobian(Cur))),
  [Mults | build_windows(I + 1, NextCur)].

dbl4(J) ->
  j_double(j_double(j_double(j_double(J)))).

build_multiples(16, _Base, _Acc) -> [];
build_multiples(0, Base, _Acc) ->
  [{0, 0} | build_multiples(1, Base, to_jacobian(Base))];
build_multiples(W, Base, Acc) ->
  [from_jacobian(Acc) | build_multiples(W + 1, Base, j_add_affine(Acc, Base))].

%% curve() ->
%%   #{ p => 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
%%      a => 16#00, b => 16#07,
%%      x => 16#79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
%%      y => 16#483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
%%      n => 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
%%      e => 16#7AE96A2B657C07106E64479EAC3434E99CF0497512F58995C1396C28719501EE
%%    }.
