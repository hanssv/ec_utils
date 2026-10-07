%%% File        : ecu_ed25519.erl
%%% Author      : Hans Svensson
%%% Description : Trying to whip together a pure Erlang ed25519
%%%               Just for usage when speed isn't crucial...
%%% Created     : 13 Jan 2022 by Hans Svensson
-module(ecu_ed25519).

-include("ecu_ed25519.hrl").

-type pt_affine() :: {non_neg_integer(), non_neg_integer()}. %% {X, Y}
-type pt_hom_ext() :: {non_neg_integer(), non_neg_integer(),
                       non_neg_integer(), non_neg_integer()}. %% {X, Y, Z, T}
-type pt_compressed() :: <<_:256>>. %% Y coord + odd/even X.

-type pt() :: pt_affine() | pt_hom_ext() | pt_compressed().

%% -type fld_elem() :: 0..(?P-1).
-type scalar() :: 0..(?N-1).

-define(ADD(A, B), ((A + B) rem ?P)).
-define(MUL(A, B), ((A * B) rem ?P)).
-define(SUB(A, B), ((A - B + ?P) rem ?P)).
-define(DIV(A, B), f_div(A, B)).

-export_type([pt/0, scalar/0]).

-export([on_curve/1, p/0, n/0, pt_eq/2,
         scalar_mul/2, scalar_mul_base/1, scalar_mul_dual_base/3,
         scalar_mul_noclamp/2, scalar_mul_base_noclamp/1,
         scalar_reduce/1,
         p_add/2, p_sub/2, p_neg/1, p_dbl/1,
         compress/1, decompress/1, is_small_order/1,
         f_add/2, f_mul/2, f_sub/2, f_div/2, f_inv/1,
         s_add/2, s_mul/2, s_sub/2, s_div/2, s_inv/1]).

-on_load(init/0).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-spec pt_eq(P1 :: pt(), P2 :: pt()) -> boolean().
pt_eq({X1, Y1}, {X2, Y2}) ->
  X1 == X2 andalso Y1 == Y2;
pt_eq(C1, C2) when is_binary(C1), is_binary(C2) ->
  C1 == C2;
pt_eq({X1, Y1, Z1, _T1}, {X2, Y2, Z2, _T2}) ->
  ?SUB(?MUL(X1, Z2), ?MUL(X2, Z1)) == 0
  andalso ?SUB(?MUL(Y1, Z2), ?MUL(Y2, Z1)) == 0;
pt_eq(P1, P2) ->
  pt_eq(to_ext_hom(P1), to_ext_hom(P2)).

%% Libsodium has additional checks
%%  - weak keys
%%  - canonical representation
%%  - main subgroup...
on_curve({X, Y}) ->
  X2 = ?MUL(X, X),
  Y2 = ?MUL(Y, Y),
  LHS = ?SUB(Y2, X2),
  RHS = ?ADD(1, ?MUL(?D, ?MUL(X2, Y2))),
  0 == ?SUB(LHS, RHS);
on_curve(P) ->
  on_curve(to_affine(P)).

p() -> ?P.

n() -> ?N.

-define(TWO_POW_255_MINUS_1, 16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).

-spec compress(P :: pt()) -> pt_compressed().
compress(<<_:32/binary>> = P) -> P;
compress({_, _, _, _} = P)    -> compress(to_affine(P));
compress({X, Y}) ->
  V = (Y band ?TWO_POW_255_MINUS_1) bor ((X band 1) bsl 255),
  <<V:256/little>>.

-spec decompress(pt_compressed()) -> pt_hom_ext().
decompress(<<Y0:256/little-unsigned-integer>>) ->
  X0 = Y0 bsr 255,
  Y  = Y0 band ?TWO_POW_255_MINUS_1,
  case Y < ?P of
    false -> error(badarg);
    true ->
      X = xrecover(Y),
      case X rem 2 == X0 of
        true  -> to_ext_hom({X, Y});
        false ->
          case X == 0 of
            true  -> error(badarg);
            false -> to_ext_hom({?P - X, Y})
          end
      end
  end;
decompress(_) ->
  error(badarg).

-spec is_small_order(Pt :: pt()) -> boolean().
is_small_order(P) ->
  P8 = p_dbl(p_dbl(p_dbl(P))),
  pt_eq(P8, {0, 1, 1, 0}).

p_neg({X, Y})       -> {?P - X, Y};
p_neg({X, Y, Z, T}) -> {?P - X, Y, Z, ?P - T};
p_neg(P)            -> p_neg(to_ext_hom(P)).

p_sub(P1, P2) -> p_add(P1, p_neg(P2)).

-spec p_add(X :: pt(), Y :: pt()) -> pt_hom_ext().
p_add({X1, Y1, Z1, T1}, {X2, Y2, Z2, T2}) ->
  A = ?MUL(?SUB(Y1, X1), ?SUB(Y2, X2)),
  B = ?MUL(?ADD(Y1, X1), ?ADD(Y2, X2)),
  C = ?MUL(?MUL(T1, T2), 2 * ?D),
  D = ?MUL(2 * Z1, Z2),
  E = ?SUB(B, A),
  F = ?SUB(D, C),
  G = ?ADD(D, C),
  H = ?ADD(A, B),
  {?MUL(E, F), ?MUL(G, H), ?MUL(F, G), ?MUL(E, H)};
p_add(P1, P2) ->
  p_add(to_ext_hom(P1), to_ext_hom(P2)).

p_dbl({X, Y, Z, _T}) ->
  A = ?MUL(X, X),
  B = ?MUL(Y, Y),
  C = ?MUL(2 * Z, Z),
  D = ?P - A,
  XY = X + Y,
  E = ?SUB(?MUL(XY, XY), ?ADD(A, B)),
  G = ?ADD(D, B),
  F = ?SUB(G, C),
  H = ?SUB(D, B),
  {?MUL(E, F), ?MUL(G, H), ?MUL(F, G), ?MUL(E, H)};
p_dbl(P) ->
  p_dbl(to_ext_hom(P)).

-spec scalar_mul_base(Scalar :: scalar() | binary()) -> pt_hom_ext().
scalar_mul_base(<<K:256/little>>) ->
  scalar_mul_base_comb(clamp(K));
scalar_mul_base(K) when is_integer(K), K >= 0, K < ?N ->
  scalar_mul_base_comb(clamp(K)).

-spec scalar_mul(Scalar :: scalar() | binary(), Pt :: pt()) -> pt_hom_ext().
scalar_mul(<<K:256/little>>, P) ->
  scalar_mul(K, P);
scalar_mul(K, P) ->
  scalar_mul_window(clamp(K), to_ext_hom(P)).

-spec scalar_mul_base_noclamp(Scalar :: scalar() | binary()) -> pt_hom_ext().
scalar_mul_base_noclamp(<<K:256/little>>) ->
  scalar_mul_base_comb(K);
scalar_mul_base_noclamp(K) when is_integer(K), K >= 0, K < ?N ->
  scalar_mul_base_comb(K).

-spec scalar_mul_noclamp(Scalar :: scalar() | binary(), Pt :: pt()) -> pt_hom_ext().
scalar_mul_noclamp(<<K:256/little>>, P) ->
  scalar_mul_noclamp(K, P);
scalar_mul_noclamp(K, P) ->
  scalar_mul_window(K, to_ext_hom(P)).

-spec scalar_mul_dual_base(K1 :: scalar(), K2 :: scalar(), P2 :: pt()) -> pt_hom_ext().
scalar_mul_dual_base(K1, K2, P2) ->
  P1 = scalar_mul_base_comb(K1),
  P2_mul = scalar_mul_window(K2, to_ext_hom(P2)),
  p_add(P1, P2_mul).

to_ext_hom({_, _, _, _} = P)    -> P;
to_ext_hom(<<_:32/binary>> = P) -> decompress(P);
to_ext_hom({X, Y})              -> {X, Y, 1, ?MUL(X, Y)}.

to_affine({_, _} = P) -> P;
to_affine(<<_:32/binary>> = P) -> to_affine(decompress(P));
to_affine({X, Y, Z, _}) ->
  ZInv = f_inv(Z),
  {?MUL(X, ZInv), ?MUL(Y, ZInv)}.

f_pow(A, B) -> ecu_misc:exp_mod(A, B, ?P).

%% Arithmetics in prime field P
f_add(A, B) -> (A + B) rem ?P.
f_mul(A, B) -> (A * B) rem ?P.
f_sub(A, B) -> (A - B + ?P) rem ?P.
f_div(A, B) -> f_mul(A, f_inv(B)).

f_inv(A) ->
  f_pow(A, ?P - 2).

%% Arithmetics in curve group order N
s_add(<<A:256/little>>, <<B:256/little>>) -> <<((A + B) rem ?N):256/little>>.
s_mul(<<A:256/little>>, <<B:256/little>>) -> <<((A * B) rem ?N):256/little>>.
s_sub(<<A:256/little>>, <<B:256/little>>) -> <<((A - B + ?N) rem ?N):256/little>>.
s_div(A, B) -> s_mul(A, s_inv(B)).

s_inv(<<A:256/little>>) ->
  {1, S, _T} = ecu_misc:eea(A, ?N),
  <<((S + ?N) rem ?N):256/little>>.

scalar_reduce(<<S:512/little>>) ->
  <<(S rem ?N):256/little>>.

%% --- internal functions
scalar_mul_(0, _P) -> {0, 1, 1, 0};
scalar_mul_(1, P)  -> P;
scalar_mul_(K, P) ->
  case K rem 2 of
    0 -> scalar_mul_(K div 2, p_dbl(P));
    1 -> p_add(P, scalar_mul_(K - 1, P))
  end.

scalar_mul_window(0, _P) ->
  {0, 1, 1, 0};
scalar_mul_window(K, P) ->
  Table = precompute_window_table(P),
  <<W0:4, Rest/bitstring>> = <<K:256>>,
  InitialAcc = element(W0 + 1, Table),
  window_loop(Rest, Table, InitialAcc).

window_loop(<<>>, _Table, Acc) ->
  Acc;
window_loop(<<W:4, Rest/bitstring>>, Table, Acc) ->
  D4 = dbl4(Acc),
  NewAcc =
    case W of
      0 -> D4;
      _ ->
        Pt = element(W + 1, Table),
        case D4 of
          {0, 1, 1, 0} -> Pt;
          _            -> p_add(D4, Pt)
        end
    end,
  window_loop(Rest, Table, NewAcc).

precompute_window_table(P) ->
  list_to_tuple(build_window_multiples(0, P, {0, 1, 1, 0})).

build_window_multiples(16, _P, _Acc) ->
  [];
build_window_multiples(0, P, Acc) ->
  [Acc | build_window_multiples(1, P, P)];
build_window_multiples(W, P, Acc) ->
  [Acc | build_window_multiples(W + 1, P, p_add(Acc, P))].

scalar_mul_base_comb(0) ->
  {0, 1, 1, 0};
scalar_mul_base_comb(K) ->
  Table = get_base_comb(),
  mul_comb(K, 1, Table, {0, 1, 1, 0}).

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
          {0, 1, 1, 0} -> Pt;
          _            -> p_add(Acc, Pt)
        end
    end,
  mul_comb(NextK, I + 1, Table, NextAcc).

init() ->
  Table = build_base_comb(),
  persistent_term:put({?MODULE, base_comb}, Table),
  ok.

get_base_comb() ->
  persistent_term:get({?MODULE, base_comb}).

build_base_comb() ->
  %% 64 windows, each with 16 multiples (0..15) of 16^i * B
  list_to_tuple(build_windows(0, ?GE)).

build_windows(64, _CurrentBase) ->
  [];
build_windows(I, CurrentBase) ->
  Multiples = list_to_tuple(build_multiples(0, CurrentBase)),
  NextBase = dbl4(CurrentBase),
  [Multiples | build_windows(I + 1, NextBase)].

dbl4(P) ->
  p_dbl(p_dbl(p_dbl(p_dbl(P)))).

build_multiples(16, _Base) ->
  [];
build_multiples(0, Base) ->
  [{0, 1, 1, 0} | build_multiples(1, Base)];
build_multiples(W, Base) ->
  Pt = scalar_mul_(W, Base),
  [Pt | build_multiples(W + 1, Base)].

clamp(K) ->
  ((K band (bnot 7)) band (bnot (128 bsl 248))) bor (64 bsl 248).

xrecover(Y) ->
  Y2 = ?MUL(Y, Y),
  case ?SUB(Y2, 1) of
    0 -> 0;
    U ->
      V     = ?ADD(?MUL(?D, Y2), 1),
      UdivV = ?DIV(U, V),
      X0    = f_pow(UdivV, ?PPLUS3DIV8),

      X0_2 = ?MUL(X0, X0),
      case ?SUB(X0_2, UdivV) of
        0 -> X0;
        _ -> case ?ADD(X0_2, UdivV) of
               0 -> ?MUL(X0, ?TWOPOWPMINUS1DIV4);
               _ -> error(badarg)
             end
      end
  end.
