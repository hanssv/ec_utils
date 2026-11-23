%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang implementation of the Jubjub elliptic curve (Zcash ZIP 216 / ZIP 243).
%%%
%%% Jubjub is a twisted Edwards curve defined over the scalar field of BLS12-381.
%%% It is specifically designed to execute natively inside zk-SNARK circuits
%%% over BLS12-381.
%%%
%%% Curve equation: a * x^2 + y^2 = 1 + d * x^2 * y^2 (mod q)
%%% where:
%%%   q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
%%%   a = -1 = q - 1
%%%   d = -(10240 / 10241) = 19257038036680949359750312669786877991949435402254120286184196891950884077233
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_jubjub).

-typing([eqwalizer]).

-export([
  q/0,
  a/0,
  d/0,
  order/0,
  suborder/0,
  cofactor/0,
  generator/0,
  base8/0,
  identity/0,

  is_on_curve/1,
  is_in_subgroup/1,
  add/2,
  double/1,
  neg/1,
  mul/2,
  mul_base8/1,
  compress/1,
  decompress/1,

  montgomery_a/0,
  is_on_montgomery/1,
  edwards_to_montgomery/1,
  montgomery_to_edwards/1,
  montgomery_ladder/2
]).

-export_type([
  point/0,
  projective_point/0,
  montgomery_point/0
]).

%%%-------------------------------------------------------------------
%%% Curve Constants & Definitions
%%%-------------------------------------------------------------------

-define(Q, 16#73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001).
-define(A_COEFF, (?Q - 1)).
-define(D_COEFF,
  19257038036680949359750312669786877991949435402254120286184196891950884077233
).

%% Subgroup prime order r_J
-define(SUBORDER,
  16#0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
).
-define(COFACTOR, 8).
%% Curve full order N = 8 * r_J
-define(ORDER, (?COFACTOR * ?SUBORDER)).

%% Subgroup generator G (ZIP 216 / ZIP 243)
-define(GEN_U,
  28336281903124990867587793011069573392383982287722241916350956173377953689573
).
-define(GEN_V,
  39385640392217313770878525135509063452020585410343666726093009378539878503883
).

%% Tonelli-Shanks parameters for Q - 1 = 2^32 * S
-define(TS_E, 32).
-define(TS_S, 12208678567578594777604504606729831043093128246378069236549469339647).
-define(TS_G, 937917089079007706106976984802249742464848817460758522850752807661925904159).

%% Montgomery Curve Constants: B*v^2 = u^3 + A*u^2 + u
%% A = 40962, B = -40964
-define(MONTGOMERY_A, 40962).
-define(MONTGOMERY_B, (?Q - 40964)).
-define(MONTGOMERY_A24, 10240).

-type point() :: {non_neg_integer(), non_neg_integer()}.
-type projective_point() :: {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
-type montgomery_point() :: {non_neg_integer(), non_neg_integer()} | infinity.

%%%-------------------------------------------------------------------
%%% API: Parameters
%%%-------------------------------------------------------------------

-spec q() -> pos_integer().
q() ->
  ?Q.

-spec a() -> pos_integer().
a() ->
  ?A_COEFF.

-spec d() -> pos_integer().
d() ->
  ?D_COEFF.

-spec order() -> pos_integer().
order() ->
  ?ORDER.

-spec suborder() -> pos_integer().
suborder() ->
  ?SUBORDER.

-spec cofactor() -> pos_integer().
cofactor() ->
  ?COFACTOR.

-spec generator() -> point().
generator() ->
  {?GEN_U, ?GEN_V}.

-spec base8() -> point().
base8() ->
  generator().

-spec identity() -> point().
identity() ->
  {0, 1}.

%%%-------------------------------------------------------------------
%%% API: Curve Arithmetic
%%%-------------------------------------------------------------------

%% @doc Check whether an affine point lies on the Jubjub curve: -x^2 + y^2 = 1 + d*x^2*y^2 (mod q).
-spec is_on_curve(point()) -> boolean().
is_on_curve({X, Y}) when is_integer(X), is_integer(Y), X >= 0, X < ?Q, Y >= 0, Y < ?Q ->
  X2 = (X * X) rem ?Q,
  Y2 = (Y * Y) rem ?Q,
  Left = (?A_COEFF * X2 + Y2) rem ?Q,
  Right = (1 + ?D_COEFF * X2 rem ?Q * Y2) rem ?Q,
  Left =:= Right;
is_on_curve(_) ->
  false.

%% @doc Check whether a point belongs to the prime-order subgroup of size r_J.
-spec is_in_subgroup(point()) -> boolean().
is_in_subgroup(Point) ->
  is_on_curve(Point) andalso (mul(Point, ?SUBORDER) =:= identity()).

%% @doc Point negation: -(x, y) = (q - x, y).
-spec neg(point()) -> point().
neg({0, Y}) when is_integer(Y), Y >= 0, Y < ?Q ->
  {0, Y};
neg({X, Y}) when is_integer(X), is_integer(Y), X > 0, X < ?Q, Y >= 0, Y < ?Q ->
  {?Q - X, Y};
neg(_) ->
  error(badarg).

%% @doc Double a point on the curve.
-spec double(point() | projective_point()) -> point().
double({X, Y}) ->
  to_affine(proj_add({X, Y, 1}, {X, Y, 1}));
double({X, Y, Z}) ->
  to_affine(proj_add({X, Y, Z}, {X, Y, Z})).

%% @doc Add two points on the curve using complete projective addition.
-spec add(point() | projective_point(), point() | projective_point()) -> point().
add(P1, P2) ->
  to_affine(proj_add(to_proj(P1), to_proj(P2))).

%% @doc Multiply a point by an integer scalar.
-spec mul(point() | projective_point(), integer()) -> point().
mul(_Point, 0) ->
  identity();
mul(Point, K) when K < 0 ->
  mul(neg(to_affine(Point)), -K);
mul(Point, K) when is_integer(K) ->
  to_affine(scalar_mul_proj(to_proj(Point), K rem ?ORDER));
mul(_, _) ->
  error(badarg).

%% @doc Multiply the subgroup generator G by an integer scalar.
-spec mul_base8(integer()) -> point().
mul_base8(K) when is_integer(K) ->
  mul(generator(), K);
mul_base8(_) ->
  error(badarg).

%% @doc Compress an affine point {X, Y} into 32 bytes according to Zcash ZIP 216 / ZIP 243.
%% Y is encoded in 32 bytes little-endian, and bit 255 stores the sign of X (X mod 2).
-spec compress(point()) -> <<_:256>>.
compress({X, Y}) when is_integer(X), is_integer(Y), X >= 0, X < ?Q, Y >= 0, Y < ?Q ->
  SignBit = (X band 1) bsl 7,
  <<Y0:248/little, YLast:8>> = <<Y:256/little>>,
  <<Y0:248/little, (YLast bor SignBit):8>>;
compress(_) ->
  error(badarg).

%% @doc Decompress a 32-byte binary into an affine point according to ZIP 216.
-spec decompress(binary()) -> {ok, point()} | {error, term()}.
decompress(<<Y0:248/little, YLast:8>>) ->
  Sign = (YLast band 16#80) =/= 0,
  Y = binary:decode_unsigned(<<Y0:248/little, (YLast band 16#7F):8>>, little),
  if
    Y >= ?Q ->
      {error, y_outside_field};
    true ->
      Y2 = (Y * Y) rem ?Q,
      Num = (Y2 - 1 + ?Q) rem ?Q,
      Den = (1 + ?D_COEFF * Y2) rem ?Q,
      case Den of
        0 ->
          {error, zero_denominator};
        _ ->
          DenInv = ecu_misc:exp_mod(Den, ?Q - 2, ?Q),
          X2 = (Num * DenInv) rem ?Q,
          case mod_sqrt(X2) of
            {ok, XRoot} ->
              if
                XRoot =:= 0 andalso Sign ->
                  {error, non_canonical};
                true ->
                  X =
                    case (XRoot band 1) =/= 0 of
                      Sign -> XRoot;
                      _ -> (?Q - XRoot) rem ?Q
                    end,
                  {ok, {X, Y}}
              end;
            error ->
              {error, not_on_curve}
          end
      end
  end;
decompress(_) ->
  {error, bad_length}.

%%%-------------------------------------------------------------------
%%% API: Montgomery Form & Ladder
%%%-------------------------------------------------------------------

-spec montgomery_a() -> non_neg_integer().
montgomery_a() ->
  ?MONTGOMERY_A.

%% @doc Check whether an affine point lies on Montgomery curve B*v^2 = u^3 + A*u^2 + u (mod q).
-spec is_on_montgomery(montgomery_point()) -> boolean().
is_on_montgomery(infinity) ->
  true;
is_on_montgomery({U, V}) when is_integer(U), is_integer(V), U >= 0, U < ?Q, V >= 0, V < ?Q ->
  Left = (?MONTGOMERY_B * (V * V rem ?Q)) rem ?Q,
  U2 = (U * U) rem ?Q,
  U3 = (U2 * U) rem ?Q,
  Right = (U3 + ?MONTGOMERY_A * U2 + U) rem ?Q,
  Left =:= Right;
is_on_montgomery(_) ->
  false.

%% @doc Convert a Twisted Edwards affine point {X, Y} to a Montgomery point {U, V} or `infinity'.
-spec edwards_to_montgomery(point()) -> montgomery_point().
edwards_to_montgomery({0, 1}) ->
  infinity;
edwards_to_montgomery({0, Y}) when Y =:= ?Q - 1 ->
  {0, 0};
edwards_to_montgomery({X, Y}) when is_integer(X), is_integer(Y), X >= 0, X < ?Q, Y >= 0, Y < ?Q ->
  case is_on_curve({X, Y}) of
    false ->
      error(badarg);
    true ->
      OneMinusY = (?Q + 1 - Y) rem ?Q,
      case OneMinusY of
        0 ->
          infinity;
        _ ->
          OnePlusY = (1 + Y) rem ?Q,
          Inv1MinusY = ecu_misc:exp_mod(OneMinusY, ?Q - 2, ?Q),
          U = (OnePlusY * Inv1MinusY) rem ?Q,
          case X of
            0 ->
              {U, 0};
            _ ->
              InvX = ecu_misc:exp_mod(X, ?Q - 2, ?Q),
              V = (U * InvX) rem ?Q,
              {U, V}
          end
      end
  end;
edwards_to_montgomery(_) ->
  error(badarg).

%% @doc Convert a Montgomery point {U, V} or `infinity' to a Twisted Edwards affine point {X, Y}.
-spec montgomery_to_edwards(montgomery_point()) -> point().
montgomery_to_edwards(infinity) ->
  {0, 1};
montgomery_to_edwards({0, 0}) ->
  {0, ?Q - 1};
montgomery_to_edwards({U, V}) when is_integer(U), is_integer(V), U >= 0, U < ?Q, V >= 0, V < ?Q ->
  case is_on_montgomery({U, V}) of
    false ->
      error(badarg);
    true ->
      InvV = ecu_misc:exp_mod(V, ?Q - 2, ?Q),
      X = (U * InvV) rem ?Q,
      UPlus1 = (U + 1) rem ?Q,
      InvUPlus1 = ecu_misc:exp_mod(UPlus1, ?Q - 2, ?Q),
      Y = ((U - 1 + ?Q) * InvUPlus1) rem ?Q,
      {X, Y}
  end;
montgomery_to_edwards(_) ->
  error(badarg).

%% @doc Evaluate scalar multiplication on the Montgomery curve using the u-only Montgomery ladder.
-spec montgomery_ladder(non_neg_integer() | <<_:256>>, non_neg_integer() | <<_:256>>) ->
  non_neg_integer() | <<_:256>>.
montgomery_ladder(Scalar, UCoord) when
  is_binary(Scalar),
  byte_size(Scalar) =:= 32,
  is_binary(UCoord),
  byte_size(UCoord) =:= 32
->
  KInt = binary:decode_unsigned(Scalar, little),
  UInt = binary:decode_unsigned(UCoord, little),
  URes = montgomery_ladder_int(KInt, UInt),
  <<URes:256/little>>;
montgomery_ladder(Scalar, UCoord) when is_integer(Scalar), is_integer(UCoord) ->
  montgomery_ladder_int(Scalar, UCoord);
montgomery_ladder(Scalar, UCoord) when
  is_binary(Scalar),
  byte_size(Scalar) =:= 32,
  is_integer(UCoord)
->
  KInt = binary:decode_unsigned(Scalar, little),
  montgomery_ladder_int(KInt, UCoord);
montgomery_ladder(Scalar, UCoord) when
  is_integer(Scalar),
  is_binary(UCoord),
  byte_size(UCoord) =:= 32
->
  UInt = binary:decode_unsigned(UCoord, little),
  URes = montgomery_ladder_int(Scalar, UInt),
  <<URes:256/little>>;
montgomery_ladder(_, _) ->
  error(badarg).

-spec montgomery_ladder_int(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
montgomery_ladder_int(0, _U) ->
  0;
montgomery_ladder_int(_K, 0) ->
  0;
montgomery_ladder_int(KInt, UInt) when KInt > 0, UInt >= 0, UInt < ?Q ->
  X1 = UInt rem ?Q,
  {X2Fin, Z2Fin, X3Fin, Z3Fin, LastSwap} =
    ladder_loop(253, KInt, X1, 1, 0, X1, 1, 0),
  {X2Res, _} = cswap(LastSwap, X2Fin, X3Fin),
  {Z2Res, _} = cswap(LastSwap, Z2Fin, Z3Fin),
  case Z2Res of
    0 ->
      0;
    _ ->
      InvZ = ecu_misc:exp_mod(Z2Res, ?Q - 2, ?Q),
      (X2Res * InvZ) rem ?Q
  end;
montgomery_ladder_int(_, _) ->
  error(badarg).

-spec ladder_loop(
  integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  0 | 1
) ->
  {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), 0 | 1}.
ladder_loop(T, _KInt, _X1, X2, Z2, X3, Z3, Swap) when T < 0 ->
  {X2, Z2, X3, Z3, Swap};
ladder_loop(T, KInt, X1, X2, Z2, X3, Z3, Swap) ->
  Kt = (KInt bsr T) band 1,
  NewSwap = Swap bxor Kt,
  {X2S, X3S} = cswap(NewSwap, X2, X3),
  {Z2S, Z3S} = cswap(NewSwap, Z2, Z3),

  A = (X2S + Z2S) rem ?Q,
  AA = (A * A) rem ?Q,
  B = (X2S - Z2S + ?Q) rem ?Q,
  BB = (B * B) rem ?Q,
  E = (AA - BB + ?Q) rem ?Q,
  C = (X3S + Z3S) rem ?Q,
  D = (X3S - Z3S + ?Q) rem ?Q,
  DA = (D * A) rem ?Q,
  CB = (C * B) rem ?Q,
  DAPlusCB = (DA + CB) rem ?Q,
  X3Next = (DAPlusCB * DAPlusCB) rem ?Q,
  DAMinusCB = (DA - CB + ?Q) rem ?Q,
  Z3Next = (X1 * ((DAMinusCB * DAMinusCB) rem ?Q)) rem ?Q,
  X2Next = (AA * BB) rem ?Q,
  Z2Next = (E * (AA + ?MONTGOMERY_A24 * E)) rem ?Q,

  ladder_loop(T - 1, KInt, X1, X2Next, Z2Next, X3Next, Z3Next, Kt).

-compile({inline, [cswap/3]}).
-spec cswap(0 | 1, non_neg_integer(), non_neg_integer()) ->
  {non_neg_integer(), non_neg_integer()}.
cswap(1, A, B) ->
  {B, A};
cswap(0, A, B) ->
  {A, B}.

%%%-------------------------------------------------------------------
%%% Internal Helpers: Projective Coordinates
%%%-------------------------------------------------------------------

-spec to_proj(point() | projective_point()) -> projective_point().
to_proj({X, Y}) ->
  {X, Y, 1};
to_proj({X, Y, Z}) ->
  {X, Y, Z}.

-spec to_affine(point() | projective_point()) -> point().
to_affine({X, Y}) ->
  {X, Y};
to_affine({X, Y, 1}) ->
  {X, Y};
to_affine({X, Y, Z}) ->
  ZInv = ecu_misc:exp_mod(Z, ?Q - 2, ?Q),
  {(X * ZInv) rem ?Q, (Y * ZInv) rem ?Q}.

%% @doc Complete projective addition formula for twisted Edwards curves with a = -1.
-spec proj_add(projective_point(), projective_point()) -> projective_point().
proj_add({X1, Y1, Z1}, {X2, Y2, Z2}) ->
  A = (Z1 * Z2) rem ?Q,
  B = (A * A) rem ?Q,
  C = (X1 * X2) rem ?Q,
  D = (Y1 * Y2) rem ?Q,
  E = (?D_COEFF * C rem ?Q * D) rem ?Q,
  F = (B - E + ?Q) rem ?Q,
  G = (B + E) rem ?Q,
  Aux = (((X1 + Y1) * (X2 + Y2) - C - D) rem ?Q + 2 * ?Q) rem ?Q,
  X3 = (A * F rem ?Q * Aux) rem ?Q,
  Dac = (D + C) rem ?Q,
  Y3 = (A * G rem ?Q * Dac) rem ?Q,
  Z3 = (F * G) rem ?Q,
  {X3, Y3, Z3}.

-spec scalar_mul_proj(projective_point(), non_neg_integer()) -> projective_point().
scalar_mul_proj(_P, 0) ->
  {0, 1, 1};
scalar_mul_proj(P, 1) ->
  P;
scalar_mul_proj(P, K) ->
  scalar_mul_loop(K, P, {0, 1, 1}).

-spec scalar_mul_loop(non_neg_integer(), projective_point(), projective_point()) ->
  projective_point().
scalar_mul_loop(0, _Exp, Acc) ->
  Acc;
scalar_mul_loop(N, Exp, Acc) ->
  Acc1 =
    if
      (N band 1) =:= 1 -> proj_add(Acc, Exp);
      true -> Acc
    end,
  scalar_mul_loop(N bsr 1, proj_add(Exp, Exp), Acc1).

%%%-------------------------------------------------------------------
%%% Internal Helpers: Tonelli-Shanks Square Root
%%%-------------------------------------------------------------------

-spec mod_sqrt(non_neg_integer()) -> {ok, non_neg_integer()} | error.
mod_sqrt(0) ->
  {ok, 0};
mod_sqrt(A) ->
  case ecu_misc:exp_mod(A, (?Q - 1) div 2, ?Q) of
    1 ->
      Y0 = ecu_misc:exp_mod(A, (?TS_S + 1) div 2, ?Q),
      B0 = ecu_misc:exp_mod(A, ?TS_S, ?Q),
      ts_loop(Y0, B0, ?TS_G, ?TS_E);
    _ ->
      error
  end.

-spec ts_loop(non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
  {ok, non_neg_integer()}.
ts_loop(Y, 1, _GCur, _R) ->
  {ok, Y};
ts_loop(Y, B, GCur, R) ->
  M = find_order((B * B) rem ?Q, 1),
  Shift = R - M - 1,
  G2 = ecu_misc:exp_mod(GCur, 1 bsl Shift, ?Q),
  NewY = (Y * G2) rem ?Q,
  NewGCur = (G2 * G2) rem ?Q,
  NewB = (B * NewGCur) rem ?Q,
  ts_loop(NewY, NewB, NewGCur, M).

-spec find_order(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
find_order(1, M) ->
  M;
find_order(T, M) ->
  find_order((T * T) rem ?Q, M + 1).
