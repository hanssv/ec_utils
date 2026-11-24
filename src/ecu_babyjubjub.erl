%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang implementation of the BabyJubjub elliptic curve (EIP-2494)
%%% and Circom-compatible EdDSA signatures with Poseidon.
%%%
%%% BabyJubjub is a twisted Edwards curve birationally equivalent to a
%%% Montgomery curve, defined over the scalar field of BN254 (alt_bn128).
%%% It is specifically designed to execute with minimal constraint count
%%% inside zk-SNARK circuits.
%%%
%%% Curve equation: a * x^2 + y^2 = 1 + d * x^2 * y^2 (mod q)
%%% where:
%%%   q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
%%%   a = 168700
%%%   d = 168696
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_babyjubjub).

-typing([eqwalizer]).

-export([
  q/0,
  a/0,
  d/0,
  order/0,
  suborder/0,
  cofactor/0,
  base8/0,
  generator/0,
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

  keypair/0,
  keypair/1,
  derive_public_key/1,
  sign/2,
  verify/3,

  montgomery_a/0,
  montgomery_b/0,
  montgomery_a24/0,
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

-ifdef(TEST).
-export([to_proj/1, to_affine/1]).
-endif.

%%%-------------------------------------------------------------------
%%% Curve Constants & Definitions
%%%-------------------------------------------------------------------

-define(Q, 16#30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001).
-define(A_COEFF, 168700).
-define(D_COEFF, 168696).

%% Curve order N = 8 * L
-define(ORDER, 21888242871839275222246405745257275088614511777268538073601725287587578984328).
%% Prime subgroup order L
-define(SUBORDER, 2736030358979909402780800718157159386076813972158567259200215660948447373041).
-define(COFACTOR, 8).

%% Subgroup generator Base8
-define(BASE8_X, 5299619240641551281634865583518297030282874472190772894086521144482721001553).
-define(BASE8_Y, 16950150798460657717958625567821834550301663161624707787222815936182638968203).

%% Full curve generator G
-define(GEN_X, 995203441582195749578291179787384436505546430278305826713579947235728471134).
-define(GEN_Y, 5472060717959818805561601436314318772137091100104008585924551046643952123905).

%% Tonelli-Shanks constants for Q = 2^28 * S + 1
-define(TS_E, 28).
-define(TS_S, 81540058820840996586704275553141814055101440848469862132140264610111).
-define(TS_G, 19103219067921713944291392827692070036145651957329286315305642004821462161904).

%% Montgomery Curve Constants: B*v^2 = u^3 + A*u^2 + u
-define(MONTGOMERY_A, 168698).
-define(MONTGOMERY_B, 1).
-define(MONTGOMERY_A24, 42174).

-type point() :: {non_neg_integer(), non_neg_integer()}.
-type projective_point() :: {non_neg_integer(), non_neg_integer(), non_neg_integer()}.
-type montgomery_point() :: {non_neg_integer(), non_neg_integer()} | infinity.

%%%-------------------------------------------------------------------
%%% API: Parameters
%%%-------------------------------------------------------------------

-spec q() -> non_neg_integer().
q() ->
  ?Q.

-spec a() -> non_neg_integer().
a() ->
  ?A_COEFF.

-spec d() -> non_neg_integer().
d() ->
  ?D_COEFF.

-spec order() -> non_neg_integer().
order() ->
  ?ORDER.

-spec suborder() -> non_neg_integer().
suborder() ->
  ?SUBORDER.

-spec cofactor() -> pos_integer().
cofactor() ->
  ?COFACTOR.

-spec base8() -> point().
base8() ->
  {?BASE8_X, ?BASE8_Y}.

-spec generator() -> point().
generator() ->
  {?GEN_X, ?GEN_Y}.

-spec identity() -> point().
identity() ->
  {0, 1}.

%%%-------------------------------------------------------------------
%%% API: Curve Arithmetic
%%%-------------------------------------------------------------------

%% @doc Check whether an affine point lies on the BabyJubjub curve.
-spec is_on_curve(point()) -> boolean().
is_on_curve({X, Y}) when X >= 0, X < ?Q, Y >= 0, Y < ?Q ->
  X2 = (X * X) rem ?Q,
  Y2 = (Y * Y) rem ?Q,
  Left = (?A_COEFF * X2 + Y2) rem ?Q,
  Right = (1 + ?D_COEFF * X2 rem ?Q * Y2) rem ?Q,
  Left =:= Right;
is_on_curve(_) ->
  false.

%% @doc Check whether a point belongs to the prime-order subgroup of size L.
-spec is_in_subgroup(point()) -> boolean().
is_in_subgroup(Point) ->
  is_on_curve(Point) andalso (mul(Point, ?SUBORDER) =:= identity()).

%% @doc Point negation: -(x, y) = (q - x, y).
-spec neg(point()) -> point().
neg({0, Y}) ->
  {0, Y};
neg({X, Y}) when X > 0, X < ?Q, Y >= 0, Y < ?Q ->
  {?Q - X, Y};
neg(_) ->
  error(badarg).

%% @doc Double a point on the curve.
-spec double(point() | projective_point()) -> point().
double({X, Y}) ->
  to_affine(proj_add({X, Y, 1}, {X, Y, 1}));
double({X, Y, Z}) ->
  to_affine(proj_add({X, Y, Z}, {X, Y, Z})).

%% @doc Add two points on the twisted Edwards curve.
-spec add(point() | projective_point(), point() | projective_point()) -> point().
add(P1, P2) ->
  P1Proj = to_proj(P1),
  P2Proj = to_proj(P2),
  to_affine(proj_add(P1Proj, P2Proj)).

%% @doc Scalar multiplication k * P.
-spec mul(point() | projective_point(), integer()) -> point().
mul(_Point, 0) ->
  identity();
mul(Point, K) when K < 0 ->
  mul(neg(to_affine(Point)), -K);
mul(Point, K) when is_integer(K) ->
  PProj = to_proj(Point),
  to_affine(scalar_mul_proj(PProj, K)).

%% @doc Fast scalar multiplication for the standard subgroup base point Base8.
-spec mul_base8(integer()) -> point().
mul_base8(K) ->
  mul(base8(), K).

%% @doc Compress an affine point into a 32-byte binary per EIP-2494 / Circom.
-spec compress(point()) -> <<_:256>>.
compress({X, Y}) when X >= 0, X < ?Q, Y >= 0, Y < ?Q ->
  <<Y0:248/little, YLast:8>> = <<Y:256/little>>,
  SignBit =
    if
      X > (?Q bsr 1) -> 16#80;
      true -> 0
    end,
  <<Y0:248/little, (YLast bor SignBit):8>>;
compress(_) ->
  error(badarg).

%% @doc Decompress a 32-byte binary into an affine point.
-spec decompress(binary()) -> {ok, point()} | {error, term()}.
decompress(<<Y0:248/little, YLast:8>>) ->
  Sign = (YLast band 16#80) =/= 0,
  Y = binary:decode_unsigned(<<Y0:248/little, (YLast band 16#7F):8>>, little),
  if
    Y >= ?Q ->
      {error, y_outside_field};
    true ->
      Y2 = (Y * Y) rem ?Q,
      Num = (1 - Y2 + ?Q) rem ?Q,
      Den = (?A_COEFF - ?D_COEFF * Y2 rem ?Q + ?Q) rem ?Q,
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
                    if
                      Sign andalso (XRoot =< (?Q bsr 1)) -> ?Q - XRoot;
                      (not Sign) andalso (XRoot > (?Q bsr 1)) -> ?Q - XRoot;
                      true -> XRoot
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
%%% API: Circom EdDSA (Poseidon)
%%%-------------------------------------------------------------------

%% @doc Generate a new random EdDSA keypair on BabyJubjub.
-spec keypair() -> {binary(), <<_:256>>}.
keypair() ->
  Seed = ecu_compat:strong_rand_bytes(32),
  keypair(Seed).

%% @doc Derive EdDSA keypair from a 32-byte secret seed.
-spec keypair(binary()) -> {binary(), <<_:256>>}.
keypair(Seed) when is_binary(Seed), byte_size(Seed) =:= 32 ->
  PK = derive_public_key(Seed),
  {Seed, PK};
keypair(_) ->
  error(badarg).

%% @doc Derive 32-byte compressed public key from a 32-byte secret seed.
-spec derive_public_key(binary()) -> <<_:256>>.
derive_public_key(Seed) when is_binary(Seed), byte_size(Seed) =:= 32 ->
  H = ecu_blake512:hash(Seed),
  <<H0_31:32/binary, _/binary>> = H,
  Scalar = prune_to_scalar(H0_31),
  PK = mul_base8(Scalar),
  compress(PK);
derive_public_key(_) ->
  error(badarg).

%% @doc Sign a field element message using Circom-compatible Poseidon EdDSA.
-spec sign(binary(), non_neg_integer() | binary()) -> <<_:512>>.
sign(Seed, Msg) when is_binary(Seed), byte_size(Seed) =:= 32 ->
  MsgInt = to_field_element(Msg),
  H = ecu_blake512:hash(Seed),
  <<H0_31:32/binary, H32_63:32/binary>> = H,
  ScalarKey = prune_to_scalar(H0_31),
  PK = mul_base8(ScalarKey),
  {PK_X, PK_Y} = PK,

  MsgLE = <<MsgInt:256/little>>,
  RHash = ecu_blake512:hash(<<H32_63/binary, MsgLE/binary>>),
  RNum = binary:decode_unsigned(RHash, little) rem ?SUBORDER,
  R8 = mul_base8(RNum),
  {R8_X, R8_Y} = R8,

  HM = ecu_poseidon:hash(bn254, [R8_X, R8_Y, PK_X, PK_Y, MsgInt]),
  S = (RNum + HM * (ScalarKey bsl 3)) rem ?SUBORDER,

  R8Comp = compress(R8),
  <<R8Comp/binary, S:256/little>>;
sign(_, _) ->
  error(badarg).

%% @doc Verify an EdDSA signature against public key and message.
-spec verify(binary() | point(), binary(), non_neg_integer() | binary()) -> boolean().
verify(PK, Sig, Msg) when is_binary(Sig), byte_size(Sig) =:= 64 ->
  try
    PKPoint =
      case PK of
        {X, Y} when is_integer(X), is_integer(Y) -> {X, Y};
        <<_:32/binary>> ->
          case decompress(PK) of
            {ok, P} -> P;
            _ -> throw(bad_pk)
          end;
        _ ->
          throw(bad_pk)
      end,
    case is_on_curve(PKPoint) andalso PKPoint =/= identity() of
      false ->
        false;
      true ->
        %% Clear cofactor on PK per circomlib eddsaposeidon.circom:
        %% A8 = 8 * PK; reject if A8.x == 0 (identity or order 2)
        A8 = mul(PKPoint, 8),
        case A8 =/= identity() andalso element(1, A8) =/= 0 of
          false ->
            false;
          true ->
            MsgInt = to_field_element(Msg),
            <<R8Comp:32/binary, S:256/little>> = Sig,
            if
              S >= ?SUBORDER ->
                false;
              true ->
                case decompress(R8Comp) of
                  {ok, R8} when R8 =/= {0, 1} ->
                    {R8_X, R8_Y} = R8,
                    {PK_X, PK_Y} = PKPoint,
                    HM = ecu_poseidon:hash(bn254, [R8_X, R8_Y, PK_X, PK_Y, MsgInt]),
                    L = mul_base8(S),
                    HM_A8 = mul(A8, HM),
                    R = add(R8, HM_A8),
                    L =:= R;
                  _ ->
                    false
                end
            end
        end
    end
  catch
    _:_ ->
      false
  end;
verify(_, _, _) ->
  false.

%%%-------------------------------------------------------------------
%%% Internal Helpers: Projective Arithmetic
%%%-------------------------------------------------------------------

-compile({inline, [to_proj/1, to_affine/1, proj_add/2]}).

-spec to_proj(term()) -> projective_point().
to_proj({X, Y}) when is_integer(X), is_integer(Y) ->
  {X, Y, 1};
to_proj({X, Y, Z}) when is_integer(X), is_integer(Y), is_integer(Z) ->
  {X, Y, Z};
to_proj(_) ->
  error(badarg).

-spec to_affine(term()) -> point().
to_affine({X, Y}) when is_integer(X), is_integer(Y) ->
  {X, Y};
to_affine({_X, _Y, 0}) ->
  identity();
to_affine({X, Y, 1}) when is_integer(X), is_integer(Y) ->
  {X, Y};
to_affine({X, Y, Z}) when is_integer(X), is_integer(Y), is_integer(Z) ->
  ZInv = ecu_misc:exp_mod(Z, ?Q - 2, ?Q),
  {(X * ZInv) rem ?Q, (Y * ZInv) rem ?Q};
to_affine(_) ->
  error(badarg).

%% @doc Complete projective addition formula for twisted Edwards curves (BBJLP).
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
  Dac = (D - ?A_COEFF * C rem ?Q + ?A_COEFF * ?Q) rem ?Q,
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

%%%-------------------------------------------------------------------
%%% Internal Helpers: Key Parsing & Pruning
%%%-------------------------------------------------------------------

-spec prune_to_scalar(<<_:256>>) -> non_neg_integer().
prune_to_scalar(<<B0:8, Mid:30/binary, B31:8>>) ->
  PB0 = B0 band 16#F8,
  PB31 = (B31 band 16#7F) bor 16#40,
  Pruned = <<PB0:8, Mid/binary, PB31:8>>,
  binary:decode_unsigned(Pruned, little) bsr 3.

-spec to_field_element(non_neg_integer() | binary()) -> non_neg_integer().
to_field_element(Msg) when is_integer(Msg), Msg >= 0, Msg < ?Q ->
  Msg;
to_field_element(Msg) when is_binary(Msg), byte_size(Msg) =< 32 ->
  Val = binary:decode_unsigned(Msg, little),
  if
    Val < ?Q -> Val;
    true -> error(badarg)
  end;
to_field_element(_) ->
  error(badarg).

%%%-------------------------------------------------------------------
%%% API: Montgomery Form & Ladder
%%%-------------------------------------------------------------------

-spec montgomery_a() -> non_neg_integer().
montgomery_a() ->
  ?MONTGOMERY_A.

-spec montgomery_b() -> non_neg_integer().
montgomery_b() ->
  ?MONTGOMERY_B.

-spec montgomery_a24() -> non_neg_integer().
montgomery_a24() ->
  ?MONTGOMERY_A24.

%% @doc Check whether an affine point lies on the Montgomery curve v^2 = u^3 + A*u^2 + u (mod q).
-spec is_on_montgomery(montgomery_point()) -> boolean().
is_on_montgomery(infinity) ->
  true;
is_on_montgomery({U, V}) when is_integer(U), is_integer(V), U >= 0, U < ?Q, V >= 0, V < ?Q ->
  Left = (V * V) rem ?Q,
  U2 = (U * U) rem ?Q,
  U3 = (U2 * U) rem ?Q,
  Right = (U3 + ?MONTGOMERY_A * U2 + U) rem ?Q,
  Left =:= Right;
is_on_montgomery(_) ->
  false.

%% @doc Convert a Twisted Edwards affine point {X, Y} to a Montgomery point {U, V} or `infinity'.
%% Identity {0, 1} maps to `infinity'.
%% Point {0, q - 1} maps to {0, 0}.
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
%% `infinity' maps to {0, 1}.
%% {0, 0} maps to {0, q - 1}.
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
%% Supports both integer coordinates and 32-byte little-endian binaries.
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
    ladder_loop(255, KInt, X1, 1, 0, X1, 1, 0),
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
