%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang BN254 (alt_bn128) elliptic curve operations for G1 and G2 groups:
%%%   - G1: Short Weierstrass curve y^2 = x^3 + 3 over Fp
%%%   - G2: Twisted Short Weierstrass curve y^2 = x^3 + 3/(9 + u) over Fp2
%%%   - Jacobian coordinate arithmetic (addition, doubling, scalar multiplication)
%%%   - Point serialization (uncompressed 64B/128B and compressed 32B/64B)
%%%   - Subgroup membership verification
%%%
%%% Reference:
%%%   - EIP-196 / EIP-197 (Ethereum alt_bn128 precompiles)
%%%   - arkworks ark-bn254
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bn254).

-typing([eqwalizer]).

-include("ecu_bn254.hrl").

-define(FP, ecu_bn254_fp).

-type fp() :: non_neg_integer().
-type fp2() :: {fp(), fp()}.

-type g1_affine() :: {fp(), fp()} | infinity.
-type g1_jacobian() :: {fp(), fp(), fp()}.
-type g1_compressed() :: <<_:256>>.
-type g1_uncompressed() :: <<_:512>>.

-type g2_affine() :: {fp2(), fp2()} | infinity.
-type g2_jacobian() :: {fp2(), fp2(), fp2()}.
-type g2_compressed() :: <<_:512>>.
-type g2_uncompressed() :: <<_:1024>>.

-type scalar() :: integer() | binary().

-export_type([
  g1_affine/0,
  g1_jacobian/0,
  g1_compressed/0,
  g1_uncompressed/0,
  g2_affine/0,
  g2_jacobian/0,
  g2_compressed/0,
  g2_uncompressed/0,
  scalar/0
]).

%% Parameters
-export([
  p/0,
  r/0,
  x/0
]).

%% G1 Operations
-export([
  g1_generator/0,
  g1_zero/0,
  g1_infinity/0,
  g1_is_zero/1,
  g1_on_curve/1,
  g1_is_in_subgroup/1,
  g1_neg/1,
  g1_double/1,
  g1_add/2,
  g1_sub/2,
  g1_scalar_mul/2,
  g1_scalar_mul_base/1,
  g1_to_jacobian/1,
  g1_from_jacobian/1,
  g1_j_double/1,
  g1_j_add/2,
  g1_j_add_affine/2,
  g1_j_scalar_mul/2,
  g1_compress/1,
  g1_decompress/1,
  g1_to_uncompressed/1,
  g1_from_uncompressed/1
]).

%% G2 Operations
-export([
  g2_generator/0,
  g2_zero/0,
  g2_infinity/0,
  g2_is_zero/1,
  g2_on_curve/1,
  g2_is_in_subgroup/1,
  g2_neg/1,
  g2_double/1,
  g2_add/2,
  g2_sub/2,
  g2_scalar_mul/2,
  g2_scalar_mul_base/1,
  g2_to_jacobian/1,
  g2_from_jacobian/1,
  g2_j_double/1,
  g2_j_add/2,
  g2_j_add_affine/2,
  g2_j_scalar_mul/2,
  g2_compress/1,
  g2_decompress/1,
  g2_to_uncompressed/1,
  g2_from_uncompressed/1
]).

%%%-------------------------------------------------------------------
%%% Parameters
%%%-------------------------------------------------------------------

-spec p() -> pos_integer().
p() -> ?BN254_P.

-spec r() -> pos_integer().
r() -> ?BN254_R.

-spec x() -> pos_integer().
x() -> ?BN254_X.

%%%-------------------------------------------------------------------
%%% G1 Operations: Curve y^2 = x^3 + 3 over Fp
%%%-------------------------------------------------------------------

-spec g1_generator() -> g1_affine().
g1_generator() ->
  {?BN254_G1_X, ?BN254_G1_Y}.

-spec g1_zero() -> g1_affine().
g1_zero() ->
  infinity.

-spec g1_infinity() -> g1_affine().
g1_infinity() ->
  infinity.

-spec g1_is_zero(g1_affine()) -> boolean().
g1_is_zero(infinity) -> true;
g1_is_zero(_) -> false.

-spec g1_on_curve(g1_affine()) -> boolean().
g1_on_curve(infinity) ->
  true;
g1_on_curve({X, Y}) when
  is_integer(X), is_integer(Y), X >= 0, X < ?BN254_P, Y >= 0, Y < ?BN254_P
->
  %% y^2 = x^3 + 3 mod p
  Left = ?FP:fp_sqr(Y),
  Right = ?FP:fp_add(?FP:fp_mul(?FP:fp_sqr(X), X), ?BN254_B),
  Left =:= Right;
g1_on_curve(_) ->
  false.

-spec g1_is_in_subgroup(g1_affine()) -> boolean().
g1_is_in_subgroup(infinity) ->
  true;
g1_is_in_subgroup(P) ->
  %% For BN254, cofactor h1 = 1, so every point on curve is in G1
  g1_on_curve(P).

-spec g1_neg(g1_affine()) -> g1_affine().
g1_neg(infinity) -> infinity;
g1_neg({X, Y}) -> {X, ?FP:fp_neg(Y)}.

-spec g1_double(g1_affine()) -> g1_affine().
g1_double(infinity) -> infinity;
g1_double(P) -> g1_from_jacobian(g1_j_double(g1_to_jacobian(P))).

-spec g1_add(g1_affine(), g1_affine()) -> g1_affine().
g1_add(infinity, Q) ->
  Q;
g1_add(P, infinity) ->
  P;
g1_add({X1, Y1}, {X2, Y2}) when X1 =:= X2 ->
  case Y1 =:= Y2 of
    true -> g1_double({X1, Y1});
    false -> infinity
  end;
g1_add(P, Q) ->
  g1_from_jacobian(g1_j_add_affine(g1_to_jacobian(P), Q)).

-spec g1_sub(g1_affine(), g1_affine()) -> g1_affine().
g1_sub(P, Q) ->
  g1_add(P, g1_neg(Q)).

-spec g1_scalar_mul(g1_affine(), scalar()) -> g1_affine().
g1_scalar_mul(infinity, _K) ->
  infinity;
g1_scalar_mul(P, Bin) when is_binary(Bin) ->
  g1_scalar_mul(P, binary:decode_unsigned(Bin));
g1_scalar_mul(_P, 0) ->
  infinity;
g1_scalar_mul(P, K) when is_integer(K), K > 0 ->
  J = g1_to_jacobian(P),
  ResJ = g1_j_scalar_mul(J, K),
  g1_from_jacobian(ResJ);
g1_scalar_mul(P, K) when is_integer(K), K < 0 ->
  g1_scalar_mul(g1_neg(P), -K).

-spec g1_scalar_mul_base(scalar()) -> g1_affine().
g1_scalar_mul_base(K) ->
  g1_scalar_mul(g1_generator(), K).

-spec g1_to_jacobian(g1_affine()) -> g1_jacobian().
g1_to_jacobian(infinity) -> {1, 1, 0};
g1_to_jacobian({X, Y}) -> {X, Y, 1}.

-spec g1_from_jacobian(g1_jacobian()) -> g1_affine().
g1_from_jacobian({_X, _Y, 0}) ->
  infinity;
g1_from_jacobian({X, Y, 1}) ->
  {X, Y};
g1_from_jacobian({X, Y, Z}) ->
  Zinv = ?FP:fp_inv(Z),
  Zinv2 = ?FP:fp_sqr(Zinv),
  Zinv3 = ?FP:fp_mul(Zinv2, Zinv),
  {?FP:fp_mul(X, Zinv2), ?FP:fp_mul(Y, Zinv3)}.

-spec g1_j_double(g1_jacobian()) -> g1_jacobian().
g1_j_double({_X, _Y, 0}) ->
  {1, 1, 0};
g1_j_double({_X, 0, _Z}) ->
  {1, 1, 0};
g1_j_double({X, Y, Z}) ->
  %% Doubling for a = 0 Short Weierstrass curve:
  Y2 = ?FP:fp_add(Y, Y),
  Y2_sqr = ?FP:fp_sqr(Y2),
  S = ?FP:fp_mul(X, Y2_sqr),
  X_sqr = ?FP:fp_sqr(X),
  M = ?FP:fp_add(?FP:fp_add(X_sqr, X_sqr), X_sqr),
  X3 = ?FP:fp_sub(?FP:fp_sqr(M), ?FP:fp_add(S, S)),
  Y_sqr = ?FP:fp_sqr(Y),
  Y4_8 = ?FP:fp_mul(8, ?FP:fp_sqr(Y_sqr)),
  Y3 = ?FP:fp_sub(?FP:fp_mul(M, ?FP:fp_sub(S, X3)), Y4_8),
  Z3 = ?FP:fp_mul(Y2, Z),
  {X3, Y3, Z3}.

-spec g1_j_add_affine(g1_jacobian(), g1_affine()) -> g1_jacobian().
g1_j_add_affine(J1, infinity) ->
  J1;
g1_j_add_affine({_X1, _Y1, 0}, {X2, Y2}) ->
  {X2, Y2, 1};
g1_j_add_affine(J1, {X2, Y2}) ->
  g1_j_add(J1, {X2, Y2, 1}).

-spec g1_j_add(g1_jacobian(), g1_jacobian()) -> g1_jacobian().
g1_j_add({_X1, _Y1, 0}, J2) ->
  J2;
g1_j_add(J1, {_X2, _Y2, 0}) ->
  J1;
g1_j_add({X1, Y1, Z1}, {X2, Y2, Z2}) ->
  Z1_sqr = ?FP:fp_sqr(Z1),
  Z2_sqr = ?FP:fp_sqr(Z2),
  U1 = ?FP:fp_mul(X1, Z2_sqr),
  U2 = ?FP:fp_mul(X2, Z1_sqr),
  S1 = ?FP:fp_mul(Y1, ?FP:fp_mul(Z2, Z2_sqr)),
  S2 = ?FP:fp_mul(Y2, ?FP:fp_mul(Z1, Z1_sqr)),
  case U1 =:= U2 of
    true ->
      case S1 =:= S2 of
        true -> g1_j_double({X1, Y1, Z1});
        false -> {1, 1, 0}
      end;
    false ->
      H = ?FP:fp_sub(U2, U1),
      I = ?FP:fp_sqr(?FP:fp_add(H, H)),
      J = ?FP:fp_mul(H, I),
      R = ?FP:fp_sub(S2, S1),
      R2 = ?FP:fp_add(R, R),
      V = ?FP:fp_mul(U1, I),
      X3 = ?FP:fp_sub(?FP:fp_sub(?FP:fp_sqr(R2), J), ?FP:fp_add(V, V)),
      Y3 = ?FP:fp_sub(?FP:fp_mul(R2, ?FP:fp_sub(V, X3)), ?FP:fp_mul(?FP:fp_add(S1, S1), J)),
      Z3 = ?FP:fp_mul(?FP:fp_sub(?FP:fp_sqr(?FP:fp_add(Z1, Z2)), ?FP:fp_add(Z1_sqr, Z2_sqr)), H),
      {X3, Y3, Z3}
  end.

-spec g1_j_scalar_mul(g1_jacobian(), non_neg_integer()) -> g1_jacobian().
g1_j_scalar_mul(_J, 0) ->
  {1, 1, 0};
g1_j_scalar_mul(J, 1) ->
  J;
g1_j_scalar_mul(J, K) ->
  g1_j_scalar_mul_acc(J, K, {1, 1, 0}).

-spec g1_j_scalar_mul_acc(g1_jacobian(), non_neg_integer(), g1_jacobian()) -> g1_jacobian().
g1_j_scalar_mul_acc(_J, 0, Acc) ->
  Acc;
g1_j_scalar_mul_acc(J, K, Acc) when K rem 2 =:= 1 ->
  g1_j_scalar_mul_acc(g1_j_double(J), K div 2, g1_j_add(Acc, J));
g1_j_scalar_mul_acc(J, K, Acc) ->
  g1_j_scalar_mul_acc(g1_j_double(J), K div 2, Acc).

%% Serialization for G1:
%% Uncompressed: 64 bytes (X || Y)
-spec g1_to_uncompressed(g1_affine()) -> g1_uncompressed().
g1_to_uncompressed(infinity) ->
  <<0:512>>;
g1_to_uncompressed({X, Y}) ->
  <<(?FP:fp_to_bin(X))/binary, (?FP:fp_to_bin(Y))/binary>>.

-spec g1_from_uncompressed(binary()) -> {ok, g1_affine()} | error.
g1_from_uncompressed(<<0:512>>) ->
  {ok, infinity};
g1_from_uncompressed(<<XB:32/binary, YB:32/binary>>) ->
  try
    X = ?FP:fp_from_bin(XB),
    Y = ?FP:fp_from_bin(YB),
    P = {X, Y},
    case g1_on_curve(P) of
      true -> {ok, P};
      false -> error
    end
  catch
    error:badarg -> error
  end;
g1_from_uncompressed(_) ->
  error.

%% Compressed G1: 32 bytes (sign flag in MSB of 256-bit word)
-spec g1_compress(g1_affine()) -> g1_compressed().
g1_compress(infinity) ->
  <<0:256>>;
g1_compress({X, Y}) ->
  SignBit =
    if
      Y > ?BN254_P div 2 -> 1;
      true -> 0
    end,
  TaggedX = (SignBit bsl 255) bor X,
  <<TaggedX:256/big>>.

-spec g1_decompress(binary()) -> {ok, g1_affine()} | error.
g1_decompress(<<0:256>>) ->
  {ok, infinity};
g1_decompress(<<TaggedX:256/big>>) ->
  SignBit = (TaggedX bsr 255) band 1,
  X = TaggedX band ((1 bsl 255) - 1),
  if
    X >= ?BN254_P ->
      error;
    true ->
      %% Solve y^2 = x^3 + 3 mod p
      Right = ?FP:fp_add(?FP:fp_mul(?FP:fp_sqr(X), X), ?BN254_B),
      case ?FP:fp_sqrt(Right) of
        error ->
          error;
        {ok, RootY} ->
          YSign =
            if
              RootY > ?BN254_P div 2 -> 1;
              true -> 0
            end,
          Y =
            case YSign =:= SignBit of
              true -> RootY;
              false -> ?FP:fp_neg(RootY)
            end,
          {ok, {X, Y}}
      end
  end;
g1_decompress(_) ->
  error.

%%%-------------------------------------------------------------------
%%% G2 Operations: Curve y^2 = x^3 + 3/(9 + u) over Fp2
%%%-------------------------------------------------------------------

-spec g2_generator() -> g2_affine().
g2_generator() ->
  {{?BN254_G2_X0, ?BN254_G2_X1}, {?BN254_G2_Y0, ?BN254_G2_Y1}}.

-spec g2_zero() -> g2_affine().
g2_zero() ->
  infinity.

-spec g2_infinity() -> g2_affine().
g2_infinity() ->
  infinity.

-spec g2_is_zero(g2_affine()) -> boolean().
g2_is_zero(infinity) -> true;
g2_is_zero(_) -> false.

-spec g2_on_curve(g2_affine()) -> boolean().
g2_on_curve(infinity) ->
  true;
g2_on_curve({{X0, X1}, {Y0, Y1}}) when
  is_integer(X0),
  is_integer(X1),
  is_integer(Y0),
  is_integer(Y1),
  X0 >= 0,
  X0 < ?BN254_P,
  X1 >= 0,
  X1 < ?BN254_P,
  Y0 >= 0,
  Y0 < ?BN254_P,
  Y1 >= 0,
  Y1 < ?BN254_P
->
  X = {X0, X1},
  Y = {Y0, Y1},
  %% y^2 = x^3 + b' over Fp2
  TwistB = {?BN254_TWIST_B0, ?BN254_TWIST_B1},
  Left = ?FP:fp2_sqr(Y),
  Right = ?FP:fp2_add(?FP:fp2_mul(?FP:fp2_sqr(X), X), TwistB),
  Left =:= Right;
g2_on_curve(_) ->
  false.

-spec g2_is_in_subgroup(g2_affine()) -> boolean().
g2_is_in_subgroup(infinity) -> true;
g2_is_in_subgroup(Q) -> g2_on_curve(Q) andalso g2_is_zero(g2_scalar_mul(Q, ?BN254_R)).

-spec g2_neg(g2_affine()) -> g2_affine().
g2_neg(infinity) -> infinity;
g2_neg({X, Y}) -> {X, ?FP:fp2_neg(Y)}.

-spec g2_double(g2_affine()) -> g2_affine().
g2_double(infinity) -> infinity;
g2_double(Q) -> g2_from_jacobian(g2_j_double(g2_to_jacobian(Q))).

-spec g2_add(g2_affine(), g2_affine()) -> g2_affine().
g2_add(infinity, Q) ->
  Q;
g2_add(P, infinity) ->
  P;
g2_add({X1, Y1}, {X2, Y2}) when X1 =:= X2 ->
  case Y1 =:= Y2 of
    true -> g2_double({X1, Y1});
    false -> infinity
  end;
g2_add(P, Q) ->
  g2_from_jacobian(g2_j_add_affine(g2_to_jacobian(P), Q)).

-spec g2_sub(g2_affine(), g2_affine()) -> g2_affine().
g2_sub(P, Q) ->
  g2_add(P, g2_neg(Q)).

-spec g2_scalar_mul(g2_affine(), scalar()) -> g2_affine().
g2_scalar_mul(infinity, _K) ->
  infinity;
g2_scalar_mul(Q, Bin) when is_binary(Bin) ->
  g2_scalar_mul(Q, binary:decode_unsigned(Bin));
g2_scalar_mul(_Q, 0) ->
  infinity;
g2_scalar_mul(Q, K) when is_integer(K), K > 0 ->
  J = g2_to_jacobian(Q),
  ResJ = g2_j_scalar_mul(J, K),
  g2_from_jacobian(ResJ);
g2_scalar_mul(Q, K) when is_integer(K), K < 0 ->
  g2_scalar_mul(g2_neg(Q), -K).

-spec g2_scalar_mul_base(scalar()) -> g2_affine().
g2_scalar_mul_base(K) ->
  g2_scalar_mul(g2_generator(), K).

-spec g2_to_jacobian(g2_affine()) -> g2_jacobian().
g2_to_jacobian(infinity) -> {?FP:fp2_one(), ?FP:fp2_one(), ?FP:fp2_zero()};
g2_to_jacobian({X, Y}) -> {X, Y, ?FP:fp2_one()}.

-spec g2_from_jacobian(g2_jacobian()) -> g2_affine().
g2_from_jacobian({_X, _Y, {0, 0}}) ->
  infinity;
g2_from_jacobian({X, Y, {1, 0}}) ->
  {X, Y};
g2_from_jacobian({X, Y, Z}) ->
  Zinv = ?FP:fp2_inv(Z),
  Zinv2 = ?FP:fp2_sqr(Zinv),
  Zinv3 = ?FP:fp2_mul(Zinv2, Zinv),
  {?FP:fp2_mul(X, Zinv2), ?FP:fp2_mul(Y, Zinv3)}.

-spec g2_j_double(g2_jacobian()) -> g2_jacobian().
g2_j_double({_X, _Y, {0, 0}}) ->
  {?FP:fp2_one(), ?FP:fp2_one(), ?FP:fp2_zero()};
g2_j_double({_X, {0, 0}, _Z}) ->
  {?FP:fp2_one(), ?FP:fp2_one(), ?FP:fp2_zero()};
g2_j_double({X, Y, Z}) ->
  Y2 = ?FP:fp2_add(Y, Y),
  Y2_sqr = ?FP:fp2_sqr(Y2),
  S = ?FP:fp2_mul(X, Y2_sqr),
  X_sqr = ?FP:fp2_sqr(X),
  M = ?FP:fp2_add(?FP:fp2_add(X_sqr, X_sqr), X_sqr),
  X3 = ?FP:fp2_sub(?FP:fp2_sqr(M), ?FP:fp2_add(S, S)),
  Y_sqr = ?FP:fp2_sqr(Y),
  Y4_8 = ?FP:fp2_mul_fp(?FP:fp2_sqr(Y_sqr), 8),
  Y3 = ?FP:fp2_sub(?FP:fp2_mul(M, ?FP:fp2_sub(S, X3)), Y4_8),
  Z3 = ?FP:fp2_mul(Y2, Z),
  {X3, Y3, Z3}.

-spec g2_j_add_affine(g2_jacobian(), g2_affine()) -> g2_jacobian().
g2_j_add_affine(J1, infinity) ->
  J1;
g2_j_add_affine({_X1, _Y1, {0, 0}}, {X2, Y2}) ->
  {X2, Y2, ?FP:fp2_one()};
g2_j_add_affine(J1, {X2, Y2}) ->
  g2_j_add(J1, {X2, Y2, ?FP:fp2_one()}).

-spec g2_j_add(g2_jacobian(), g2_jacobian()) -> g2_jacobian().
g2_j_add({_X1, _Y1, {0, 0}}, J2) ->
  J2;
g2_j_add(J1, {_X2, _Y2, {0, 0}}) ->
  J1;
g2_j_add({X1, Y1, Z1}, {X2, Y2, Z2}) ->
  Z1_sqr = ?FP:fp2_sqr(Z1),
  Z2_sqr = ?FP:fp2_sqr(Z2),
  U1 = ?FP:fp2_mul(X1, Z2_sqr),
  U2 = ?FP:fp2_mul(X2, Z1_sqr),
  S1 = ?FP:fp2_mul(Y1, ?FP:fp2_mul(Z2, Z2_sqr)),
  S2 = ?FP:fp2_mul(Y2, ?FP:fp2_mul(Z1, Z1_sqr)),
  case U1 =:= U2 of
    true ->
      case S1 =:= S2 of
        true -> g2_j_double({X1, Y1, Z1});
        false -> {?FP:fp2_one(), ?FP:fp2_one(), ?FP:fp2_zero()}
      end;
    false ->
      H = ?FP:fp2_sub(U2, U1),
      I = ?FP:fp2_sqr(?FP:fp2_add(H, H)),
      J = ?FP:fp2_mul(H, I),
      R = ?FP:fp2_sub(S2, S1),
      R2 = ?FP:fp2_add(R, R),
      V = ?FP:fp2_mul(U1, I),
      X3 = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(R2), J), ?FP:fp2_add(V, V)),
      Y3 = ?FP:fp2_sub(?FP:fp2_mul(R2, ?FP:fp2_sub(V, X3)), ?FP:fp2_mul(?FP:fp2_add(S1, S1), J)),
      Z3 = ?FP:fp2_mul(?FP:fp2_sub(?FP:fp2_sqr(?FP:fp2_add(Z1, Z2)), ?FP:fp2_add(Z1_sqr, Z2_sqr)), H),
      {X3, Y3, Z3}
  end.

-spec g2_j_scalar_mul(g2_jacobian(), non_neg_integer()) -> g2_jacobian().
g2_j_scalar_mul(_J, 0) ->
  {?FP:fp2_one(), ?FP:fp2_one(), ?FP:fp2_zero()};
g2_j_scalar_mul(J, 1) ->
  J;
g2_j_scalar_mul(J, K) ->
  g2_j_scalar_mul_acc(J, K, {?FP:fp2_one(), ?FP:fp2_one(), ?FP:fp2_zero()}).

-spec g2_j_scalar_mul_acc(g2_jacobian(), non_neg_integer(), g2_jacobian()) -> g2_jacobian().
g2_j_scalar_mul_acc(_J, 0, Acc) ->
  Acc;
g2_j_scalar_mul_acc(J, K, Acc) when K rem 2 =:= 1 ->
  g2_j_scalar_mul_acc(g2_j_double(J), K div 2, g2_j_add(Acc, J));
g2_j_scalar_mul_acc(J, K, Acc) ->
  g2_j_scalar_mul_acc(g2_j_double(J), K div 2, Acc).

%% Serialization for G2:
%% Uncompressed: 128 bytes in EIP-197 order: [X1, X0, Y1, Y0] (32 bytes each)
-spec g2_to_uncompressed(g2_affine()) -> g2_uncompressed().
g2_to_uncompressed(infinity) ->
  <<0:1024>>;
g2_to_uncompressed({{X0, X1}, {Y0, Y1}}) ->
  <<
    (?FP:fp_to_bin(X1))/binary,
    (?FP:fp_to_bin(X0))/binary,
    (?FP:fp_to_bin(Y1))/binary,
    (?FP:fp_to_bin(Y0))/binary
  >>.

-spec g2_from_uncompressed(binary()) -> {ok, g2_affine()} | error.
g2_from_uncompressed(<<0:1024>>) ->
  {ok, infinity};
g2_from_uncompressed(<<X1B:32/binary, X0B:32/binary, Y1B:32/binary, Y0B:32/binary>>) ->
  try
    X1 = ?FP:fp_from_bin(X1B),
    X0 = ?FP:fp_from_bin(X0B),
    Y1 = ?FP:fp_from_bin(Y1B),
    Y0 = ?FP:fp_from_bin(Y0B),
    Q = {{X0, X1}, {Y0, Y1}},
    case g2_is_in_subgroup(Q) of
      true -> {ok, Q};
      false -> error
    end
  catch
    error:badarg -> error
  end;
g2_from_uncompressed(_) ->
  error.

%% Compressed G2: 64 bytes ([X1, X0] with sign in MSB of X1)
-spec g2_compress(g2_affine()) -> g2_compressed().
g2_compress(infinity) ->
  <<0:512>>;
g2_compress({{X0, X1}, {_Y0, Y1} = Y}) ->
  SignBit =
    if
      Y1 > ?BN254_P div 2 orelse (Y1 =:= 0 andalso element(1, Y) > ?BN254_P div 2) -> 1;
      true -> 0
    end,
  TaggedX1 = (SignBit bsl 255) bor X1,
  <<TaggedX1:256/big, (?FP:fp_to_bin(X0))/binary>>.

-spec g2_decompress(binary()) -> {ok, g2_affine()} | error.
g2_decompress(<<0:512>>) ->
  {ok, infinity};
g2_decompress(<<TaggedX1:256/big, X0B:32/binary>>) ->
  SignBit = (TaggedX1 bsr 255) band 1,
  X1 = TaggedX1 band ((1 bsl 255) - 1),
  try
    X0 = ?FP:fp_from_bin(X0B),
    if
      X1 >= ?BN254_P ->
        error;
      true ->
        X = {X0, X1},
        TwistB = {?BN254_TWIST_B0, ?BN254_TWIST_B1},
        Right = ?FP:fp2_add(?FP:fp2_mul(?FP:fp2_sqr(X), X), TwistB),
        case ?FP:fp2_sqrt(Right) of
          error ->
            error;
          {ok, {RootY0, RootY1} = RootY} ->
            YSign =
              if
                RootY1 > ?BN254_P div 2 orelse (RootY1 =:= 0 andalso RootY0 > ?BN254_P div 2) -> 1;
                true -> 0
              end,
            Y =
              case YSign =:= SignBit of
                true -> RootY;
                false -> ?FP:fp2_neg(RootY)
              end,
            Point = {X, Y},
            case g2_is_in_subgroup(Point) of
              true -> {ok, Point};
              false -> error
            end
        end
    end
  catch
    error:badarg -> error
  end;
g2_decompress(_) ->
  error.
