%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang BLS12-381 elliptic curve operations for G1 and G2 groups:
%%%   - G1: Short Weierstrass curve y^2 = x^3 + 4 over Fp
%%%   - G2: Twisted Short Weierstrass curve y^2 = x^3 + 4(1 + u) over Fp2
%%%   - Jacobian coordinate arithmetic (addition, doubling, scalar multiplication)
%%%   - Point compression and decompression per RFC 9380 and Zcash specifications
%%%   - Subgroup membership verification
%%%
%%% Reference:
%%%   - RFC 9380: https://www.rfc-editor.org/rfc/rfc9380.html
%%%   - draft-irtf-cfrg-pairing-friendly-curves:
%%%     https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves
%%%   - Zcash BLS12-381 specification:
%%%     https://github.com/zkcrypto/bls12_381
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381).

-typing([eqwalizer]).

-include("ecu_bls12_381.hrl").

-define(FP, ecu_bls12_381_fp).

-type fp() :: non_neg_integer().
-type fp2() :: {fp(), fp()}.

-type g1_affine() :: {fp(), fp()} | infinity.
-type g1_jacobian() :: {fp(), fp(), fp()}.
-type g1_compressed() :: <<_:384>>.
-type g1_uncompressed() :: <<_:768>>.

-type g2_affine() :: {fp2(), fp2()} | infinity.
-type g2_jacobian() :: {fp2(), fp2(), fp2()}.
-type g2_compressed() :: <<_:768>>.
-type g2_uncompressed() :: <<_:1536>>.

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

%% G1 Operations
-export([
  g1_generator/0,
  g1_infinity/0,
  g1_is_zero/1,
  g1_on_curve/1,
  g1_is_in_subgroup/1,
  g1_add/2,
  g1_double/1,
  g1_neg/1,
  g1_sub/2,
  g1_scalar_mul/2,
  g1_scalar_mul_base/1,
  g1_compress/1,
  g1_decompress/1,
  g1_serialize_uncompressed/1,
  g1_deserialize_uncompressed/1
]).

%% G2 Operations
-export([
  g2_generator/0,
  g2_infinity/0,
  g2_is_zero/1,
  g2_on_curve/1,
  g2_is_in_subgroup/1,
  g2_add/2,
  g2_double/1,
  g2_neg/1,
  g2_sub/2,
  g2_scalar_mul/2,
  g2_scalar_mul_base/1,
  g2_compress/1,
  g2_decompress/1,
  g2_serialize_uncompressed/1,
  g2_deserialize_uncompressed/1
]).

%% Jacobian Operations
-export([
  g1_to_jacobian/1,
  g1_from_jacobian/1,
  g1_j_add/2,
  g1_j_add_affine/2,
  g1_j_double/1,
  g2_to_jacobian/1,
  g2_from_jacobian/1,
  g2_j_add/2,
  g2_j_add_affine/2,
  g2_j_double/1
]).

%% Pairing Operations
-export([
  pairing/2,
  pairing_check/1,
  pairing_check/4
]).

%% Hash-to-Curve Operations (RFC 9380)
-export([
  g1_hash_to_curve/1,
  g1_hash_to_curve/2,
  g1_hash_to_curve/3,
  g1_encode_to_curve/1,
  g1_encode_to_curve/2,
  g1_encode_to_curve/3,
  g2_hash_to_curve/1,
  g2_hash_to_curve/2,
  g2_hash_to_curve/3,
  g2_encode_to_curve/1,
  g2_encode_to_curve/2,
  g2_encode_to_curve/3
]).

%%%-------------------------------------------------------------------
%%% G1 Operations (over Fp)
%%%-------------------------------------------------------------------

-spec g1_generator() -> g1_affine().
g1_generator() ->
  {?BLS12_381_G1_X, ?BLS12_381_G1_Y}.

-spec g1_infinity() -> g1_affine().
g1_infinity() ->
  infinity.

-spec g1_is_zero(g1_affine() | g1_jacobian()) -> boolean().
g1_is_zero(infinity) -> true;
g1_is_zero({_X, _Y, 0}) -> true;
g1_is_zero(_) -> false.

-spec g1_on_curve(g1_affine()) -> boolean().
g1_on_curve(infinity) ->
  true;
g1_on_curve({X, Y}) when
  is_integer(X), is_integer(Y), X >= 0, X < ?BLS12_381_P, Y >= 0, Y < ?BLS12_381_P
->
  %% y^2 = x^3 + 4 mod p
  Left = ?FP:fp_sqr(Y),
  Right = ?FP:fp_add(?FP:fp_mul(?FP:fp_sqr(X), X), ?BLS12_381_B),
  Left =:= Right;
g1_on_curve(_) ->
  false.

-spec g1_is_in_subgroup(g1_affine()) -> boolean().
g1_is_in_subgroup(infinity) -> true;
g1_is_in_subgroup(P) -> g1_on_curve(P) andalso g1_is_zero(g1_scalar_mul(P, ?BLS12_381_R)).

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
g1_scalar_mul(P, K) when is_integer(K) ->
  ModK = ((K rem ?BLS12_381_R) + ?BLS12_381_R) rem ?BLS12_381_R,
  case ModK of
    0 ->
      infinity;
    _ ->
      J = g1_to_jacobian(P),
      ResJ = g1_j_scalar_mul(J, ModK),
      g1_from_jacobian(ResJ)
  end.

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
  %% Y2_sqr = (2*Y)^2 = 4*Y^2
  %% S = X * Y2_sqr
  %% M = 3 * X^2
  %% X' = M^2 - 2*S
  %% Y' = M * (S - X') - 2 * (Y2_sqr)^2 / 4 = M * (S - X') - (Y2_sqr^2)/2
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

-spec g1_j_add_affine(g1_jacobian(), {fp(), fp()}) -> g1_jacobian().
g1_j_add_affine({_X1, _Y1, 0}, {X2, Y2}) ->
  {X2, Y2, 1};
g1_j_add_affine({X1, Y1, Z1}, {X2, Y2}) ->
  Z1_sqr = ?FP:fp_sqr(Z1),
  Z1_cub = ?FP:fp_mul(Z1_sqr, Z1),
  U2 = ?FP:fp_mul(X2, Z1_sqr),
  S2 = ?FP:fp_mul(Y2, Z1_cub),
  case X1 =:= U2 of
    true ->
      case Y1 =:= S2 of
        true -> g1_j_double({X1, Y1, Z1});
        false -> {1, 1, 0}
      end;
    false ->
      H = ?FP:fp_sub(U2, X1),
      HH = ?FP:fp_sqr(H),
      I = ?FP:fp_mul(4, HH),
      J = ?FP:fp_mul(H, I),
      R0 = ?FP:fp_sub(S2, Y1),
      R = ?FP:fp_add(R0, R0),
      V = ?FP:fp_mul(X1, I),
      X3 = ?FP:fp_sub(?FP:fp_sub(?FP:fp_sqr(R), J), ?FP:fp_add(V, V)),
      Y3 = ?FP:fp_sub(?FP:fp_mul(R, ?FP:fp_sub(V, X3)), ?FP:fp_mul(?FP:fp_add(Y1, Y1), J)),
      Z3 = ?FP:fp_mul(?FP:fp_add(Z1, Z1), H),
      {X3, Y3, Z3}
  end.

-spec g1_j_add(g1_jacobian(), g1_jacobian()) -> g1_jacobian().
g1_j_add({_X1, _Y1, 0}, P2) ->
  P2;
g1_j_add(P1, {_X2, _Y2, 0}) ->
  P1;
g1_j_add({X1, Y1, Z1}, {X2, Y2, 1}) ->
  g1_j_add_affine({X1, Y1, Z1}, {X2, Y2});
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
      R0 = ?FP:fp_sub(S2, S1),
      R = ?FP:fp_add(R0, R0),
      V = ?FP:fp_mul(U1, I),
      X3 = ?FP:fp_sub(?FP:fp_sub(?FP:fp_sqr(R), J), ?FP:fp_add(V, V)),
      Y3 = ?FP:fp_sub(?FP:fp_mul(R, ?FP:fp_sub(V, X3)), ?FP:fp_mul(?FP:fp_add(S1, S1), J)),
      Z3_term = ?FP:fp_sub(?FP:fp_sub(?FP:fp_sqr(?FP:fp_add(Z1, Z2)), Z1_sqr), Z2_sqr),
      Z3 = ?FP:fp_mul(Z3_term, H),
      {X3, Y3, Z3}
  end.

-spec g1_j_scalar_mul(g1_jacobian(), pos_integer()) -> g1_jacobian().
g1_j_scalar_mul(P, K) ->
  Bits = integer_to_bits(K),
  g1_j_scalar_mul_loop(tl(Bits), P, P).

-spec g1_j_scalar_mul_loop([0 | 1], g1_jacobian(), g1_jacobian()) -> g1_jacobian().
g1_j_scalar_mul_loop([], _P, Acc) ->
  Acc;
g1_j_scalar_mul_loop([0 | Rest], P, Acc) ->
  g1_j_scalar_mul_loop(Rest, P, g1_j_double(Acc));
g1_j_scalar_mul_loop([1 | Rest], P, Acc) ->
  Dbl = g1_j_double(Acc),
  g1_j_scalar_mul_loop(Rest, P, g1_j_add(Dbl, P)).

%%%-------------------------------------------------------------------
%%% G1 Serialization (48 bytes compressed, 96 bytes uncompressed)
%%%-------------------------------------------------------------------

-spec g1_compress(g1_affine()) -> g1_compressed().
g1_compress(infinity) ->
  <<16#C0, 0:376>>;
g1_compress({X, Y}) ->
  SignBit =
    case Y > ?BLS12_381_P - Y of
      true -> 1;
      false -> 0
    end,
  TopByte = 16#80 bor (SignBit bsl 5) bor (X bsr 376),
  RemX = X band ((1 bsl 376) - 1),
  <<TopByte:8, RemX:376>>.

-spec g1_decompress(binary()) -> {ok, g1_affine()} | {error, term()}.
g1_decompress(<<B0:8, RemX:376>>) ->
  IsCompressed = (B0 band 16#80) =/= 0,
  IsInfinity = (B0 band 16#40) =/= 0,
  SignBit = (B0 band 16#20) bsr 5,
  case IsCompressed of
    false ->
      {error, not_compressed};
    true ->
      case IsInfinity of
        true ->
          case (B0 band 16#3F) =:= 0 andalso RemX =:= 0 of
            true -> {ok, infinity};
            false -> {error, invalid_infinity_encoding}
          end;
        false ->
          TopX = B0 band 16#1F,
          X = (TopX bsl 376) bor RemX,
          case X < ?BLS12_381_P of
            false ->
              {error, coordinate_out_of_range};
            true ->
              Y2 = ?FP:fp_add(?FP:fp_mul(?FP:fp_sqr(X), X), ?BLS12_381_B),
              case ?FP:fp_sqrt(Y2) of
                error ->
                  {error, point_not_on_curve};
                {ok, Y} ->
                  YGreater = Y > ?BLS12_381_P - Y,
                  ChosenY =
                    case (YGreater andalso SignBit =:= 1) orelse (not YGreater andalso SignBit =:= 0) of
                      true -> Y;
                      false -> ?FP:fp_neg(Y)
                    end,
                  Point = {X, ChosenY},
                  case g1_is_in_subgroup(Point) of
                    true -> {ok, Point};
                    false -> {error, point_not_in_subgroup}
                  end
              end
          end
      end
  end;
g1_decompress(_) ->
  {error, invalid_encoding}.

-spec g1_serialize_uncompressed(g1_affine()) -> g1_uncompressed().
g1_serialize_uncompressed(infinity) ->
  <<16#40, 0:760>>;
g1_serialize_uncompressed({X, Y}) ->
  TopByte = X bsr 376,
  RemX = X band ((1 bsl 376) - 1),
  <<TopByte:8, RemX:376, Y:384>>.

-spec g1_deserialize_uncompressed(binary()) -> {ok, g1_affine()} | {error, term()}.
g1_deserialize_uncompressed(<<B0:8, RemX:376, Y:384>>) ->
  IsCompressed = (B0 band 16#80) =/= 0,
  IsInfinity = (B0 band 16#40) =/= 0,
  case IsCompressed of
    true ->
      {error, unexpected_compressed};
    false ->
      case IsInfinity of
        true ->
          case (B0 band 16#3F) =:= 0 andalso RemX =:= 0 andalso Y =:= 0 of
            true -> {ok, infinity};
            false -> {error, invalid_infinity_encoding}
          end;
        false ->
          TopX = B0 band 16#1F,
          X = (TopX bsl 376) bor RemX,
          case X < ?BLS12_381_P andalso Y < ?BLS12_381_P of
            false ->
              {error, coordinate_out_of_range};
            true ->
              Point = {X, Y},
              case g1_on_curve(Point) of
                false ->
                  {error, point_not_on_curve};
                true ->
                  case g1_is_in_subgroup(Point) of
                    true -> {ok, Point};
                    false -> {error, point_not_in_subgroup}
                  end
              end
          end
      end
  end;
g1_deserialize_uncompressed(_) ->
  {error, invalid_encoding}.

%%%-------------------------------------------------------------------
%%% G2 Operations (over Fp2)
%%%-------------------------------------------------------------------

-spec g2_generator() -> g2_affine().
g2_generator() ->
  {{?BLS12_381_G2_X0, ?BLS12_381_G2_X1}, {?BLS12_381_G2_Y0, ?BLS12_381_G2_Y1}}.

-spec g2_infinity() -> g2_affine().
g2_infinity() ->
  infinity.

-spec g2_is_zero(g2_affine() | g2_jacobian()) -> boolean().
g2_is_zero(infinity) -> true;
g2_is_zero({_X, _Y, {0, 0}}) -> true;
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
  X0 < ?BLS12_381_P,
  X1 >= 0,
  X1 < ?BLS12_381_P,
  Y0 >= 0,
  Y0 < ?BLS12_381_P,
  Y1 >= 0,
  Y1 < ?BLS12_381_P
->
  %% y^2 = x^3 + 4(1 + u) mod p
  X = {X0, X1},
  Y = {Y0, Y1},
  Left = ?FP:fp2_sqr(Y),
  Right = ?FP:fp2_add(?FP:fp2_mul(?FP:fp2_sqr(X), X), {4, 4}),
  Left =:= Right;
g2_on_curve(_) ->
  false.

-spec g2_is_in_subgroup(g2_affine()) -> boolean().
g2_is_in_subgroup(infinity) -> true;
g2_is_in_subgroup(Q) -> g2_on_curve(Q) andalso g2_is_zero(g2_scalar_mul(Q, ?BLS12_381_R)).

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
g2_scalar_mul(Q, K) when is_integer(K) ->
  ModK = ((K rem ?BLS12_381_R) + ?BLS12_381_R) rem ?BLS12_381_R,
  case ModK of
    0 ->
      infinity;
    _ ->
      J = g2_to_jacobian(Q),
      ResJ = g2_j_scalar_mul(J, ModK),
      g2_from_jacobian(ResJ)
  end.

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

-spec g2_j_add_affine(g2_jacobian(), {fp2(), fp2()}) -> g2_jacobian().
g2_j_add_affine({_X1, _Y1, {0, 0}}, {X2, Y2}) ->
  {X2, Y2, ?FP:fp2_one()};
g2_j_add_affine({X1, Y1, Z1}, {X2, Y2}) ->
  Z1_sqr = ?FP:fp2_sqr(Z1),
  Z1_cub = ?FP:fp2_mul(Z1_sqr, Z1),
  U2 = ?FP:fp2_mul(X2, Z1_sqr),
  S2 = ?FP:fp2_mul(Y2, Z1_cub),
  case X1 =:= U2 of
    true ->
      case Y1 =:= S2 of
        true -> g2_j_double({X1, Y1, Z1});
        false -> {?FP:fp2_one(), ?FP:fp2_one(), ?FP:fp2_zero()}
      end;
    false ->
      H = ?FP:fp2_sub(U2, X1),
      HH = ?FP:fp2_sqr(H),
      I = ?FP:fp2_mul_fp(HH, 4),
      J = ?FP:fp2_mul(H, I),
      R0 = ?FP:fp2_sub(S2, Y1),
      R = ?FP:fp2_add(R0, R0),
      V = ?FP:fp2_mul(X1, I),
      X3 = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(R), J), ?FP:fp2_add(V, V)),
      Y3 = ?FP:fp2_sub(?FP:fp2_mul(R, ?FP:fp2_sub(V, X3)), ?FP:fp2_mul(?FP:fp2_add(Y1, Y1), J)),
      Z3 = ?FP:fp2_mul(?FP:fp2_add(Z1, Z1), H),
      {X3, Y3, Z3}
  end.

-spec g2_j_add(g2_jacobian(), g2_jacobian()) -> g2_jacobian().
g2_j_add({_X1, _Y1, {0, 0}}, P2) ->
  P2;
g2_j_add(P1, {_X2, _Y2, {0, 0}}) ->
  P1;
g2_j_add({X1, Y1, Z1}, {X2, Y2, {1, 0}}) ->
  g2_j_add_affine({X1, Y1, Z1}, {X2, Y2});
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
      R0 = ?FP:fp2_sub(S2, S1),
      R = ?FP:fp2_add(R0, R0),
      V = ?FP:fp2_mul(U1, I),
      X3 = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(R), J), ?FP:fp2_add(V, V)),
      Y3 = ?FP:fp2_sub(?FP:fp2_mul(R, ?FP:fp2_sub(V, X3)), ?FP:fp2_mul(?FP:fp2_add(S1, S1), J)),
      Z3_term = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(?FP:fp2_add(Z1, Z2)), Z1_sqr), Z2_sqr),
      Z3 = ?FP:fp2_mul(Z3_term, H),
      {X3, Y3, Z3}
  end.

-spec g2_j_scalar_mul(g2_jacobian(), pos_integer()) -> g2_jacobian().
g2_j_scalar_mul(Q, K) ->
  Bits = integer_to_bits(K),
  g2_j_scalar_mul_loop(tl(Bits), Q, Q).

-spec g2_j_scalar_mul_loop([0 | 1], g2_jacobian(), g2_jacobian()) -> g2_jacobian().
g2_j_scalar_mul_loop([], _Q, Acc) ->
  Acc;
g2_j_scalar_mul_loop([0 | Rest], Q, Acc) ->
  g2_j_scalar_mul_loop(Rest, Q, g2_j_double(Acc));
g2_j_scalar_mul_loop([1 | Rest], Q, Acc) ->
  Dbl = g2_j_double(Acc),
  g2_j_scalar_mul_loop(Rest, Q, g2_j_add(Dbl, Q)).

%%%-------------------------------------------------------------------
%%% G2 Serialization (96 bytes compressed, 192 bytes uncompressed)
%%% In Fp2, x = x0 + x1*u. Serialization writes x1 first, then x0.
%%%-------------------------------------------------------------------

-spec g2_compress(g2_affine()) -> g2_compressed().
g2_compress(infinity) ->
  <<16#C0, 0:760>>;
g2_compress({{X0, X1}, {Y0, Y1}}) ->
  SignBit =
    case fp2_is_lexicographically_largest({Y0, Y1}) of
      true -> 1;
      false -> 0
    end,
  TopByte = 16#80 bor (SignBit bsl 5) bor (X1 bsr 376),
  RemX1 = X1 band ((1 bsl 376) - 1),
  <<TopByte:8, RemX1:376, X0:384>>.

-spec g2_decompress(binary()) -> {ok, g2_affine()} | {error, term()}.
g2_decompress(<<B0:8, RemX1:376, X0:384>>) ->
  IsCompressed = (B0 band 16#80) =/= 0,
  IsInfinity = (B0 band 16#40) =/= 0,
  SignBit = (B0 band 16#20) bsr 5,
  case IsCompressed of
    false ->
      {error, not_compressed};
    true ->
      case IsInfinity of
        true ->
          case (B0 band 16#3F) =:= 0 andalso RemX1 =:= 0 andalso X0 =:= 0 of
            true -> {ok, infinity};
            false -> {error, invalid_infinity_encoding}
          end;
        false ->
          TopX1 = B0 band 16#1F,
          X1 = (TopX1 bsl 376) bor RemX1,
          case X0 < ?BLS12_381_P andalso X1 < ?BLS12_381_P of
            false ->
              {error, coordinate_out_of_range};
            true ->
              X = {X0, X1},
              Y2 = ?FP:fp2_add(?FP:fp2_mul(?FP:fp2_sqr(X), X), {4, 4}),
              case ?FP:fp2_sqrt(Y2) of
                error ->
                  {error, point_not_on_curve};
                {ok, Y} ->
                  YGreater = fp2_is_lexicographically_largest(Y),
                  ChosenY =
                    case (YGreater andalso SignBit =:= 1) orelse (not YGreater andalso SignBit =:= 0) of
                      true -> Y;
                      false -> ?FP:fp2_neg(Y)
                    end,
                  Point = {X, ChosenY},
                  case g2_is_in_subgroup(Point) of
                    true -> {ok, Point};
                    false -> {error, point_not_in_subgroup}
                  end
              end
          end
      end
  end;
g2_decompress(_) ->
  {error, invalid_encoding}.

-spec g2_serialize_uncompressed(g2_affine()) -> g2_uncompressed().
g2_serialize_uncompressed(infinity) ->
  <<16#40, 0:1528>>;
g2_serialize_uncompressed({{X0, X1}, {Y0, Y1}}) ->
  TopByte = X1 bsr 376,
  RemX1 = X1 band ((1 bsl 376) - 1),
  <<TopByte:8, RemX1:376, X0:384, Y1:384, Y0:384>>.

-spec g2_deserialize_uncompressed(binary()) -> {ok, g2_affine()} | {error, term()}.
g2_deserialize_uncompressed(<<B0:8, RemX1:376, X0:384, Y1:384, Y0:384>>) ->
  IsCompressed = (B0 band 16#80) =/= 0,
  IsInfinity = (B0 band 16#40) =/= 0,
  case IsCompressed of
    true ->
      {error, unexpected_compressed};
    false ->
      case IsInfinity of
        true ->
          case
            (B0 band 16#3F) =:= 0 andalso RemX1 =:= 0 andalso X0 =:= 0 andalso Y1 =:= 0 andalso Y0 =:= 0
          of
            true -> {ok, infinity};
            false -> {error, invalid_infinity_encoding}
          end;
        false ->
          TopX1 = B0 band 16#1F,
          X1 = (TopX1 bsl 376) bor RemX1,
          case
            X0 < ?BLS12_381_P andalso X1 < ?BLS12_381_P andalso Y0 < ?BLS12_381_P andalso
              Y1 < ?BLS12_381_P
          of
            false ->
              {error, coordinate_out_of_range};
            true ->
              Point = {{X0, X1}, {Y0, Y1}},
              case g2_on_curve(Point) of
                false ->
                  {error, point_not_on_curve};
                true ->
                  case g2_is_in_subgroup(Point) of
                    true -> {ok, Point};
                    false -> {error, point_not_in_subgroup}
                  end
              end
          end
      end
  end;
g2_deserialize_uncompressed(_) ->
  {error, invalid_encoding}.

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

-spec fp2_is_lexicographically_largest(fp2()) -> boolean().
fp2_is_lexicographically_largest({Y0, Y1}) ->
  case Y1 > ?BLS12_381_P - Y1 of
    true ->
      true;
    false ->
      case Y1 =:= 0 of
        true -> Y0 > ?BLS12_381_P - Y0;
        false -> false
      end
  end.

-spec integer_to_bits(pos_integer()) -> [0 | 1].
integer_to_bits(N) ->
  integer_to_bits(N, []).

-spec integer_to_bits(non_neg_integer(), [0 | 1]) -> [0 | 1].
integer_to_bits(0, Acc) -> Acc;
integer_to_bits(N, Acc) -> integer_to_bits(N bsr 1, [(N band 1) | Acc]).

%%%-------------------------------------------------------------------
%%% Pairing Operations
%%%-------------------------------------------------------------------

-spec pairing(g1_affine(), g2_affine()) -> ?FP:fp12().
pairing(P, Q) ->
  ecu_bls12_381_pairing:pairing(P, Q).

-spec pairing_check([{g1_affine(), g2_affine()}]) -> boolean().
pairing_check(Pairs) ->
  ecu_bls12_381_pairing:pairing_check(Pairs).

-spec pairing_check(g1_affine(), g2_affine(), g1_affine(), g2_affine()) -> boolean().
pairing_check(P1, Q1, P2, Q2) ->
  ecu_bls12_381_pairing:pairing_check(P1, Q1, P2, Q2).

%%%-------------------------------------------------------------------
%%% Hash-to-Curve Operations (RFC 9380)
%%%-------------------------------------------------------------------

-spec g1_hash_to_curve(binary()) -> g1_affine().
g1_hash_to_curve(Msg) ->
  ecu_bls12_381_h2c:hash_to_curve_g1(Msg).

-spec g1_hash_to_curve(binary(), binary()) -> g1_affine().
g1_hash_to_curve(Msg, DST) ->
  ecu_bls12_381_h2c:hash_to_curve_g1(Msg, DST).

-spec g1_hash_to_curve(binary(), binary(), binary()) -> g1_affine().
g1_hash_to_curve(Msg, DST, Aug) ->
  ecu_bls12_381_h2c:hash_to_curve_g1(Msg, DST, Aug).

-spec g1_encode_to_curve(binary()) -> g1_affine().
g1_encode_to_curve(Msg) ->
  ecu_bls12_381_h2c:encode_to_curve_g1(Msg).

-spec g1_encode_to_curve(binary(), binary()) -> g1_affine().
g1_encode_to_curve(Msg, DST) ->
  ecu_bls12_381_h2c:encode_to_curve_g1(Msg, DST).

-spec g1_encode_to_curve(binary(), binary(), binary()) -> g1_affine().
g1_encode_to_curve(Msg, DST, Aug) ->
  ecu_bls12_381_h2c:encode_to_curve_g1(Msg, DST, Aug).

-spec g2_hash_to_curve(binary()) -> g2_affine().
g2_hash_to_curve(Msg) ->
  ecu_bls12_381_h2c:hash_to_curve_g2(Msg).

-spec g2_hash_to_curve(binary(), binary()) -> g2_affine().
g2_hash_to_curve(Msg, DST) ->
  ecu_bls12_381_h2c:hash_to_curve_g2(Msg, DST).

-spec g2_hash_to_curve(binary(), binary(), binary()) -> g2_affine().
g2_hash_to_curve(Msg, DST, Aug) ->
  ecu_bls12_381_h2c:hash_to_curve_g2(Msg, DST, Aug).

-spec g2_encode_to_curve(binary()) -> g2_affine().
g2_encode_to_curve(Msg) ->
  ecu_bls12_381_h2c:encode_to_curve_g2(Msg).

-spec g2_encode_to_curve(binary(), binary()) -> g2_affine().
g2_encode_to_curve(Msg, DST) ->
  ecu_bls12_381_h2c:encode_to_curve_g2(Msg, DST).

-spec g2_encode_to_curve(binary(), binary(), binary()) -> g2_affine().
g2_encode_to_curve(Msg, DST, Aug) ->
  ecu_bls12_381_h2c:encode_to_curve_g2(Msg, DST, Aug).
