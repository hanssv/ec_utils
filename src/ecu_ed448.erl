%%% File        : ecu_ed448.erl
%%% Description : Pure Erlang Ed448 (Curve448 / Goldilocks) elliptic curve arithmetic
-module(ecu_ed448).

-typing([eqwalizer]).

-include("ecu_ed448.hrl").

-type pt_affine() :: {field_elem(), field_elem()}. %% {X, Y}
-type pt_projective() :: {field_elem(), field_elem(), field_elem()}. %% {X, Y, Z}
-type pt_compressed() :: <<_:456>>. %% Y coord + odd/even X (57 bytes)

-type pt() :: pt_affine() | pt_projective() | pt_compressed().

-type scalar_elem() :: 0..(?N-1).
-type scalar() :: non_neg_integer() | <<_:456>>.
-type field_elem() :: non_neg_integer().

-define(ADD(A, B), ((A + B) rem ?P)).
-define(MUL(A, B), ((A * B) rem ?P)).
-define(SUB(A, B), ((A - B + ?P) rem ?P)).
-define(DIV(A, B), f_div(A, B)).

-export_type([pt/0, pt_affine/0, pt_projective/0, pt_compressed/0,
              scalar/0, scalar_elem/0, field_elem/0]).

-export([on_curve/1, p/0, n/0, pt_eq/2,
         scalar_mul/2, scalar_mul_base/1, scalar_mul_dual_base/3,
         scalar_mul_noclamp/2, scalar_mul_base_noclamp/1,
         multi_scalar_mul/1,
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
pt_eq({X1, Y1, Z1}, {X2, Y2, Z2}) ->
  ?SUB(?MUL(X1, Z2), ?MUL(X2, Z1)) == 0
  andalso ?SUB(?MUL(Y1, Z2), ?MUL(Y2, Z1)) == 0;
pt_eq(P1, P2) ->
  pt_eq(to_projective(P1), to_projective(P2)).

-spec on_curve(pt()) -> boolean().
on_curve({X, Y}) when is_integer(X), is_integer(Y) ->
  X2 = ?MUL(X, X),
  Y2 = ?MUL(Y, Y),
  LHS = ?ADD(X2, Y2),
  RHS = ?ADD(1, ?MUL(?D, ?MUL(X2, Y2))),
  0 == ?SUB(LHS, RHS);
on_curve(P) ->
  on_curve(to_affine(P)).

-spec p() -> pos_integer().
p() -> ?P.

-spec n() -> pos_integer().
n() -> ?N.

-spec compress(P :: pt()) -> pt_compressed().
compress(<<_:57/binary>> = P) -> P;
compress({_, _, _} = P)       -> compress(to_affine(P));
compress({X, Y}) when is_integer(X), is_integer(Y) ->
  Sign = X band 1,
  EncY = <<Y:448/little>>,
  <<EncY/binary, (Sign bsl 7):8>>.

-spec decompress(pt_compressed()) -> pt_projective().
decompress(<<Y_bytes:56/binary, LastByte:8>>) ->
  case LastByte band 16#7f of
    0 ->
      X0 = LastByte bsr 7,
      <<Y:448/little>> = Y_bytes,
      case Y < ?P of
        false -> error(badarg);
        true ->
          X = xrecover(Y, X0),
          to_projective({X, Y})
      end;
    _ ->
      error(badarg)
  end;
decompress(_) ->
  error(badarg).

-spec is_small_order(Pt :: pt()) -> boolean().
is_small_order(P) ->
  P4 = p_dbl(p_dbl(P)),
  pt_eq(P4, {0, 1, 1}).

-spec p_neg(pt()) -> pt().
p_neg({X, Y}) when is_integer(X), is_integer(Y) -> {?SUB(0, X), Y};
p_neg({X, Y, Z}) when is_integer(X), is_integer(Y), is_integer(Z) -> {?SUB(0, X), Y, Z};
p_neg(P) -> p_neg(to_projective(P)).

-spec p_sub(pt(), pt()) -> pt_projective().
p_sub(P1, P2) -> p_add(P1, p_neg(P2)).

-spec p_add(pt(), pt()) -> pt_projective().
p_add({X1, Y1, Z1}, {X2, Y2, Z2})
  when is_integer(X1), is_integer(Y1), is_integer(Z1),
       is_integer(X2), is_integer(Y2), is_integer(Z2) ->
  A = ?MUL(Z1, Z2),
  B = ?MUL(A, A),
  C = ?MUL(X1, X2),
  D = ?MUL(Y1, Y2),
  E = ?MUL(?D, ?MUL(C, D)),
  F = ?SUB(B, E),
  G = ?ADD(B, E),
  H = ?MUL(?ADD(X1, Y1), ?ADD(X2, Y2)),
  X3 = ?MUL(?MUL(A, F), ?SUB(H, ?ADD(C, D))),
  Y3 = ?MUL(?MUL(A, G), ?SUB(D, C)),
  Z3 = ?MUL(F, G),
  {X3, Y3, Z3};
p_add(P1, P2) ->
  p_add(to_projective(P1), to_projective(P2)).

-spec p_dbl(pt()) -> pt_projective().
p_dbl({X1, Y1, Z1})
  when is_integer(X1), is_integer(Y1), is_integer(Z1) ->
  XY = ?ADD(X1, Y1),
  B = ?MUL(XY, XY),
  C = ?MUL(X1, X1),
  D = ?MUL(Y1, Y1),
  E = ?ADD(C, D),
  H = ?MUL(Z1, Z1),
  J = ?SUB(E, ?ADD(H, H)),
  X3 = ?MUL(?SUB(B, E), J),
  Y3 = ?MUL(E, ?SUB(C, D)),
  Z3 = ?MUL(E, J),
  {X3, Y3, Z3};
p_dbl(P) ->
  p_dbl(to_projective(P)).

-spec scalar_mul_base(Scalar :: scalar()) -> pt_projective().
scalar_mul_base(<<K:456/little>>) ->
  scalar_mul_base_comb(clamp(K));
scalar_mul_base(K) when is_integer(K), K >= 0 ->
  scalar_mul_base_comb(clamp(K)).

-spec scalar_mul(Scalar :: scalar(), Pt :: pt()) -> pt_projective().
scalar_mul(<<K:456/little>>, P) ->
  scalar_mul(K, P);
scalar_mul(K, P) when is_integer(K), K >= 0 ->
  scalar_mul_window(clamp(K), to_projective(P)).

-spec scalar_mul_base_noclamp(Scalar :: scalar()) -> pt_projective().
scalar_mul_base_noclamp(<<K:456/little>>) ->
  scalar_mul_base_comb(K);
scalar_mul_base_noclamp(K) when is_integer(K), K >= 0 ->
  scalar_mul_base_comb(K).

-spec scalar_mul_noclamp(Scalar :: scalar(), Pt :: pt()) -> pt_projective().
scalar_mul_noclamp(<<K:456/little>>, P) ->
  scalar_mul_noclamp(K, P);
scalar_mul_noclamp(K, P) when is_integer(K), K >= 0 ->
  scalar_mul_window(K, to_projective(P)).

-spec scalar_mul_dual_base(K1 :: scalar(), K2 :: scalar(), P2 :: pt()) -> pt_projective().
scalar_mul_dual_base(<<K1:456/little>>, K2, P2) ->
  scalar_mul_dual_base(K1, K2, P2);
scalar_mul_dual_base(K1, <<K2:456/little>>, P2) ->
  scalar_mul_dual_base(K1, K2, P2);
scalar_mul_dual_base(K1, K2, P2) when is_integer(K1), K1 >= 0, is_integer(K2), K2 >= 0 ->
  P1 = scalar_mul_base_comb(K1),
  P2_mul = scalar_mul_window(K2, to_projective(P2)),
  p_add(P1, P2_mul).

-spec multi_scalar_mul([{scalar() | <<_:128>>, pt()}]) -> pt_projective().
multi_scalar_mul([]) ->
  {0, 1, 1};
multi_scalar_mul(Pairs) ->
  PointsWithTables =
    lists:filtermap(
      fun({Scalar, Pt}) ->
        K = to_scalar_int(Scalar),
        case K of
          0 -> false;
          _ ->
            ProjPt = to_projective(Pt),
            Table = precompute_window_table(ProjPt),
            {true, {nibbles(<<K:456>>), Table}}
        end
      end,
      Pairs
    ),
  case PointsWithTables of
    [] ->
      {0, 1, 1};
    _ ->
      Slices = build_slices(114, PointsWithTables),
      multi_scalar_loop(Slices, {0, 1, 1})
  end.

-spec to_scalar_int(scalar() | <<_:128>>) -> non_neg_integer().
to_scalar_int(<<K:456/little>>) -> K rem ?N;
to_scalar_int(<<K:128/little>>) -> K rem ?N;
to_scalar_int(K) when is_integer(K), K >= 0 -> K rem ?N.

-spec nibbles(bitstring()) -> [0..15].
nibbles(<<>>) ->
  [];
nibbles(<<W:4, Rest/bitstring>>) ->
  [W | nibbles(Rest)].

-spec build_slices(non_neg_integer(), [{[0..15], dynamic()}]) -> [[dynamic()]].
build_slices(0, _Points) ->
  [];
build_slices(StepCount, Points) ->
  {SlicePoints, NextPoints} = collect_slice(Points, [], []),
  [SlicePoints | build_slices(StepCount - 1, NextPoints)].

-spec collect_slice([{[0..15], dynamic()}], [dynamic()], [{[0..15], dynamic()}]) ->
    {[dynamic()], [{[0..15], dynamic()}]}.
collect_slice([], SliceAcc, NextAcc) ->
  {SliceAcc, NextAcc};
collect_slice([{[], _Table} | _], SliceAcc, NextAcc) ->
  {SliceAcc, NextAcc};
collect_slice([{ [0 | Rest], Table } | More], SliceAcc, NextAcc) ->
  collect_slice(More, SliceAcc, [{Rest, Table} | NextAcc]);
collect_slice([{ [W | Rest], Table } | More], SliceAcc, NextAcc) ->
  Pt = element(W + 1, Table),
  collect_slice(More, [Pt | SliceAcc], [{Rest, Table} | NextAcc]).

-spec multi_scalar_loop([[dynamic()]], pt_projective()) -> pt_projective().
multi_scalar_loop([], Acc) ->
  Acc;
multi_scalar_loop([Slice | RestSlices], Acc) ->
  D4 = case Acc of
         {0, 1, 1} -> {0, 1, 1};
         _         -> dbl4(Acc)
       end,
  NewAcc = lists:foldl(fun(Pt, CurAcc) ->
                         case CurAcc of
                           {0, 1, 1} -> Pt;
                           _         -> p_add(CurAcc, Pt)
                         end
                       end, D4, Slice),
  multi_scalar_loop(RestSlices, NewAcc).

-spec to_projective(pt()) -> pt_projective().
to_projective({_, _, _} = P)       -> P;
to_projective(<<_:57/binary>> = P) -> decompress(P);
to_projective({X, Y})              -> {X, Y, 1}.

-spec to_affine(pt()) -> pt_affine().
to_affine({_, _} = P) -> P;
to_affine(<<_:57/binary>> = P) -> to_affine(decompress(P));
to_affine({X, Y, Z}) ->
  ZInv = f_inv(Z),
  {?MUL(X, ZInv), ?MUL(Y, ZInv)}.

-spec f_pow(field_elem(), non_neg_integer()) -> field_elem().
f_pow(A, B) when is_integer(A), is_integer(B), B >= 0 ->
  ecu_misc:exp_mod(A, B, ?P).

%% Arithmetics in prime field P
-spec f_add(field_elem(), field_elem()) -> field_elem().
f_add(A, B) when is_integer(A), is_integer(B) -> (A + B) rem ?P.

-spec f_mul(field_elem(), field_elem()) -> field_elem().
f_mul(A, B) when is_integer(A), is_integer(B) -> (A * B) rem ?P.

-spec f_sub(field_elem(), field_elem()) -> field_elem().
f_sub(A, B) when is_integer(A), is_integer(B) -> (A - B + ?P) rem ?P.

-spec f_div(field_elem(), field_elem()) -> field_elem().
f_div(A, B) when is_integer(A), is_integer(B) -> f_mul(A, f_inv(B)).

-spec f_inv(field_elem()) -> field_elem().
f_inv(A) when is_integer(A) ->
  f_pow(A, ?P - 2).

%% Arithmetics in curve group order N
-spec s_add(<<_:456>>, <<_:456>>) -> <<_:456>>.
s_add(<<A:456/little>>, <<B:456/little>>) -> <<((A + B) rem ?N):456/little>>.

-spec s_mul(<<_:456>>, <<_:456>>) -> <<_:456>>.
s_mul(<<A:456/little>>, <<B:456/little>>) -> <<((A * B) rem ?N):456/little>>.

-spec s_sub(<<_:456>>, <<_:456>>) -> <<_:456>>.
s_sub(<<A:456/little>>, <<B:456/little>>) -> <<((A - B + ?N) rem ?N):456/little>>.

-spec s_div(<<_:456>>, <<_:456>>) -> <<_:456>>.
s_div(A, B) when is_binary(A), is_binary(B) -> s_mul(A, s_inv(B)).

-spec s_inv(<<_:456>>) -> <<_:456>>.
s_inv(<<A:456/little>>) ->
  case A rem ?N of
    0 -> error(badarg);
    A_red ->
      case ecu_misc:eea(A_red, ?N) of
        {1, S, _T} -> <<((S + ?N) rem ?N):456/little>>;
        _ -> error(badarg)
      end
  end.

-spec scalar_reduce(<<_:912>> | binary() | non_neg_integer()) -> <<_:456>>.
scalar_reduce(<<S:912/little>>) ->
  <<(S rem ?N):456/little>>;
scalar_reduce(Bin) when is_binary(Bin) ->
  Size = byte_size(Bin) * 8,
  <<S:Size/little>> = Bin,
  <<(S rem ?N):456/little>>;
scalar_reduce(S) when is_integer(S), S >= 0 ->
  <<(S rem ?N):456/little>>.

%% --- internal functions
-spec scalar_mul_(non_neg_integer(), pt_projective()) -> pt_projective().
scalar_mul_(0, _P) -> {0, 1, 1};
scalar_mul_(1, P)  -> P;
scalar_mul_(K, P) ->
  case K rem 2 of
    0 -> scalar_mul_(K div 2, p_dbl(P));
    1 -> p_add(P, scalar_mul_(K - 1, P))
  end.

-spec scalar_mul_window(non_neg_integer(), pt_projective()) -> pt_projective().
scalar_mul_window(0, _P) ->
  {0, 1, 1};
scalar_mul_window(K, P) ->
  case K rem ?N of
    0 ->
      {0, 1, 1};
    RedK ->
      Table = precompute_window_table(P),
      <<W0:4, Rest/bitstring>> = <<RedK:456>>,
      InitialAcc = element(W0 + 1, Table),
      window_loop(Rest, Table, InitialAcc)
  end.

-spec window_loop(bitstring(), dynamic(), dynamic()) -> pt_projective().
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
          {0, 1, 1} -> Pt;
          _         -> p_add(D4, Pt)
        end
    end,
  window_loop(Rest, Table, NewAcc).

-spec precompute_window_table(pt_projective()) -> dynamic().
precompute_window_table(P) ->
  list_to_tuple(build_window_multiples(0, P, {0, 1, 1})).

-spec build_window_multiples(non_neg_integer(), pt_projective(), pt_projective()) -> [pt_projective()].
build_window_multiples(16, _P, _Acc) ->
  [];
build_window_multiples(0, P, Acc) ->
  [Acc | build_window_multiples(1, P, P)];
build_window_multiples(W, P, Acc) ->
  [Acc | build_window_multiples(W + 1, P, p_add(Acc, P))].

-spec scalar_mul_base_comb(non_neg_integer()) -> pt_projective().
scalar_mul_base_comb(0) ->
  {0, 1, 1};
scalar_mul_base_comb(K) ->
  RedK = K rem ?N,
  case RedK of
    0 -> {0, 1, 1};
    _ ->
      Table = get_base_comb(),
      mul_comb(RedK, 1, Table, {0, 1, 1})
  end.

-spec mul_comb(non_neg_integer(), pos_integer(), dynamic(), pt_projective()) -> pt_projective().
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
          {0, 1, 1} -> Pt;
          _         -> p_add(Acc, Pt)
        end
    end,
  mul_comb(NextK, I + 1, Table, NextAcc).

-spec init() -> ok.
init() ->
  Table = build_base_comb(),
  persistent_term:put({?MODULE, base_comb}, Table),
  ok.

-spec get_base_comb() -> dynamic().
get_base_comb() ->
  persistent_term:get({?MODULE, base_comb}).

-spec build_base_comb() -> dynamic().
build_base_comb() ->
  %% 114 windows, each with 16 multiples (0..15) of 16^i * B
  list_to_tuple(build_windows(0, ?GP)).

-spec build_windows(non_neg_integer(), pt_projective()) -> [tuple()].
build_windows(114, _CurrentBase) ->
  [];
build_windows(I, CurrentBase) ->
  Multiples = list_to_tuple(build_multiples(0, CurrentBase)),
  NextBase = dbl4(CurrentBase),
  [Multiples | build_windows(I + 1, NextBase)].

-spec dbl4(pt_projective()) -> pt_projective().
dbl4(P) ->
  p_dbl(p_dbl(p_dbl(p_dbl(P)))).

-spec build_multiples(non_neg_integer(), pt_projective()) -> [pt_projective()].
build_multiples(16, _Base) ->
  [];
build_multiples(0, Base) ->
  [{0, 1, 1} | build_multiples(1, Base)];
build_multiples(W, Base) ->
  Pt = scalar_mul_(W, Base),
  [Pt | build_multiples(W + 1, Base)].

-spec clamp(non_neg_integer()) -> non_neg_integer().
clamp(K) ->
  K1 = K band (bnot 3),
  K2 = K1 bor (1 bsl 447),
  K2 band ((1 bsl 448) - 1).

-spec xrecover(field_elem(), 0..1) -> field_elem().
xrecover(Y, X0) ->
  Y2 = ?MUL(Y, Y),
  case ?SUB(Y2, 1) of
    0 ->
      case X0 of
        0 -> 0;
        1 -> error(badarg)
      end;
    U ->
      V = ?SUB(?MUL(?D, Y2), 1),
      case V of
        0 -> error(badarg);
        _ ->
          UdivV = ?DIV(U, V),
          X_cand = f_pow(UdivV, ?PPLUS1DIV4),
          case ?MUL(V, ?MUL(X_cand, X_cand)) == U of
            false -> error(badarg);
            true ->
              case X_cand rem 2 == X0 of
                true -> X_cand;
                false ->
                  case X_cand == 0 of
                    true  -> error(badarg);
                    false -> ?P - X_cand
                  end
              end
          end
      end
  end.
