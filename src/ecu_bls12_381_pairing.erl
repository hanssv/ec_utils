%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang optimal Ate pairing engine for BLS12-381:
%%%   - Line evaluation (tangent and chord lines)
%%%   - Miller loop over x = -0xd201000000010000
%%%   - Multi-pairing accumulation
%%%   - Final exponentiation: easy part f^((p^6 - 1)(p^2 + 1)) and hard part
%%%   - Pairing verification: prod_i e(P_i, Q_i) == 1
%%%
%%% Reference:
%%%   - draft-irtf-cfrg-pairing-friendly-curves:
%%%     https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves
%%%   - Zcash BLS12-381 specification:
%%%     https://github.com/zkcrypto/bls12_381
%%%   - blst (Supranational):
%%%     https://github.com/supranational/blst
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_pairing).

-typing([eqwalizer]).

-include("ecu_bls12_381.hrl").

-define(FP, ecu_bls12_381_fp).
-define(BLS, ecu_bls12_381).

-type fp() :: non_neg_integer().
-type fp2() :: {fp(), fp()}.
-type fp6() :: {fp2(), fp2(), fp2()}.
-type fp12() :: {fp6(), fp6()}.

-type g1_affine() :: ?BLS:g1_affine().
-type g2_affine() :: ?BLS:g2_affine().
-type g2_jacobian() :: ?BLS:g2_jacobian().

-type line() :: {fp2(), fp2(), fp2()}.
-type px2() :: {fp(), fp()}.

-export([
  pairing/2,
  miller_loop/2,
  miller_loop/1,
  final_exp/1,
  pairing_check/1,
  pairing_check/4
]).

%% Internal line evaluations
-export([
  line_dbl/1,
  line_add/2,
  line_by_px2/2,
  line_to_fp12/1
]).

%%%-------------------------------------------------------------------
%%% Public API
%%%-------------------------------------------------------------------

%% Optimal Ate pairing e(P, Q) -> Fp12
-spec pairing(g1_affine(), g2_affine()) -> fp12().
pairing(infinity, _Q) -> ?FP:fp12_one();
pairing(_P, infinity) -> ?FP:fp12_one();
pairing(P, Q) -> final_exp(miller_loop(P, Q)).

%% Pairing check: verifies prod_i e(P_i, Q_i) == 1
-spec pairing_check([{g1_affine(), g2_affine()}]) -> boolean().
pairing_check([]) ->
  true;
pairing_check(Pairs) ->
  Ml = miller_loop(Pairs),
  final_exp(Ml) =:= ?FP:fp12_one().

-spec pairing_check(g1_affine(), g2_affine(), g1_affine(), g2_affine()) -> boolean().
pairing_check(P1, Q1, P2, Q2) ->
  pairing_check([{P1, Q1}, {P2, Q2}]).

%%%-------------------------------------------------------------------
%%% Miller Loop
%%%-------------------------------------------------------------------

-spec miller_loop(g1_affine(), g2_affine()) -> fp12().
miller_loop(infinity, _Q) ->
  ?FP:fp12_one();
miller_loop(_P, infinity) ->
  ?FP:fp12_one();
miller_loop({Px, Py}, {{Qx0, Qx1}, {Qy0, Qy1}}) ->
  Px2 = compute_px2(Px, Py),
  Q = {{Qx0, Qx1}, {Qy0, Qy1}},
  T0 = {{Qx0, Qx1}, {Qy0, Qy1}, ?FP:fp2_one()},

  %% First step: line_dbl (bit 62)
  {Line0, T1} = line_dbl(T0),
  Ret0 = line_to_fp12(line_by_px2(Line0, Px2)),

  %% Chain of add_n_dbl corresponding to distances between 1s in |x|:
  %% |x| = 0xd201000000010000
  {Ret1, T2} = add_n_dbl(Ret0, T1, Q, Px2, 2),
  {Ret2, T3} = add_n_dbl(Ret1, T2, Q, Px2, 3),
  {Ret3, T4} = add_n_dbl(Ret2, T3, Q, Px2, 9),
  {Ret4, T5} = add_n_dbl(Ret3, T4, Q, Px2, 32),
  {Ret5, _T6} = add_n_dbl(Ret4, T5, Q, Px2, 16),

  %% Account for x being negative
  ?FP:fp12_conj(Ret5).

-spec miller_loop([{g1_affine(), g2_affine()}]) -> fp12().
miller_loop(Pairs) ->
  %% Filter out pairs with point at infinity
  ValidPairs = [
    {P, Q}
   || {P, Q} <- Pairs,
    P =/= infinity,
    Q =/= infinity,
    not ?BLS:g1_is_zero(P),
    not ?BLS:g2_is_zero(Q)
  ],
  case ValidPairs of
    [] ->
      ?FP:fp12_one();
    _ ->
      multi_miller_loop(ValidPairs)
  end.

-spec multi_miller_loop([{g1_affine(), g2_affine()}]) -> fp12().
multi_miller_loop(Pairs) ->
  %% Prepare points: Px2 and initial T = Q
  Prepared = [
    begin
      {Px, Py} = P,
      Q_aff = {Qx, Qy} = Q,
      T = {Qx, Qy, ?FP:fp2_one()},
      Px2 = compute_px2(Px, Py),
      {T, Q_aff, Px2}
    end
   || {P, Q} <- Pairs
  ],

  %% First step: line_dbl on all pairs
  {Ret0, Ts1} = start_multi_dbl(Prepared),

  %% add_n_dbl across all pairs
  {Ret1, Ts2} = multi_add_n_dbl(Ret0, Ts1, 2),
  {Ret2, Ts3} = multi_add_n_dbl(Ret1, Ts2, 3),
  {Ret3, Ts4} = multi_add_n_dbl(Ret2, Ts3, 9),
  {Ret4, Ts5} = multi_add_n_dbl(Ret3, Ts4, 32),
  {Ret5, _Ts6} = multi_add_n_dbl(Ret4, Ts5, 16),

  %% Account for x being negative
  ?FP:fp12_conj(Ret5).

%%%-------------------------------------------------------------------
%%% Line Functions
%%%-------------------------------------------------------------------

-spec compute_px2(fp(), fp()) -> px2().
compute_px2(Px, Py) ->
  Px2_X = ?FP:fp_neg(?FP:fp_add(Px, Px)),
  Px2_Y = ?FP:fp_add(Py, Py),
  {Px2_X, Px2_Y}.

-spec line_by_px2(line(), px2()) -> line().
line_by_px2({L0, L1, L2}, {Px2_X, Px2_Y}) ->
  {
    L0,
    ?FP:fp2_mul_fp(L1, Px2_X),
    ?FP:fp2_mul_fp(L2, Px2_Y)
  }.

%% Convert {L0, L1, L2} into sparse Fp12 element:
%% {{L0, L1, 0}, {0, L2, 0}}
-spec line_to_fp12(line()) -> fp12().
line_to_fp12({L0, L1, L2}) ->
  Zero = ?FP:fp2_zero(),
  {
    {L0, L1, Zero},
    {Zero, L2, Zero}
  }.

%% Doubling step and tangent line evaluation
-spec line_dbl(g2_jacobian()) -> {line(), g2_jacobian()}.
line_dbl({X, Y, Z}) ->
  A = ?FP:fp2_sqr(X),
  B = ?FP:fp2_sqr(Y),
  ZZ = ?FP:fp2_sqr(Z),
  C = ?FP:fp2_sqr(B),

  XB = ?FP:fp2_add(X, B),
  D_sub = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(XB), A), C),
  D = ?FP:fp2_add(D_sub, D_sub),

  E = ?FP:fp2_add(?FP:fp2_add(A, A), A),
  F = ?FP:fp2_sqr(E),

  X3 = ?FP:fp2_sub(F, ?FP:fp2_add(D, D)),

  YZ = ?FP:fp2_add(Y, Z),
  Z3 = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(YZ), B), ZZ),

  C8 = ?FP:fp2_mul_fp(C, 8),
  Y3 = ?FP:fp2_sub(?FP:fp2_mul(E, ?FP:fp2_sub(D, X3)), C8),

  %% Line coefficients
  EX = ?FP:fp2_add(E, X),
  L0_sub = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(EX), A), F),
  B4 = ?FP:fp2_mul_fp(B, 4),
  L0 = ?FP:fp2_sub(L0_sub, B4),
  L1 = ?FP:fp2_mul(E, ZZ),
  L2 = ?FP:fp2_mul(Z3, ZZ),

  {{L0, L1, L2}, {X3, Y3, Z3}}.

%% Addition step and chord line evaluation
-spec line_add(g2_jacobian(), {fp2(), fp2()}) -> {line(), g2_jacobian()}.
line_add({X1, Y1, Z1}, {X2, Y2}) ->
  Z1Z1 = ?FP:fp2_sqr(Z1),
  U2 = ?FP:fp2_mul(X2, Z1Z1),

  S2 = ?FP:fp2_mul(?FP:fp2_mul(Y2, Z1), Z1Z1),

  H = ?FP:fp2_sub(U2, X1),
  HH = ?FP:fp2_sqr(H),
  I = ?FP:fp2_mul_fp(HH, 4),
  J = ?FP:fp2_mul(H, I),

  R_sub = ?FP:fp2_sub(S2, Y1),
  R = ?FP:fp2_add(R_sub, R_sub),

  V = ?FP:fp2_mul(X1, I),

  X3 = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(R), J), ?FP:fp2_add(V, V)),

  Y1J = ?FP:fp2_mul(Y1, J),
  Y3 = ?FP:fp2_sub(?FP:fp2_mul(R, ?FP:fp2_sub(V, X3)), ?FP:fp2_add(Y1J, Y1J)),

  Z1H = ?FP:fp2_add(Z1, H),
  Z3 = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_sqr(Z1H), Z1Z1), HH),

  %% Line coefficients
  RX2 = ?FP:fp2_mul(R, X2),
  Y2Z3 = ?FP:fp2_mul(Y2, Z3),
  L0_sub = ?FP:fp2_sub(RX2, Y2Z3),
  L0 = ?FP:fp2_add(L0_sub, L0_sub),
  L1 = R,
  L2 = Z3,

  {{L0, L1, L2}, {X3, Y3, Z3}}.

%%%-------------------------------------------------------------------
%%% Miller Loop Step Helpers
%%%-------------------------------------------------------------------

-spec add_n_dbl(fp12(), g2_jacobian(), {fp2(), fp2()}, px2(), non_neg_integer()) ->
  {fp12(), g2_jacobian()}.
add_n_dbl(Ret, T, Q, Px2, N) ->
  %% Chord line addition
  {LineAdd, T1} = line_add(T, Q),
  LineAddFp12 = line_to_fp12(line_by_px2(LineAdd, Px2)),
  Ret1 = ?FP:fp12_mul(Ret, LineAddFp12),
  dbl_loop(Ret1, T1, Px2, N).

-spec dbl_loop(fp12(), g2_jacobian(), px2(), non_neg_integer()) ->
  {fp12(), g2_jacobian()}.
dbl_loop(Ret, T, _Px2, 0) ->
  {Ret, T};
dbl_loop(Ret, T, Px2, N) ->
  {LineDbl, T1} = line_dbl(T),
  LineDblFp12 = line_to_fp12(line_by_px2(LineDbl, Px2)),
  Ret1 = ?FP:fp12_mul(?FP:fp12_sqr(Ret), LineDblFp12),
  dbl_loop(Ret1, T1, Px2, N - 1).

%%% Multi-pair helpers

-spec start_multi_dbl([{g2_jacobian(), {fp2(), fp2()}, px2()}]) ->
  {fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}]}.
start_multi_dbl([{T0, Q, Px2} | Rest]) ->
  {Line0, T1} = line_dbl(T0),
  InitRet = line_to_fp12(line_by_px2(Line0, Px2)),
  start_multi_dbl_loop(Rest, [{T1, Q, Px2}], InitRet).

-spec start_multi_dbl_loop(
  [{g2_jacobian(), {fp2(), fp2()}, px2()}],
  [{g2_jacobian(), {fp2(), fp2()}, px2()}],
  fp12()
) -> {fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}]}.
start_multi_dbl_loop([], AccT, Ret) ->
  {Ret, lists:reverse(AccT)};
start_multi_dbl_loop([{T0, Q, Px2} | Rest], AccT, Ret) ->
  {Line0, T1} = line_dbl(T0),
  LineFp12 = line_to_fp12(line_by_px2(Line0, Px2)),
  NewRet = ?FP:fp12_mul(Ret, LineFp12),
  start_multi_dbl_loop(Rest, [{T1, Q, Px2} | AccT], NewRet).

-spec multi_add_n_dbl(fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}], non_neg_integer()) ->
  {fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}]}.
multi_add_n_dbl(Ret, Triples, N) ->
  %% Add step across all pairs
  {Ret1, Triples1} = multi_line_add(Triples, Ret, []),
  multi_dbl_loop(Ret1, Triples1, N).

-spec multi_line_add(
  [{g2_jacobian(), {fp2(), fp2()}, px2()}],
  fp12(),
  [{g2_jacobian(), {fp2(), fp2()}, px2()}]
) -> {fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}]}.
multi_line_add([], Ret, Acc) ->
  {Ret, lists:reverse(Acc)};
multi_line_add([{T, Q, Px2} | Rest], Ret, Acc) ->
  {Line, T1} = line_add(T, Q),
  LineFp12 = line_to_fp12(line_by_px2(Line, Px2)),
  NewRet = ?FP:fp12_mul(Ret, LineFp12),
  multi_line_add(Rest, NewRet, [{T1, Q, Px2} | Acc]).

-spec multi_dbl_loop(fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}], non_neg_integer()) ->
  {fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}]}.
multi_dbl_loop(Ret, Triples, 0) ->
  {Ret, Triples};
multi_dbl_loop(Ret, Triples, N) ->
  SqrRet = ?FP:fp12_sqr(Ret),
  {NewRet, NewTriples} = multi_line_dbl(Triples, SqrRet, []),
  multi_dbl_loop(NewRet, NewTriples, N - 1).

-spec multi_line_dbl(
  [{g2_jacobian(), {fp2(), fp2()}, px2()}],
  fp12(),
  [{g2_jacobian(), {fp2(), fp2()}, px2()}]
) -> {fp12(), [{g2_jacobian(), {fp2(), fp2()}, px2()}]}.
multi_line_dbl([], Ret, Acc) ->
  {Ret, lists:reverse(Acc)};
multi_line_dbl([{T, Q, Px2} | Rest], Ret, Acc) ->
  {Line, T1} = line_dbl(T),
  LineFp12 = line_to_fp12(line_by_px2(Line, Px2)),
  NewRet = ?FP:fp12_mul(Ret, LineFp12),
  multi_line_dbl(Rest, NewRet, [{T1, Q, Px2} | Acc]).

%%%-------------------------------------------------------------------
%%% Final Exponentiation
%%% f^((p^12 - 1) / r)
%%%
%%% Easy part: f^((p^6 - 1) * (p^2 + 1))
%%% Hard part: f^((p^4 - p^2 + 1) / r)
%%% Algorithm per <zkcrypto>/pairing / blst / Fuentes-Castaneda et al.
%%%-------------------------------------------------------------------

-spec final_exp(fp12()) -> fp12().
final_exp(F) ->
  %% Easy part
  %% y1 = conjugate(F) = F^(p^6)
  Y1 = ?FP:fp12_conj(F),
  %% y2 = F^-1
  Y2 = ?FP:fp12_inv(F),
  %% ret = F^(p^6 - 1)
  Ret0 = ?FP:fp12_mul(Y1, Y2),
  %% y2 = ret^(p^2)
  Y2_p2 = ?FP:fp12_frobenius2(Ret0),
  %% ret = ret * ret^(p^2) = F^((p^6 - 1)(p^2 + 1))
  Ret = ?FP:fp12_mul(Ret0, Y2_p2),

  %% Hard part (in cyclotomic subgroup G_Phi12)
  Y0 = ?FP:fp12_cyclotomic_sqr(Ret),
  Y1_a = raise_to_z(Y0),
  Y2_a = raise_to_z_div_by_2(Y1_a),
  Y3_a = ?FP:fp12_conj(Ret),
  Y1_b = ?FP:fp12_mul(Y1_a, Y3_a),
  Y1_c = ?FP:fp12_conj(Y1_b),
  Y1_d = ?FP:fp12_mul(Y1_c, Y2_a),
  Y2_b = raise_to_z(Y1_d),
  Y3_b = raise_to_z(Y2_b),
  Y1_e = ?FP:fp12_conj(Y1_d),
  Y3_c = ?FP:fp12_mul(Y3_b, Y1_e),
  Y1_f = ?FP:fp12_conj(Y1_e),
  Y1_g = ?FP:fp12_frobenius3(Y1_f),
  Y2_c = ?FP:fp12_frobenius2(Y2_b),
  Y1_h = ?FP:fp12_mul(Y1_g, Y2_c),
  Y2_d = raise_to_z(Y3_c),
  Y2_e = ?FP:fp12_mul(Y2_d, Y0),
  Y2_f = ?FP:fp12_mul(Y2_e, Ret),
  Y1_i = ?FP:fp12_mul(Y1_h, Y2_f),
  Y2_g = ?FP:fp12_frobenius(Y3_c),
  ?FP:fp12_mul(Y1_i, Y2_g).

-spec raise_to_z(fp12()) -> fp12().
raise_to_z(A) ->
  ?FP:fp12_cyclotomic_sqr(raise_to_z_div_by_2(A)).

-spec raise_to_z_div_by_2(fp12()) -> fp12().
raise_to_z_div_by_2(A) ->
  %% Exponent |z| / 2 = 0x6900800000008000
  S0 = ?FP:fp12_cyclotomic_sqr(A),
  S1 = mul_n_sqr(S0, A, 2),
  S2 = mul_n_sqr(S1, A, 3),
  S3 = mul_n_sqr(S2, A, 9),
  S4 = mul_n_sqr(S3, A, 32),
  S5 = mul_n_sqr(S4, A, 15),
  %% Account for z being negative
  ?FP:fp12_conj(S5).

-spec mul_n_sqr(fp12(), fp12(), non_neg_integer()) -> fp12().
mul_n_sqr(Ret, A, N) ->
  Mul = ?FP:fp12_mul(Ret, A),
  sqr_n(Mul, N).

-spec sqr_n(fp12(), non_neg_integer()) -> fp12().
sqr_n(Ret, 0) -> Ret;
sqr_n(Ret, N) -> sqr_n(?FP:fp12_cyclotomic_sqr(Ret), N - 1).
