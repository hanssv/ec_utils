%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang optimal Ate pairing engine for BN254 (alt_bn128):
%%%   - Line evaluations (tangent and chord lines) in homogeneous coordinates
%%%   - Miller loop over ATE_LOOP_COUNT (NAF expansion of 6x + 2)
%%%   - Multi-pairing accumulation
%%%   - Final exponentiation (easy part and Fuentes-Castaneda hard part)
%%%   - Pairing verification: prod_i e(P_i, Q_i) == 1
%%%
%%% Reference:
%%%   - EIP-197: Optimal Ate pairing on alt_bn128
%%%   - arkworks ark-bn254 (models/bn/mod.rs, g2.rs)
%%%   - Beuchat et al.: "High-Speed Software Implementation of the Optimal Ate Pairing"
%%%   - Fuentes-Castaneda et al.: "Faster Hashing to G2"
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bn254_pairing).

-typing([eqwalizer]).

-include("ecu_bn254.hrl").

-define(FP, ecu_bn254_fp).
-define(BN, ecu_bn254).

-type fp() :: non_neg_integer().
-type fp2() :: {fp(), fp()}.
-type fp6() :: {fp2(), fp2(), fp2()}.
-type fp12() :: {fp6(), fp6()}.

-type g1_affine() :: ?BN:g1_affine().
-type g2_affine() :: ?BN:g2_affine().

-type ell_coeff() :: {fp2(), fp2(), fp2()}.

-export([
  pairing/2,
  miller_loop/1,
  miller_loop/2,
  final_exp/1,
  pairing_check/1,
  pairing_check/4
]).

%% Internal line evaluations
-export([
  twist_mul_by_q_x/0,
  twist_mul_by_q_y/0,
  mul_by_char/1,
  prepare_g2/1,
  ell/3
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
  case
    lists:all(
      fun({P, Q}) ->
        ?BN:g1_is_in_subgroup(P) andalso ?BN:g2_is_in_subgroup(Q)
      end,
      Pairs
    )
  of
    false ->
      false;
    true ->
      Ml = miller_loop(Pairs),
      final_exp(Ml) =:= ?FP:fp12_one()
  end.

-spec pairing_check(g1_affine(), g2_affine(), g1_affine(), g2_affine()) -> boolean().
pairing_check(P1, Q1, P2, Q2) ->
  pairing_check([{P1, Q1}, {P2, Q2}]).

%%%-------------------------------------------------------------------
%%% Miller Loop
%%%-------------------------------------------------------------------

-spec miller_loop(g1_affine(), g2_affine()) -> fp12().
miller_loop(infinity, _Q) -> ?FP:fp12_one();
miller_loop(_P, infinity) -> ?FP:fp12_one();
miller_loop(P, Q) -> miller_loop([{P, Q}]).

-spec miller_loop([{g1_affine(), g2_affine()}]) -> fp12().
miller_loop(Pairs) ->
  ValidPairs = [
    {P, Q}
   || {P, Q} <- Pairs,
    P =/= infinity,
    Q =/= infinity,
    not ?BN:g1_is_zero(P),
    not ?BN:g2_is_zero(Q)
  ],
  case ValidPairs of
    [] ->
      ?FP:fp12_one();
    _ ->
      multi_miller_loop(ValidPairs)
  end.

-spec multi_miller_loop([{g1_affine(), g2_affine()}]) -> fp12().
multi_miller_loop(Pairs) ->
  Prepared = [
    {P, prepare_g2(Q)}
   || {P, Q} <- Pairs
  ],
  LoopCount = ate_loop_count(),
  %% Loop from index 64 down to 1
  %% Initial f = 1
  F0 = ?FP:fp12_one(),
  {F_loop, PreparedRest} = miller_main_loop(64, LoopCount, F0, Prepared),
  %% Post-loop: Q1 and Q2 corrections
  F_q1 = lists:foldl(
    fun({P, [Coeff | _]}, Acc) ->
      ell(Acc, Coeff, P)
    end,
    F_loop,
    PreparedRest
  ),
  F_final = lists:foldl(
    fun({P, [_Coeff1, Coeff2 | _]}, Acc) ->
      ell(Acc, Coeff2, P)
    end,
    F_q1,
    PreparedRest
  ),
  F_final.

-spec miller_main_loop(
  non_neg_integer(),
  [integer()],
  fp12(),
  [{g1_affine(), [ell_coeff()]}]
) -> {fp12(), [{g1_affine(), [ell_coeff()]}]}.
miller_main_loop(0, _LoopCount, F, Prepared) ->
  {F, Prepared};
miller_main_loop(I, LoopCount, F, Prepared) ->
  %% If i != 64, f = f^2
  F_sqr =
    case I =:= 64 of
      true -> F;
      false -> ?FP:fp12_sqr(F)
    end,
  %% Multiply doubling line: next coeff
  {F_dbl, Prepared1} = lists:foldl(
    fun({P, [Coeff | Rest]}, {AccF, AccPrep}) ->
      AccF1 = ell(AccF, Coeff, P),
      {AccF1, [{P, Rest} | AccPrep]}
    end,
    {F_sqr, []},
    Prepared
  ),
  PreparedDbl = lists:reverse(Prepared1),
  %% Check bit at index I - 1 (1-based from 0 in ATE_LOOP_COUNT)
  Bit = lists:nth(I, LoopCount),
  case Bit =:= 1 orelse Bit =:= -1 of
    true ->
      {F_add, Prepared2} = lists:foldl(
        fun({P, [Coeff | Rest]}, {AccF, AccPrep}) ->
          AccF1 = ell(AccF, Coeff, P),
          {AccF1, [{P, Rest} | AccPrep]}
        end,
        {F_dbl, []},
        PreparedDbl
      ),
      miller_main_loop(I - 1, LoopCount, F_add, lists:reverse(Prepared2));
    false ->
      miller_main_loop(I - 1, LoopCount, F_dbl, PreparedDbl)
  end.

%%%-------------------------------------------------------------------
%%% Ell Evaluation
%%% For D-type twist:
%%% C0 = Coeff0 * P.y
%%% C3 = Coeff1 * P.x
%%% C4 = Coeff2
%%% Multiplies F by sparse element {{C0, 0, 0}, {C3, C4, 0}}
%%%-------------------------------------------------------------------

-spec ell(fp12(), ell_coeff(), g1_affine()) -> fp12().
ell(F, _Coeff, infinity) ->
  F;
ell(F, {Coeff0, Coeff1, Coeff2}, {Px, Py}) ->
  C0 = ?FP:fp2_mul_fp(Coeff0, Py),
  C3 = ?FP:fp2_mul_fp(Coeff1, Px),
  C4 = Coeff2,
  mul_by_034(F, C0, C3, C4).

-spec mul_by_034(fp12(), fp2(), fp2(), fp2()) -> fp12().
mul_by_034({F_C0, F_C1}, C0, C3, C4) ->
  %% A = F_C0 * C0 = {c0*C0, c1*C0, c2*C0}
  {F_C00, F_C01, F_C02} = F_C0,
  A0 = ?FP:fp2_mul(F_C00, C0),
  A1 = ?FP:fp2_mul(F_C01, C0),
  A2 = ?FP:fp2_mul(F_C02, C0),
  A = {A0, A1, A2},
  %% B = F_C1 * {C3, C4, 0}
  B = fp6_mul_01(F_C1, C3, C4),
  %% E = (F_C0 + F_C1) * {C0 + C3, C4, 0}
  C0_plus_C3 = ?FP:fp2_add(C0, C3),
  E = fp6_mul_01(?FP:fp6_add(F_C0, F_C1), C0_plus_C3, C4),
  %% Out_C1 = E - (A + B)
  Out_C1 = ?FP:fp6_sub(E, ?FP:fp6_add(A, B)),
  %% Out_C0 = B * v + A
  Out_C0 = ?FP:fp6_add(?FP:fp6_mul_v(B), A),
  {Out_C0, Out_C1}.

-spec fp6_mul_01(fp6(), fp2(), fp2()) -> fp6().
fp6_mul_01({A0, A1, A2}, C0, C1) ->
  AA = ?FP:fp2_mul(A0, C0),
  BB = ?FP:fp2_mul(A1, C1),
  T1 = ?FP:fp2_add(AA, ?FP:fp2_mul_xi(?FP:fp2_sub(?FP:fp2_mul(?FP:fp2_add(A1, A2), C1), BB))),
  T2 = ?FP:fp2_sub(?FP:fp2_sub(?FP:fp2_mul(?FP:fp2_add(A0, A1), ?FP:fp2_add(C0, C1)), AA), BB),
  T3 = ?FP:fp2_add(?FP:fp2_sub(?FP:fp2_mul(?FP:fp2_add(A0, A2), C0), AA), BB),
  {T1, T2, T3}.

%%%-------------------------------------------------------------------
%%% G2 Preparation
%%%-------------------------------------------------------------------

-spec prepare_g2(g2_affine()) -> [ell_coeff()].
prepare_g2(infinity) ->
  [];
prepare_g2({Qx, Qy}) ->
  Q = {Qx, Qy},
  NegQ = {Qx, ?FP:fp2_neg(Qy)},
  TwoInv = (?BN254_P + 1) div 2,
  R0 = {Qx, Qy, ?FP:fp2_one()},
  LoopCount = ate_loop_count(),
  %% Loop from index 63 down to 0
  {R_final, CoeffsRev} = prepare_loop(63, LoopCount, R0, Q, NegQ, TwoInv, []),
  CoeffsLoop = lists:reverse(CoeffsRev),
  %% Frobenius points
  Q1 = mul_by_char(Q),
  Q2_raw = mul_by_char(Q1),
  Q2_neg = {element(1, Q2_raw), ?FP:fp2_neg(element(2, Q2_raw))},
  {Coeff_q1, R_after_q1} = hom_add(R_final, Q1),
  {Coeff_q2, _R_after_q2} = hom_add(R_after_q1, Q2_neg),
  CoeffsLoop ++ [Coeff_q1, Coeff_q2].

-spec prepare_loop(
  integer(),
  [integer()],
  {fp2(), fp2(), fp2()},
  {fp2(), fp2()},
  {fp2(), fp2()},
  pos_integer(),
  [ell_coeff()]
) -> {{fp2(), fp2(), fp2()}, [ell_coeff()]}.
prepare_loop(-1, _LoopCount, R, _Q, _NegQ, _TwoInv, Acc) ->
  {R, Acc};
prepare_loop(Idx, LoopCount, R, Q, NegQ, TwoInv, Acc) ->
  {Coeff_dbl, R_dbl} = hom_double(R, TwoInv),
  Bit = lists:nth(Idx + 1, LoopCount),
  case Bit of
    1 ->
      {Coeff_add, R_add} = hom_add(R_dbl, Q),
      prepare_loop(Idx - 1, LoopCount, R_add, Q, NegQ, TwoInv, [Coeff_add, Coeff_dbl | Acc]);
    -1 ->
      {Coeff_add, R_add} = hom_add(R_dbl, NegQ),
      prepare_loop(Idx - 1, LoopCount, R_add, Q, NegQ, TwoInv, [Coeff_add, Coeff_dbl | Acc]);
    0 ->
      prepare_loop(Idx - 1, LoopCount, R_dbl, Q, NegQ, TwoInv, [Coeff_dbl | Acc])
  end.

%% Homogeneous doubling:
%% Line coeff for D-type twist: {-H, 3*J, I}
-spec hom_double({fp2(), fp2(), fp2()}, pos_integer()) ->
  {ell_coeff(), {fp2(), fp2(), fp2()}}.
hom_double({X, Y, Z}, TwoInv) ->
  A_raw = ?FP:fp2_mul(X, Y),
  A = ?FP:fp2_mul_fp(A_raw, TwoInv),
  B = ?FP:fp2_sqr(Y),
  C = ?FP:fp2_sqr(Z),
  TwistB = {?BN254_TWIST_B0, ?BN254_TWIST_B1},
  C3 = ?FP:fp2_add(?FP:fp2_add(C, C), C),
  E = ?FP:fp2_mul(TwistB, C3),
  F = ?FP:fp2_add(?FP:fp2_add(E, E), E),
  G_raw = ?FP:fp2_add(B, F),
  G = ?FP:fp2_mul_fp(G_raw, TwoInv),
  H = ?FP:fp2_sub(?FP:fp2_sqr(?FP:fp2_add(Y, Z)), ?FP:fp2_add(B, C)),
  I = ?FP:fp2_sub(E, B),
  J = ?FP:fp2_sqr(X),
  E_sqr = ?FP:fp2_sqr(E),
  X_new = ?FP:fp2_mul(A, ?FP:fp2_sub(B, F)),
  Y_new = ?FP:fp2_sub(?FP:fp2_sqr(G), ?FP:fp2_add(?FP:fp2_add(E_sqr, E_sqr), E_sqr)),
  Z_new = ?FP:fp2_mul(B, H),
  %% Coeffs: {-H, 3*J, I}
  J3 = ?FP:fp2_add(?FP:fp2_add(J, J), J),
  NegH = ?FP:fp2_neg(H),
  {{NegH, J3, I}, {X_new, Y_new, Z_new}}.

%% Homogeneous addition:
%% Line coeff for D-type twist: {lambda, -theta, j}
-spec hom_add({fp2(), fp2(), fp2()}, {fp2(), fp2()}) ->
  {ell_coeff(), {fp2(), fp2(), fp2()}}.
hom_add({X, Y, Z}, {Qx, Qy}) ->
  Theta = ?FP:fp2_sub(Y, ?FP:fp2_mul(Qy, Z)),
  Lambda = ?FP:fp2_sub(X, ?FP:fp2_mul(Qx, Z)),
  C = ?FP:fp2_sqr(Theta),
  D = ?FP:fp2_sqr(Lambda),
  E = ?FP:fp2_mul(Lambda, D),
  F = ?FP:fp2_mul(Z, C),
  G = ?FP:fp2_mul(X, D),
  H = ?FP:fp2_sub(?FP:fp2_add(E, F), ?FP:fp2_add(G, G)),
  X_new = ?FP:fp2_mul(Lambda, H),
  Y_new = ?FP:fp2_sub(?FP:fp2_mul(Theta, ?FP:fp2_sub(G, H)), ?FP:fp2_mul(E, Y)),
  Z_new = ?FP:fp2_mul(Z, E),
  J = ?FP:fp2_sub(?FP:fp2_mul(Theta, Qx), ?FP:fp2_mul(Lambda, Qy)),
  NegTheta = ?FP:fp2_neg(Theta),
  {{Lambda, NegTheta, J}, {X_new, Y_new, Z_new}}.

%%%-------------------------------------------------------------------
%%% Frobenius and Constants
%%%-------------------------------------------------------------------

-spec twist_mul_by_q_x() -> fp2().
twist_mul_by_q_x() ->
  {
    21575463638280843010398324269430826099269044274347216827212613867836435027261,
    10307601595873709700152284273816112264069230130616436755625194854815875713954
  }.

-spec twist_mul_by_q_y() -> fp2().
twist_mul_by_q_y() ->
  {
    2821565182194536844548159561693502659359617185244120367078079554186484126554,
    3505843767911556378687030309984248845540243509899259641013678093033130930403
  }.

-spec mul_by_char({fp2(), fp2()}) -> {fp2(), fp2()}.
mul_by_char({X, Y}) ->
  X_frob = ?FP:fp2_frobenius(X),
  Y_frob = ?FP:fp2_frobenius(Y),
  {?FP:fp2_mul(X_frob, twist_mul_by_q_x()), ?FP:fp2_mul(Y_frob, twist_mul_by_q_y())}.

-spec ate_loop_count() -> [integer()].
ate_loop_count() ->
  [
    0,
    0,
    0,
    1,
    0,
    1,
    0,
    -1,
    0,
    0,
    -1,
    0,
    0,
    0,
    1,
    0,
    0,
    -1,
    0,
    -1,
    0,
    0,
    0,
    1,
    0,
    -1,
    0,
    0,
    0,
    0,
    -1,
    0,
    0,
    1,
    0,
    -1,
    0,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    -1,
    0,
    0,
    -1,
    0,
    1,
    0,
    -1,
    0,
    0,
    0,
    -1,
    0,
    -1,
    0,
    0,
    0,
    1,
    0,
    1,
    1
  ].

%%%-------------------------------------------------------------------
%%% Final Exponentiation: Easy Part and Laura Fuentes-Castaneda Hard Part
%%%-------------------------------------------------------------------

-spec final_exp(fp12()) -> fp12().
final_exp(F) ->
  %% Easy part: (conj(f) * f^-1)^(p^2 + 1)
  F1 = ?FP:fp12_conj(F),
  F2 = ?FP:fp12_inv(F),
  R_easy1 = ?FP:fp12_mul(F1, F2),
  R_easy2 = ?FP:fp12_mul(?FP:fp12_frobenius2(R_easy1), R_easy1),

  %% Hard part:
  %% x = 4965661367192848881
  Y0 = exp_by_neg_x(R_easy2),
  Y1 = ?FP:fp12_cyclotomic_sqr(Y0),
  Y2 = ?FP:fp12_cyclotomic_sqr(Y1),
  Y3 = ?FP:fp12_mul(Y2, Y1),
  Y4 = exp_by_neg_x(Y3),
  Y5 = ?FP:fp12_cyclotomic_sqr(Y4),
  Y6_raw = exp_by_neg_x(Y5),
  Y3_inv = ?FP:fp12_conj(Y3),
  Y6 = ?FP:fp12_conj(Y6_raw),
  Y7 = ?FP:fp12_mul(Y6, Y4),
  Y8 = ?FP:fp12_mul(Y7, Y3_inv),
  Y9 = ?FP:fp12_mul(Y8, Y1),
  Y10 = ?FP:fp12_mul(Y8, Y4),
  Y11 = ?FP:fp12_mul(Y10, R_easy2),
  Y12 = ?FP:fp12_frobenius(Y9),
  Y13 = ?FP:fp12_mul(Y12, Y11),
  Y14 = ?FP:fp12_mul(?FP:fp12_frobenius2(Y8), Y13),
  R_inv = ?FP:fp12_conj(R_easy2),
  Y15 = ?FP:fp12_mul(R_inv, Y9),
  Y15_frob3 = ?FP:fp12_frobenius3(Y15),
  ?FP:fp12_mul(Y15_frob3, Y14).

-spec exp_by_neg_x(fp12()) -> fp12().
exp_by_neg_x(F) ->
  %% Since x is positive in BN254, exp_by_neg_x(F) = (F^x)^-1 = conj(F^x)
  PowX = ?FP:fp12_pow(F, ?BN254_X),
  ?FP:fp12_conj(PowX).
