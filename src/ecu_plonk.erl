%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang PLONK zk-SNARK verifier.
%%%
%%% Implements universal succinct non-interactive zero-knowledge argument
%%% verification based on the PLONK protocol (Gabizon, Williamson, Ciobotaru, 2019)
%%% over pairing-friendly elliptic curves:
%%%   - BN254 / alt_bn128 (Ethereum EVM EIP-196/197, Circom, SnarkJS)
%%%   - BLS12-381
%%%
%%% Features:
%%%   - Single-proof verification (`verify/3,4')
%%%   - Multi-curve support with strict curve parameter dispatch
%%%   - Keccak-256 Fiat-Shamir transcript generation (compatible with SnarkJS)
%%%   - Lagrange polynomial evaluations and public input combination
%%%   - Linearization polynomial evaluation and multi-scalar accumulation
%%%   - Batched KZG multi-point opening verification via single 2-pairing check
%%%   - Flexible input formats: `#plonk_vk{}', `#plonk_proof{}', JSON maps/binaries
%%%   - Strict subgroup validation and fail-closed security invariants
%%%
%%% Reference:
%%%   Ariel Gabizon, Zachary J. Williamson, Oana Ciobotaru.
%%%   "PLONK: Permutations over Lagrange-bases for Oecumenical Non-interactive
%%%   arguments of Knowledge" (Cryptology ePrint Archive, Report 2019/953).
%%%   https://eprint.iacr.org/2019/953.pdf
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_plonk).

-typing([eqwalizer]).

-include("ecu_plonk.hrl").
-include("ecu_bn254.hrl").
-include("ecu_bls12_381.hrl").

-define(BN, ecu_bn254).
-define(BN_PAIRING, ecu_bn254_pairing).
-define(BLS, ecu_bls12_381).
-define(BLS_PAIRING, ecu_bls12_381_pairing).

-type curve() :: bn254 | bls12_381.

-type plonk_vk_input() :: #plonk_vk{} | map() | binary() | tuple().
-type plonk_proof_input() :: #plonk_proof{} | map() | binary() | tuple().
-type plonk_public_input() :: [integer() | binary()] | binary().

-export_type([
  curve/0,
  plonk_vk_input/0,
  plonk_proof_input/0,
  plonk_public_input/0
]).

-export([
  verify/3,
  verify/4,
  parse_vk/1,
  parse_vk/2,
  parse_proof/1,
  parse_proof/2,
  parse_public_inputs/1,
  parse_public_inputs/2
]).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Verify a PLONK proof using the curve indicated in the verification key (or default bn254).
-spec verify(plonk_vk_input(), plonk_public_input(), plonk_proof_input()) -> boolean().
verify(VK, PublicInputs, Proof) ->
  Curve = detect_curve(VK),
  verify(Curve, VK, PublicInputs, Proof).

%% @doc Verify a PLONK proof under the specified curve.
-spec verify(curve(), plonk_vk_input(), plonk_public_input(), plonk_proof_input()) -> boolean().
verify(Curve, VK, PublicInputs, Proof) when Curve =:= bn254; Curve =:= bls12_381 ->
  case {parse_vk(VK, Curve), parse_proof(Proof, Curve), parse_public_inputs(PublicInputs, Curve)} of
    {{ok, DecVK}, {ok, DecProof}, {ok, DecPub}} ->
      do_verify(Curve, DecVK, DecPub, DecProof);
    _ ->
      false
  end;
verify(_, _, _, _) ->
  false.

%% @doc Parse a PLONK verification key using the default or auto-detected curve.
-spec parse_vk(plonk_vk_input()) -> {ok, #plonk_vk{}} | error.
parse_vk(VK) ->
  Curve = detect_curve(VK),
  parse_vk(VK, Curve).

%% @doc Parse a PLONK verification key for the specified curve.
-spec parse_vk(plonk_vk_input(), curve()) -> {ok, #plonk_vk{}} | error.
parse_vk(Bin, Curve) when is_binary(Bin) ->
  try json:decode(Bin) of
    Map when is_map(Map) -> parse_vk_map(Map, Curve);
    _ -> error
  catch
    _:_ -> error
  end;
parse_vk(#plonk_vk{curve = Curve} = VK, Curve) ->
  normalize_vk_record(VK, Curve);
parse_vk(#plonk_vk{}, _Curve) ->
  error;
parse_vk(Map, Curve) when is_map(Map) ->
  parse_vk_map(Map, Curve);
parse_vk(_, _) ->
  error.

%% @doc Parse a PLONK proof using the default bn254 curve.
-spec parse_proof(plonk_proof_input()) -> {ok, #plonk_proof{}} | error.
parse_proof(Proof) ->
  parse_proof(Proof, bn254).

%% @doc Parse a PLONK proof for the specified curve.
-spec parse_proof(plonk_proof_input(), curve()) -> {ok, #plonk_proof{}} | error.
parse_proof(Bin, Curve) when is_binary(Bin) ->
  try json:decode(Bin) of
    Map when is_map(Map) -> parse_proof_map(Map, Curve);
    _ -> error
  catch
    _:_ -> error
  end;
parse_proof(#plonk_proof{} = Proof, Curve) ->
  normalize_proof_record(Proof, Curve);
parse_proof(Map, Curve) when is_map(Map) ->
  parse_proof_map(Map, Curve);
parse_proof(_, _) ->
  error.

%% @doc Parse PLONK public inputs using the default bn254 curve.
-spec parse_public_inputs(plonk_public_input()) -> {ok, [non_neg_integer()]} | error.
parse_public_inputs(Pub) ->
  parse_public_inputs(Pub, bn254).

%% @doc Parse PLONK public inputs for the specified curve.
-spec parse_public_inputs(plonk_public_input(), curve()) -> {ok, [non_neg_integer()]} | error.
parse_public_inputs(Bin, Curve) when is_binary(Bin) ->
  try json:decode(Bin) of
    List when is_list(List) -> parse_public_inputs(List, Curve);
    _ -> error
  catch
    _:_ -> error
  end;
parse_public_inputs(List, Curve) when is_list(List) ->
  R = curve_r(Curve),
  parse_scalars_loop(List, R, []);
parse_public_inputs(_, _) ->
  error.

%%%===================================================================
%%% Internal Verification Logic
%%%===================================================================

-spec do_verify(curve(), #plonk_vk{}, [non_neg_integer()], #plonk_proof{}) -> boolean().
do_verify(Curve, VK, PublicInputs, Proof) ->
  #plonk_vk{
    power = Power,
    n_public = NPub,
    k1 = K1,
    k2 = K2,
    w = W_omega,
    qm = Qm,
    ql = Ql,
    qr = Qr,
    qo = Qo,
    qc = Qc,
    s1 = S1,
    s2 = S2,
    s3 = S3,
    x_2 = X_2
  } = VK,
  #plonk_proof{
    a = A,
    b = B,
    c = C,
    z = Z,
    t1 = T1,
    t2 = T2,
    t3 = T3,
    eval_a = EvalA,
    eval_b = EvalB,
    eval_c = EvalC,
    eval_s1 = EvalS1,
    eval_s2 = EvalS2,
    eval_zw = EvalZw,
    wxi = Wxi,
    wxiw = Wxiw
  } = Proof,

  %% Verify public input count matches VK
  case length(PublicInputs) =:= NPub of
    false ->
      false;
    true ->
      R = curve_r(Curve),

      %% Round 2 challenges: Beta, Gamma
      BufBeta = <<
        (enc_g1(Qm, Curve))/binary,
        (enc_g1(Ql, Curve))/binary,
        (enc_g1(Qr, Curve))/binary,
        (enc_g1(Qo, Curve))/binary,
        (enc_g1(Qc, Curve))/binary,
        (enc_g1(S1, Curve))/binary,
        (enc_g1(S2, Curve))/binary,
        (enc_g1(S3, Curve))/binary,
        (list_to_binary([enc_sc(P, Curve) || P <- PublicInputs]))/binary,
        (enc_g1(A, Curve))/binary,
        (enc_g1(B, Curve))/binary,
        (enc_g1(C, Curve))/binary
      >>,
      Beta = hash_to_fr(BufBeta, R),
      Gamma = hash_to_fr(enc_sc(Beta, Curve), R),

      %% Round 3 challenge: Alpha
      BufAlpha = <<
        (enc_sc(Beta, Curve))/binary,
        (enc_sc(Gamma, Curve))/binary,
        (enc_g1(Z, Curve))/binary
      >>,
      Alpha = hash_to_fr(BufAlpha, R),

      %% Round 4 challenge: Xi
      BufXi = <<
        (enc_sc(Alpha, Curve))/binary,
        (enc_g1(T1, Curve))/binary,
        (enc_g1(T2, Curve))/binary,
        (enc_g1(T3, Curve))/binary
      >>,
      Xi = hash_to_fr(BufXi, R),

      %% Round 5 challenges: V1..V5
      BufV = <<
        (enc_sc(Xi, Curve))/binary,
        (enc_sc(EvalA, Curve))/binary,
        (enc_sc(EvalB, Curve))/binary,
        (enc_sc(EvalC, Curve))/binary,
        (enc_sc(EvalS1, Curve))/binary,
        (enc_sc(EvalS2, Curve))/binary,
        (enc_sc(EvalZw, Curve))/binary
      >>,
      V1 = hash_to_fr(BufV, R),
      V2 = (V1 * V1) rem R,
      V3 = (V2 * V1) rem R,
      V4 = (V3 * V1) rem R,
      V5 = (V4 * V1) rem R,

      %% Round 6 challenge: U
      BufU = <<
        (enc_g1(Wxi, Curve))/binary,
        (enc_g1(Wxiw, Curve))/binary
      >>,
      U = hash_to_fr(BufU, R),

      %% Lagrange evaluations L_i(xi)
      DomainSize = 1 bsl Power,
      Xin = lists:foldl(fun(_, Acc) -> (Acc * Acc) rem R end, Xi, lists:seq(1, Power)),
      Zh = (Xin - 1 + R) rem R,

      NumL = max(1, NPub),
      case compute_lagrange_evals(NumL, Xi, Zh, DomainSize, W_omega, R) of
        error ->
          false;
        {ok, L} ->
          L1 = lists:nth(1, L),

          %% Public input polynomial PI(xi) = - sum(w_i * L_{i+1}(xi))
          PI = lists:foldl(
            fun({PubVal, LVal}, Acc) ->
              (Acc - ((PubVal * LVal) rem R) + R) rem R
            end,
            0,
            lists:zip(PublicInputs, lists:sublist(L, length(PublicInputs)))
          ),

          %% Linearization scalar r0
          Alpha2 = (Alpha * Alpha) rem R,
          E1 = PI,
          E2 = (L1 * Alpha2) rem R,
          E3a = (EvalA + Beta * EvalS1 + Gamma) rem R,
          E3b = (EvalB + Beta * EvalS2 + Gamma) rem R,
          E3c = (EvalC + Gamma) rem R,
          E3 = ((((((E3a * E3b) rem R) * E3c) rem R) * EvalZw) rem R * Alpha) rem R,
          R0 = ((E1 - E2 - E3) rem R + R) rem R,

          %% Linearized commitment D = D1 + D2 - D3 - D4
          D1_m = g1_scalar_mul((EvalA * EvalB) rem R, Qm, Curve),
          D1_l = g1_scalar_mul(EvalA, Ql, Curve),
          D1_r = g1_scalar_mul(EvalB, Qr, Curve),
          D1_o = g1_scalar_mul(EvalC, Qo, Curve),
          D1 = lists:foldl(
            fun(P, Acc) -> g1_add(Acc, P, Curve) end,
            Qc,
            [D1_m, D1_l, D1_r, D1_o]
          ),

          BetaXi = (Beta * Xi) rem R,
          D2a1 = (EvalA + BetaXi + Gamma) rem R,
          D2a2 = (EvalB + BetaXi * K1 + Gamma) rem R,
          D2a3 = (EvalC + BetaXi * K2 + Gamma) rem R,
          D2a = (((((D2a1 * D2a2) rem R) * D2a3) rem R) * Alpha) rem R,
          D2b = (L1 * Alpha2) rem R,
          Sz = (D2a + D2b + U) rem R,
          D2 = g1_scalar_mul(Sz, Z, Curve),

          D3a = (EvalA + Beta * EvalS1 + Gamma) rem R,
          D3b = (EvalB + Beta * EvalS2 + Gamma) rem R,
          D3c = (((Alpha * Beta) rem R) * EvalZw) rem R,
          Ss3 = (((D3a * D3b) rem R) * D3c) rem R,
          D3 = g1_scalar_mul(Ss3, S3, Curve),

          D4mid = g1_scalar_mul(Xin, T2, Curve),
          D4high = g1_scalar_mul((Xin * Xin) rem R, T3, Curve),
          D4sum = g1_add(T1, g1_add(D4mid, D4high, Curve), Curve),
          D4 = g1_scalar_mul(Zh, D4sum, Curve),

          D = g1_sub(g1_sub(g1_add(D1, D2, Curve), D3, Curve), D4, Curve),

          %% Commitment F
          F = lists:foldl(
            fun({Coeff, P}, Acc) -> g1_add(Acc, g1_scalar_mul(Coeff, P, Curve), Curve) end,
            D,
            [{V1, A}, {V2, B}, {V3, C}, {V4, S1}, {V5, S2}]
          ),

          %% Commitment E
          ESum =
            (R - R0) +
              V1 * EvalA +
              V2 * EvalB +
              V3 * EvalC +
              V4 * EvalS1 +
              V5 * EvalS2 +
              U * EvalZw,
          EScalar = ((ESum rem R) + R) rem R,
          G1Gen = curve_g1_generator(Curve),
          E = g1_scalar_mul(EScalar, G1Gen, Curve),

          %% Batch opening proof commitments A1 and B1
          A1 = g1_add(Wxi, g1_scalar_mul(U, Wxiw, Curve), Curve),
          B1_1 = g1_scalar_mul(Xi, Wxi, Curve),
          SParam = ((((U * Xi) rem R) * W_omega) rem R),
          B1_2 = g1_scalar_mul(SParam, Wxiw, Curve),
          B1 = g1_sub(g1_add(g1_add(B1_1, B1_2, Curve), F, Curve), E, Curve),

          %% Single 2-pairing check: e(-A1, X_2) * e(B1, G2_generator) == 1
          NegA1 = g1_neg(A1, Curve),
          G2Gen = curve_g2_generator(Curve),
          pairing_check([{NegA1, X_2}, {B1, G2Gen}], Curve)
      end
  end.

%%%===================================================================
%%% Field & Point Arithmetic Helpers
%%%===================================================================

-spec curve_r(curve()) -> non_neg_integer().
curve_r(bn254) -> ?BN254_R;
curve_r(bls12_381) -> ?BLS12_381_R.

-spec curve_g1_generator(curve()) -> plonk_g1().
curve_g1_generator(bn254) -> ?BN:g1_generator();
curve_g1_generator(bls12_381) -> ?BLS:g1_generator().

-spec curve_g2_generator(curve()) -> plonk_g2().
curve_g2_generator(bn254) -> ?BN:g2_generator();
curve_g2_generator(bls12_381) -> ?BLS:g2_generator().

-spec g1_add(plonk_g1(), plonk_g1(), curve()) -> plonk_g1().
g1_add(P1, P2, bn254) -> ?BN:g1_add(P1, P2);
g1_add(P1, P2, bls12_381) -> ?BLS:g1_add(P1, P2).

-spec g1_sub(plonk_g1(), plonk_g1(), curve()) -> plonk_g1().
g1_sub(P1, P2, bn254) -> ?BN:g1_sub(P1, P2);
g1_sub(P1, P2, bls12_381) -> ?BLS:g1_sub(P1, P2).

-spec g1_neg(plonk_g1(), curve()) -> plonk_g1().
g1_neg(P, bn254) -> ?BN:g1_neg(P);
g1_neg(P, bls12_381) -> ?BLS:g1_neg(P).

-spec g1_scalar_mul(non_neg_integer(), plonk_g1(), curve()) -> plonk_g1().
g1_scalar_mul(Scalar, P, bn254) -> ?BN:g1_scalar_mul(P, Scalar);
g1_scalar_mul(Scalar, P, bls12_381) -> ?BLS:g1_scalar_mul(P, Scalar).

-spec pairing_check([{plonk_g1(), plonk_g2()}], curve()) -> boolean().
pairing_check(Pairs, bn254) -> ?BN_PAIRING:pairing_check(Pairs);
pairing_check(Pairs, bls12_381) -> ?BLS_PAIRING:pairing_check(Pairs).

-spec enc_g1(plonk_g1(), curve()) -> binary().
enc_g1({X, Y}, bn254) ->
  <<X:256/big, Y:256/big>>;
enc_g1({X, Y}, bls12_381) ->
  <<X:384/big, Y:384/big>>;
enc_g1(infinity, bn254) ->
  <<0:512>>;
enc_g1(infinity, bls12_381) ->
  <<0:768>>.

-spec enc_sc(non_neg_integer(), curve()) -> binary().
enc_sc(S, _Curve) ->
  <<S:256/big>>.

-spec hash_to_fr(binary(), non_neg_integer()) -> non_neg_integer().
hash_to_fr(Data, R) ->
  binary:decode_unsigned(ecu_keccak:keccak256(Data)) rem R.

-spec mod_inv(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
mod_inv(A, R) ->
  case ecu_compat:mod_pow(A rem R, R - 2, R) of
    Bin when is_binary(Bin) -> binary:decode_unsigned(Bin)
  end.

-spec detect_curve(term()) -> curve().
detect_curve(#plonk_vk{curve = C}) when C =:= bn254; C =:= bls12_381 ->
  C;
detect_curve(#{curve := C}) when C =:= bn254; C =:= bls12_381 ->
  C;
detect_curve(#{<<"curve">> := C}) ->
  case C of
    <<"bls12381">> -> bls12_381;
    <<"bls12-381">> -> bls12_381;
    <<"BLS12381">> -> bls12_381;
    <<"BLS12-381">> -> bls12_381;
    _ -> bn254
  end;
detect_curve(Bin) when is_binary(Bin) ->
  try json:decode(Bin) of
    Map when is_map(Map) -> detect_curve(Map);
    _ -> bn254
  catch
    _:_ -> bn254
  end;
detect_curve(_) ->
  bn254.

%%%===================================================================
%%% Parsers & Normalizers
%%%===================================================================

-spec parse_vk_map(map(), curve()) -> {ok, #plonk_vk{}} | error.
parse_vk_map(Map, Curve) ->
  try
    R = curve_r(Curve),
    Power = get_int_field([<<"power">>, power], Map),
    NPub = get_int_field([<<"nPublic">>, <<"n_public">>, nPublic, n_public], Map),
    K1 = get_int_field([<<"k1">>, k1], Map, 2),
    K2 = get_int_field([<<"k2">>, k2], Map, 3),
    W = get_int_field([<<"w">>, w], Map),

    case
      Power >= 1 andalso Power =< 28 andalso
        NPub >= 0 andalso
        K1 > 0 andalso K1 < R andalso
        K2 > 0 andalso K2 < R andalso
        W > 0 andalso W < R andalso
        pow_mod(W, 1 bsl Power, R) =:= 1
    of
      false ->
        error;
      true ->
        {ok, Qm} = normalize_g1(get_field([<<"Qm">>, qm], Map), Curve),
        {ok, Ql} = normalize_g1(get_field([<<"Ql">>, ql], Map), Curve),
        {ok, Qr} = normalize_g1(get_field([<<"Qr">>, qr], Map), Curve),
        {ok, Qo} = normalize_g1(get_field([<<"Qo">>, qo], Map), Curve),
        {ok, Qc} = normalize_g1(get_field([<<"Qc">>, qc], Map), Curve),
        {ok, S1} = normalize_g1(get_field([<<"S1">>, s1], Map), Curve),
        {ok, S2} = normalize_g1(get_field([<<"S2">>, s2], Map), Curve),
        {ok, S3} = normalize_g1(get_field([<<"S3">>, s3], Map), Curve),
        {ok, X_2} = normalize_g2(get_field([<<"X_2">>, <<"x_2">>, x_2, x2], Map), Curve),

        {ok, #plonk_vk{
          curve = Curve,
          power = Power,
          n_public = NPub,
          k1 = K1,
          k2 = K2,
          w = W,
          qm = Qm,
          ql = Ql,
          qr = Qr,
          qo = Qo,
          qc = Qc,
          s1 = S1,
          s2 = S2,
          s3 = S3,
          x_2 = X_2
        }}
    end
  catch
    _:_ -> error
  end.

-spec parse_proof_map(map(), curve()) -> {ok, #plonk_proof{}} | error.
parse_proof_map(Map, Curve) ->
  R = curve_r(Curve),
  try
    {ok, A} = normalize_g1(get_field([<<"A">>, a], Map), Curve),
    {ok, B} = normalize_g1(get_field([<<"B">>, b], Map), Curve),
    {ok, C} = normalize_g1(get_field([<<"C">>, c], Map), Curve),
    {ok, Z} = normalize_g1(get_field([<<"Z">>, z], Map), Curve),
    {ok, T1} = normalize_g1(get_field([<<"T1">>, t1], Map), Curve),
    {ok, T2} = normalize_g1(get_field([<<"T2">>, t2], Map), Curve),
    {ok, T3} = normalize_g1(get_field([<<"T3">>, t3], Map), Curve),
    {ok, Wxi} = normalize_g1(get_field([<<"Wxi">>, wxi], Map), Curve),
    {ok, Wxiw} = normalize_g1(get_field([<<"Wxiw">>, wxiw], Map), Curve),

    EvalA = get_fr_field([<<"eval_a">>, eval_a], Map, R),
    EvalB = get_fr_field([<<"eval_b">>, eval_b], Map, R),
    EvalC = get_fr_field([<<"eval_c">>, eval_c], Map, R),
    EvalS1 = get_fr_field([<<"eval_s1">>, eval_s1], Map, R),
    EvalS2 = get_fr_field([<<"eval_s2">>, eval_s2], Map, R),
    EvalZw = get_fr_field([<<"eval_zw">>, eval_zw], Map, R),

    {ok, #plonk_proof{
      a = A,
      b = B,
      c = C,
      z = Z,
      t1 = T1,
      t2 = T2,
      t3 = T3,
      eval_a = EvalA,
      eval_b = EvalB,
      eval_c = EvalC,
      eval_s1 = EvalS1,
      eval_s2 = EvalS2,
      eval_zw = EvalZw,
      wxi = Wxi,
      wxiw = Wxiw
    }}
  catch
    _:_ -> error
  end.

-spec normalize_vk_record(#plonk_vk{}, curve()) -> {ok, #plonk_vk{}} | error.
normalize_vk_record(
  #plonk_vk{power = Power, n_public = NPub, k1 = K1, k2 = K2, w = W} = VK,
  Curve
) ->
  R = curve_r(Curve),
  case
    is_integer(Power) andalso Power >= 1 andalso Power =< 28 andalso
      is_integer(NPub) andalso NPub >= 0 andalso
      is_integer(K1) andalso K1 > 0 andalso K1 < R andalso
      is_integer(K2) andalso K2 > 0 andalso K2 < R andalso
      is_integer(W) andalso W > 0 andalso W < R andalso
      pow_mod(W, 1 bsl Power, R) =:= 1
  of
    false ->
      error;
    true ->
      case
        {
          normalize_g1(VK#plonk_vk.qm, Curve),
          normalize_g1(VK#plonk_vk.ql, Curve),
          normalize_g1(VK#plonk_vk.qr, Curve),
          normalize_g1(VK#plonk_vk.qo, Curve),
          normalize_g1(VK#plonk_vk.qc, Curve),
          normalize_g1(VK#plonk_vk.s1, Curve),
          normalize_g1(VK#plonk_vk.s2, Curve),
          normalize_g1(VK#plonk_vk.s3, Curve),
          normalize_g2(VK#plonk_vk.x_2, Curve)
        }
      of
        {
          {ok, Qm},
          {ok, Ql},
          {ok, Qr},
          {ok, Qo},
          {ok, Qc},
          {ok, S1},
          {ok, S2},
          {ok, S3},
          {ok, X2}
        } ->
          {ok, VK#plonk_vk{
            qm = Qm,
            ql = Ql,
            qr = Qr,
            qo = Qo,
            qc = Qc,
            s1 = S1,
            s2 = S2,
            s3 = S3,
            x_2 = X2
          }};
        _ ->
          error
      end
  end.

-spec normalize_proof_record(#plonk_proof{}, curve()) -> {ok, #plonk_proof{}} | error.
normalize_proof_record(#plonk_proof{} = Proof, Curve) ->
  R = curve_r(Curve),
  ValidEvals =
    is_valid_fr(Proof#plonk_proof.eval_a, R) andalso
      is_valid_fr(Proof#plonk_proof.eval_b, R) andalso
      is_valid_fr(Proof#plonk_proof.eval_c, R) andalso
      is_valid_fr(Proof#plonk_proof.eval_s1, R) andalso
      is_valid_fr(Proof#plonk_proof.eval_s2, R) andalso
      is_valid_fr(Proof#plonk_proof.eval_zw, R),
  case ValidEvals of
    false ->
      error;
    true ->
      case
        {
          normalize_g1(Proof#plonk_proof.a, Curve),
          normalize_g1(Proof#plonk_proof.b, Curve),
          normalize_g1(Proof#plonk_proof.c, Curve),
          normalize_g1(Proof#plonk_proof.z, Curve),
          normalize_g1(Proof#plonk_proof.t1, Curve),
          normalize_g1(Proof#plonk_proof.t2, Curve),
          normalize_g1(Proof#plonk_proof.t3, Curve),
          normalize_g1(Proof#plonk_proof.wxi, Curve),
          normalize_g1(Proof#plonk_proof.wxiw, Curve)
        }
      of
        {
          {ok, A},
          {ok, B},
          {ok, C},
          {ok, Z},
          {ok, T1},
          {ok, T2},
          {ok, T3},
          {ok, Wxi},
          {ok, Wxiw}
        } ->
          {ok, Proof#plonk_proof{
            a = A,
            b = B,
            c = C,
            z = Z,
            t1 = T1,
            t2 = T2,
            t3 = T3,
            wxi = Wxi,
            wxiw = Wxiw
          }};
        _ ->
          error
      end
  end.

-spec is_valid_fr(term(), non_neg_integer()) -> boolean().
is_valid_fr(V, R) ->
  is_integer(V) andalso V >= 0 andalso V < R.

-spec normalize_g1(term(), curve()) -> {ok, plonk_g1()} | error.
normalize_g1(infinity, _Curve) ->
  error;
normalize_g1({X, Y}, bn254) when is_integer(X), is_integer(Y) ->
  Pt = {X, Y},
  case ?BN:g1_on_curve(Pt) andalso ?BN:g1_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g1({X, Y}, bls12_381) when is_integer(X), is_integer(Y) ->
  Pt = {X, Y},
  case ?BLS:g1_on_curve(Pt) andalso ?BLS:g1_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g1([XBin, YBin | _], Curve) ->
  try
    X = to_int(XBin),
    Y = to_int(YBin),
    normalize_g1({X, Y}, Curve)
  catch
    _:_ -> error
  end;
normalize_g1(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 64 ->
  case ?BN:g1_from_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 32 ->
  case ?BN:g1_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 96 ->
  case ?BLS:g1_deserialize_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 48 ->
  case ?BLS:g1_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(_, _) ->
  error.

-spec normalize_g2(term(), curve()) -> {ok, plonk_g2()} | error.
normalize_g2(infinity, _Curve) ->
  error;
normalize_g2({{X0, X1}, {Y0, Y1}} = Pt, bn254) when
  is_integer(X0), is_integer(X1), is_integer(Y0), is_integer(Y1)
->
  case ?BN:g2_on_curve(Pt) andalso ?BN:g2_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g2({{X0, X1}, {Y0, Y1}} = Pt, bls12_381) when
  is_integer(X0), is_integer(X1), is_integer(Y0), is_integer(Y1)
->
  case ?BLS:g2_on_curve(Pt) andalso ?BLS:g2_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g2([[X0Bin, X1Bin | _], [Y0Bin, Y1Bin | _] | _], Curve) ->
  try
    X0 = to_int(X0Bin),
    X1 = to_int(X1Bin),
    Y0 = to_int(Y0Bin),
    Y1 = to_int(Y1Bin),
    normalize_g2({{X0, X1}, {Y0, Y1}}, Curve)
  catch
    _:_ -> error
  end;
normalize_g2(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 128 ->
  case ?BN:g2_from_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 64 ->
  case ?BN:g2_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 192 ->
  case ?BLS:g2_deserialize_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 96 ->
  case ?BLS:g2_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(_, _) ->
  error.

-spec parse_scalars_loop([term()], non_neg_integer(), [non_neg_integer()]) ->
  {ok, [non_neg_integer()]} | error.
parse_scalars_loop([], _R, Acc) ->
  {ok, lists:reverse(Acc)};
parse_scalars_loop([H | T], R, Acc) ->
  case parse_one_scalar(H, R) of
    {ok, Val} ->
      parse_scalars_loop(T, R, [Val | Acc]);
    error ->
      error
  end.

-spec parse_one_scalar(term(), non_neg_integer()) -> {ok, non_neg_integer()} | error.
parse_one_scalar(Val, R) when is_integer(Val), Val >= 0, Val < R ->
  {ok, Val};
parse_one_scalar(Bin, R) when is_binary(Bin), byte_size(Bin) =:= 32 ->
  case is_ascii_digits(Bin) of
    true ->
      try binary_to_integer(Bin, 10) of
        Val when Val >= 0, Val < R -> {ok, Val};
        _ -> error
      catch
        _:_ -> error
      end;
    false ->
      Val = binary:decode_unsigned(Bin),
      case Val < R of
        true -> {ok, Val};
        false -> error
      end
  end;
parse_one_scalar(Other, R) ->
  try to_int(Other) of
    Val when is_integer(Val), Val >= 0, Val < R -> {ok, Val};
    _ -> error
  catch
    _:_ -> error
  end.

-spec get_field([term()], map()) -> term().
get_field([], _Map) ->
  throw({field_not_found});
get_field([Key | Rest], Map) ->
  case maps:find(Key, Map) of
    {ok, Val} -> Val;
    error -> get_field(Rest, Map)
  end.

-spec get_int_field([term()], map()) -> non_neg_integer().
get_int_field(Keys, Map) ->
  to_int(get_field(Keys, Map)).

-spec get_int_field([term()], map(), non_neg_integer()) -> non_neg_integer().
get_int_field(Keys, Map, Default) ->
  try
    get_int_field(Keys, Map)
  catch
    _:_ -> Default
  end.

-spec get_fr_field([term()], map(), non_neg_integer()) -> non_neg_integer().
get_fr_field(Keys, Map, R) ->
  Val = to_int(get_field(Keys, Map)),
  case Val >= 0 andalso Val < R of
    true -> Val;
    false -> throw({scalar_out_of_range, Val})
  end.

-spec to_int(term()) -> non_neg_integer().
to_int(Val) when is_integer(Val), Val >= 0 ->
  Val;
to_int(<<"0x", Hex/binary>>) when byte_size(Hex) > 0 ->
  binary_to_integer(Hex, 16);
to_int(<<"0X", Hex/binary>>) when byte_size(Hex) > 0 ->
  binary_to_integer(Hex, 16);
to_int(Bin) when is_binary(Bin), byte_size(Bin) > 0 ->
  case is_ascii_digits(Bin) of
    true -> binary_to_integer(Bin, 10);
    false -> error(badarg)
  end;
to_int([H | _] = Str) when is_integer(H) ->
  Bytes = [X || X <- Str, is_integer(X), X >= 0, X =< 255],
  case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, Bytes) of
    true -> list_to_integer(Bytes);
    false -> error(badarg)
  end;
to_int(_) ->
  error(badarg).

-spec compute_lagrange_evals(
  pos_integer(),
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  non_neg_integer(),
  pos_integer()
) -> {ok, [non_neg_integer()]} | error.
compute_lagrange_evals(NumL, Xi, Zh, DomainSize, W_omega, R) ->
  compute_lagrange_loop(1, NumL, 1, Xi, Zh, DomainSize, W_omega, R, []).

-spec compute_lagrange_loop(
  pos_integer(),
  pos_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  non_neg_integer(),
  pos_integer(),
  [non_neg_integer()]
) -> {ok, [non_neg_integer()]} | error.
compute_lagrange_loop(I, NumL, _Wi, _Xi, _Zh, _DomainSize, _W_omega, _R, Acc) when I > NumL ->
  {ok, lists:reverse(Acc)};
compute_lagrange_loop(I, NumL, Wi, Xi, Zh, DomainSize, W_omega, R, Acc) ->
  Den = (DomainSize * ((Xi - Wi + R) rem R)) rem R,
  case Den of
    0 ->
      error;
    _ ->
      Num = (Wi * Zh) rem R,
      Li = (Num * mod_inv(Den, R)) rem R,
      NextWi = (Wi * W_omega) rem R,
      compute_lagrange_loop(I + 1, NumL, NextWi, Xi, Zh, DomainSize, W_omega, R, [Li | Acc])
  end.

-spec pow_mod(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
pow_mod(Base, Exp, Mod) ->
  case ecu_compat:mod_pow(Base rem Mod, Exp, Mod) of
    Bin when is_binary(Bin) -> binary:decode_unsigned(Bin)
  end.

-spec is_ascii_digits(binary()) -> boolean().
is_ascii_digits(<<>>) -> false;
is_ascii_digits(Bin) -> is_ascii_digits_loop(Bin).

-spec is_ascii_digits_loop(binary()) -> boolean().
is_ascii_digits_loop(<<>>) ->
  true;
is_ascii_digits_loop(<<B, Rest/binary>>) when B >= $0, B =< $9 ->
  is_ascii_digits_loop(Rest);
is_ascii_digits_loop(_) ->
  false.
