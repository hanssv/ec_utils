%%%-------------------------------------------------------------------
%%% @doc
%%% Comprehensive EUnit tests for pure-Erlang PLONK zk-SNARK verifier.
%%% Tests BN254 (SnarkJS vectors & synthetic vectors), BLS12-381,
%%% input formats, tampering rejection, and differential NIF oracle.
%%% @end
%%%-------------------------------------------------------------------
-module(plonk_tests).

-include_lib("eunit/include/eunit.hrl").
-include("ecu_plonk.hrl").
-include("ecu_bn254.hrl").
-include("ecu_bls12_381.hrl").

-define(BN, ecu_bn254).
-define(BN_NIF, ecu_bn254_nif).
-define(BLS, ecu_bls12_381).

enc_g1({X, Y}) -> <<X:256/big, Y:256/big>>.
enc_sc(S) -> <<S:256/big>>.

%%%===================================================================
%%% 1. SnarkJS Vector Tests (BN254)
%%%===================================================================

snarkjs_vector_raw_binary_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, PubJson} = file:read_file("test/data/plonk_bn254_public.json"),

  %% Verify using raw JSON binary strings
  ?assert(ecu_plonk:verify(VKJson, PubJson, ProofJson)),
  ?assert(ecu_plonk:verify(bn254, VKJson, PubJson, ProofJson)).

snarkjs_vector_decoded_maps_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, PubJson} = file:read_file("test/data/plonk_bn254_public.json"),

  VKMap = json:decode(VKJson),
  ProofMap = json:decode(ProofJson),
  PubList = json:decode(PubJson),

  %% Verify using decoded map structures
  ?assert(ecu_plonk:verify(VKMap, PubList, ProofMap)),
  ?assert(ecu_plonk:verify(bn254, VKMap, PubList, ProofMap)).

snarkjs_vector_records_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, PubJson} = file:read_file("test/data/plonk_bn254_public.json"),

  {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
  {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),
  {ok, Pub} = ecu_plonk:parse_public_inputs(PubJson, bn254),

  %% Verify parsed Erlang record structures
  ?assert(ecu_plonk:verify(VK, Pub, Proof)),
  ?assert(ecu_plonk:verify(bn254, VK, Pub, Proof)).

snarkjs_differential_nif_oracle_test() ->
  case ecu_plonk_nif:is_loaded() of
    true ->
      {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
      {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
      {ok, PubJson} = file:read_file("test/data/plonk_bn254_public.json"),

      {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
      {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),
      {ok, Pub} = ecu_plonk:parse_public_inputs(PubJson, bn254),

      %% Pure Erlang passes
      ?assert(ecu_plonk:verify(VK, Pub, Proof)),

      %% Arkworks Rust NIF oracle passes
      NifResult = ecu_plonk_nif:verify_bn254(
        VK#plonk_vk.power,
        enc_sc(VK#plonk_vk.k1),
        enc_sc(VK#plonk_vk.k2),
        enc_sc(VK#plonk_vk.w),
        enc_g1(VK#plonk_vk.qm),
        enc_g1(VK#plonk_vk.ql),
        enc_g1(VK#plonk_vk.qr),
        enc_g1(VK#plonk_vk.qo),
        enc_g1(VK#plonk_vk.qc),
        enc_g1(VK#plonk_vk.s1),
        enc_g1(VK#plonk_vk.s2),
        enc_g1(VK#plonk_vk.s3),
        ?BN:g2_to_uncompressed(VK#plonk_vk.x_2),
        [enc_sc(P) || P <- Pub],
        enc_g1(Proof#plonk_proof.a),
        enc_g1(Proof#plonk_proof.b),
        enc_g1(Proof#plonk_proof.c),
        enc_g1(Proof#plonk_proof.z),
        enc_g1(Proof#plonk_proof.t1),
        enc_g1(Proof#plonk_proof.t2),
        enc_g1(Proof#plonk_proof.t3),
        enc_sc(Proof#plonk_proof.eval_a),
        enc_sc(Proof#plonk_proof.eval_b),
        enc_sc(Proof#plonk_proof.eval_c),
        enc_sc(Proof#plonk_proof.eval_s1),
        enc_sc(Proof#plonk_proof.eval_s2),
        enc_sc(Proof#plonk_proof.eval_zw),
        enc_g1(Proof#plonk_proof.wxi),
        enc_g1(Proof#plonk_proof.wxiw)
      ),
      ?assert(NifResult);
    false ->
      ok
  end.

%%%===================================================================
%%% 2. Negative & Tampering Rejection Tests
%%%===================================================================

tampered_public_input_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
  {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),

  %% Correct public input: [7776, 1]
  %% Tampered public inputs should fail
  ?assertNot(ecu_plonk:verify(VK, [7777, 1], Proof)),
  ?assertNot(ecu_plonk:verify(VK, [7776, 2], Proof)),
  ?assertNot(ecu_plonk:verify(VK, [0, 0], Proof)).

wrong_public_input_length_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
  {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),

  %% VK specifies nPublic = 2
  ?assertNot(ecu_plonk:verify(VK, [7776], Proof)),
  ?assertNot(ecu_plonk:verify(VK, [7776, 1, 42], Proof)),
  ?assertNot(ecu_plonk:verify(VK, [], Proof)).

tampered_evaluations_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, PubJson} = file:read_file("test/data/plonk_bn254_public.json"),
  {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
  {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),
  {ok, Pub} = ecu_plonk:parse_public_inputs(PubJson, bn254),

  BadEvalA = Proof#plonk_proof{eval_a = (Proof#plonk_proof.eval_a + 1) rem ?BN254_R},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadEvalA)),

  BadEvalB = Proof#plonk_proof{eval_b = (Proof#plonk_proof.eval_b + 1) rem ?BN254_R},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadEvalB)),

  BadEvalC = Proof#plonk_proof{eval_c = (Proof#plonk_proof.eval_c + 1) rem ?BN254_R},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadEvalC)),

  BadEvalS1 = Proof#plonk_proof{eval_s1 = (Proof#plonk_proof.eval_s1 + 1) rem ?BN254_R},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadEvalS1)),

  BadEvalS2 = Proof#plonk_proof{eval_s2 = (Proof#plonk_proof.eval_s2 + 1) rem ?BN254_R},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadEvalS2)),

  BadEvalZw = Proof#plonk_proof{eval_zw = (Proof#plonk_proof.eval_zw + 1) rem ?BN254_R},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadEvalZw)).

tampered_commitments_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, PubJson} = file:read_file("test/data/plonk_bn254_public.json"),
  {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
  {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),
  {ok, Pub} = ecu_plonk:parse_public_inputs(PubJson, bn254),

  G1 = ?BN:g1_generator(),

  BadA = Proof#plonk_proof{a = ?BN:g1_add(Proof#plonk_proof.a, G1)},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadA)),

  BadB = Proof#plonk_proof{b = ?BN:g1_add(Proof#plonk_proof.b, G1)},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadB)),

  BadC = Proof#plonk_proof{c = ?BN:g1_add(Proof#plonk_proof.c, G1)},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadC)),

  BadZ = Proof#plonk_proof{z = ?BN:g1_add(Proof#plonk_proof.z, G1)},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadZ)),

  BadT1 = Proof#plonk_proof{t1 = ?BN:g1_add(Proof#plonk_proof.t1, G1)},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadT1)),

  BadWxi = Proof#plonk_proof{wxi = ?BN:g1_add(Proof#plonk_proof.wxi, G1)},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadWxi)),

  BadWxiw = Proof#plonk_proof{wxiw = ?BN:g1_add(Proof#plonk_proof.wxiw, G1)},
  ?assertNot(ecu_plonk:verify(VK, Pub, BadWxiw)).

out_of_range_scalars_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
  {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),

  %% Scalar exceeding field modulus R
  BadPub = [?BN254_R + 5, 1],
  ?assertEqual(error, ecu_plonk:parse_public_inputs(BadPub, bn254)),
  ?assertNot(ecu_plonk:verify(VK, BadPub, Proof)),

  BadProofRec = Proof#plonk_proof{eval_a = ?BN254_R + 10},
  ?assertNot(ecu_plonk:verify(VK, [7776, 1], BadProofRec)).

point_not_on_curve_rejection_test() ->
  {ok, VKJson} = file:read_file("test/data/plonk_bn254_vk.json"),
  {ok, ProofJson} = file:read_file("test/data/plonk_bn254_proof.json"),
  {ok, VK} = ecu_plonk:parse_vk(VKJson, bn254),
  {ok, Proof} = ecu_plonk:parse_proof(ProofJson, bn254),

  %% Point {1, 1} is not on BN254 curve
  NotOnCurvePt = {1, 1},
  ?assertNot(?BN:g1_on_curve(NotOnCurvePt)),

  BadProof = Proof#plonk_proof{a = NotOnCurvePt},
  ?assertNot(ecu_plonk:verify(VK, [7776, 1], BadProof)),

  BadVK = VK#plonk_vk{qm = NotOnCurvePt},
  ?assertNot(ecu_plonk:verify(BadVK, [7776, 1], Proof)).

%%%===================================================================
%%% 3. Synthetic Multi-Curve Test Vectors (BN254 & BLS12-381)
%%%===================================================================

%% Generates a mathematically valid, self-consistent PLONK instance on any curve
generate_synthetic_plonk_instance(Curve, Power, PublicInputs, SeedOffset) ->
  R =
    case Curve of
      bn254 -> ?BN254_R;
      bls12_381 -> ?BLS12_381_R
    end,
  G1Gen =
    case Curve of
      bn254 -> ?BN:g1_generator();
      bls12_381 -> ?BLS:g1_generator()
    end,
  G2Gen =
    case Curve of
      bn254 -> ?BN:g2_generator();
      bls12_381 -> ?BLS:g2_generator()
    end,

  MulG1 = fun(Pt, S) ->
    case Curve of
      bn254 -> ?BN:g1_scalar_mul(Pt, S);
      bls12_381 -> ?BLS:g1_scalar_mul(Pt, S)
    end
  end,
  MulG2 = fun(Pt, S) ->
    case Curve of
      bn254 -> ?BN:g2_scalar_mul(Pt, S);
      bls12_381 -> ?BLS:g2_scalar_mul(Pt, S)
    end
  end,

  ModInv = fun(A) ->
    case ecu_compat:mod_pow(A rem R, R - 2, R) of
      Bin when is_binary(Bin) -> binary:decode_unsigned(Bin)
    end
  end,

  HashToFr = fun(Data) ->
    binary:decode_unsigned(ecu_keccak:keccak256(Data)) rem R
  end,

  EncG1 = fun(Pt) ->
    {X, Y} = Pt,
    case Curve of
      bn254 -> <<X:256/big, Y:256/big>>;
      bls12_381 -> <<X:384/big, Y:384/big>>
    end
  end,
  EncSc = fun(S) -> <<S:256/big>> end,

  %% 1. SRS trapdoor x
  TrapdoorX = (98765432101234567 + SeedOffset * 17) rem R,
  X_2 = MulG2(G2Gen, TrapdoorX),

  %% 2. Root of unity w
  DomainSize = 1 bsl Power,
  GeneratorField =
    case Curve of
      bn254 -> 5;
      bls12_381 -> 7
    end,
  Exp = (R - 1) div DomainSize,
  W_omega =
    case ecu_compat:mod_pow(GeneratorField, Exp, R) of
      Bin when is_binary(Bin) -> binary:decode_unsigned(Bin)
    end,

  %% 3. Circuit selectors and permutations
  K1 = 2,
  K2 = 3,
  Qm = MulG1(G1Gen, (101 + SeedOffset) rem R),
  Ql = MulG1(G1Gen, (102 + SeedOffset) rem R),
  Qr = MulG1(G1Gen, (103 + SeedOffset) rem R),
  Qo = MulG1(G1Gen, (104 + SeedOffset) rem R),
  Qc = MulG1(G1Gen, (105 + SeedOffset) rem R),
  S1 = MulG1(G1Gen, (106 + SeedOffset) rem R),
  S2 = MulG1(G1Gen, (107 + SeedOffset) rem R),
  S3 = MulG1(G1Gen, (108 + SeedOffset) rem R),

  NPub = length(PublicInputs),
  VK = #plonk_vk{
    curve = Curve,
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
  },

  %% 4. Proof wire commitments and quotient parts
  A = MulG1(G1Gen, (201 + SeedOffset) rem R),
  B = MulG1(G1Gen, (202 + SeedOffset) rem R),
  C = MulG1(G1Gen, (203 + SeedOffset) rem R),
  Z = MulG1(G1Gen, (204 + SeedOffset) rem R),
  T1 = MulG1(G1Gen, (205 + SeedOffset) rem R),
  T2 = MulG1(G1Gen, (206 + SeedOffset) rem R),
  T3 = MulG1(G1Gen, (207 + SeedOffset) rem R),

  %% 5. Polynomial evaluations
  EvalA = (301 + SeedOffset) rem R,
  EvalB = (302 + SeedOffset) rem R,
  EvalC = (303 + SeedOffset) rem R,
  EvalS1 = (304 + SeedOffset) rem R,
  EvalS2 = (305 + SeedOffset) rem R,
  EvalZw = (306 + SeedOffset) rem R,

  %% 6. Opening commitment Wxiw
  _Wxiw_init = MulG1(G1Gen, (401 + SeedOffset) rem R),

  %% 7. Transcript challenges
  BufBeta = <<
    (EncG1(Qm))/binary,
    (EncG1(Ql))/binary,
    (EncG1(Qr))/binary,
    (EncG1(Qo))/binary,
    (EncG1(Qc))/binary,
    (EncG1(S1))/binary,
    (EncG1(S2))/binary,
    (EncG1(S3))/binary,
    (list_to_binary([EncSc(P) || P <- PublicInputs]))/binary,
    (EncG1(A))/binary,
    (EncG1(B))/binary,
    (EncG1(C))/binary
  >>,
  Beta = HashToFr(BufBeta),
  Gamma = HashToFr(EncSc(Beta)),
  Alpha = HashToFr(<<(EncSc(Beta))/binary, (EncSc(Gamma))/binary, (EncG1(Z))/binary>>),
  Xi = HashToFr(<<(EncSc(Alpha))/binary, (EncG1(T1))/binary, (EncG1(T2))/binary, (EncG1(T3))/binary>>),

  BufV = <<
    (EncSc(Xi))/binary,
    (EncSc(EvalA))/binary,
    (EncSc(EvalB))/binary,
    (EncSc(EvalC))/binary,
    (EncSc(EvalS1))/binary,
    (EncSc(EvalS2))/binary,
    (EncSc(EvalZw))/binary
  >>,
  V1 = HashToFr(BufV),
  V2 = (V1 * V1) rem R,
  V3 = (V2 * V1) rem R,
  V4 = (V3 * V1) rem R,
  V5 = (V4 * V1) rem R,

  %% 8. Lagrange evaluations and PI
  Xin = lists:foldl(fun(_, Acc) -> (Acc * Acc) rem R end, Xi, lists:seq(1, Power)),
  Zh = (Xin - 1 + R) rem R,

  CalcL = fun(Idx) ->
    Wi = lists:foldl(fun(_, Acc) -> (Acc * W_omega) rem R end, 1, lists:seq(1, Idx - 1)),
    Num = (Wi * Zh) rem R,
    Den = (DomainSize * ((Xi - Wi + R) rem R)) rem R,
    (Num * ModInv(Den)) rem R
  end,
  L = [CalcL(I) || I <- lists:seq(1, max(1, NPub))],
  L1 = lists:nth(1, L),

  PI = lists:foldl(
    fun({PubVal, LVal}, Acc) ->
      (Acc - ((PubVal * LVal) rem R) + R) rem R
    end,
    0,
    lists:zip(PublicInputs, lists:sublist(L, length(PublicInputs)))
  ),

  %% 9. r0
  Alpha2 = (Alpha * Alpha) rem R,
  E1 = PI,
  E2 = (L1 * Alpha2) rem R,
  E3a = (EvalA + Beta * EvalS1 + Gamma) rem R,
  E3b = (EvalB + Beta * EvalS2 + Gamma) rem R,
  E3c = (EvalC + Gamma) rem R,
  E3 = ((((((E3a * E3b) rem R) * E3c) rem R) * EvalZw) rem R * Alpha) rem R,
  R0 = ((E1 - E2 - E3) rem R + R) rem R,

  BetaXi = (Beta * Xi) rem R,
  D2a1 = (EvalA + BetaXi + Gamma) rem R,
  D2a2 = (EvalB + BetaXi * K1 + Gamma) rem R,
  D2a3 = (EvalC + BetaXi * K2 + Gamma) rem R,
  D2a = (((((D2a1 * D2a2) rem R) * D2a3) rem R) * Alpha) rem R,
  D2b = (L1 * Alpha2) rem R,

  D3a = (EvalA + Beta * EvalS1 + Gamma) rem R,
  D3b = (EvalB + Beta * EvalS2 + Gamma) rem R,
  D3c = (((Alpha * Beta) rem R) * EvalZw) rem R,
  Ss3 = (((D3a * D3b) rem R) * D3c) rem R,

  %% Fix Wxi and Wxiw, then solve for SRS trapdoor x:
  ScalarA = (201 + SeedOffset) rem R,
  ScalarB = (202 + SeedOffset) rem R,
  ScalarC = (203 + SeedOffset) rem R,
  ScalarZ = (204 + SeedOffset) rem R,
  ScalarT1 = (205 + SeedOffset) rem R,
  ScalarT2 = (206 + SeedOffset) rem R,
  ScalarT3 = (207 + SeedOffset) rem R,
  ScalarWxi = (401 + SeedOffset) rem R,
  ScalarWxiw = (402 + SeedOffset) rem R,

  PtWxi = MulG1(G1Gen, ScalarWxi),
  PtWxiw = MulG1(G1Gen, ScalarWxiw),
  UVal = HashToFr(<<(EncG1(PtWxi))/binary, (EncG1(PtWxiw))/binary>>),

  Sz = (D2a + D2b + UVal) rem R,
  ScalarD1 =
    (105 + SeedOffset + (101 + SeedOffset) * EvalA * EvalB + (102 + SeedOffset) * EvalA +
      (103 + SeedOffset) * EvalB + (104 + SeedOffset) * EvalC) rem R,
  ScalarD2 = (ScalarZ * Sz) rem R,
  ScalarD3 = ((108 + SeedOffset) * Ss3) rem R,
  ScalarD4 = ((ScalarT1 + ScalarT2 * Xin + ScalarT3 * ((Xin * Xin) rem R)) * Zh) rem R,
  ScalarD = ((ScalarD1 + ScalarD2 - ScalarD3 - ScalarD4) rem R + R) rem R,

  ScalarF =
    (ScalarD + V1 * ScalarA + V2 * ScalarB + V3 * ScalarC + V4 * (106 + SeedOffset) +
      V5 * (107 + SeedOffset)) rem R,
  ScalarE =
    ((R - R0) + V1 * EvalA + V2 * EvalB + V3 * EvalC + V4 * EvalS1 + V5 * EvalS2 + UVal * EvalZw) rem R,

  %% TrapdoorX * A1_scalar = B1_rhs_scalar:
  %% A1_scalar = (ScalarWxi + UVal * ScalarWxiw) mod R
  %% B1_rhs = (Xi * ScalarWxi + (UVal * Xi * W_omega) * ScalarWxiw + ScalarF - ScalarE) mod R
  A1Scalar = (ScalarWxi + UVal * ScalarWxiw) rem R,
  B1Rhs =
    ((Xi * ScalarWxi + ((((UVal * Xi) rem R) * W_omega) rem R) * ScalarWxiw + ScalarF - ScalarE) rem R +
      R) rem R,
  SolTrapdoorX = (B1Rhs * ModInv(A1Scalar)) rem R,

  SolX2 = MulG2(G2Gen, SolTrapdoorX),
  SolVK = VK#plonk_vk{x_2 = SolX2},

  Proof = #plonk_proof{
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
    wxi = PtWxi,
    wxiw = PtWxiw
  },
  {SolVK, Proof}.

synthetic_bn254_valid_proof_test() ->
  PublicInputs = [42, 100, 2026],
  {VK, Proof} = generate_synthetic_plonk_instance(bn254, 3, PublicInputs, 1),
  ?assert(ecu_plonk:verify(bn254, VK, PublicInputs, Proof)),
  %% Tampered input fails
  ?assertNot(ecu_plonk:verify(bn254, VK, [43, 100, 2026], Proof)),
  %% Tampered proof fails
  BadProof = Proof#plonk_proof{eval_a = (Proof#plonk_proof.eval_a + 1) rem ?BN254_R},
  ?assertNot(ecu_plonk:verify(bn254, VK, PublicInputs, BadProof)).

synthetic_bls12_381_valid_proof_test() ->
  PublicInputs = [123, 456, 789],
  {VK, Proof} = generate_synthetic_plonk_instance(bls12_381, 3, PublicInputs, 2),
  ?assert(ecu_plonk:verify(bls12_381, VK, PublicInputs, Proof)),
  %% Tampered input fails
  ?assertNot(ecu_plonk:verify(bls12_381, VK, [124, 456, 789], Proof)),
  %% Tampered proof fails
  BadProof = Proof#plonk_proof{eval_c = (Proof#plonk_proof.eval_c + 1) rem ?BLS12_381_R},
  ?assertNot(ecu_plonk:verify(bls12_381, VK, PublicInputs, BadProof)).

synthetic_bn254_nif_cross_verification_test() ->
  case ecu_plonk_nif:is_loaded() of
    true ->
      PublicInputs = [999, 888],
      {VK, Proof} = generate_synthetic_plonk_instance(bn254, 3, PublicInputs, 7),
      ?assert(ecu_plonk:verify(bn254, VK, PublicInputs, Proof)),

      %% Verify with NIF Oracle
      NifResult = ecu_plonk_nif:verify_bn254(
        VK#plonk_vk.power,
        enc_sc(VK#plonk_vk.k1),
        enc_sc(VK#plonk_vk.k2),
        enc_sc(VK#plonk_vk.w),
        enc_g1(VK#plonk_vk.qm),
        enc_g1(VK#plonk_vk.ql),
        enc_g1(VK#plonk_vk.qr),
        enc_g1(VK#plonk_vk.qo),
        enc_g1(VK#plonk_vk.qc),
        enc_g1(VK#plonk_vk.s1),
        enc_g1(VK#plonk_vk.s2),
        enc_g1(VK#plonk_vk.s3),
        ?BN:g2_to_uncompressed(VK#plonk_vk.x_2),
        [enc_sc(P) || P <- PublicInputs],
        enc_g1(Proof#plonk_proof.a),
        enc_g1(Proof#plonk_proof.b),
        enc_g1(Proof#plonk_proof.c),
        enc_g1(Proof#plonk_proof.z),
        enc_g1(Proof#plonk_proof.t1),
        enc_g1(Proof#plonk_proof.t2),
        enc_g1(Proof#plonk_proof.t3),
        enc_sc(Proof#plonk_proof.eval_a),
        enc_sc(Proof#plonk_proof.eval_b),
        enc_sc(Proof#plonk_proof.eval_c),
        enc_sc(Proof#plonk_proof.eval_s1),
        enc_sc(Proof#plonk_proof.eval_s2),
        enc_sc(Proof#plonk_proof.eval_zw),
        enc_g1(Proof#plonk_proof.wxi),
        enc_g1(Proof#plonk_proof.wxiw)
      ),
      ?assert(NifResult),

      %% Tampered input -> both reject
      TamperedInputs = [1000, 888],
      ?assertNot(ecu_plonk:verify(bn254, VK, TamperedInputs, Proof)),
      NifTampered = ecu_plonk_nif:verify_bn254(
        VK#plonk_vk.power,
        enc_sc(VK#plonk_vk.k1),
        enc_sc(VK#plonk_vk.k2),
        enc_sc(VK#plonk_vk.w),
        enc_g1(VK#plonk_vk.qm),
        enc_g1(VK#plonk_vk.ql),
        enc_g1(VK#plonk_vk.qr),
        enc_g1(VK#plonk_vk.qo),
        enc_g1(VK#plonk_vk.qc),
        enc_g1(VK#plonk_vk.s1),
        enc_g1(VK#plonk_vk.s2),
        enc_g1(VK#plonk_vk.s3),
        ?BN:g2_to_uncompressed(VK#plonk_vk.x_2),
        [enc_sc(P) || P <- TamperedInputs],
        enc_g1(Proof#plonk_proof.a),
        enc_g1(Proof#plonk_proof.b),
        enc_g1(Proof#plonk_proof.c),
        enc_g1(Proof#plonk_proof.z),
        enc_g1(Proof#plonk_proof.t1),
        enc_g1(Proof#plonk_proof.t2),
        enc_g1(Proof#plonk_proof.t3),
        enc_sc(Proof#plonk_proof.eval_a),
        enc_sc(Proof#plonk_proof.eval_b),
        enc_sc(Proof#plonk_proof.eval_c),
        enc_sc(Proof#plonk_proof.eval_s1),
        enc_sc(Proof#plonk_proof.eval_s2),
        enc_sc(Proof#plonk_proof.eval_zw),
        enc_g1(Proof#plonk_proof.wxi),
        enc_g1(Proof#plonk_proof.wxiw)
      ),
      ?assertNot(NifTampered);
    false ->
      ok
  end.
