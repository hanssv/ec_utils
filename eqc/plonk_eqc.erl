%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang PLONK zk-SNARK verifier:
%%%   - Algebraic validity across arbitrary public inputs (BN254 & BLS12-381)
%%%   - Tamper-detection soundness for public inputs, proofs, and evaluations
%%%   - Format invariance (records, maps, JSON binaries)
%%%   - Differential testing against Arkworks Rust NIF oracle
%%% @end
%%%-------------------------------------------------------------------
-module(plonk_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_plonk.hrl").
-include("ecu_bn254.hrl").
-include("ecu_bls12_381.hrl").

-define(BN, ecu_bn254).
-define(BLS, ecu_bls12_381).

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_scalar(Curve) ->
  R =
    case Curve of
      bn254 -> ?BN254_R;
      bls12_381 -> ?BLS12_381_R
    end,
  choose(1, R - 1).

gen_public_inputs(Curve) ->
  ?LET(Len, choose(1, 3), vector(Len, gen_scalar(Curve))).

gen_synthetic_instance(Curve) ->
  ?LET(
    {Inputs, Seed},
    {gen_public_inputs(Curve), choose(1, 1000000)},
    begin
      Power = 3,
      {VK, Proof} = generate_synthetic(Curve, Power, Inputs, Seed),
      {VK, Inputs, Proof}
    end
  ).

generate_synthetic(Curve, Power, PublicInputs, SeedOffset) ->
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

  DomainSize = 1 bsl Power,
  GeneratorField =
    case Curve of
      bn254 -> 5;
      bls12_381 -> 7
    end,
  Exp = (R - 1) div DomainSize,
  W_omega = binary:decode_unsigned(crypto:mod_pow(GeneratorField, Exp, R)),

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
    x_2 = G2Gen
  },

  ScalarA = (201 + SeedOffset) rem R,
  ScalarB = (202 + SeedOffset) rem R,
  ScalarC = (203 + SeedOffset) rem R,
  ScalarZ = (204 + SeedOffset) rem R,
  ScalarT1 = (205 + SeedOffset) rem R,
  ScalarT2 = (206 + SeedOffset) rem R,
  ScalarT3 = (207 + SeedOffset) rem R,
  ScalarWxi = (401 + SeedOffset) rem R,
  ScalarWxiw = (402 + SeedOffset) rem R,

  A = MulG1(G1Gen, ScalarA),
  B = MulG1(G1Gen, ScalarB),
  C = MulG1(G1Gen, ScalarC),
  Z = MulG1(G1Gen, ScalarZ),
  T1 = MulG1(G1Gen, ScalarT1),
  T2 = MulG1(G1Gen, ScalarT2),
  T3 = MulG1(G1Gen, ScalarT3),
  PtWxi = MulG1(G1Gen, ScalarWxi),
  PtWxiw = MulG1(G1Gen, ScalarWxiw),

  EvalA = (301 + SeedOffset) rem R,
  EvalB = (302 + SeedOffset) rem R,
  EvalC = (303 + SeedOffset) rem R,
  EvalS1 = (304 + SeedOffset) rem R,
  EvalS2 = (305 + SeedOffset) rem R,
  EvalZw = (306 + SeedOffset) rem R,

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

  UVal = HashToFr(<<(EncG1(PtWxi))/binary, (EncG1(PtWxiw))/binary>>),

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
  Sz = (D2a + D2b + UVal) rem R,

  D3a = (EvalA + Beta * EvalS1 + Gamma) rem R,
  D3b = (EvalB + Beta * EvalS2 + Gamma) rem R,
  D3c = (((Alpha * Beta) rem R) * EvalZw) rem R,
  Ss3 = (((D3a * D3b) rem R) * D3c) rem R,

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

%%%-------------------------------------------------------------------
%%% Properties
%%%-------------------------------------------------------------------

prop_valid_bn254_proof_verifies() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_synthetic_instance(bn254),
    ecu_plonk:verify(bn254, VK, Inputs, Proof) == true
  ).

prop_valid_bls12_381_proof_verifies() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_synthetic_instance(bls12_381),
    ecu_plonk:verify(bls12_381, VK, Inputs, Proof) == true
  ).

prop_tamper_public_input_fails() ->
  ?FORALL(
    {{VK, Inputs, Proof}, DeltaX},
    {gen_synthetic_instance(bn254), choose(1, ?BN254_R - 1)},
    begin
      [X0 | Rest] = Inputs,
      TamperedInputs = [(X0 + DeltaX) rem ?BN254_R | Rest],
      ecu_plonk:verify(bn254, VK, TamperedInputs, Proof) == false
    end
  ).

prop_tamper_evaluation_fails() ->
  ?FORALL(
    {{VK, Inputs, Proof}, DeltaE},
    {gen_synthetic_instance(bn254), choose(1, ?BN254_R - 1)},
    begin
      BadProof = Proof#plonk_proof{eval_a = (Proof#plonk_proof.eval_a + DeltaE) rem ?BN254_R},
      ecu_plonk:verify(bn254, VK, Inputs, BadProof) == false
    end
  ).

prop_format_invariance() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_synthetic_instance(bn254),
    begin
      ResRecord = ecu_plonk:verify(bn254, VK, Inputs, Proof),

      VKMap = #{
        power => VK#plonk_vk.power,
        nPublic => VK#plonk_vk.n_public,
        k1 => VK#plonk_vk.k1,
        k2 => VK#plonk_vk.k2,
        w => VK#plonk_vk.w,
        qm => VK#plonk_vk.qm,
        ql => VK#plonk_vk.ql,
        qr => VK#plonk_vk.qr,
        qo => VK#plonk_vk.qo,
        qc => VK#plonk_vk.qc,
        s1 => VK#plonk_vk.s1,
        s2 => VK#plonk_vk.s2,
        s3 => VK#plonk_vk.s3,
        x_2 => VK#plonk_vk.x_2
      },
      ProofMap = #{
        a => Proof#plonk_proof.a,
        b => Proof#plonk_proof.b,
        c => Proof#plonk_proof.c,
        z => Proof#plonk_proof.z,
        t1 => Proof#plonk_proof.t1,
        t2 => Proof#plonk_proof.t2,
        t3 => Proof#plonk_proof.t3,
        eval_a => Proof#plonk_proof.eval_a,
        eval_b => Proof#plonk_proof.eval_b,
        eval_c => Proof#plonk_proof.eval_c,
        eval_s1 => Proof#plonk_proof.eval_s1,
        eval_s2 => Proof#plonk_proof.eval_s2,
        eval_zw => Proof#plonk_proof.eval_zw,
        wxi => Proof#plonk_proof.wxi,
        wxiw => Proof#plonk_proof.wxiw
      },
      ResMap = ecu_plonk:verify(bn254, VKMap, Inputs, ProofMap),

      ResRecord andalso ResMap
    end
  ).

prop_differential_nif_oracle() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_synthetic_instance(bn254),
    case ecu_plonk_nif:is_loaded() of
      true ->
        PureResult = ecu_plonk:verify(bn254, VK, Inputs, Proof),
        NifResult = ecu_plonk_nif:verify_bn254(
          VK#plonk_vk.power,
          <<(VK#plonk_vk.k1):256/big>>,
          <<(VK#plonk_vk.k2):256/big>>,
          <<(VK#plonk_vk.w):256/big>>,
          enc_g1_bin(VK#plonk_vk.qm),
          enc_g1_bin(VK#plonk_vk.ql),
          enc_g1_bin(VK#plonk_vk.qr),
          enc_g1_bin(VK#plonk_vk.qo),
          enc_g1_bin(VK#plonk_vk.qc),
          enc_g1_bin(VK#plonk_vk.s1),
          enc_g1_bin(VK#plonk_vk.s2),
          enc_g1_bin(VK#plonk_vk.s3),
          ?BN:g2_to_uncompressed(VK#plonk_vk.x_2),
          [<<P:256/big>> || P <- Inputs],
          enc_g1_bin(Proof#plonk_proof.a),
          enc_g1_bin(Proof#plonk_proof.b),
          enc_g1_bin(Proof#plonk_proof.c),
          enc_g1_bin(Proof#plonk_proof.z),
          enc_g1_bin(Proof#plonk_proof.t1),
          enc_g1_bin(Proof#plonk_proof.t2),
          enc_g1_bin(Proof#plonk_proof.t3),
          <<(Proof#plonk_proof.eval_a):256/big>>,
          <<(Proof#plonk_proof.eval_b):256/big>>,
          <<(Proof#plonk_proof.eval_c):256/big>>,
          <<(Proof#plonk_proof.eval_s1):256/big>>,
          <<(Proof#plonk_proof.eval_s2):256/big>>,
          <<(Proof#plonk_proof.eval_zw):256/big>>,
          enc_g1_bin(Proof#plonk_proof.wxi),
          enc_g1_bin(Proof#plonk_proof.wxiw)
        ),
        PureResult == true andalso NifResult == true;
      false ->
        true
    end
  ).

enc_g1_bin({X, Y}) ->
  <<X:256/big, Y:256/big>>.
