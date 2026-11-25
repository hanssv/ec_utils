%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang BN254 (alt_bn128) cryptography:
%%%   - G1 and G2 curve arithmetic and compression roundtrips
%%%   - Subgroup membership invariants
%%%   - Optimal Ate pairing bilinearity and pairing check
%%%   - Groth16 zk-SNARK verification soundness
%%%   - Differential equivalence against Arkworks reference NIF
%%% @end
%%%-------------------------------------------------------------------
-module(bn254_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_bn254.hrl").
-include("ecu_groth16.hrl").

-define(FP, ecu_bn254_fp).
-define(BN, ecu_bn254).
-define(PAIRING, ecu_bn254_pairing).
-define(NIF, ecu_bn254_nif).

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_scalar() ->
  choose(1, ?BN254_R - 1).

gen_small_scalar() ->
  choose(1, 1000).

gen_g1_point() ->
  ?LET(K, gen_small_scalar(), ?BN:g1_scalar_mul_base(K)).

gen_g2_point() ->
  ?LET(K, gen_small_scalar(), ?BN:g2_scalar_mul_base(K)).

gen_public_inputs() ->
  ?LET(Len, choose(1, 3), vector(Len, gen_scalar())).

mod_inv(A, M) ->
  case ecu_misc:eea(A, M) of
    {1, X, _} -> (X rem M + M) rem M
  end.

%%%-------------------------------------------------------------------
%%% Group Properties
%%%-------------------------------------------------------------------

prop_g1_compress_decompress() ->
  ?FORALL(
    K,
    gen_small_scalar(),
    begin
      P = ?BN:g1_scalar_mul_base(K),
      Comp = ?BN:g1_compress(P),
      case ?BN:g1_decompress(Comp) of
        {ok, P2} ->
          P2 =:= P andalso ?BN:g1_is_in_subgroup(P2);
        _ ->
          false
      end
    end
  ).

prop_g1_uncompressed_roundtrip() ->
  ?FORALL(
    K,
    gen_small_scalar(),
    begin
      P = ?BN:g1_scalar_mul_base(K),
      Bin = ?BN:g1_to_uncompressed(P),
      case ?BN:g1_from_uncompressed(Bin) of
        {ok, P2} ->
          P2 =:= P andalso ?BN:g1_on_curve(P2);
        _ ->
          false
      end
    end
  ).

prop_g1_arithmetic() ->
  ?FORALL(
    {K1, K2},
    {gen_small_scalar(), gen_small_scalar()},
    begin
      P1 = ?BN:g1_scalar_mul_base(K1),
      P2 = ?BN:g1_scalar_mul_base(K2),
      SumP = ?BN:g1_add(P1, P2),
      ExpectedSum = ?BN:g1_scalar_mul_base((K1 + K2) rem ?BN254_R),
      SumP =:= ExpectedSum andalso
        ?BN:g1_double(P1) =:= ?BN:g1_add(P1, P1) andalso
        ?BN:g1_add(P1, ?BN:g1_neg(P1)) =:= ?BN:g1_infinity()
    end
  ).

prop_g2_compress_decompress() ->
  ?FORALL(
    K,
    gen_small_scalar(),
    begin
      Q = ?BN:g2_scalar_mul_base(K),
      Comp = ?BN:g2_compress(Q),
      case ?BN:g2_decompress(Comp) of
        {ok, Q2} ->
          Q2 =:= Q andalso ?BN:g2_is_in_subgroup(Q2);
        _ ->
          false
      end
    end
  ).

prop_g2_uncompressed_roundtrip() ->
  ?FORALL(
    K,
    gen_small_scalar(),
    begin
      Q = ?BN:g2_scalar_mul_base(K),
      Bin = ?BN:g2_to_uncompressed(Q),
      case ?BN:g2_from_uncompressed(Bin) of
        {ok, Q2} ->
          Q2 =:= Q andalso ?BN:g2_on_curve(Q2);
        _ ->
          false
      end
    end
  ).

prop_g2_arithmetic() ->
  ?FORALL(
    {K1, K2},
    {gen_small_scalar(), gen_small_scalar()},
    begin
      Q1 = ?BN:g2_scalar_mul_base(K1),
      Q2 = ?BN:g2_scalar_mul_base(K2),
      SumQ = ?BN:g2_add(Q1, Q2),
      ExpectedSum = ?BN:g2_scalar_mul_base((K1 + K2) rem ?BN254_R),
      SumQ =:= ExpectedSum andalso
        ?BN:g2_double(Q1) =:= ?BN:g2_add(Q1, Q1) andalso
        ?BN:g2_add(Q1, ?BN:g2_neg(Q1)) =:= ?BN:g2_infinity()
    end
  ).

prop_g2_twist_subgroup_rejection_adversarial() ->
  ?FORALL(
    Seed,
    choose(1, 1000000000),
    begin
      TwistB = {
        16#2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5,
        16#9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2
      },
      FindPt = fun Loop(X0) ->
        X = {X0 rem ?BN254_P, 0},
        Rhs = ?FP:fp2_add(
          ?FP:fp2_mul(?FP:fp2_sqr(X), X),
          TwistB
        ),
        case ?FP:fp2_sqrt(Rhs) of
          {ok, Y} -> {X, Y};
          error -> Loop(X0 + 1)
        end
      end,
      TwistPt = FindPt(Seed),
      OnCurve = ?BN:g2_on_curve(TwistPt),
      InSub = ?BN:g2_is_in_subgroup(TwistPt),
      case InSub of
        false ->
          DecompRes = ?BN:g2_decompress(?BN:g2_compress(TwistPt)),
          DeserRes = ?BN:g2_from_uncompressed(?BN:g2_to_uncompressed(TwistPt)),
          PairingCheckRes = ?PAIRING:pairing_check([{?BN:g1_generator(), TwistPt}]),
          OnCurve andalso
            (DecompRes =:= error) andalso
            (DeserRes =:= error) andalso
            (not PairingCheckRes);
        true ->
          %% Extremely rare case where point happens to be in G2
          true
      end
    end
  ).

prop_boundary_scalars_homomorphism() ->
  ?FORALL(
    {K, ScalarChoice},
    {gen_small_scalar(), elements([0, ?BN254_R, -1, -?BN254_R, ?BN254_R - 1])},
    begin
      P = ?BN:g1_scalar_mul_base(K),
      Q = ?BN:g2_scalar_mul_base(K),
      Zero1 = ?BN:g1_scalar_mul(P, 0),
      Zero2 = ?BN:g2_scalar_mul(Q, 0),
      Inf1 = ?BN:g1_scalar_mul(P, ?BN254_R),
      Inf2 = ?BN:g2_scalar_mul(Q, ?BN254_R),
      Neg1 = ?BN:g1_scalar_mul(P, -1),
      Neg2 = ?BN:g2_scalar_mul(Q, -1),
      MulP = ?BN:g1_scalar_mul(P, ScalarChoice),
      MulQ = ?BN:g2_scalar_mul(Q, ScalarChoice),
      Zero1 =:= ?BN:g1_infinity() andalso
        Zero2 =:= ?BN:g2_infinity() andalso
        Inf1 =:= ?BN:g1_infinity() andalso
        Inf2 =:= ?BN:g2_infinity() andalso
        Neg1 =:= ?BN:g1_neg(P) andalso
        Neg2 =:= ?BN:g2_neg(Q) andalso
        ?BN:g1_is_in_subgroup(MulP) andalso
        ?BN:g2_is_in_subgroup(MulQ)
    end
  ).

%%%-------------------------------------------------------------------
%%% Pairing Properties
%%%-------------------------------------------------------------------

prop_pairing_bilinearity() ->
  ?FORALL(
    {A, B},
    {choose(1, 10), choose(1, 10)},
    begin
      G1 = ?BN:g1_generator(),
      G2 = ?BN:g2_generator(),
      P = ?BN:g1_scalar_mul(G1, A),
      Q = ?BN:g2_scalar_mul(G2, B),
      Pair_AP_BQ = ?PAIRING:pairing(P, Q),
      Pair_G1_G2 = ?PAIRING:pairing(G1, G2),
      Expected = ?FP:fp12_pow(Pair_G1_G2, (A * B) rem ?BN254_R),
      Pair_AP_BQ =:= Expected
    end
  ).

prop_pairing_check() ->
  ?FORALL(
    {A, B},
    {choose(1, 10), choose(1, 10)},
    begin
      G1 = ?BN:g1_generator(),
      G2 = ?BN:g2_generator(),
      P = ?BN:g1_scalar_mul(G1, A),
      Q = ?BN:g2_scalar_mul(G2, B),
      NegP = ?BN:g1_neg(P),
      ?PAIRING:pairing_check([{P, Q}, {NegP, Q}]) andalso
        not ?PAIRING:pairing_check([{P, Q}, {P, Q}])
    end
  ).

%%%-------------------------------------------------------------------
%%% Differential Oracle Properties vs Arkworks NIF
%%%-------------------------------------------------------------------

prop_differential_g1_mult() ->
  ?FORALL(
    K,
    choose(1, 100000),
    begin
      case ?NIF:is_loaded() of
        true ->
          P = ?BN:g1_scalar_mul_base(K),
          PBin = ?BN:g1_to_uncompressed(P),
          G1_nif = ?NIF:g1_generator(),
          {ok, NifMul} = ?NIF:g1_mult(G1_nif, <<K:256/big>>),
          PBin =:= NifMul;
        false ->
          true
      end
    end
  ).

prop_differential_g1_add() ->
  ?FORALL(
    {K1, K2},
    {choose(1, 10000), choose(1, 10000)},
    begin
      case ?NIF:is_loaded() of
        true ->
          P1 = ?BN:g1_scalar_mul_base(K1),
          P2 = ?BN:g1_scalar_mul_base(K2),
          SumP = ?BN:g1_add(P1, P2),
          SumBin = ?BN:g1_to_uncompressed(SumP),
          P1Bin = ?BN:g1_to_uncompressed(P1),
          P2Bin = ?BN:g1_to_uncompressed(P2),
          {ok, NifSum} = ?NIF:g1_add(P1Bin, P2Bin),
          SumBin =:= NifSum;
        false ->
          true
      end
    end
  ).

prop_differential_g2_mult() ->
  ?FORALL(
    K,
    choose(1, 10000),
    begin
      case ?NIF:is_loaded() of
        true ->
          Q = ?BN:g2_scalar_mul_base(K),
          QBin = ?BN:g2_to_uncompressed(Q),
          G2_nif = ?NIF:g2_generator(),
          {ok, NifMul} = ?NIF:g2_mult(G2_nif, <<K:256/big>>),
          QBin =:= NifMul;
        false ->
          true
      end
    end
  ).

prop_differential_g2_add() ->
  ?FORALL(
    {K1, K2},
    {choose(1, 1000), choose(1, 1000)},
    begin
      case ?NIF:is_loaded() of
        true ->
          Q1 = ?BN:g2_scalar_mul_base(K1),
          Q2 = ?BN:g2_scalar_mul_base(K2),
          SumQ = ?BN:g2_add(Q1, Q2),
          SumBin = ?BN:g2_to_uncompressed(SumQ),
          Q1Bin = ?BN:g2_to_uncompressed(Q1),
          Q2Bin = ?BN:g2_to_uncompressed(Q2),
          {ok, NifSum} = ?NIF:g2_add(Q1Bin, Q2Bin),
          SumBin =:= NifSum;
        false ->
          true
      end
    end
  ).

prop_differential_pairing_check() ->
  ?FORALL(
    {A, B},
    {choose(1, 5), choose(1, 5)},
    begin
      case ?NIF:is_loaded() of
        true ->
          G1 = ?BN:g1_generator(),
          G2 = ?BN:g2_generator(),
          P = ?BN:g1_scalar_mul(G1, A),
          Q = ?BN:g2_scalar_mul(G2, B),
          NegP = ?BN:g1_neg(P),
          ErlCheck = ?PAIRING:pairing_check([{P, Q}, {NegP, Q}]),
          PBin = ?BN:g1_to_uncompressed(P),
          NegPBin = ?BN:g1_to_uncompressed(NegP),
          QBin = ?BN:g2_to_uncompressed(Q),
          NifCheck = ?NIF:pairing_check([{PBin, QBin}, {NegPBin, QBin}]),
          ErlCheck =:= true andalso ErlCheck =:= NifCheck;
        false ->
          true
      end
    end
  ).

prop_differential_groth16() ->
  ?FORALL(
    Inputs,
    gen_public_inputs(),
    begin
      R = ?BN254_R,
      AlphaVal = 123456789123456789 rem R,
      BetaVal = 987654321987654321 rem R,
      GammaVal = 112233445566778899 rem R,
      DeltaVal = 998877665544332211 rem R,

      G1 = ?BN:g1_generator(),
      G2 = ?BN:g2_generator(),

      AlphaG1 = ?BN:g1_scalar_mul(G1, AlphaVal),
      BetaG2 = ?BN:g2_scalar_mul(G2, BetaVal),
      GammaG2 = ?BN:g2_scalar_mul(G2, GammaVal),
      DeltaG2 = ?BN:g2_scalar_mul(G2, DeltaVal),

      NumInputs = length(Inputs),
      ICCoeffs = [(314159265 + I * 10007) rem R || I <- lists:seq(0, NumInputs)],
      IC = [?BN:g1_scalar_mul(G1, Coeff) || Coeff <- ICCoeffs],

      VK = #groth16_vk{
        alpha_g1 = AlphaG1,
        beta_g2 = BetaG2,
        gamma_g2 = GammaG2,
        delta_g2 = DeltaG2,
        ic = IC
      },

      AVal = 777777777 rem R,
      BVal = 888888888 rem R,

      A = ?BN:g1_scalar_mul(G1, AVal),
      B = ?BN:g2_scalar_mul(G2, BVal),

      [IC0 | RestICCoeffs] = ICCoeffs,
      KPubScalar =
        lists:foldl(
          fun({X, Coeff}, Acc) ->
            (Acc + X * Coeff) rem R
          end,
          IC0,
          lists:zip(Inputs, RestICCoeffs)
        ),

      DeltaInv = mod_inv(DeltaVal, R),
      AB = (AVal * BVal) rem R,
      AlphaBeta = (AlphaVal * BetaVal) rem R,
      KPubGamma = (KPubScalar * GammaVal) rem R,
      Num = (AB - AlphaBeta - KPubGamma) rem R,
      NumPos = (Num + R) rem R,
      CVal = (NumPos * DeltaInv) rem R,
      C = ?BN:g1_scalar_mul(G1, CVal),
      Proof = #groth16_proof{a = A, b = B, c = C},

      ErlVerify = ecu_groth16:verify(bn254, VK, Inputs, Proof),
      case ?NIF:is_loaded() of
        true ->
          AlphaBin = ?BN:g1_to_uncompressed(AlphaG1),
          BetaBin = ?BN:g2_to_uncompressed(BetaG2),
          GammaBin = ?BN:g2_to_uncompressed(GammaG2),
          DeltaBin = ?BN:g2_to_uncompressed(DeltaG2),
          ICBins = [?BN:g1_to_uncompressed(Pt) || Pt <- IC],
          InputBins = [<<X:256/big>> || X <- Inputs],
          ABin = ?BN:g1_to_uncompressed(A),
          BBin = ?BN:g2_to_uncompressed(B),
          CBin = ?BN:g1_to_uncompressed(C),
          NifVerify = ?NIF:groth16_verify(
            AlphaBin, BetaBin, GammaBin, DeltaBin, ICBins, InputBins, ABin, BBin, CBin
          ),
          ErlVerify =:= true andalso ErlVerify =:= NifVerify;
        false ->
          ErlVerify =:= true
      end
    end
  ).
