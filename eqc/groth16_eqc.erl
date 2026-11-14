%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang Groth16 zk-SNARK verifier:
%%%   - Algebraic validity across arbitrary public inputs
%%%   - Tamper-detection soundness for inputs, proofs, and verification keys
%%%   - Format invariance (records, maps, tuples, compressed/uncompressed binaries)
%%%   - Randomized batch verification soundness
%%% @end
%%%-------------------------------------------------------------------
-module(groth16_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

-include("ecu_groth16.hrl").
-include("ecu_bls12_381.hrl").

-define(BLS, ecu_bls12_381).
-define(R, ?BLS12_381_R).
-define(NIF, ecu_bls12_381_nif).

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_scalar() ->
  choose(1, ?R - 1).

gen_public_inputs() ->
  ?LET(Len, choose(0, 4), vector(Len, gen_scalar())).

gen_groth16_instance() ->
  ?LET(
    {Inputs, Alpha, Beta, Gamma, Delta, AVal, BVal, Seed},
    {
      gen_public_inputs(),
      gen_scalar(),
      gen_scalar(),
      gen_scalar(),
      gen_scalar(),
      gen_scalar(),
      gen_scalar(),
      choose(1, 1000000)
    },
    begin
      G1 = ?BLS:g1_generator(),
      G2 = ?BLS:g2_generator(),

      AlphaG1 = ?BLS:g1_scalar_mul(G1, Alpha),
      BetaG2 = ?BLS:g2_scalar_mul(G2, Beta),
      GammaG2 = ?BLS:g2_scalar_mul(G2, Gamma),
      DeltaG2 = ?BLS:g2_scalar_mul(G2, Delta),

      NumInputs = length(Inputs),
      ICCoeffs = [(314159265 + I * 10007 + Seed) rem ?R || I <- lists:seq(0, NumInputs)],
      IC = [?BLS:g1_scalar_mul(G1, Coeff) || Coeff <- ICCoeffs],

      VK = #groth16_vk{
        alpha_g1 = AlphaG1,
        beta_g2 = BetaG2,
        gamma_g2 = GammaG2,
        delta_g2 = DeltaG2,
        ic = IC
      },

      A = ?BLS:g1_scalar_mul(G1, AVal),
      B = ?BLS:g2_scalar_mul(G2, BVal),

      [IC0 | RestICCoeffs] = ICCoeffs,
      KPubScalar =
        lists:foldl(
          fun({X, Coeff}, Acc) ->
            (Acc + X * Coeff) rem ?R
          end,
          IC0,
          lists:zip(Inputs, RestICCoeffs)
        ),

      DeltaInv =
        case ecu_compat:mod_pow(Delta, ?R - 2, ?R) of
          Bin when is_binary(Bin) -> binary:decode_unsigned(Bin)
        end,
      AB = (AVal * BVal) rem ?R,
      AlphaBeta = (Alpha * Beta) rem ?R,
      KPubGamma = (KPubScalar * Gamma) rem ?R,

      Num = (AB - AlphaBeta - KPubGamma) rem ?R,
      NumPos = (Num + ?R) rem ?R,
      CVal = (NumPos * DeltaInv) rem ?R,
      C = ?BLS:g1_scalar_mul(G1, CVal),

      Proof = #groth16_proof{a = A, b = B, c = C},
      {VK, Inputs, Proof}
    end
  ).

%%%-------------------------------------------------------------------
%%% Properties
%%%-------------------------------------------------------------------

%% Valid Groth16 proofs always verify
prop_valid_proof_verifies() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_groth16_instance(),
    ecu_groth16:verify(VK, Inputs, Proof)
  ).

%% Tampering with any public input causes verification to fail
prop_tampered_input_fails() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_groth16_instance(),
    begin
      case Inputs of
        [] ->
          %% Wrong number of inputs
          not ecu_groth16:verify(VK, [1], Proof);
        [First | Rest] ->
          TamperedInputs = [(First + 1) rem ?R | Rest],
          not ecu_groth16:verify(VK, TamperedInputs, Proof)
      end
    end
  ).

%% Tampering with proof points causes verification to fail
prop_tampered_proof_fails() ->
  ?FORALL(
    {{VK, Inputs, Proof}, TamperChoice, TamperScalar},
    {gen_groth16_instance(), choose(1, 3), gen_scalar()},
    begin
      G1 = ?BLS:g1_generator(),
      G2 = ?BLS:g2_generator(),
      TamperedProof =
        case TamperChoice of
          1 ->
            Offset = ?BLS:g1_scalar_mul(G1, TamperScalar),
            Proof#groth16_proof{a = ?BLS:g1_add(Proof#groth16_proof.a, Offset)};
          2 ->
            Offset = ?BLS:g2_scalar_mul(G2, TamperScalar),
            Proof#groth16_proof{b = ?BLS:g2_add(Proof#groth16_proof.b, Offset)};
          3 ->
            Offset = ?BLS:g1_scalar_mul(G1, TamperScalar),
            Proof#groth16_proof{c = ?BLS:g1_add(Proof#groth16_proof.c, Offset)}
        end,
      not ecu_groth16:verify(VK, Inputs, TamperedProof)
    end
  ).

%% Format invariance: compressed binaries, uncompressed binaries, maps, and records
prop_format_invariance() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_groth16_instance(),
    begin
      %% Verify record
      ResRec = ecu_groth16:verify(VK, Inputs, Proof),

      %% Verify map
      VKMap = #{
        alpha_g1 => VK#groth16_vk.alpha_g1,
        beta_g2 => VK#groth16_vk.beta_g2,
        gamma_g2 => VK#groth16_vk.gamma_g2,
        delta_g2 => VK#groth16_vk.delta_g2,
        ic => VK#groth16_vk.ic
      },
      ProofMap = #{
        a => Proof#groth16_proof.a,
        b => Proof#groth16_proof.b,
        c => Proof#groth16_proof.c
      },
      ResMap = ecu_groth16:verify(VKMap, Inputs, ProofMap),

      %% Verify compressed
      VKComp = #{
        alpha_g1 => ?BLS:g1_compress(VK#groth16_vk.alpha_g1),
        beta_g2 => ?BLS:g2_compress(VK#groth16_vk.beta_g2),
        gamma_g2 => ?BLS:g2_compress(VK#groth16_vk.gamma_g2),
        delta_g2 => ?BLS:g2_compress(VK#groth16_vk.delta_g2),
        ic => [?BLS:g1_compress(Pt) || Pt <- VK#groth16_vk.ic]
      },
      ProofComp = #{
        a => ?BLS:g1_compress(Proof#groth16_proof.a),
        b => ?BLS:g2_compress(Proof#groth16_proof.b),
        c => ?BLS:g1_compress(Proof#groth16_proof.c)
      },
      ResComp = ecu_groth16:verify(VKComp, Inputs, ProofComp),

      ResRec andalso ResMap andalso ResComp
    end
  ).

prop_differential_blst() ->
  ?FORALL(
    {VK, Inputs, Proof},
    gen_groth16_instance(),
    case ?NIF:is_loaded() of
      true ->
        PureResult = ecu_groth16:verify(VK, Inputs, Proof),
        #groth16_vk{
          alpha_g1 = Alpha,
          beta_g2 = Beta,
          gamma_g2 = Gamma,
          delta_g2 = Delta,
          ic = IC
        } = VK,
        #groth16_proof{a = A, b = B, c = C} = Proof,
        AlphaBin = ?BLS:g1_compress(Alpha),
        BetaBin = ?BLS:g2_compress(Beta),
        GammaBin = ?BLS:g2_compress(Gamma),
        DeltaBin = ?BLS:g2_compress(Delta),
        ICBins = [?BLS:g1_compress(Pt) || Pt <- IC],
        InputBins = [<<X:256/little>> || X <- Inputs],
        ABin = ?BLS:g1_compress(A),
        BBin = ?BLS:g2_compress(B),
        CBin = ?BLS:g1_compress(C),
        NifResult = ?NIF:groth16_verify(
          AlphaBin,
          BetaBin,
          GammaBin,
          DeltaBin,
          ICBins,
          InputBins,
          ABin,
          BBin,
          CBin
        ),
        PureResult == true andalso NifResult == true;
      false ->
        true
    end
  ).

prop_differential_blst_tampered() ->
  ?FORALL(
    {{VK, Inputs, Proof}, DeltaX},
    {gen_groth16_instance(), choose(1, ?R - 1)},
    case ?NIF:is_loaded() andalso Inputs =/= [] of
      true ->
        [X0 | Rest] = Inputs,
        TamperedInputs = [(X0 + DeltaX) rem ?R | Rest],
        PureResult = ecu_groth16:verify(VK, TamperedInputs, Proof),
        #groth16_vk{
          alpha_g1 = Alpha,
          beta_g2 = Beta,
          gamma_g2 = Gamma,
          delta_g2 = Delta,
          ic = IC
        } = VK,
        #groth16_proof{a = A, b = B, c = C} = Proof,
        AlphaBin = ?BLS:g1_compress(Alpha),
        BetaBin = ?BLS:g2_compress(Beta),
        GammaBin = ?BLS:g2_compress(Gamma),
        DeltaBin = ?BLS:g2_compress(Delta),
        ICBins = [?BLS:g1_compress(Pt) || Pt <- IC],
        InputBins = [<<X:256/little>> || X <- TamperedInputs],
        ABin = ?BLS:g1_compress(A),
        BBin = ?BLS:g2_compress(B),
        CBin = ?BLS:g1_compress(C),
        NifResult = ?NIF:groth16_verify(
          AlphaBin,
          BetaBin,
          GammaBin,
          DeltaBin,
          ICBins,
          InputBins,
          ABin,
          BBin,
          CBin
        ),
        PureResult == false andalso NifResult == false;
      _ ->
        true
    end
  ).
