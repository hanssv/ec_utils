%%%-------------------------------------------------------------------
%%% @doc
%%% Comprehensive EUnit tests for pure-Erlang Groth16 zk-SNARK verifier.
%%% Tests valid proofs, public input combinations, batch verification,
%%% compressed/uncompressed formats, tampering, and invalid points.
%%% @end
%%%-------------------------------------------------------------------
-module(groth16_tests).

-include_lib("eunit/include/eunit.hrl").
-include("ecu_groth16.hrl").
-include("ecu_bls12_381.hrl").

-define(BLS, ecu_bls12_381).
-define(R, ?BLS12_381_R).
-define(NIF, ecu_bls12_381_nif).

%%%===================================================================
%%% Helper: Generate a mathematically valid Groth16 instance
%%%===================================================================

mod_inv(A, M) ->
  case ecu_compat:mod_pow(A, M - 2, M) of
    Bin when is_binary(Bin) -> binary:decode_unsigned(Bin)
  end.

generate_groth16_instance(Scalars, SeedOffset) ->
  %% Deterministic distinct toxic waste
  AlphaVal = (123456789123456789 + SeedOffset) rem ?R,
  BetaVal = (987654321987654321 + SeedOffset * 2) rem ?R,
  GammaVal = (112233445566778899 + SeedOffset * 3) rem ?R,
  DeltaVal = (998877665544332211 + SeedOffset * 4) rem ?R,

  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),

  AlphaG1 = ?BLS:g1_scalar_mul(G1, AlphaVal),
  BetaG2 = ?BLS:g2_scalar_mul(G2, BetaVal),
  GammaG2 = ?BLS:g2_scalar_mul(G2, GammaVal),
  DeltaG2 = ?BLS:g2_scalar_mul(G2, DeltaVal),

  %% IC coefficients: IC_0, IC_1, ..., IC_m
  NumInputs = length(Scalars),
  ICCoeffs = [(314159265 + I * 10007 + SeedOffset) rem ?R || I <- lists:seq(0, NumInputs)],
  IC = [?BLS:g1_scalar_mul(G1, Coeff) || Coeff <- ICCoeffs],

  VK = #groth16_vk{
    alpha_g1 = AlphaG1,
    beta_g2 = BetaG2,
    gamma_g2 = GammaG2,
    delta_g2 = DeltaG2,
    ic = IC
  },

  %% Prover random scalars r, s for blinding (Groth16 randomizers)
  AVal = (777777777 + SeedOffset * 5) rem ?R,
  BVal = (888888888 + SeedOffset * 6) rem ?R,

  A = ?BLS:g1_scalar_mul(G1, AVal),
  B = ?BLS:g2_scalar_mul(G2, BVal),

  %% K_pub scalar = IC_0 + sum(x_i * IC_i)
  [IC0_coeff | RestICCoeffs] = ICCoeffs,
  KPubScalar =
    lists:foldl(
      fun({X, IC_coeff}, Acc) ->
        (Acc + X * IC_coeff) rem ?R
      end,
      IC0_coeff,
      lists:zip(Scalars, RestICCoeffs)
    ),

  %% Groth16 relation:
  %% a * b = alpha * beta + K_pub * gamma + c * delta (mod r)
  %% c = (a * b - alpha * beta - K_pub * gamma) * delta^(-1) (mod r)
  DeltaInv = mod_inv(DeltaVal, ?R),
  AB = (AVal * BVal) rem ?R,
  AlphaBeta = (AlphaVal * BetaVal) rem ?R,
  KPubGamma = (KPubScalar * GammaVal) rem ?R,

  Num = (AB - AlphaBeta - KPubGamma) rem ?R,
  NumPos = (Num + ?R) rem ?R,
  CVal = (NumPos * DeltaInv) rem ?R,

  C = ?BLS:g1_scalar_mul(G1, CVal),

  Proof = #groth16_proof{a = A, b = B, c = C},
  {VK, Proof}.

%%%===================================================================
%%% Unit Tests
%%%===================================================================

valid_single_proof_test() ->
  PublicInputs = [42, 100, 2026],
  {VK, Proof} = generate_groth16_instance(PublicInputs, 1),

  %% Verify using record
  ?assert(ecu_groth16:verify(VK, PublicInputs, Proof)),
  ?assert(ecu_groth16:verify(bls12_381, VK, PublicInputs, Proof)).

format_flexibility_test() ->
  PublicInputs = [123, 456],
  {VK, Proof} = generate_groth16_instance(PublicInputs, 2),

  %% 1. Map format
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
  ?assert(ecu_groth16:verify(VKMap, PublicInputs, ProofMap)),

  %% 2. Tuple format
  VKTuple = {
    VK#groth16_vk.alpha_g1,
    VK#groth16_vk.beta_g2,
    VK#groth16_vk.gamma_g2,
    VK#groth16_vk.delta_g2,
    VK#groth16_vk.ic
  },
  ProofTuple = {
    Proof#groth16_proof.a,
    Proof#groth16_proof.b,
    Proof#groth16_proof.c
  },
  ?assert(ecu_groth16:verify(VKTuple, PublicInputs, ProofTuple)),

  %% 3. Compressed points (48 bytes for G1, 96 bytes for G2)
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
  ?assert(ecu_groth16:verify(VKComp, PublicInputs, ProofComp)),

  %% 4. Uncompressed points (96 bytes for G1, 192 bytes for G2)
  VKUncomp = #{
    alpha_g1 => ?BLS:g1_serialize_uncompressed(VK#groth16_vk.alpha_g1),
    beta_g2 => ?BLS:g2_serialize_uncompressed(VK#groth16_vk.beta_g2),
    gamma_g2 => ?BLS:g2_serialize_uncompressed(VK#groth16_vk.gamma_g2),
    delta_g2 => ?BLS:g2_serialize_uncompressed(VK#groth16_vk.delta_g2),
    ic => [?BLS:g1_serialize_uncompressed(Pt) || Pt <- VK#groth16_vk.ic]
  },
  ProofUncomp = #{
    a => ?BLS:g1_serialize_uncompressed(Proof#groth16_proof.a),
    b => ?BLS:g2_serialize_uncompressed(Proof#groth16_proof.b),
    c => ?BLS:g1_serialize_uncompressed(Proof#groth16_proof.c)
  },
  ?assert(ecu_groth16:verify(VKUncomp, PublicInputs, ProofUncomp)),

  %% 5. Binary scalars (32-byte big-endian)
  PublicInputsBin = [<<X:256/big-unsigned-integer>> || X <- PublicInputs],
  ?assert(ecu_groth16:verify(VK, PublicInputsBin, Proof)).

tampered_inputs_test() ->
  PublicInputs = [10, 20],
  {VK, Proof} = generate_groth16_instance(PublicInputs, 3),
  ?assert(ecu_groth16:verify(VK, PublicInputs, Proof)),

  %% Tamper input value
  ?assertNot(ecu_groth16:verify(VK, [11, 20], Proof)),
  ?assertNot(ecu_groth16:verify(VK, [10, 21], Proof)),

  %% Wrong number of public inputs
  ?assertNot(ecu_groth16:verify(VK, [10], Proof)),
  ?assertNot(ecu_groth16:verify(VK, [10, 20, 30], Proof)),

  %% Out-of-range scalar (>= r)
  ?assertNot(ecu_groth16:verify(VK, [?R, 20], Proof)),
  ?assertNot(ecu_groth16:verify(VK, [10, ?R + 1], Proof)),
  ?assertNot(ecu_groth16:verify(VK, [<<(?R):256/big>>, <<20:256/big>>], Proof)).

tampered_proof_test() ->
  PublicInputs = [55],
  {VK, Proof} = generate_groth16_instance(PublicInputs, 4),
  ?assert(ecu_groth16:verify(VK, PublicInputs, Proof)),

  G1 = ?BLS:g1_generator(),
  G2 = ?BLS:g2_generator(),

  %% Tamper A
  ProofBadA = Proof#groth16_proof{a = ?BLS:g1_add(Proof#groth16_proof.a, G1)},
  ?assertNot(ecu_groth16:verify(VK, PublicInputs, ProofBadA)),

  %% Tamper B
  ProofBadB = Proof#groth16_proof{b = ?BLS:g2_add(Proof#groth16_proof.b, G2)},
  ?assertNot(ecu_groth16:verify(VK, PublicInputs, ProofBadB)),

  %% Tamper C
  ProofBadC = Proof#groth16_proof{c = ?BLS:g1_add(Proof#groth16_proof.c, G1)},
  ?assertNot(ecu_groth16:verify(VK, PublicInputs, ProofBadC)),

  %% Tamper VK alpha
  VKBadAlpha = VK#groth16_vk{alpha_g1 = ?BLS:g1_add(VK#groth16_vk.alpha_g1, G1)},
  ?assertNot(ecu_groth16:verify(VKBadAlpha, PublicInputs, Proof)),

  %% Infinity rejection
  ProofInfA = Proof#groth16_proof{a = infinity},
  ?assertNot(ecu_groth16:verify(VK, PublicInputs, ProofInfA)),
  ProofInfB = Proof#groth16_proof{b = infinity},
  ?assertNot(ecu_groth16:verify(VK, PublicInputs, ProofInfB)),
  ProofInfC = Proof#groth16_proof{c = infinity},
  ?assertNot(ecu_groth16:verify(VK, PublicInputs, ProofInfC)).

batch_verification_test() ->
  Inputs1 = [1, 2],
  Inputs2 = [3, 4],
  Inputs3 = [5, 6],

  {VK, Proof1} = generate_groth16_instance(Inputs1, 10),
  %% Same VK, different proofs and inputs:
  {_, Proof2} = generate_groth16_instance(Inputs2, 10),
  {_, Proof3} = generate_groth16_instance(Inputs3, 10),

  %% Verify all 3 individually
  ?assert(ecu_groth16:verify(VK, Inputs1, Proof1)),
  ?assert(ecu_groth16:verify(VK, Inputs2, Proof2)),
  ?assert(ecu_groth16:verify(VK, Inputs3, Proof3)),

  %% Empty batch
  ?assert(ecu_groth16:verify_batch(VK, [])),

  %% Single item batch
  ?assert(ecu_groth16:verify_batch(VK, [{Inputs1, Proof1}])),

  %% Full 3-item batch
  Batch = [
    {Inputs1, Proof1},
    {Inputs2, Proof2},
    {Inputs3, Proof3}
  ],
  ?assert(ecu_groth16:verify_batch(VK, Batch)),
  ?assert(ecu_groth16:verify_batch(bls12_381, VK, Batch)),

  %% Corrupt one proof in batch -> must fail!
  G1 = ?BLS:g1_generator(),
  BadProof2 = Proof2#groth16_proof{a = ?BLS:g1_add(Proof2#groth16_proof.a, G1)},
  BadBatch = [
    {Inputs1, Proof1},
    {Inputs2, BadProof2},
    {Inputs3, Proof3}
  ],
  ?assertNot(ecu_groth16:verify_batch(VK, BadBatch)).

official_test_vector_test() ->
  Path =
    case filelib:is_regular("test/data/groth16_bls12_381.json") of
      true -> "test/data/groth16_bls12_381.json";
      false -> filename:join([code:lib_dir(ec_utils), "test", "data", "groth16_bls12_381.json"])
    end,
  {ok, Bin} = file:read_file(Path),
  Data = json:decode(Bin),
  #{
    <<"vk">> := #{
      <<"alpha_g1">> := AlphaHex,
      <<"beta_g2">> := BetaHex,
      <<"gamma_g2">> := GammaHex,
      <<"delta_g2">> := DeltaHex,
      <<"ic">> := ICHexList
    },
    <<"public_inputs">> := InputStrs,
    <<"proof">> := #{
      <<"a">> := AHex,
      <<"b">> := BHex,
      <<"c">> := CHex
    }
  } = Data,
  Alpha = binary:decode_hex(AlphaHex),
  Beta = binary:decode_hex(BetaHex),
  Gamma = binary:decode_hex(GammaHex),
  Delta = binary:decode_hex(DeltaHex),
  IC = [binary:decode_hex(H) || H <- ICHexList],
  Inputs = [binary_to_integer(S) || S <- InputStrs],
  A = binary:decode_hex(AHex),
  B = binary:decode_hex(BHex),
  C = binary:decode_hex(CHex),
  VK = #{
    alpha_g1 => Alpha,
    beta_g2 => Beta,
    gamma_g2 => Gamma,
    delta_g2 => Delta,
    ic => IC
  },
  Proof = #{a => A, b => B, c => C},
  %% 1. Pure Erlang verifies official vector
  ?assert(ecu_groth16:verify(VK, Inputs, Proof)),
  %% 2. blst NIF cross-check
  case ?NIF:is_loaded() of
    true ->
      InputBins = [<<X:256/little>> || X <- Inputs],
      ?assert(?NIF:groth16_verify(Alpha, Beta, Gamma, Delta, IC, InputBins, A, B, C));
    false ->
      ok
  end,
  %% 3. Tampered input rejection
  TamperedInputs = [123456788, 987654321],
  ?assertNot(ecu_groth16:verify(VK, TamperedInputs, Proof)),
  %% 4. Tampered proof rejection
  G1 = ?BLS:g1_generator(),
  {ok, DecA} = ?BLS:g1_decompress(A),
  ProofBadA = Proof#{a => ?BLS:g1_compress(?BLS:g1_add(DecA, G1))},
  ?assertNot(ecu_groth16:verify(VK, Inputs, ProofBadA)).

differential_blst_oracle_test() ->
  case ?NIF:is_loaded() of
    true ->
      Inputs = [42, 84, 126],
      {VK, Proof} = generate_groth16_instance(Inputs, 777),
      %% Both pure Erlang and blst agree on valid instance
      ?assert(ecu_groth16:verify(VK, Inputs, Proof)),
      #groth16_vk{alpha_g1 = Alpha, beta_g2 = Beta, gamma_g2 = Gamma, delta_g2 = Delta, ic = IC} = VK,
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
      ?assert(
        ?NIF:groth16_verify(AlphaBin, BetaBin, GammaBin, DeltaBin, ICBins, InputBins, ABin, BBin, CBin)
      ),
      %% Tamper scalar input -> both reject
      TamperedInputs = [43, 84, 126],
      TamperedInputBins = [<<X:256/little>> || X <- TamperedInputs],
      ?assertNot(ecu_groth16:verify(VK, TamperedInputs, Proof)),
      ?assertNot(
        ?NIF:groth16_verify(
          AlphaBin, BetaBin, GammaBin, DeltaBin, ICBins, TamperedInputBins, ABin, BBin, CBin
        )
      ),
      %% Tamper proof point C -> both reject
      G1 = ?BLS:g1_generator(),
      BadPtC = ?BLS:g1_add(C, G1),
      BadC = ?BLS:g1_compress(BadPtC),
      BadProofC = Proof#groth16_proof{c = BadPtC},
      ?assertNot(ecu_groth16:verify(VK, Inputs, BadProofC)),
      ?assertNot(
        ?NIF:groth16_verify(AlphaBin, BetaBin, GammaBin, DeltaBin, ICBins, InputBins, ABin, BBin, BadC)
      );
    false ->
      ok
  end.
