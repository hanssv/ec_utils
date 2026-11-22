%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for pure Erlang KZG polynomial commitments (ecu_kzg)
%%% and finite field polynomial arithmetic (ecu_poly).
%%% @end
%%%-------------------------------------------------------------------
-module(kzg_tests).

-include_lib("eunit/include/eunit.hrl").
-include("ecu_bls12_381.hrl").

-define(R, ?BLS12_381_R).

%%%-------------------------------------------------------------------
%%% Polynomial Arithmetic Tests
%%%-------------------------------------------------------------------

poly_eval_test() ->
  %% P(x) = 3 + 2x + 5x^2
  P = [3, 2, 5],
  ?assertEqual(3, ecu_poly:eval(P, 0)),
  ?assertEqual(10, ecu_poly:eval(P, 1)),
  ?assertEqual(3 + 4 + 20, ecu_poly:eval(P, 2)),
  ?assertEqual(3 + 20 + 500, ecu_poly:eval(P, 10)),
  ?assertEqual(0, ecu_poly:eval([], 100)),
  ?assertEqual(0, ecu_poly:eval([0, 0], 50)).

poly_arithmetic_test() ->
  P1 = [1, 2, 3],
  P2 = [4, 5],
  %% P1 + P2 = [5, 7, 3]
  ?assertEqual([5, 7, 3], ecu_poly:add(P1, P2)),
  %% P1 - P2 = [-3, -3, 3] mod r
  Diff = ecu_poly:sub(P1, P2),
  ?assertEqual((1 - 4 + ?R) rem ?R, lists:nth(1, Diff)),
  ?assertEqual((2 - 5 + ?R) rem ?R, lists:nth(2, Diff)),
  ?assertEqual(3, lists:nth(3, Diff)),
  %% mul_scalar
  ?assertEqual([2, 4, 6], ecu_poly:mul_scalar(P1, 2)),
  %% P1 * P2: (1 + 2x + 3x^2)*(4 + 5x) = 4 + 13x + 22x^2 + 15x^3
  Prod = ecu_poly:mul(P1, P2),
  ?assertEqual([4, 13, 22, 15], Prod),
  %% Evaluation equivalence: (P1 * P2)(X) == P1(X) * P2(X) mod r
  X = 7,
  ValP1 = ecu_poly:eval(P1, X),
  ValP2 = ecu_poly:eval(P2, X),
  ValProd = ecu_poly:eval(Prod, X),
  ?assertEqual((ValP1 * ValP2) rem ?R, ValProd).

poly_synthetic_division_test() ->
  %% P(x) = x^2 - 4x + 3 = [3, -4, 1]
  P = [3, (?R - 4), 1],
  Z = 2,
  {Q, Remainder} = ecu_poly:divide_by_linear(P, Z),
  %% Remainder = P(2) = 4 - 8 + 3 = -1 = ?R - 1
  ?assertEqual(?R - 1, Remainder),
  ?assertEqual(ecu_poly:eval(P, Z), Remainder),
  %% Q(x) = x - 2 = [-2, 1] = [?R - 2, 1]
  ?assertEqual([?R - 2, 1], Q),
  %% Verify P(x) == Q(x)*(x - Z) + Remainder
  Linear = [(?R - Z) rem ?R, 1],
  Reconstructed = ecu_poly:add(ecu_poly:mul(Q, Linear), [Remainder]),
  ?assertEqual(ecu_poly:trim(P), ecu_poly:trim(Reconstructed)).

%%%-------------------------------------------------------------------
%%% KZG Commitment & Verification Tests
%%%-------------------------------------------------------------------

kzg_setup_test() ->
  Tau = 7,
  SRS = ecu_kzg:setup(3, Tau),
  G1Points = ecu_kzg:srs_g1(SRS),
  G2Points = ecu_kzg:srs_g2(SRS),
  ?assertEqual(4, length(G1Points)),
  ?assertEqual(2, length(G2Points)),
  G1Gen = ecu_bls12_381:g1_generator(),
  G2Gen = ecu_bls12_381:g2_generator(),
  ?assertEqual(G1Gen, lists:nth(1, G1Points)),
  ?assertEqual(ecu_bls12_381:g1_scalar_mul(G1Gen, 7), lists:nth(2, G1Points)),
  ?assertEqual(ecu_bls12_381:g1_scalar_mul(G1Gen, 49), lists:nth(3, G1Points)),
  ?assertEqual(G2Gen, lists:nth(1, G2Points)),
  ?assertEqual(ecu_bls12_381:g2_scalar_mul(G2Gen, 7), lists:nth(2, G2Points)).

kzg_commit_open_verify_test() ->
  SecretTau = 987654321012345,
  SRS = ecu_kzg:setup(10, SecretTau),
  %% P(x) = 5 + 3x + 7x^2 + 2x^3
  Poly = [5, 3, 7, 2],
  Commitment = ecu_kzg:commit(SRS, Poly),
  ?assert(ecu_bls12_381:g1_on_curve(Commitment)),

  Z = 42,
  {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),
  ?assertEqual(ecu_poly:eval(Poly, Z), Y),
  ?assert(ecu_bls12_381:g1_on_curve(Proof)),

  %% Verify proof in pure Erlang
  ?assertEqual(true, ecu_kzg:verify(SRS, Commitment, Z, Y, Proof)),

  %% Verify with compressed representation
  CompC = ecu_kzg:commit_compressed(SRS, Poly),
  {CompProof, Y} = ecu_kzg:create_proof_compressed(SRS, Poly, Z),
  ?assertEqual(true, ecu_kzg:verify_compressed(SRS, CompC, Z, Y, CompProof)).

kzg_tamper_test() ->
  SecretTau = 555111222333,
  SRS = ecu_kzg:setup(6, SecretTau),
  Poly = [1, 2, 3, 4],
  Commitment = ecu_kzg:commit(SRS, Poly),
  Z = 13,
  {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),

  %% Valid
  ?assertEqual(true, ecu_kzg:verify(SRS, Commitment, Z, Y, Proof)),

  %% Tampered Y
  ?assertEqual(false, ecu_kzg:verify(SRS, Commitment, Z, Y + 1, Proof)),

  %% Tampered Z
  ?assertEqual(false, ecu_kzg:verify(SRS, Commitment, Z + 1, Y, Proof)),

  %% Tampered Commitment
  G1Gen = ecu_bls12_381:g1_generator(),
  TamperedC = ecu_bls12_381:g1_add(Commitment, G1Gen),
  ?assertEqual(false, ecu_kzg:verify(SRS, TamperedC, Z, Y, Proof)),

  %% Tampered Proof
  TamperedProof = ecu_bls12_381:g1_add(Proof, G1Gen),
  ?assertEqual(false, ecu_kzg:verify(SRS, Commitment, Z, Y, TamperedProof)).

kzg_batch_verify_test() ->
  SecretTau = 123456789987654321,
  SRS = ecu_kzg:setup(8, SecretTau),

  %% Generate 4 independent polynomial commitments and evaluation proofs
  Tuples =
    lists:map(
      fun(I) ->
        Poly = [I, I * 2, I * 3, I * 4],
        C = ecu_kzg:commit(SRS, Poly),
        Z = I * 10 + 3,
        {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),
        {C, Z, Y, Proof}
      end,
      [1, 2, 3, 4]
    ),

  %% Batch verification of all 4 proofs in a single 2-pairing check
  ?assertEqual(true, ecu_kzg:verify_batch(SRS, Tuples)),

  %% Tamper the second tuple's Y
  {C2, Z2, Y2, Pi2} = lists:nth(2, Tuples),
  TamperedTuples = lists:keyreplace(C2, 1, Tuples, {C2, Z2, Y2 + 1, Pi2}),
  ?assertEqual(false, ecu_kzg:verify_batch(SRS, TamperedTuples)).

kzg_eip4844_point_evaluation_test() ->
  SecretTau = 777888999,
  SRS = ecu_kzg:setup(4, SecretTau),
  Poly = [10, 20, 30],
  CompC = ecu_kzg:commit_compressed(SRS, Poly),
  Z = 99,
  {CompProof, Y} = ecu_kzg:create_proof_compressed(SRS, Poly, Z),

  %% Form standard EIP-4844 192-byte input
  Sha = ecu_compat:hash(sha256, CompC),
  <<_:8, RestSha:31/binary>> = Sha,
  VersionedHash = <<16#01:8, RestSha:31/binary>>,
  ValidInput = <<VersionedHash:32/binary, Z:256/big, Y:256/big, CompC:48/binary, CompProof:48/binary>>,

  %% Successful evaluation
  ExpectedReturn = <<4096:256/big, ?R:256/big>>,
  ?assertEqual({ok, ExpectedReturn}, ecu_kzg:point_evaluation(SRS, ValidInput)),

  %% Tampered VersionedHash
  BadHash = <<16#02:8, RestSha:31/binary>>,
  BadInput1 = <<BadHash:32/binary, Z:256/big, Y:256/big, CompC:48/binary, CompProof:48/binary>>,
  ?assertEqual({error, invalid_versioned_hash}, ecu_kzg:point_evaluation(SRS, BadInput1)),

  %% Tampered Y
  BadInput2 =
    <<VersionedHash:32/binary, Z:256/big, (Y + 1):256/big, CompC:48/binary, CompProof:48/binary>>,
  ?assertEqual({error, verification_failed}, ecu_kzg:point_evaluation(SRS, BadInput2)),

  %% Invalid length
  ?assertEqual({error, invalid_input_length}, ecu_kzg:point_evaluation(SRS, <<0:100>>)).

kzg_nif_cross_verification_test() ->
  case code:ensure_loaded(ecu_bls12_381_nif) of
    {module, ecu_bls12_381_nif} ->
      case ecu_bls12_381_nif:is_available() of
        true ->
          SecretTau = 314159265358979,
          SRS = ecu_kzg:setup(6, SecretTau),
          Poly = [42, 17, 99, 100],
          CompC = ecu_kzg:commit_compressed(SRS, Poly),
          Z = 55,
          {CompProof, Y} = ecu_kzg:create_proof_compressed(SRS, Poly, Z),

          [G2Gen, TauG2] = ecu_kzg:srs_g2(SRS),
          CompG2Gen = ecu_bls12_381:g2_compress(G2Gen),
          CompTauG2 = ecu_bls12_381:g2_compress(TauG2),

          ZBin = <<Z:256/big>>,
          YBin = <<Y:256/big>>,

          %% Pure Erlang
          ErlRes = ecu_kzg:verify_compressed(SRS, CompC, Z, Y, CompProof),
          ?assertEqual(true, ErlRes),

          %% Rust NIF (blst) verify
          NifRes = ecu_bls12_381_nif:kzg_verify(
            CompC, ZBin, YBin, CompProof, CompG2Gen, CompTauG2
          ),
          ?assertEqual(true, NifRes),

          %% Tampered check in Rust NIF
          BadYBin = <<(Y + 1):256/big>>,
          NifBadRes = ecu_bls12_381_nif:kzg_verify(
            CompC, ZBin, BadYBin, CompProof, CompG2Gen, CompTauG2
          ),
          ?assertEqual(false, NifBadRes),

          %% Rust NIF commit cross-verification
          G1Bins = [ecu_bls12_381:g1_compress(Pt) || Pt <- ecu_kzg:srs_g1(SRS)],
          ScalarBins = [<<C:256/big>> || C <- Poly],
          {ok, NifCommit} = ecu_bls12_381_nif:kzg_commit(G1Bins, ScalarBins),
          ?assertEqual(CompC, NifCommit),

          %% Rust NIF proof creation cross-verification
          {ok, {NifProof, NifY}} = ecu_bls12_381_nif:kzg_create_proof(G1Bins, ScalarBins, ZBin),
          ?assertEqual(CompProof, NifProof),
          ?assertEqual(YBin, NifY),

          %% Rust NIF batch verify cross-verification
          Tuples =
            lists:map(
              fun(I) ->
                P = [I, I * 2, I * 3],
                C = ecu_kzg:commit_compressed(SRS, P),
                PtZ = I * 10 + 3,
                {Prf, ValY} = ecu_kzg:create_proof_compressed(SRS, P, PtZ),
                {C, <<PtZ:256/big>>, <<ValY:256/big>>, Prf}
              end,
              [1, 2, 3]
            ),
          ?assertEqual(true, ecu_bls12_381_nif:kzg_batch_verify(Tuples, CompG2Gen, CompTauG2)),

          %% Tampered batch verify in Rust NIF
          {C1, Z1, Y1, P1} = hd(Tuples),
          BadY1Val = (binary:decode_unsigned(Y1) + 1) rem ?R,
          BadTuples = [{C1, Z1, <<BadY1Val:256/big>>, P1} | tl(Tuples)],
          ?assertEqual(false, ecu_bls12_381_nif:kzg_batch_verify(BadTuples, CompG2Gen, CompTauG2)),

          %% Rust NIF EIP-4844 point evaluation cross-verification
          Sha = ecu_compat:hash(sha256, CompC),
          <<_:8, RestSha:31/binary>> = Sha,
          VersionedHash = <<16#01:8, RestSha:31/binary>>,
          ValidEipInput =
            <<VersionedHash:32/binary, ZBin:32/binary, YBin:32/binary, CompC:48/binary,
              CompProof:48/binary>>,
          ?assertEqual(
            true,
            ecu_bls12_381_nif:kzg_eip4844_point_eval(ValidEipInput, CompG2Gen, CompTauG2)
          ),

          BadEipInput =
            <<VersionedHash:32/binary, ZBin:32/binary, BadYBin:32/binary, CompC:48/binary,
              CompProof:48/binary>>,
          ?assertEqual(
            false,
            ecu_bls12_381_nif:kzg_eip4844_point_eval(BadEipInput, CompG2Gen, CompTauG2)
          );
        false ->
          ok
      end;
    _ ->
      ok
  end.
