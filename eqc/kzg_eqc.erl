%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang KZG polynomial commitments
%%% (ecu_kzg) and polynomial arithmetic (ecu_poly):
%%%   - Polynomial evaluation homomorphism and synthetic division
%%%   - Commitment linearity and homomorphic addition
%%%   - Proof evaluation soundness (P(z) = y)
%%%   - Tampering detection (Z, Y, C, Proof)
%%%   - Randomized batch verification
%%%   - Differential cross-verification against Rust reference NIF (blst)
%%% @end
%%%-------------------------------------------------------------------
-module(kzg_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_bls12_381.hrl").

-define(R, ?BLS12_381_R).

%%%-------------------------------------------------------------------
%%% Test SRS Cache
%%%-------------------------------------------------------------------

get_srs() ->
  case persistent_term:get({?MODULE, srs}, undefined) of
    undefined ->
      SRS = ecu_kzg:setup(8, 1234567890987654321),
      persistent_term:put({?MODULE, srs}, SRS),
      SRS;
    SRS ->
      SRS
  end.

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_field_element() ->
  choose(0, ?R - 1).

gen_non_zero_scalar() ->
  choose(1, ?R - 1).

gen_poly(MaxDegree) ->
  ?LET(
    Len,
    choose(1, MaxDegree + 1),
    vector(Len, gen_field_element())
  ).

gen_small_poly() ->
  gen_poly(5).

%%%-------------------------------------------------------------------
%%% Properties: Polynomial Arithmetic
%%%-------------------------------------------------------------------

prop_poly_eval_homomorphism() ->
  ?FORALL(
    {P1, P2, X},
    {gen_small_poly(), gen_small_poly(), gen_field_element()},
    begin
      Sum = ecu_poly:add(P1, P2),
      Prod = ecu_poly:mul(P1, P2),
      Val1 = ecu_poly:eval(P1, X),
      Val2 = ecu_poly:eval(P2, X),
      ValSum = ecu_poly:eval(Sum, X),
      ValProd = ecu_poly:eval(Prod, X),
      (ValSum =:= (Val1 + Val2) rem ?R) andalso (ValProd =:= (Val1 * Val2) rem ?R)
    end
  ).

prop_poly_synthetic_division() ->
  ?FORALL(
    {P, Z},
    {gen_small_poly(), gen_field_element()},
    begin
      {Q, Remainder} = ecu_poly:divide_by_linear(P, Z),
      ExpectedRemainder = ecu_poly:eval(P, Z),
      Linear = [(?R - Z) rem ?R, 1],
      Reconstructed = ecu_poly:add(ecu_poly:mul(Q, Linear), [Remainder]),
      (Remainder =:= ExpectedRemainder) andalso
        (ecu_poly:trim(P) =:= ecu_poly:trim(Reconstructed))
    end
  ).

%%%-------------------------------------------------------------------
%%% Properties: KZG Commitments & Proofs
%%%-------------------------------------------------------------------

prop_kzg_commitment_homomorphism() ->
  SRS = get_srs(),
  ?FORALL(
    {P1, P2},
    {gen_small_poly(), gen_small_poly()},
    begin
      SumP = ecu_poly:add(P1, P2),
      C1 = ecu_kzg:commit(SRS, P1),
      C2 = ecu_kzg:commit(SRS, P2),
      CSum = ecu_kzg:commit(SRS, SumP),
      CAdd = ecu_bls12_381:g1_add(C1, C2),
      CSum =:= CAdd
    end
  ).

prop_kzg_open_verify() ->
  SRS = get_srs(),
  ?FORALL(
    {Poly, Z},
    {gen_small_poly(), gen_field_element()},
    begin
      C = ecu_kzg:commit(SRS, Poly),
      {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),
      ExpectedY = ecu_poly:eval(Poly, Z),
      (Y =:= ExpectedY) andalso ecu_kzg:verify(SRS, C, Z, Y, Proof)
    end
  ).

prop_kzg_tamper_detection() ->
  SRS = get_srs(),
  ?FORALL(
    {Poly, Z, BadYOffset},
    {gen_small_poly(), gen_field_element(), choose(1, 1000)},
    begin
      C = ecu_kzg:commit(SRS, Poly),
      {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),
      BadY = (Y + BadYOffset) rem ?R,
      BadZ = (Z + BadYOffset) rem ?R,
      G1Gen = ecu_bls12_381:g1_generator(),
      BadProof = ecu_bls12_381:g1_add(Proof, G1Gen),
      BadC = ecu_bls12_381:g1_add(C, G1Gen),

      BadZValid = (ecu_poly:eval(Poly, BadZ) =:= Y),
      BadZCheck =
        case BadZValid of
          true -> true;
          false -> not ecu_kzg:verify(SRS, C, BadZ, Y, Proof)
        end,

      (not ecu_kzg:verify(SRS, C, Z, BadY, Proof)) andalso
        BadZCheck andalso
        (not ecu_kzg:verify(SRS, BadC, Z, Y, Proof)) andalso
        (not ecu_kzg:verify(SRS, C, Z, Y, BadProof))
    end
  ).

prop_kzg_batch_verify() ->
  SRS = get_srs(),
  ?FORALL(
    PolysWithZ,
    non_empty(list({gen_small_poly(), gen_field_element()})),
    begin
      Tuples =
        [
          begin
            C = ecu_kzg:commit(SRS, Poly),
            {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),
            {C, Z, Y, Proof}
          end
         || {Poly, Z} <- PolysWithZ
        ],
      Valid = ecu_kzg:verify_batch(SRS, Tuples),
      %% Tamper the first element's Y
      [{C0, Z0, Y0, Pi0} | Rest] = Tuples,
      BadTuples = [{C0, Z0, (Y0 + 1) rem ?R, Pi0} | Rest],
      Invalid = ecu_kzg:verify_batch(SRS, BadTuples),
      Valid andalso (not Invalid)
    end
  ).

prop_kzg_nif_differential() ->
  case code:ensure_loaded(ecu_bls12_381_nif) of
    {module, ecu_bls12_381_nif} ->
      case ecu_bls12_381_nif:is_available() of
        true ->
          SRS = get_srs(),
          G1Bins = [ecu_bls12_381:g1_compress(Pt) || Pt <- ecu_kzg:srs_g1(SRS)],
          [G2Gen, TauG2] = ecu_kzg:srs_g2(SRS),
          CompG2Gen = ecu_bls12_381:g2_compress(G2Gen),
          CompTauG2 = ecu_bls12_381:g2_compress(TauG2),
          ?FORALL(
            {Poly, Z},
            {gen_small_poly(), gen_field_element()},
            begin
              ScalarBins = [<<C:256/big>> || C <- Poly],
              CompC = ecu_kzg:commit_compressed(SRS, Poly),
              {CompProof, Y} = ecu_kzg:create_proof_compressed(SRS, Poly, Z),
              ZBin = <<Z:256/big>>,
              YBin = <<Y:256/big>>,

              %% 1. Verify differential
              ErlRes = ecu_kzg:verify_compressed(SRS, CompC, Z, Y, CompProof),
              NifRes = ecu_bls12_381_nif:kzg_verify(
                CompC, ZBin, YBin, CompProof, CompG2Gen, CompTauG2
              ),

              BadYBin = <<((Y + 1) rem ?R):256/big>>,
              NifBadRes = ecu_bls12_381_nif:kzg_verify(
                CompC, ZBin, BadYBin, CompProof, CompG2Gen, CompTauG2
              ),

              %% 2. Commit differential
              {ok, NifCommit} = ecu_bls12_381_nif:kzg_commit(G1Bins, ScalarBins),
              CommitMatches = (CompC =:= NifCommit),

              %% 3. Proof creation differential
              {ok, {NifProof, NifY}} = ecu_bls12_381_nif:kzg_create_proof(
                G1Bins, ScalarBins, ZBin
              ),
              ProofMatches = (CompProof =:= NifProof) andalso (YBin =:= NifY),

              ErlRes andalso NifRes andalso (not NifBadRes) andalso CommitMatches andalso
                ProofMatches
            end
          );
        false ->
          true
      end;
    _ ->
      true
  end.

prop_kzg_batch_verify_differential() ->
  case code:ensure_loaded(ecu_bls12_381_nif) of
    {module, ecu_bls12_381_nif} ->
      case ecu_bls12_381_nif:is_available() of
        true ->
          SRS = get_srs(),
          [G2Gen, TauG2] = ecu_kzg:srs_g2(SRS),
          CompG2Gen = ecu_bls12_381:g2_compress(G2Gen),
          CompTauG2 = ecu_bls12_381:g2_compress(TauG2),
          ?FORALL(
            PolysWithZ,
            non_empty(list({gen_small_poly(), gen_field_element()})),
            begin
              Tuples =
                [
                  begin
                    C = ecu_kzg:commit_compressed(SRS, Poly),
                    {Proof, Y} = ecu_kzg:create_proof_compressed(SRS, Poly, Z),
                    {C, <<Z:256/big>>, <<Y:256/big>>, Proof}
                  end
                 || {Poly, Z} <- PolysWithZ
                ],
              ErlTuples = [
                {C, binary:decode_unsigned(ZBin), binary:decode_unsigned(YBin), P}
               || {C, ZBin, YBin, P} <- Tuples
              ],
              ErlBatch = ecu_kzg:verify_batch(SRS, ErlTuples),
              NifBatch = ecu_bls12_381_nif:kzg_batch_verify(Tuples, CompG2Gen, CompTauG2),

              [{C0, Z0, Y0, Pi0} | Rest] = Tuples,
              BadY0Val = (binary:decode_unsigned(Y0) + 1) rem ?R,
              BadTuples = [{C0, Z0, <<BadY0Val:256/big>>, Pi0} | Rest],
              NifBadBatch = ecu_bls12_381_nif:kzg_batch_verify(
                BadTuples, CompG2Gen, CompTauG2
              ),

              ErlBatch andalso NifBatch andalso (not NifBadBatch)
            end
          );
        false ->
          true
      end;
    _ ->
      true
  end.

prop_kzg_adversarial_rejections() ->
  SRS = get_srs(),
  ?FORALL(
    {Poly, Z, BadScalarOffset},
    {gen_small_poly(), gen_field_element(), choose(1, 1000)},
    begin
      C = ecu_kzg:commit(SRS, Poly),
      {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),

      %% 1. Rejection of empty batch
      EmptyBatchRejected = not ecu_kzg:verify_batch(SRS, []),

      %% 2. Rejection of out-of-range scalars (Z >= ?R, Y >= ?R, negative)
      BadZ1 = ?R + BadScalarOffset,
      BadZ2 = -BadScalarOffset,
      BadY1 = ?R + BadScalarOffset,
      BadY2 = -BadScalarOffset,

      OutOfRangeZ1 = not ecu_kzg:verify(SRS, C, BadZ1, Y, Proof),
      OutOfRangeZ2 = not ecu_kzg:verify(SRS, C, BadZ2, Y, Proof),
      OutOfRangeY1 = not ecu_kzg:verify(SRS, C, Z, BadY1, Proof),
      OutOfRangeY2 = not ecu_kzg:verify(SRS, C, Z, BadY2, Proof),

      %% 3. Rejection of out-of-range scalars in batch verify
      BadBatchZ = not ecu_kzg:verify_batch(SRS, [{C, BadZ1, Y, Proof}]),
      BadBatchY = not ecu_kzg:verify_batch(SRS, [{C, Z, BadY1, Proof}]),

      %% 4. Rejection of invalid Tau in setup
      InvalidTauZero =
        try ecu_kzg:setup(3, 0) of
          _ -> false
        catch
          error:invalid_secret_tau -> true;
          _:_ -> false
        end,
      InvalidTauOne =
        try ecu_kzg:setup(3, 1) of
          _ -> false
        catch
          error:invalid_secret_tau -> true;
          _:_ -> false
        end,
      InvalidTauR =
        try ecu_kzg:setup(3, ?R) of
          _ -> false
        catch
          error:invalid_secret_tau -> true;
          _:_ -> false
        end,
      InvalidTauNeg =
        try ecu_kzg:setup(3, -5) of
          _ -> false
        catch
          error:invalid_secret_tau -> true;
          _:_ -> false
        end,

      %% 5. Rejection of invalid degree in setup
      InvalidDegree =
        try ecu_kzg:setup(0, 7) of
          _ -> false
        catch
          error:invalid_degree -> true;
          _:_ -> false
        end,

      %% 6. Rejection of torsion point in commitment / proof / batch
      TorsionPt = {0, 2},
      TorsionCRejected = not ecu_kzg:verify(SRS, TorsionPt, Z, Y, Proof),
      TorsionProofRejected = not ecu_kzg:verify(SRS, C, Z, Y, TorsionPt),
      TorsionBatchRejected = not ecu_kzg:verify_batch(SRS, [{TorsionPt, Z, Y, Proof}]),

      EmptyBatchRejected andalso OutOfRangeZ1 andalso OutOfRangeZ2 andalso
        OutOfRangeY1 andalso OutOfRangeY2 andalso BadBatchZ andalso BadBatchY andalso
        InvalidTauZero andalso InvalidTauOne andalso InvalidTauR andalso InvalidTauNeg andalso
        InvalidDegree andalso TorsionCRejected andalso TorsionProofRejected andalso
        TorsionBatchRejected
    end
  ).
