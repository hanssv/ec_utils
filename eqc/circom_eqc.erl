%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang Circom R1CS and WTNS tooling:
%%%   - R1CS binary serialization and parsing roundtrip
%%%   - WTNS binary serialization and parsing roundtrip
%%%   - Constraint satisfaction completeness on generated circuits
%%%   - Tamper detection on mutated witnesses
%%%   - Public input extraction invariants
%%%   - Differential cross-verification against Rust reference NIF (r1cs-file, wtns-file)
%%% @end
%%%-------------------------------------------------------------------
-module(circom_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_circom.hrl").
-include("ecu_bn254.hrl").
-include("ecu_bls12_381.hrl").

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_prime() ->
  elements([?BN254_R, ?BLS12_381_R]).

gen_field_element(Prime) ->
  choose(0, Prime - 1).

%% Generator for a sequence of multiplication gates:
%% Wire 0 = 1
%% Private inputs: wires 1 .. NIn
%% Multiplier gates: each gate k = 1 + NIn + GateIdx computes w[k] = w[i] * w[j] rem Prime
gen_valid_circuit_and_witness() ->
  ?LET(
    Prime,
    gen_prime(),
    ?LET(
      NIn,
      choose(1, 4),
      ?LET(
        Inputs,
        vector(NIn, choose(1, 1000)),
        gen_gates_and_witness(Prime, NIn, Inputs)
      )
    )
  ).

gen_gates_and_witness(Prime, NIn, Inputs) ->
  ?LET(
    NGates,
    choose(1, 6),
    begin
      InitialWitness = [1 | Inputs],
      build_gates(NGates, 0, NIn, InitialWitness, [], [], Prime)
    end
  ).

build_gates(0, _Idx, NIn, Witness, Constraints, OutWires, Prime) ->
  NWires = length(Witness),
  Header = #r1cs_header{
    field_size = 32,
    prime = Prime,
    n_wires = NWires,
    n_pub_out = 1,
    n_pub_in = NIn - 1,
    n_prvt_in = 1,
    n_labels = NWires,
    n_constraints = length(Constraints)
  },
  R1CS = ecu_circom:new_r1cs(Header, lists:reverse(Constraints)),
  WTNS = ecu_circom:new_wtns(Witness, Prime, 32),
  {R1CS, WTNS, Prime, lists:reverse(OutWires)};
build_gates(Remaining, GateIdx, NIn, Witness, Constraints, OutWires, Prime) ->
  MaxWire = length(Witness) - 1,
  ?LET(
    {WireA, WireB},
    {choose(0, MaxWire), choose(0, MaxWire)},
    begin
      ValA = lists:nth(WireA + 1, Witness),
      ValB = lists:nth(WireB + 1, Witness),
      OutWire = length(Witness),
      OutVal = (ValA * ValB) rem Prime,
      NewWitness = Witness ++ [OutVal],
      NewConstraint = {
        [{WireA, 1}],
        [{WireB, 1}],
        [{OutWire, 1}]
      },
      build_gates(
        Remaining - 1,
        GateIdx + 1,
        NIn,
        NewWitness,
        [NewConstraint | Constraints],
        [OutWire | OutWires],
        Prime
      )
    end
  ).

%%%-------------------------------------------------------------------
%%% Properties: Binary Roundtrip
%%%-------------------------------------------------------------------

prop_r1cs_roundtrip() ->
  ?FORALL(
    {R1CS, _WTNS, _Prime, _OutWires},
    gen_valid_circuit_and_witness(),
    begin
      Bin = ecu_circom:serialize_r1cs(R1CS),
      case ecu_circom:parse_r1cs(Bin) of
        {ok, Parsed} ->
          (Parsed#r1cs.header =:= R1CS#r1cs.header) andalso
            (Parsed#r1cs.constraints =:= R1CS#r1cs.constraints);
        _ ->
          false
      end
    end
  ).

prop_wtns_roundtrip() ->
  ?FORALL(
    {_R1CS, WTNS, _Prime, _OutWires},
    gen_valid_circuit_and_witness(),
    begin
      Bin = ecu_circom:serialize_wtns(WTNS),
      case ecu_circom:parse_wtns(Bin) of
        {ok, Parsed} ->
          (Parsed#wtns.header =:= WTNS#wtns.header) andalso
            (Parsed#wtns.witness =:= WTNS#wtns.witness);
        _ ->
          false
      end
    end
  ).

%%%-------------------------------------------------------------------
%%% Properties: Constraint Satisfaction & Tamper Detection
%%%-------------------------------------------------------------------

prop_constraint_satisfaction() ->
  ?FORALL(
    {R1CS, WTNS, _Prime, _OutWires},
    gen_valid_circuit_and_witness(),
    begin
      ecu_circom:is_satisfied(R1CS, WTNS) andalso
        (ecu_circom:check_constraints(R1CS, WTNS) =:= ok)
    end
  ).

prop_tamper_detection() ->
  ?FORALL(
    {R1CS, WTNS, Prime, OutWires},
    gen_valid_circuit_and_witness(),
    begin
      Witness = WTNS#wtns.witness,
      ?LET(
        MutateIdx,
        elements(OutWires),
        begin
          OldVal = lists:nth(MutateIdx + 1, Witness),
          NewVal = (OldVal + 1) rem Prime,
          MutatedWitness = set_nth(MutateIdx + 1, Witness, NewVal),
          MutatedWTNS = WTNS#wtns{witness = MutatedWitness},
          %% Tampered witness should not satisfy the circuit constraints
          not ecu_circom:is_satisfied(R1CS, MutatedWTNS)
        end
      )
    end
  ).

prop_public_input_extraction() ->
  ?FORALL(
    {R1CS, WTNS, _Prime, _OutWires},
    gen_valid_circuit_and_witness(),
    begin
      PubInputs = ecu_circom:extract_public_inputs(WTNS, R1CS),
      H = R1CS#r1cs.header,
      TotalPub = H#r1cs_header.n_pub_out + H#r1cs_header.n_pub_in,
      LengthMatch = (length(PubInputs) =:= TotalPub),
      Witness = WTNS#wtns.witness,
      SliceMatch = (PubInputs =:= lists:sublist(Witness, 2, TotalPub)),
      LengthMatch andalso SliceMatch
    end
  ).

%%%-------------------------------------------------------------------
%%% Properties: Differential Cross-Verification against Rust NIF
%%%-------------------------------------------------------------------

prop_differential_nif() ->
  case code:ensure_loaded(ecu_circom_nif) of
    {module, ecu_circom_nif} ->
      case ecu_circom_nif:is_available() of
        true ->
          ?FORALL(
            {R1CS, WTNS, Prime, OutWires},
            gen_valid_circuit_and_witness(),
            begin
              case Prime of
                ?BN254_R ->
                  R1CSBin = ecu_circom:serialize_r1cs(R1CS),
                  WTNSBin = ecu_circom:serialize_wtns(WTNS),

                  %% 1. Rust roundtrips binary identical
                  {ok, NifR1CSBin} = ecu_circom_nif:r1cs_roundtrip(R1CSBin),
                  {ok, NifWTNSBin} = ecu_circom_nif:wtns_roundtrip(WTNSBin),
                  R1CSMatch = (R1CSBin =:= NifR1CSBin),
                  WTNSMatch = (WTNSBin =:= NifWTNSBin),

                  %% 2. Rust verifies satisfying witness
                  {ok, NifSatisfied} = ecu_circom_nif:check_constraints(R1CSBin, WTNSBin),
                  ErlSatisfied = ecu_circom:is_satisfied(R1CS, WTNS),

                  %% 3. Rust rejects tampered witness
                  Witness = WTNS#wtns.witness,
                  MutateWire = lists:last(OutWires),
                  MutatedWitness = set_nth(
                    MutateWire + 1, Witness, (lists:nth(MutateWire + 1, Witness) + 1) rem Prime
                  ),
                  MutatedWTNSBin = ecu_circom:serialize_wtns(MutatedWitness, Prime),
                  {ok, NifRejects} = ecu_circom_nif:check_constraints(R1CSBin, MutatedWTNSBin),

                  R1CSMatch andalso WTNSMatch andalso NifSatisfied andalso ErlSatisfied andalso
                    (not NifRejects);
                _ ->
                  %% Rust NIF r1cs-file<32> is instantiated with BN254 field size
                  true
              end
            end
          );
        false ->
          true
      end;
    _ ->
      true
  end.

prop_circom_adversarial_rejections() ->
  ?FORALL(
    {R1CS, WTNS, Prime, _OutWires},
    gen_valid_circuit_and_witness(),
    begin
      Witness = WTNS#wtns.witness,
      H = R1CS#r1cs.header,

      %% 1. All-zero witness (Wire 0 = 0) must be rejected
      AllZeroWitness = lists:duplicate(length(Witness), 0),
      ZeroRejected =
        (not ecu_circom:is_satisfied(R1CS, AllZeroWitness)) andalso
          (ecu_circom:check_constraints(R1CS, AllZeroWitness) =:= {error, invalid_wire_zero}),

      %% 2. Non-unitary Wire 0 (Wire 0 = 2) must be rejected
      NonUnitaryWitness = set_nth(1, Witness, 2),
      NonUnitaryRejected =
        (not ecu_circom:is_satisfied(R1CS, NonUnitaryWitness)) andalso
          (ecu_circom:check_constraints(R1CS, NonUnitaryWitness) =:= {error, invalid_wire_zero}),

      %% 3. Prime mismatch between circuit and witness must be rejected
      MismatchedPrime =
        case Prime of
          ?BN254_R -> ?BLS12_381_R;
          _ -> ?BN254_R
        end,
      MismatchedWTNS = WTNS#wtns{header = (WTNS#wtns.header)#wtns_header{prime = MismatchedPrime}},
      PrimeMismatchRejected =
        (not ecu_circom:is_satisfied(R1CS, MismatchedWTNS)) andalso
          (ecu_circom:check_constraints(R1CS, MismatchedWTNS) =:=
            {error, {prime_mismatch, MismatchedPrime, H#r1cs_header.prime}}),

      %% 4. Truncated WTNS binary must return error tuple and not crash
      WTNSBin = ecu_circom:serialize_wtns(WTNS),
      TruncatedBin =
        case byte_size(WTNSBin) > 32 of
          true -> binary:part(WTNSBin, 0, byte_size(WTNSBin) - 32);
          false -> <<>>
        end,
      TruncatedRejected =
        case ecu_circom:parse_wtns(TruncatedBin) of
          {error, _} -> true;
          _ -> false
        end,

      ZeroRejected andalso NonUnitaryRejected andalso PrimeMismatchRejected andalso TruncatedRejected
    end
  ).

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

set_nth(1, [_ | Rest], Val) ->
  [Val | Rest];
set_nth(N, [Head | Rest], Val) when N > 1 ->
  [Head | set_nth(N - 1, Rest, Val)].
