%%%-------------------------------------------------------------------
%%% @doc
%%% Comprehensive EUnit test suite for Circom R1CS and WTNS tooling,
%%% including differential testing against Rust reference NIF (r1cs-file and wtns-file).
%%% @end
%%%-------------------------------------------------------------------
-module(circom_tests).

-include_lib("eunit/include/eunit.hrl").
-include("ecu_circom.hrl").
-include("ecu_bn254.hrl").
-include("ecu_bls12_381.hrl").
-include("ecu_groth16.hrl").

%%%===================================================================
%%% Unit Tests - Multiplier Circuit ($x \times y = out$)
%%%===================================================================

multiplier_circuit_test() ->
  %% Circuit: x * y = out
  %% Wires:
  %% 0: 1 (constant)
  %% 1: out (public output)
  %% 2: x (private input)
  %% 3: y (private input)
  Header = #r1cs_header{
    field_size = 32,
    prime = ?BN254_R,
    n_wires = 4,
    n_pub_out = 1,
    n_pub_in = 0,
    n_prvt_in = 2,
    n_labels = 4,
    n_constraints = 1
  },
  Constraint = {
    % 1 * x
    [{2, 1}],
    % 1 * y
    [{3, 1}],
    % 1 * out
    [{1, 1}]
  },
  WireMap = [100, 101, 102, 103],
  R1CS = ecu_circom:new_r1cs(Header, [Constraint], WireMap),

  %% Valid witness: x = 3, y = 11, out = 33
  WitnessGood = [1, 33, 3, 11],
  WTNSGood = ecu_circom:new_wtns(WitnessGood, 32),

  ?assertEqual(ok, ecu_circom:check_constraints(R1CS, WTNSGood)),
  ?assertEqual(ok, ecu_circom:check_constraints(R1CS, WitnessGood)),
  ?assert(ecu_circom:is_satisfied(R1CS, WTNSGood)),
  ?assert(ecu_circom:is_satisfied(R1CS, WitnessGood)),

  %% Invalid witness: x = 3, y = 11, out = 34 (tampered)
  WitnessBad = [1, 34, 3, 11],
  WTNSBad = ecu_circom:new_wtns(WitnessBad, 32),
  ?assertMatch(
    {error, {constraint_violated, 0, 3, 11, 34}}, ecu_circom:check_constraints(R1CS, WTNSBad)
  ),
  ?assertNot(ecu_circom:is_satisfied(R1CS, WTNSBad)),

  %% Extract public inputs
  ?assertEqual([33], ecu_circom:extract_public_inputs(WTNSGood, R1CS)),
  ?assertEqual([33], ecu_circom:extract_public_inputs(WitnessGood, Header)),
  PubMap = ecu_circom:extract_public_inputs_map(WTNSGood, R1CS),
  ?assertEqual(#{public_outputs => [33], public_inputs => []}, PubMap).

%%%===================================================================
%%% Unit Tests - Binary Roundtrip & Rust Oracle Cross-Verification
%%%===================================================================

r1cs_and_wtns_binary_roundtrip_test() ->
  Header = #r1cs_header{
    field_size = 32,
    prime = ?BN254_R,
    n_wires = 5,
    n_pub_out = 1,
    n_pub_in = 1,
    n_prvt_in = 2,
    n_labels = 5,
    n_constraints = 2
  },
  %% Constraints:
  %% 1: x * y = tmp   (w[3] * w[4] = w[2])
  %% 2: tmp + pub_in = out  ((w[2] + w[1]) * 1 = w[0]... or (tmp + pub_in) * 1 = out)
  %% Wire map:
  %% 0: constant 1
  %% 1: out (pub out)
  %% 2: pub_in (pub in)
  %% 3: x (private in)
  %% 4: y (private in)
  %% 5: tmp (intermediate wire) -> let's make n_wires = 6
  Header6 = Header#r1cs_header{n_wires = 6, n_labels = 6},
  % x * y = tmp
  C1 = {[{3, 1}], [{4, 1}], [{5, 1}]},
  % (tmp + pub_in) * 1 = out
  C2 = {[{5, 1}, {2, 1}], [{0, 1}], [{1, 1}]},
  WireMap = [0, 10, 20, 30, 40, 50],
  R1CS = ecu_circom:new_r1cs(Header6, [C1, C2], WireMap),

  %% Pure Erlang R1CS serialization and parsing
  R1CSBin = ecu_circom:serialize_r1cs(R1CS),
  {ok, ParsedR1CS} = ecu_circom:parse_r1cs(R1CSBin),
  ?assertEqual(R1CS#r1cs.header, ParsedR1CS#r1cs.header),
  ?assertEqual(R1CS#r1cs.constraints, ParsedR1CS#r1cs.constraints),
  ?assertEqual(R1CS#r1cs.wire_map, ParsedR1CS#r1cs.wire_map),

  %% Witness: x = 4, y = 5 -> tmp = 20; pub_in = 7 -> out = 27
  %% Wires: 0: 1, 1: 27, 2: 7, 3: 4, 4: 5, 5: 20
  Witness = [1, 27, 7, 4, 5, 20],
  WTNS = ecu_circom:new_wtns(Witness, 32),
  WTNSBin = ecu_circom:serialize_wtns(WTNS),
  {ok, ParsedWTNS} = ecu_circom:parse_wtns(WTNSBin),
  ?assertEqual(WTNS#wtns.header, ParsedWTNS#wtns.header),
  ?assertEqual(WTNS#wtns.witness, ParsedWTNS#wtns.witness),

  ?assertEqual(ok, ecu_circom:check_constraints(ParsedR1CS, ParsedWTNS)),

  %% Differential testing against Rust reference NIF (if available)
  case ecu_circom_nif:is_available() of
    true ->
      %% 1. Rust NIF parse info
      {ok, RustR1CSInfo} = ecu_circom_nif:r1cs_info(R1CSBin),
      ?assertEqual(6, maps:get(n_wires, RustR1CSInfo)),
      ?assertEqual(2, maps:get(n_constraints, RustR1CSInfo)),
      ?assertEqual(1, maps:get(n_pub_out, RustR1CSInfo)),
      ?assertEqual(1, maps:get(n_pub_in, RustR1CSInfo)),

      {ok, RustWTNSInfo} = ecu_circom_nif:wtns_info(WTNSBin),
      ?assertEqual(6, maps:get(witness_len, RustWTNSInfo)),

      %% 2. Rust NIF roundtrip equality
      {ok, RustR1CSRoundtrip} = ecu_circom_nif:r1cs_roundtrip(R1CSBin),
      ?assertEqual(R1CSBin, RustR1CSRoundtrip),

      {ok, RustWTNSRoundtrip} = ecu_circom_nif:wtns_roundtrip(WTNSBin),
      ?assertEqual(WTNSBin, RustWTNSRoundtrip),

      %% 3. Rust NIF constraint verification
      ?assertEqual({ok, true}, ecu_circom_nif:check_constraints(R1CSBin, WTNSBin)),

      %% 4. Tampered witness fails in both Erlang and Rust
      TamperedWitness = [1, 28, 7, 4, 5, 20],
      TamperedWTNSBin = ecu_circom:serialize_wtns(TamperedWitness, ?BN254_R),
      ?assertEqual(
        {error, {constraint_violated, 1, 27, 1, 28}}, ecu_circom:check_constraints(R1CS, TamperedWitness)
      ),
      ?assertEqual({ok, false}, ecu_circom_nif:check_constraints(R1CSBin, TamperedWTNSBin));
    false ->
      ok
  end.

%%%===================================================================
%%% Unit Tests - Boolean Constraints & Modular Factors
%%%===================================================================

boolean_constraint_test() ->
  %% Constraint: b * (1 - b) = 0
  %% In R1CS form: (b) * (1 - b) = 0
  %% A = [{1, 1}]  (1 * b)
  %% B = [{0, 1}, {1, -1}]  (1 * 1 + (-1) * b)
  %% C = []  (0)
  Prime = ?BN254_R,
  Header = #r1cs_header{
    field_size = 32,
    prime = Prime,
    n_wires = 2,
    n_pub_out = 0,
    n_pub_in = 1,
    n_prvt_in = 0,
    n_labels = 2,
    n_constraints = 1
  },
  C = {
    [{1, 1}],
    [{0, 1}, {1, -1}],
    []
  },
  R1CS = ecu_circom:new_r1cs(Header, [C]),

  %% Test b = 0 (valid)
  ?assertEqual(ok, ecu_circom:check_constraints(R1CS, [1, 0])),

  %% Test b = 1 (valid)
  ?assertEqual(ok, ecu_circom:check_constraints(R1CS, [1, 1])),

  %% Test b = 2 (invalid)
  ?assertMatch({error, {constraint_violated, 0, _, _, _}}, ecu_circom:check_constraints(R1CS, [1, 2])),

  %% Test roundtrip with negative factor
  R1CSBin = ecu_circom:serialize_r1cs(R1CS),
  {ok, ParsedR1CS} = ecu_circom:parse_r1cs(R1CSBin),
  ?assertEqual(ok, ecu_circom:check_constraints(ParsedR1CS, [1, 0])),
  ?assertEqual(ok, ecu_circom:check_constraints(ParsedR1CS, [1, 1])),
  ?assertMatch({error, _}, ecu_circom:check_constraints(ParsedR1CS, [1, 2])).

%%%===================================================================
%%% Unit Tests - BLS12-381 Scalar Field
%%%===================================================================

bls12_381_circuit_test() ->
  Prime = ecu_circom:default_prime(bls12_381),
  ?assertEqual(?BLS12_381_R, Prime),

  Header = #r1cs_header{
    field_size = 32,
    prime = Prime,
    n_wires = 3,
    n_pub_out = 1,
    n_pub_in = 1,
    n_prvt_in = 0,
    n_labels = 3,
    n_constraints = 1
  },
  %% Constraint: in * in = out
  C = {[{2, 1}], [{2, 1}], [{1, 1}]},
  R1CS = ecu_circom:new_r1cs(Header, [C]),

  %% Witness: in = 7, out = 49
  Witness = [1, 49, 7],
  WTNS = ecu_circom:new_wtns(Witness, Prime, 32),

  ?assertEqual(ok, ecu_circom:check_constraints(R1CS, WTNS)),

  R1CSBin = ecu_circom:serialize_r1cs(R1CS),
  WTNSBin = ecu_circom:serialize_wtns(WTNS),

  {ok, ParsedR1CS} = ecu_circom:parse_r1cs(R1CSBin),
  {ok, ParsedWTNS} = ecu_circom:parse_wtns(WTNSBin),

  ?assertEqual(ok, ecu_circom:check_constraints(ParsedR1CS, ParsedWTNS)).

%%%===================================================================
%%% Unit Tests - File I/O
%%%===================================================================

file_io_test() ->
  TmpDir = os:cmd("mktemp -d"),
  CleanTmpDir = string:trim(TmpDir),
  R1csPath = filename:join(CleanTmpDir, "test.r1cs"),
  WtnsPath = filename:join(CleanTmpDir, "test.wtns"),

  Header = #r1cs_header{
    field_size = 32,
    prime = ?BN254_R,
    n_wires = 3,
    n_pub_out = 1,
    n_pub_in = 1,
    n_prvt_in = 0,
    n_labels = 3,
    n_constraints = 1
  },
  C = {[{2, 1}], [{2, 1}], [{1, 1}]},
  R1CS = ecu_circom:new_r1cs(Header, [C]),
  Witness = [1, 100, 10],
  WTNS = ecu_circom:new_wtns(Witness, 32),

  ok = file:write_file(R1csPath, ecu_circom:serialize_r1cs(R1CS)),
  ok = file:write_file(WtnsPath, ecu_circom:serialize_wtns(WTNS)),

  {ok, FileR1CS} = ecu_circom:parse_r1cs(R1csPath),
  {ok, FileWTNS} = ecu_circom:parse_wtns(WtnsPath),

  ?assertEqual(ok, ecu_circom:check_constraints(FileR1CS, FileWTNS)),
  ?assertEqual([100, 10], ecu_circom:extract_public_inputs(FileWTNS, FileR1CS)),

  _ = file:delete(R1csPath),
  _ = file:delete(WtnsPath),
  _ = file:del_dir(CleanTmpDir).

%%%===================================================================
%%% Unit Tests - Public Input Extraction & Groth16 Compatibility
%%%===================================================================

groth16_public_input_bridge_test() ->
  %% Test that extracted public inputs match the scalar list required by Groth16
  Header = #r1cs_header{
    field_size = 32,
    prime = ?BN254_R,
    n_wires = 6,
    n_pub_out = 2,
    n_pub_in = 1,
    n_prvt_in = 2,
    n_labels = 6,
    n_constraints = 1
  },
  %% Wire layout:
  %% 0: 1 (const)
  %% 1: out1
  %% 2: out2
  %% 3: pub_in1
  %% 4: priv_in1
  %% 5: priv_in2
  Witness = [1, 111, 222, 333, 444, 555],

  PublicInputs = ecu_circom:extract_public_inputs(Witness, Header),
  ?assertEqual([111, 222, 333], PublicInputs),

  PubMap = ecu_circom:extract_public_inputs_map(Witness, Header),
  ?assertEqual(
    #{
      public_outputs => [111, 222],
      public_inputs => [333]
    },
    PubMap
  ).

%%%===================================================================
%%% Unit Tests - Error Handling & Edge Cases
%%%===================================================================

error_handling_test() ->
  %% Bad magic
  ?assertEqual({error, invalid_r1cs_magic}, ecu_circom:parse_r1cs(<<"bad_data_here">>)),
  ?assertEqual({error, invalid_wtns_magic}, ecu_circom:parse_wtns(<<"bad_data_here">>)),

  %% Witness too short
  Header = #r1cs_header{
    field_size = 32,
    prime = ?BN254_R,
    n_wires = 5,
    n_pub_out = 1,
    n_pub_in = 0,
    n_prvt_in = 3,
    n_labels = 5,
    n_constraints = 1
  },
  R1CS = ecu_circom:new_r1cs(Header, [{[{2, 1}], [{3, 1}], [{1, 1}]}]),
  ShortWitness = [1, 6],
  ?assertEqual({error, {witness_too_short, 2, 5}}, ecu_circom:check_constraints(R1CS, ShortWitness)),

  %% Wire ID out of bounds in constraint
  BadConstraint = {[{99, 1}], [{1, 1}], [{1, 1}]},
  BadR1CS = ecu_circom:new_r1cs(Header#r1cs_header{n_wires = 5}, [BadConstraint]),
  ?assertEqual(
    {error, {invalid_wire_id, 99, 4}}, ecu_circom:check_constraints(BadR1CS, [1, 2, 3, 4, 5])
  ).
