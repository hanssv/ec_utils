%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang Circom 2 and ZoKrates R1CS & Witness (.wtns) Tooling.
%%%
%%% Implements binary serialization, parsing, constraint checking, and
%%% public input extraction for zero-knowledge arithmetic circuits in
%%% Circom 2 format (`.r1cs` version 1) and witness format (`.wtns` version 2).
%%%
%%% Features:
%%%   - Binary parser and serializer for Circom 2 `.r1cs` files
%%%   - Binary parser and serializer for Circom `.wtns` witness files
%%%   - Constraint satisfaction validator: verifies witness vector $W$
%%%     against R1CS constraints: $(A \cdot W) \times (B \cdot W) \equiv (C \cdot W) \pmod q$
%%%   - Fast $O(1)$ wire lookup during linear combination evaluation
%%%   - Public input / output vector extraction compatible with `ecu_groth16:verify/3,4`
%%%   - Default support for BN254 (alt_bn128) and BLS12-381 scalar fields
%%%
%%% Reference:
%%%   Circom 2 R1CS binary specification and SnarkJS witness architecture.
%%%   https://github.com/iden3/r1csfile
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_circom).

-typing([eqwalizer]).

-include("ecu_circom.hrl").
-include("ecu_bn254.hrl").
-include("ecu_bls12_381.hrl").

-export([
  parse_r1cs/1,
  serialize_r1cs/1,
  r1cs_info/1,
  parse_wtns/1,
  serialize_wtns/1,
  serialize_wtns/2,
  serialize_wtns/3,
  wtns_info/1,
  eval_lc/3,
  check_constraints/2,
  is_satisfied/2,
  extract_public_inputs/2,
  extract_public_inputs_map/2,
  new_r1cs/2,
  new_r1cs/3,
  new_wtns/2,
  new_wtns/3,
  default_prime/0,
  default_prime/1
]).

-export_type([
  r1cs/0,
  r1cs_header/0,
  wtns/0,
  wtns_header/0,
  linear_combination/0,
  term_entry/0,
  r1cs_constraint/0,
  input_data/0
]).

-type r1cs() :: #r1cs{}.
-type r1cs_header() :: #r1cs_header{}.
-type wtns() :: #wtns{}.
-type wtns_header() :: #wtns_header{}.
-type input_data() :: binary() | file:name_all().

-type witness_input() ::
  wtns()
  | [integer()]
  | tuple()
  | #{witness := [integer()], header => wtns_header() | #{prime := integer()}}
  | binary().

-type r1cs_header_input() ::
  r1cs_header()
  | #{
    n_pub_out := non_neg_integer(),
    n_pub_in := non_neg_integer(),
    _ => _
  }.

-type r1cs_input() ::
  r1cs()
  | #{
    header := r1cs_header() | map(),
    constraints := [r1cs_constraint()],
    wire_map => [non_neg_integer()],
    custom_sections => [{non_neg_integer(), binary()}]
  }.

%%%===================================================================
%%% Public API - Default Field Primes
%%%===================================================================

%% @doc Returns the default circuit modulus (BN254 / alt_bn128 scalar field r).
-spec default_prime() -> integer().
default_prime() ->
  ?BN254_R.

%% @doc Returns the circuit modulus for the specified curve (`bn254` or `bls12_381`).
-spec default_prime(bn254 | bls12_381) -> integer().
default_prime(bn254) ->
  ?BN254_R;
default_prime(bls12_381) ->
  ?BLS12_381_R.

%%%===================================================================
%%% Public API - Constructors
%%%===================================================================

%% @doc Create an R1CS structure with header and constraints.
-spec new_r1cs(r1cs_header_input(), [r1cs_constraint()]) -> #r1cs{}.
new_r1cs(HeaderInput, Constraints) ->
  Header = to_r1cs_header(HeaderInput),
  #r1cs{
    header = Header#r1cs_header{n_constraints = length(Constraints)},
    constraints = Constraints,
    wire_map = [],
    custom_sections = []
  }.

%% @doc Create an R1CS structure with header, constraints, and wire-to-label map.
-spec new_r1cs(r1cs_header_input(), [r1cs_constraint()], [non_neg_integer()]) -> #r1cs{}.
new_r1cs(HeaderInput, Constraints, WireMap) ->
  Header = to_r1cs_header(HeaderInput),
  #r1cs{
    header = Header#r1cs_header{
      n_constraints = length(Constraints),
      n_labels = length(WireMap)
    },
    constraints = Constraints,
    wire_map = WireMap,
    custom_sections = []
  }.

%% @doc Create a WTNS witness structure with default BN254 prime.
-spec new_wtns([integer()], non_neg_integer()) -> #wtns{}.
new_wtns(Witness, FieldSize) ->
  new_wtns(Witness, default_prime(), FieldSize).

%% @doc Create a WTNS witness structure with given prime and field size.
-spec new_wtns([integer()], integer(), non_neg_integer()) -> #wtns{}.
new_wtns(Witness, Prime, FieldSize) ->
  #wtns{
    header = #wtns_header{
      field_size = FieldSize,
      prime = Prime,
      witness_len = length(Witness)
    },
    witness = Witness
  }.

%%%===================================================================
%%% Public API - R1CS Parsing & Serialization
%%%===================================================================

%% @doc Parse a Circom 2 `.r1cs` binary or file.
-spec parse_r1cs(input_data()) -> {ok, #r1cs{}} | {error, term()}.
parse_r1cs(<<"r1cs", _/binary>> = Bin) ->
  decode_r1cs(Bin);
parse_r1cs(Bin) when is_binary(Bin) ->
  case filelib:is_file(Bin) of
    true ->
      case file:read_file(Bin) of
        {ok, Data} -> decode_r1cs(Data);
        {error, Reason} -> {error, {file_read_error, Reason}}
      end;
    false ->
      decode_r1cs(Bin)
  end;
parse_r1cs(Path) when is_list(Path) ->
  case file:read_file(Path) of
    {ok, Bin} -> decode_r1cs(Bin);
    {error, Reason} -> {error, {file_read_error, Reason}}
  end;
parse_r1cs(_) ->
  {error, invalid_input}.

%% @doc Get header information from an R1CS binary, file, or parsed record.
-spec r1cs_info(input_data() | #r1cs{}) -> {ok, #r1cs_header{}} | {error, term()}.
r1cs_info(#r1cs{header = H}) ->
  {ok, H};
r1cs_info(Input) ->
  case parse_r1cs(Input) of
    {ok, #r1cs{header = H}} -> {ok, H};
    {error, Reason} -> {error, Reason}
  end.

%% @doc Serialize an R1CS structure into Circom 2 `.r1cs` binary format.
-spec serialize_r1cs(r1cs_input()) -> binary().
serialize_r1cs(#r1cs{
  header = Header,
  constraints = Constraints,
  wire_map = WireMap,
  custom_sections = Custom
}) ->
  encode_r1cs(Header, Constraints, WireMap, Custom);
serialize_r1cs(#{header := HMap, constraints := Constraints} = Map) ->
  Header = to_r1cs_header(HMap),
  WireMap = maps:get(wire_map, Map, []),
  Custom = maps:get(custom_sections, Map, []),
  encode_r1cs(Header, Constraints, WireMap, Custom).

%%%===================================================================
%%% Public API - WTNS Parsing & Serialization
%%%===================================================================

%% @doc Parse a Circom `.wtns` binary or file.
-spec parse_wtns(input_data()) -> {ok, #wtns{}} | {error, term()}.
parse_wtns(<<"wtns", _/binary>> = Bin) ->
  decode_wtns(Bin);
parse_wtns(Bin) when is_binary(Bin) ->
  case filelib:is_file(Bin) of
    true ->
      case file:read_file(Bin) of
        {ok, Data} -> decode_wtns(Data);
        {error, Reason} -> {error, {file_read_error, Reason}}
      end;
    false ->
      decode_wtns(Bin)
  end;
parse_wtns(Path) when is_list(Path) ->
  case file:read_file(Path) of
    {ok, Bin} -> decode_wtns(Bin);
    {error, Reason} -> {error, {file_read_error, Reason}}
  end;
parse_wtns(_) ->
  {error, invalid_input}.

%% @doc Get header information from a WTNS binary, file, or parsed record.
-spec wtns_info(input_data() | #wtns{}) -> {ok, #wtns_header{}} | {error, term()}.
wtns_info(#wtns{header = H}) ->
  {ok, H};
wtns_info(Input) ->
  case parse_wtns(Input) of
    {ok, #wtns{header = H}} -> {ok, H};
    {error, Reason} -> {error, Reason}
  end.

%% @doc Serialize a WTNS structure into Circom `.wtns` binary format.
-spec serialize_wtns(wtns() | witness_input()) -> binary().
serialize_wtns(#wtns{header = H, witness = W}) ->
  encode_wtns(H#wtns_header.prime, H#wtns_header.field_size, W);
serialize_wtns(#{header := HMap, witness := W}) ->
  Header = to_wtns_header(HMap),
  encode_wtns(Header#wtns_header.prime, Header#wtns_header.field_size, W);
serialize_wtns(WitnessList) when is_list(WitnessList) ->
  encode_wtns(default_prime(), 32, WitnessList).

%% @doc Serialize a witness list with a specific modulus into Circom `.wtns` format.
-spec serialize_wtns([integer()], integer()) -> binary().
serialize_wtns(WitnessList, Prime) ->
  encode_wtns(Prime, 32, WitnessList).

%% @doc Serialize a witness list with a specific modulus and field size into `.wtns`.
-spec serialize_wtns([integer()], integer(), non_neg_integer()) -> binary().
serialize_wtns(WitnessList, Prime, FieldSize) ->
  encode_wtns(Prime, FieldSize, WitnessList).

%%%===================================================================
%%% Public API - Constraint Checking & Satisfaction
%%%===================================================================

%% @doc Evaluate a linear combination $\sum c_i \cdot W_{w_i} \pmod q$.
-spec eval_lc(linear_combination(), tuple() | [integer()], integer()) -> integer().
eval_lc(Terms, WitnessTuple, Modulus) when is_tuple(WitnessTuple) ->
  eval_lc_tuple(Terms, WitnessTuple, Modulus, 0);
eval_lc(Terms, WitnessList, Modulus) when is_list(WitnessList) ->
  eval_lc(Terms, list_to_tuple(WitnessList), Modulus).

%% @doc Check whether a witness vector satisfies all constraints of an R1CS system.
%% Returns `ok` if all constraints are satisfied, or `{error, Reason}`.
-spec check_constraints(r1cs_input(), witness_input()) -> ok | {error, term()}.
check_constraints(R1CSInput, WitnessInput) ->
  case {to_r1cs_record(R1CSInput), to_witness_tuple(WitnessInput)} of
    {{error, _} = Err, _} ->
      Err;
    {_, {error, _} = Err} ->
      Err;
    {#r1cs{header = H, constraints = Constraints}, {WitnessTuple, PrimeOpt}} ->
      Prime = H#r1cs_header.prime,
      case is_integer(Prime) andalso Prime > 1 of
        false ->
          {error, invalid_circuit_prime};
        true ->
          case PrimeOpt of
            undefined ->
              check_witness_and_constraints(Constraints, WitnessTuple, Prime, H#r1cs_header.n_wires);
            P when is_integer(P), P =:= Prime ->
              check_witness_and_constraints(Constraints, WitnessTuple, Prime, H#r1cs_header.n_wires);
            P when is_integer(P) ->
              {error, {prime_mismatch, P, Prime}}
          end
      end
  end.

-spec check_witness_and_constraints([r1cs_constraint()], tuple(), integer(), non_neg_integer()) ->
  ok | {error, term()}.
check_witness_and_constraints(Constraints, WitnessTuple, Prime, NWires) ->
  WLen = tuple_size(WitnessTuple),
  case WLen < NWires of
    true ->
      {error, {witness_too_short, WLen, NWires}};
    false ->
      case WLen >= 1 andalso element(1, WitnessTuple) =:= 1 of
        false ->
          {error, invalid_wire_zero};
        true ->
          check_constraints_loop(Constraints, WitnessTuple, Prime, 0)
      end
  end.

%% @doc Check whether a witness satisfies all constraints (boolean version).
-spec is_satisfied(r1cs_input(), witness_input()) -> boolean().
is_satisfied(R1CSInput, WitnessInput) ->
  case check_constraints(R1CSInput, WitnessInput) of
    ok -> true;
    _ -> false
  end.

%%%===================================================================
%%% Public API - Public Input Extraction
%%%===================================================================

%% @doc Extract the public input vector $[W_1, W_2, ..., W_{nPubOut + nPubIn}]$
%% for verification with `ecu_groth16:verify/3,4`.
%%
%% Note: Wire 0 is the constant 1 and is omitted. The extracted list corresponds
%% exactly to $IC[1 \dots l]$ in Groth16 verification keys.
-spec extract_public_inputs(witness_input(), r1cs_input() | r1cs_header_input()) -> [integer()].
extract_public_inputs(WitnessInput, #r1cs_header{n_pub_out = NOut, n_pub_in = NIn}) ->
  WitnessList = to_witness_list(WitnessInput),
  TotalPub = NOut + NIn,
  extract_sublist(WitnessList, 1, TotalPub);
extract_public_inputs(WitnessInput, #r1cs{header = H}) ->
  extract_public_inputs(WitnessInput, H);
extract_public_inputs(WitnessInput, #{header := #r1cs_header{} = H}) ->
  extract_public_inputs(WitnessInput, H);
extract_public_inputs(WitnessInput, #{header := H}) when is_map(H) ->
  extract_public_inputs(WitnessInput, to_r1cs_header(H));
extract_public_inputs(WitnessInput, #{n_pub_out := _, n_pub_in := _} = HMap) ->
  extract_public_inputs(WitnessInput, to_r1cs_header(HMap)).

%% @doc Extract public outputs and public inputs as a structured map.
-spec extract_public_inputs_map(witness_input(), r1cs_input() | r1cs_header_input()) ->
  #{public_outputs := [integer()], public_inputs := [integer()]}.
extract_public_inputs_map(WitnessInput, #r1cs_header{n_pub_out = NOut, n_pub_in = NIn}) ->
  WitnessList = to_witness_list(WitnessInput),
  PubOut = extract_sublist(WitnessList, 1, NOut),
  PubIn = extract_sublist(WitnessList, 1 + NOut, NIn),
  #{public_outputs => PubOut, public_inputs => PubIn};
extract_public_inputs_map(WitnessInput, #r1cs{header = H}) ->
  extract_public_inputs_map(WitnessInput, H);
extract_public_inputs_map(WitnessInput, #{header := #r1cs_header{} = H}) ->
  extract_public_inputs_map(WitnessInput, H);
extract_public_inputs_map(WitnessInput, #{header := H}) when is_map(H) ->
  extract_public_inputs_map(WitnessInput, to_r1cs_header(H));
extract_public_inputs_map(WitnessInput, #{n_pub_out := _, n_pub_in := _} = HMap) ->
  extract_public_inputs_map(WitnessInput, to_r1cs_header(HMap)).

%%%===================================================================
%%% Internal Functions - R1CS Decoder
%%%===================================================================

-spec decode_r1cs(binary()) -> {ok, #r1cs{}} | {error, term()}.
decode_r1cs(
  <<"r1cs", Version:32/little-unsigned-integer, NumSections:32/little-unsigned-integer, Rest/binary>>
) ->
  case Version of
    ?R1CS_VERSION ->
      case read_sections(Rest, NumSections, #{}) of
        {ok, Sections} ->
          assemble_r1cs(Sections);
        {error, _} = Err ->
          Err
      end;
    Other ->
      {error, {unsupported_r1cs_version, Other}}
  end;
decode_r1cs(_) ->
  {error, invalid_r1cs_magic}.

-spec read_sections(binary(), non_neg_integer(), map()) ->
  {ok, map()} | {error, term()}.
read_sections(<<>>, 0, Acc) ->
  {ok, Acc};
read_sections(_Rest, Remaining, _Acc) when Remaining > 1000 ->
  {error, too_many_sections};
read_sections(<<>>, Remaining, _Acc) when Remaining > 0 ->
  {error, unexpected_eof_in_sections};
read_sections(
  <<SecType:32/little-unsigned-integer, SecSize:64/little-unsigned-integer, Rest/binary>>,
  Remaining,
  Acc
) ->
  case byte_size(Rest) >= SecSize of
    true ->
      <<SecData:SecSize/binary, NextRest/binary>> = Rest,
      List = maps:get(SecType, Acc, []),
      NewAcc = maps:put(SecType, List ++ [SecData], Acc),
      read_sections(NextRest, Remaining - 1, NewAcc);
    false ->
      {error, truncated_section_data}
  end;
read_sections(_, _, _) ->
  {error, malformed_section_header}.

-spec assemble_r1cs(map()) -> {ok, #r1cs{}} | {error, term()}.
assemble_r1cs(Sections) ->
  case maps:get(?R1CS_SEC_HEADER, Sections, undefined) of
    undefined ->
      {error, missing_header_section};
    [HeaderBin | _] ->
      case decode_r1cs_header(HeaderBin) of
        {ok, Header} ->
          FS = Header#r1cs_header.field_size,
          P = Header#r1cs_header.prime,
          ConstraintsRes =
            case maps:get(?R1CS_SEC_CONSTRAINTS, Sections, undefined) of
              undefined ->
                {ok, []};
              [ConstraintsBin | _] ->
                decode_constraints(ConstraintsBin, Header#r1cs_header.n_constraints, FS, P)
            end,
          case ConstraintsRes of
            {error, _} = Err ->
              Err;
            {ok, Constraints} ->
              WireMap =
                case maps:get(?R1CS_SEC_WIRE_MAP, Sections, undefined) of
                  undefined ->
                    [];
                  [WireMapBin | _] ->
                    decode_wire_map(WireMapBin)
                end,
              Custom =
                maps:fold(
                  fun(K, VList, Acc) ->
                    case K of
                      ?R1CS_SEC_HEADER -> Acc;
                      ?R1CS_SEC_CONSTRAINTS -> Acc;
                      ?R1CS_SEC_WIRE_MAP -> Acc;
                      OtherType -> Acc ++ [{OtherType, V} || V <- VList]
                    end
                  end,
                  [],
                  Sections
                ),
              {ok, #r1cs{
                header = Header,
                constraints = Constraints,
                wire_map = WireMap,
                custom_sections = Custom
              }}
          end;
        {error, _} = Err ->
          Err
      end
  end.

-spec decode_r1cs_header(binary()) -> {ok, #r1cs_header{}} | {error, term()}.
decode_r1cs_header(<<FS:32/little-unsigned-integer, Rest/binary>>) ->
  case FS >= 1 andalso FS =< 256 of
    false ->
      {error, invalid_field_size};
    true ->
      case byte_size(Rest) >= FS + 28 of
        true ->
          <<PrimeBin:FS/binary, NWires:32/little-unsigned-integer, NPubOut:32/little-unsigned-integer,
            NPubIn:32/little-unsigned-integer, NPrvtIn:32/little-unsigned-integer,
            NLabels:64/little-unsigned-integer, NConstraints:32/little-unsigned-integer,
            _/binary>> = Rest,
          <<Prime:FS/little-unsigned-integer-unit:8>> = PrimeBin,
          case Prime > 1 of
            false ->
              {error, invalid_prime};
            true ->
              case 1 + NPubOut + NPubIn + NPrvtIn > NWires of
                true ->
                  {error, invalid_wire_counts};
                false ->
                  {ok, #r1cs_header{
                    field_size = FS,
                    prime = Prime,
                    n_wires = NWires,
                    n_pub_out = NPubOut,
                    n_pub_in = NPubIn,
                    n_prvt_in = NPrvtIn,
                    n_labels = NLabels,
                    n_constraints = NConstraints
                  }}
              end
          end;
        false ->
          {error, truncated_r1cs_header}
      end
  end;
decode_r1cs_header(_) ->
  {error, invalid_r1cs_header}.

-spec decode_constraints(binary(), non_neg_integer(), non_neg_integer(), integer()) ->
  {ok, [r1cs_constraint()]} | {error, term()}.
decode_constraints(Bin, NConstraints, FS, Prime) ->
  decode_constraints_loop(Bin, NConstraints, FS, Prime, []).

-spec decode_constraints_loop(
  binary(),
  non_neg_integer(),
  non_neg_integer(),
  integer(),
  [r1cs_constraint()]
) -> {ok, [r1cs_constraint()]} | {error, term()}.
decode_constraints_loop(<<>>, 0, _FS, _Prime, Acc) ->
  {ok, lists:reverse(Acc)};
decode_constraints_loop(<<>>, Remaining, _FS, _Prime, _Acc) when Remaining > 0 ->
  {error, truncated_constraints};
decode_constraints_loop(Bin, Remaining, FS, Prime, Acc) when Remaining > 0 ->
  case decode_linear_comb(Bin, FS, Prime) of
    {ok, {A, Rest1}} ->
      case decode_linear_comb(Rest1, FS, Prime) of
        {ok, {B, Rest2}} ->
          case decode_linear_comb(Rest2, FS, Prime) of
            {ok, {C, Rest3}} ->
              decode_constraints_loop(Rest3, Remaining - 1, FS, Prime, [{A, B, C} | Acc]);
            {error, _} = Err ->
              Err
          end;
        {error, _} = Err ->
          Err
      end;
    {error, _} = Err ->
      Err
  end.

-spec decode_linear_comb(binary(), non_neg_integer(), integer()) ->
  {ok, {linear_combination(), binary()}} | {error, term()}.
decode_linear_comb(<<NTerms:32/little-unsigned-integer, Rest/binary>>, FS, Prime) ->
  decode_terms(Rest, NTerms, FS, Prime, []);
decode_linear_comb(_Bin, _FS, _Prime) ->
  {error, truncated_linear_combination}.

-spec decode_terms(binary(), non_neg_integer(), non_neg_integer(), integer(), linear_combination()) ->
  {ok, {linear_combination(), binary()}} | {error, term()}.
decode_terms(Rest, 0, _FS, _Prime, Acc) ->
  {ok, {lists:reverse(Acc), Rest}};
decode_terms(Bin, Remaining, FS, Prime, Acc) when Remaining > 0 ->
  case Bin of
    <<WireId:32/little-unsigned-integer, FactorBin:FS/binary, Rest/binary>> ->
      <<Factor:FS/little-unsigned-integer-unit:8>> = FactorBin,
      NormFactor = Factor rem Prime,
      decode_terms(Rest, Remaining - 1, FS, Prime, [{WireId, NormFactor} | Acc]);
    _ ->
      {error, truncated_linear_combination}
  end.

-spec decode_wire_map(binary()) -> [non_neg_integer()].
decode_wire_map(Bin) ->
  decode_wire_map_loop(Bin, []).

-spec decode_wire_map_loop(binary(), [non_neg_integer()]) -> [non_neg_integer()].
decode_wire_map_loop(<<>>, Acc) ->
  lists:reverse(Acc);
decode_wire_map_loop(<<LabelId:64/little-unsigned-integer, Rest/binary>>, Acc) ->
  decode_wire_map_loop(Rest, [LabelId | Acc]).

%%%===================================================================
%%% Internal Functions - R1CS Encoder
%%%===================================================================

-spec encode_r1cs(#r1cs_header{}, [r1cs_constraint()], [non_neg_integer()], [
  {non_neg_integer(), binary()}
]) -> binary().
encode_r1cs(Header, Constraints, WireMap, CustomSections) ->
  FS = Header#r1cs_header.field_size,
  Prime = Header#r1cs_header.prime,
  EffectiveWireMap =
    case WireMap of
      [] -> lists:seq(0, Header#r1cs_header.n_wires - 1);
      _ -> WireMap
    end,
  HBin = encode_r1cs_header_payload(Header, length(Constraints), length(EffectiveWireMap)),
  CBin = encode_constraints_payload(Constraints, FS, Prime),
  WBin = encode_wire_map_payload(EffectiveWireMap),
  NumSec = 3 + length(CustomSections),
  Sec1 = encode_section(?R1CS_SEC_HEADER, HBin),
  Sec2 = encode_section(?R1CS_SEC_CONSTRAINTS, CBin),
  Sec3 = encode_section(?R1CS_SEC_WIRE_MAP, WBin),
  CustomBins = [encode_section(T, D) || {T, D} <- CustomSections],
  iolist_to_binary([
    ?R1CS_MAGIC,
    <<?R1CS_VERSION:32/little-unsigned-integer>>,
    <<NumSec:32/little-unsigned-integer>>,
    Sec1,
    Sec2,
    Sec3,
    CustomBins
  ]).

-spec encode_section(non_neg_integer(), binary()) -> binary().
encode_section(SecType, SecData) ->
  Size = byte_size(SecData),
  <<SecType:32/little-unsigned-integer, Size:64/little-unsigned-integer, SecData/binary>>.

-spec encode_r1cs_header_payload(#r1cs_header{}, non_neg_integer(), non_neg_integer()) -> binary().
encode_r1cs_header_payload(Header, NConstraints, NWireMapLen) ->
  FS = Header#r1cs_header.field_size,
  Prime = Header#r1cs_header.prime,
  NLabels =
    case NWireMapLen > 0 of
      true -> NWireMapLen;
      false -> Header#r1cs_header.n_labels
    end,
  <<FS:32/little-unsigned-integer, Prime:FS/little-unsigned-integer-unit:8,
    (Header#r1cs_header.n_wires):32/little-unsigned-integer,
    (Header#r1cs_header.n_pub_out):32/little-unsigned-integer,
    (Header#r1cs_header.n_pub_in):32/little-unsigned-integer,
    (Header#r1cs_header.n_prvt_in):32/little-unsigned-integer, NLabels:64/little-unsigned-integer,
    NConstraints:32/little-unsigned-integer>>.

-spec encode_constraints_payload([r1cs_constraint()], non_neg_integer(), integer()) -> binary().
encode_constraints_payload(Constraints, FS, Prime) ->
  iolist_to_binary([encode_one_constraint(C, FS, Prime) || C <- Constraints]).

-spec encode_one_constraint(r1cs_constraint(), non_neg_integer(), integer()) -> iolist().
encode_one_constraint({A, B, C}, FS, Prime) ->
  [
    encode_lc_payload(A, FS, Prime),
    encode_lc_payload(B, FS, Prime),
    encode_lc_payload(C, FS, Prime)
  ].

-spec encode_lc_payload(linear_combination(), non_neg_integer(), integer()) -> iolist().
encode_lc_payload(Terms, FS, Prime) ->
  NTerms = length(Terms),
  TermsBin = [
    begin
      NormFactor = mod(Factor, Prime),
      <<WireId:32/little-unsigned-integer, NormFactor:FS/little-unsigned-integer-unit:8>>
    end
   || {WireId, Factor} <- Terms
  ],
  [<<NTerms:32/little-unsigned-integer>>, TermsBin].

-spec encode_wire_map_payload([non_neg_integer()]) -> binary().
encode_wire_map_payload(WireMap) ->
  iolist_to_binary([<<LabelId:64/little-unsigned-integer>> || LabelId <- WireMap]).

%%%===================================================================
%%% Internal Functions - WTNS Decoder
%%%===================================================================

-spec decode_wtns(binary()) -> {ok, #wtns{}} | {error, term()}.
decode_wtns(
  <<"wtns", Version:32/little-unsigned-integer, NumSections:32/little-unsigned-integer, Rest/binary>>
) ->
  case Version of
    ?WTNS_VERSION ->
      case read_sections(Rest, NumSections, #{}) of
        {ok, Sections} ->
          assemble_wtns(Sections);
        {error, _} = Err ->
          Err
      end;
    Other ->
      {error, {unsupported_wtns_version, Other}}
  end;
decode_wtns(_) ->
  {error, invalid_wtns_magic}.

-spec assemble_wtns(map()) -> {ok, #wtns{}} | {error, term()}.
assemble_wtns(Sections) ->
  case maps:get(?WTNS_SEC_HEADER, Sections, undefined) of
    undefined ->
      {error, missing_wtns_header};
    [HeaderBin | _] ->
      case decode_wtns_header(HeaderBin) of
        {ok, Header} ->
          case maps:get(?WTNS_SEC_WITNESS, Sections, undefined) of
            undefined ->
              {error, missing_wtns_witness};
            [WitnessBin | _] ->
              case
                decode_witness_vector(
                  WitnessBin,
                  Header#wtns_header.witness_len,
                  Header#wtns_header.field_size,
                  Header#wtns_header.prime
                )
              of
                {ok, Witness} ->
                  {ok, #wtns{header = Header, witness = Witness}};
                {error, _} = Err ->
                  Err
              end
          end;
        {error, _} = Err ->
          Err
      end
  end.

-spec decode_wtns_header(binary()) -> {ok, #wtns_header{}} | {error, term()}.
decode_wtns_header(<<FS:32/little-unsigned-integer, Rest/binary>>) ->
  case FS >= 1 andalso FS =< 256 of
    false ->
      {error, invalid_field_size};
    true ->
      case byte_size(Rest) >= FS + 4 of
        true ->
          <<PrimeBin:FS/binary, WLen:32/little-unsigned-integer, _/binary>> = Rest,
          <<Prime:FS/little-unsigned-integer-unit:8>> = PrimeBin,
          case Prime > 1 of
            false ->
              {error, invalid_prime};
            true ->
              {ok, #wtns_header{
                field_size = FS,
                prime = Prime,
                witness_len = WLen
              }}
          end;
        false ->
          {error, truncated_wtns_header}
      end
  end;
decode_wtns_header(_) ->
  {error, invalid_wtns_header}.

-spec decode_witness_vector(binary(), non_neg_integer(), non_neg_integer(), integer()) ->
  {ok, [integer()]} | {error, term()}.
decode_witness_vector(Bin, WLen, FS, Prime) ->
  ExpectedBytes = WLen * FS,
  case byte_size(Bin) < ExpectedBytes of
    true ->
      {error, truncated_wtns_witness};
    false ->
      decode_witness_loop(Bin, WLen, FS, Prime, [])
  end.

-spec decode_witness_loop(binary(), non_neg_integer(), non_neg_integer(), integer(), [integer()]) ->
  {ok, [integer()]}.
decode_witness_loop(_Bin, 0, _FS, _Prime, Acc) ->
  {ok, lists:reverse(Acc)};
decode_witness_loop(Bin, Remaining, FS, Prime, Acc) when Remaining > 0 ->
  <<ElemBin:FS/binary, Rest/binary>> = Bin,
  <<Elem:FS/little-unsigned-integer-unit:8>> = ElemBin,
  NormElem = Elem rem Prime,
  decode_witness_loop(Rest, Remaining - 1, FS, Prime, [NormElem | Acc]).

%%%===================================================================
%%% Internal Functions - WTNS Encoder
%%%===================================================================

-spec encode_wtns(integer(), non_neg_integer(), [integer()]) -> binary().
encode_wtns(Prime, FieldSize, WitnessList) ->
  WLen = length(WitnessList),
  HeaderBin =
    <<FieldSize:32/little-unsigned-integer, Prime:FieldSize/little-unsigned-integer-unit:8,
      WLen:32/little-unsigned-integer>>,
  WitnessBin = iolist_to_binary([
    begin
      Norm = mod(W, Prime),
      <<Norm:FieldSize/little-unsigned-integer-unit:8>>
    end
   || W <- WitnessList
  ]),
  Sec1 = encode_section(?WTNS_SEC_HEADER, HeaderBin),
  Sec2 = encode_section(?WTNS_SEC_WITNESS, WitnessBin),
  iolist_to_binary([
    ?WTNS_MAGIC,
    <<?WTNS_VERSION:32/little-unsigned-integer>>,
    <<2:32/little-unsigned-integer>>,
    Sec1,
    Sec2
  ]).

%%%===================================================================
%%% Internal Functions - Constraint Evaluation Loop
%%%===================================================================

-spec check_constraints_loop([r1cs_constraint()], tuple(), integer(), non_neg_integer()) ->
  ok | {error, term()}.
check_constraints_loop([], _WTmp, _Prime, _Idx) ->
  ok;
check_constraints_loop([{A, B, C} | Rest], WTuple, Prime, Idx) ->
  try
    AVal = eval_lc_tuple(A, WTuple, Prime, 0),
    BVal = eval_lc_tuple(B, WTuple, Prime, 0),
    CVal = eval_lc_tuple(C, WTuple, Prime, 0),
    Left = (AVal * BVal) rem Prime,
    Right = CVal rem Prime,
    case Left =:= Right of
      true ->
        check_constraints_loop(Rest, WTuple, Prime, Idx + 1);
      false ->
        {error, {constraint_violated, Idx, AVal, BVal, CVal}}
    end
  catch
    error:{bad_wire_id, BadWire} ->
      {error, {invalid_wire_id, BadWire, tuple_size(WTuple) - 1}}
  end.

-spec eval_lc_tuple(linear_combination(), tuple(), integer(), integer()) -> integer().
eval_lc_tuple([], _WTuple, Prime, Acc) ->
  mod(Acc, Prime);
eval_lc_tuple([{WireId, Factor} | Rest], WTuple, Prime, Acc) ->
  Index = WireId + 1,
  case Index > 0 andalso Index =< tuple_size(WTuple) of
    true ->
      case element(Index, WTuple) of
        WireVal when is_integer(WireVal) ->
          Term = (Factor * WireVal) rem Prime,
          eval_lc_tuple(Rest, WTuple, Prime, Acc + Term);
        _ ->
          erlang:error({bad_wire_val, WireId})
      end;
    false ->
      erlang:error({bad_wire_id, WireId})
  end.

-spec mod(integer(), integer()) -> integer().
mod(Val, Prime) ->
  Rem = Val rem Prime,
  case Rem < 0 of
    true -> Rem + Prime;
    false -> Rem
  end.

%%%===================================================================
%%% Internal Functions - Conversion Helpers
%%%===================================================================

-spec to_r1cs_record(r1cs_input()) -> #r1cs{} | {error, term()}.
to_r1cs_record(#r1cs{} = R) ->
  R;
to_r1cs_record(#{header := HMap, constraints := Constraints} = Map) ->
  #r1cs{
    header = to_r1cs_header(HMap),
    constraints = Constraints,
    wire_map = maps:get(wire_map, Map, []),
    custom_sections = maps:get(custom_sections, Map, [])
  };
to_r1cs_record(Input) ->
  case parse_r1cs(Input) of
    {ok, #r1cs{} = R} -> R;
    {error, _} = Err -> Err
  end.

-spec to_r1cs_header(#r1cs_header{} | map()) -> #r1cs_header{}.
to_r1cs_header(#r1cs_header{} = H) ->
  H;
to_r1cs_header(Map) when is_map(Map) ->
  #r1cs_header{
    field_size = maps:get(field_size, Map, 32),
    prime = maps:get(prime, Map, default_prime()),
    n_wires = maps:get(n_wires, Map, 0),
    n_pub_out = maps:get(n_pub_out, Map, 0),
    n_pub_in = maps:get(n_pub_in, Map, 0),
    n_prvt_in = maps:get(n_prvt_in, Map, 0),
    n_labels = maps:get(n_labels, Map, 0),
    n_constraints = maps:get(n_constraints, Map, 0)
  }.

-spec to_wtns_header(#wtns_header{} | map()) -> #wtns_header{}.
to_wtns_header(#wtns_header{} = H) ->
  H;
to_wtns_header(Map) when is_map(Map) ->
  #wtns_header{
    field_size = maps:get(field_size, Map, 32),
    prime = maps:get(prime, Map, default_prime()),
    witness_len = maps:get(witness_len, Map, 0)
  }.

-spec to_witness_tuple(witness_input() | input_data()) ->
  {tuple(), integer() | undefined} | {error, term()}.
to_witness_tuple(#wtns{header = H, witness = W}) ->
  {list_to_tuple(W), H#wtns_header.prime};
to_witness_tuple(WitnessTuple) when is_tuple(WitnessTuple) ->
  {WitnessTuple, undefined};
to_witness_tuple(WitnessList) when is_list(WitnessList) ->
  {list_to_tuple(WitnessList), undefined};
to_witness_tuple(#{witness := W} = Map) ->
  Prime =
    case maps:get(header, Map, undefined) of
      #wtns_header{prime = P} -> P;
      #{prime := P} -> P;
      _ -> undefined
    end,
  {list_to_tuple(W), Prime};
to_witness_tuple(Input) ->
  case parse_wtns(Input) of
    {ok, #wtns{header = H, witness = W}} ->
      {list_to_tuple(W), H#wtns_header.prime};
    {error, _} = Err ->
      Err
  end.

-spec to_witness_list(witness_input()) -> [integer()].
to_witness_list(#wtns{witness = W}) ->
  W;
to_witness_list(WitnessList) when is_list(WitnessList) ->
  WitnessList;
to_witness_list(WitnessTuple) when is_tuple(WitnessTuple) ->
  [X || X <- tuple_to_list(WitnessTuple), is_integer(X)];
to_witness_list(#{witness := W}) ->
  W;
to_witness_list(Bin) when is_binary(Bin) ->
  case parse_wtns(Bin) of
    {ok, #wtns{witness = W}} -> W;
    _ -> []
  end.

-spec extract_sublist([T], non_neg_integer(), non_neg_integer()) -> [T].
extract_sublist(_List, _Start, 0) ->
  [];
extract_sublist(List, Start, Count) ->
  case Start =< length(List) of
    true ->
      lists:sublist(List, Start + 1, Count);
    false ->
      []
  end.
