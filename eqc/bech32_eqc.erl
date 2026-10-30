%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for ecu_bech32 (BIP-173, BIP-350).
%%% @end
%%%-------------------------------------------------------------------
-module(bech32_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_hrp() ->
  ?LET(
    Len,
    choose(1, 10),
    ?LET(Chars, vector(Len, choose($a, $z)), list_to_binary(Chars))
  ).

gen_data5bit() ->
  ?LET(Len, choose(0, 40), ?LET(Vals, vector(Len, choose(0, 31)), list_to_binary(Vals))).

gen_variant() ->
  elements([bech32, bech32m]).

gen_program() ->
  ?LET(Len, choose(2, 40), binary(Len)).

gen_segwit_version_and_program() ->
  ?LET(
    Version,
    choose(0, 16),
    case Version of
      0 ->
        ?LET(Len, elements([20, 32]), {0, binary(Len)});
      V ->
        ?LET(Prog, gen_program(), {V, Prog})
    end
  ).

%% ===================================================================
%% Properties: Bech32 & Bech32m Roundtrip
%% ===================================================================

prop_bech32_roundtrip() ->
  ?FORALL(
    {Hrp, Data},
    {gen_hrp(), gen_data5bit()},
    begin
      {ok, Encoded} = ecu_bech32:encode(Hrp, Data, bech32),
      Decoded = ecu_bech32:decode(Encoded),
      Decoded == {ok, {Hrp, Data, bech32}}
    end
  ).

prop_bech32m_roundtrip() ->
  ?FORALL(
    {Hrp, Data},
    {gen_hrp(), gen_data5bit()},
    begin
      {ok, Encoded} = ecu_bech32:encode(Hrp, Data, bech32m),
      Decoded = ecu_bech32:decode(Encoded),
      Decoded == {ok, {Hrp, Data, bech32m}}
    end
  ).

%% ===================================================================
%% Properties: Bit Conversion & SegWit Addresses
%% ===================================================================

prop_convert_bits_roundtrip() ->
  ?FORALL(
    Data,
    ?LET(Len, choose(1, 40), binary(Len)),
    begin
      {ok, Bits5} = ecu_bech32:convert_bits(Data, 8, 5, true),
      {ok, Recovered} = ecu_bech32:convert_bits(Bits5, 5, 8, false),
      Recovered == Data
    end
  ).

prop_segwit_address_roundtrip() ->
  ?FORALL(
    {Hrp, {Version, Program}},
    {gen_hrp(), gen_segwit_version_and_program()},
    begin
      {ok, Address} = ecu_bech32:encode_segwit_address(Hrp, Version, Program),
      Decoded = ecu_bech32:decode_segwit_address(Hrp, Address),
      Decoded == {ok, {Version, Program}}
    end
  ).

%% ===================================================================
%% Properties: Differential Verification against Rust Reference NIF
%% ===================================================================

prop_reference_equivalence() ->
  ?FORALL(
    {Hrp, Data, Variant},
    {gen_hrp(), gen_data5bit(), gen_variant()},
    case ecu_rustcrypto_nif:is_available() of
      true ->
        VarBin = atom_to_binary(Variant, utf8),
        {ok, EncErl} = ecu_bech32:encode(Hrp, Data, Variant),
        EncNif = ecu_rustcrypto_nif:bech32_encode(Hrp, Data, VarBin),
        {NifHrp, NifData, NifVar} = ecu_rustcrypto_nif:bech32_decode(EncErl),
        EncErl == EncNif andalso NifHrp == Hrp andalso NifData == Data andalso NifVar == Variant;
      false ->
        true
    end
  ).

%% ===================================================================
%% Properties: Error Detection on Tampering
%% ===================================================================

prop_tamper_detection() ->
  ?FORALL(
    {Hrp, Data, Variant},
    {gen_hrp(), gen_data5bit(), gen_variant()},
    begin
      {ok, Encoded} = ecu_bech32:encode(Hrp, Data, Variant),
      Str = binary_to_list(Encoded),
      ?FORALL(
        Idx,
        choose(1, length(Str)),
        begin
          OrigChar = lists:nth(Idx, Str),
          %% Replace with an alphabet character or a different printable character
          Replacement =
            case OrigChar of
              $q -> $p;
              _ -> $q
            end,
          Tampered = list_to_binary(replace_char(Str, Idx, Replacement)),
          Tampered == Encoded orelse ecu_bech32:decode(Tampered) =/= {ok, {Hrp, Data, Variant}}
        end
      )
    end
  ).

replace_char(List, Idx, NewChar) ->
  {Before, [_ | After]} = lists:split(Idx - 1, List),
  Before ++ [NewChar | After].
