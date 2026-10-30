%%%-------------------------------------------------------------------
%%% @doc
%%% Bech32 and Bech32m checksummed base32 encoding (BIP-173, BIP-350).
%%%
%%% Implements Bech32 (BIP-173) and Bech32m (BIP-350) encoding and decoding,
%%% bit-width conversion (8-bit to 5-bit and vice versa), and Bitcoin SegWit
%%% (P2WPKH, P2WSH, P2TR Taproot) address derivation and parsing.
%%%
%%% References:
%%% - BIP-173: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
%%% - BIP-350: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bech32).

-typing([eqwalizer]).

-export([
  encode/3,
  decode/1,
  decode_lenient/1,
  convert_bits/4,
  encode_segwit_address/3,
  decode_segwit_address/2
]).

-type variant() :: bech32 | bech32m.
-type error_reason() ::
  invalid_hrp
  | invalid_character
  | mixed_case
  | string_too_long
  | string_too_short
  | missing_separator
  | invalid_data_length
  | invalid_checksum
  | invalid_padding
  | invalid_witness_version
  | invalid_witness_program
  | invalid_witness_length
  | invalid_checksum_variant.

-export_type([variant/0, error_reason/0]).

-define(BECH32_CONST, 1).
-define(BECH32M_CONST, 16#2bc830a3).

-define(ALPHABET, "qpzry9x8gf2tvdw0s3jn54khce6mua7l").

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Encodes human-readable part and 5-bit data payload using Bech32 or Bech32m.
-spec encode(Hrp :: binary() | string(), Data5Bit :: binary() | [0..31], Variant :: variant()) ->
  {ok, binary()} | {error, error_reason()}.
encode(Hrp, Data5Bit, Variant) ->
  HrpStr = to_string(Hrp),
  case validate_hrp(HrpStr) of
    ok ->
      case to_5bit_list(Data5Bit) of
        {ok, DataList} ->
          Const =
            case Variant of
              bech32 -> ?BECH32_CONST;
              bech32m -> ?BECH32M_CONST
            end,
          Checksum = create_checksum(HrpStr, DataList, Const),
          Combined = DataList ++ Checksum,
          Chars = [alphabet_char(D) || D <- Combined],
          Total = HrpStr ++ "1" ++ Chars,
          {ok, list_to_binary(Total)};
        error ->
          {error, invalid_character}
      end;
    {error, Reason} ->
      {error, Reason}
  end.

%% @doc Decodes a Bech32 or Bech32m string enforcing the 90-character limit.
-spec decode(String :: binary() | string()) ->
  {ok, {binary(), binary(), variant()}} | {error, error_reason()}.
decode(String) ->
  decode_internal(to_string(String), true).

%% @doc Decodes a Bech32 or Bech32m string without enforcing the 90-character limit.
-spec decode_lenient(String :: binary() | string()) ->
  {ok, {binary(), binary(), variant()}} | {error, error_reason()}.
decode_lenient(String) ->
  decode_internal(to_string(String), false).

%% @doc Converts bits between bit-widths (e.g., 8-bit bytes to 5-bit words).
-spec convert_bits(
  Data :: binary() | [non_neg_integer()],
  FromBits :: pos_integer(),
  ToBits :: pos_integer(),
  Pad :: boolean()
) -> {ok, binary()} | {error, error_reason()}.
convert_bits(Data, FromBits, ToBits, Pad) ->
  Input =
    if
      is_binary(Data) -> binary_to_list(Data);
      is_list(Data) -> Data
    end,
  MaxIn = (1 bsl FromBits) - 1,
  case lists:all(fun(V) -> is_integer(V) andalso V >= 0 andalso V =< MaxIn end, Input) of
    false ->
      {error, invalid_character};
    true ->
      convert_bits_loop(Input, FromBits, ToBits, Pad, 0, 0, [])
  end.

%% @doc Encodes a Bitcoin SegWit address for witness version 0..16.
%% Automatically selects Bech32 for v0 and Bech32m for v1+ (Taproot) per BIP-350.
-spec encode_segwit_address(
  Hrp :: binary() | string(),
  WitnessVersion :: 0..16,
  WitnessProgram :: binary()
) -> {ok, binary()} | {error, error_reason()}.
encode_segwit_address(Hrp, WitnessVersion, WitnessProgram) when
  is_integer(WitnessVersion),
  WitnessVersion >= 0,
  WitnessVersion =< 16,
  is_binary(WitnessProgram)
->
  ProgLen = byte_size(WitnessProgram),
  case validate_witness_program(WitnessVersion, ProgLen) of
    ok ->
      case convert_bits(WitnessProgram, 8, 5, true) of
        {ok, Converted} ->
          Data5Bit = <<WitnessVersion:8, Converted/binary>>,
          Variant =
            case WitnessVersion of
              0 -> bech32;
              _ -> bech32m
            end,
          encode(Hrp, Data5Bit, Variant);
        {error, Reason} ->
          {error, Reason}
      end;
    {error, Reason} ->
      {error, Reason}
  end;
encode_segwit_address(_Hrp, _WitnessVersion, _WitnessProgram) ->
  {error, invalid_witness_version}.

%% @doc Decodes a Bitcoin SegWit address and validates checksum variant per BIP-350.
-spec decode_segwit_address(Hrp :: binary() | string(), Address :: binary() | string()) ->
  {ok, {0..16, binary()}} | {error, error_reason()}.
decode_segwit_address(ExpectedHrp, Address) ->
  ExpectedHrpBin =
    if
      is_binary(ExpectedHrp) -> string:lowercase(ExpectedHrp);
      is_list(ExpectedHrp) -> string:lowercase(list_to_binary(ExpectedHrp))
    end,
  case decode(Address) of
    {ok, {HrpBin, Data5Bit, Variant}} ->
      case HrpBin =:= ExpectedHrpBin of
        false ->
          {error, invalid_hrp};
        true ->
          case Data5Bit of
            <<>> ->
              {error, invalid_witness_length};
            <<WitnessVersion:8, Prog5Bit/binary>> ->
              case WitnessVersion of
                V when V >= 0, V =< 16 ->
                  ExpectedVariant =
                    case V of
                      0 -> bech32;
                      _ -> bech32m
                    end,
                  case Variant =:= ExpectedVariant of
                    false ->
                      {error, invalid_checksum_variant};
                    true ->
                      case convert_bits(Prog5Bit, 5, 8, false) of
                        {ok, Program} ->
                          case validate_witness_program(V, byte_size(Program)) of
                            ok ->
                              {ok, {V, Program}};
                            {error, Reason} ->
                              {error, Reason}
                          end;
                        {error, Reason} ->
                          {error, Reason}
                      end
                  end;
                _ ->
                  {error, invalid_witness_version}
              end
          end
      end;
    {error, Reason} ->
      {error, Reason}
  end.

%% ===================================================================
%% Internal Helpers
%% ===================================================================

-spec decode_internal(string(), boolean()) ->
  {ok, {binary(), binary(), variant()}} | {error, error_reason()}.
decode_internal(Str, StrictLen) ->
  Len = length(Str),
  if
    Len < 8 ->
      {error, string_too_short};
    StrictLen andalso Len > 90 ->
      {error, string_too_long};
    true ->
      case check_casing(Str) of
        error ->
          {error, mixed_case};
        ok ->
          Lower = string:lowercase(Str),
          case find_last_separator(Lower) of
            error ->
              {error, missing_separator};
            {ok, HrpPart, DataPart} ->
              case validate_hrp(HrpPart) of
                {error, Reason} ->
                  {error, Reason};
                ok ->
                  if
                    length(DataPart) < 6 ->
                      {error, invalid_data_length};
                    true ->
                      case parse_data_chars(DataPart) of
                        {error, Reason} ->
                          {error, Reason};
                        {ok, AllValues} ->
                          DataLen = length(AllValues) - 6,
                          {DataPayload, _ChecksumValues} = lists:split(DataLen, AllValues),
                          ValuesForPoly = hrp_expand(HrpPart) ++ AllValues,
                          case polymod(ValuesForPoly) of
                            ?BECH32_CONST ->
                              {ok, {list_to_binary(HrpPart), list_to_binary(DataPayload), bech32}};
                            ?BECH32M_CONST ->
                              {ok, {list_to_binary(HrpPart), list_to_binary(DataPayload), bech32m}};
                            _ ->
                              {error, invalid_checksum}
                          end
                      end
                  end
              end
          end
      end
  end.

-spec validate_hrp(string()) -> ok | {error, error_reason()}.
validate_hrp(Hrp) ->
  Len = length(Hrp),
  if
    Len < 1 ->
      {error, invalid_hrp};
    Len > 83 ->
      {error, invalid_hrp};
    true ->
      Valid = lists:all(fun(C) -> C >= 33 andalso C =< 126 end, Hrp),
      case Valid of
        true -> ok;
        false -> {error, invalid_hrp}
      end
  end.

-spec validate_witness_program(0..16, non_neg_integer()) -> ok | {error, error_reason()}.
validate_witness_program(0, Len) ->
  case Len =:= 20 orelse Len =:= 32 of
    true -> ok;
    false -> {error, invalid_witness_length}
  end;
validate_witness_program(V, Len) when V >= 1, V =< 16 ->
  case Len >= 2 andalso Len =< 40 of
    true -> ok;
    false -> {error, invalid_witness_length}
  end;
validate_witness_program(_V, _Len) ->
  {error, invalid_witness_version}.

-spec check_casing(string()) -> ok | error.
check_casing(Str) ->
  HasLower = lists:any(fun(C) -> C >= $a andalso C =< $z end, Str),
  HasUpper = lists:any(fun(C) -> C >= $A andalso C =< $Z end, Str),
  case HasLower andalso HasUpper of
    true -> error;
    false -> ok
  end.

-spec find_last_separator(string()) -> {ok, string(), string()} | error.
find_last_separator(Str) ->
  case lists:splitwith(fun(C) -> C =/= $1 end, lists:reverse(Str)) of
    {_RevData, []} ->
      error;
    {RevData, [$1 | RevHrp]} ->
      {ok, lists:reverse(RevHrp), lists:reverse(RevData)}
  end.

-spec parse_data_chars(string()) -> {ok, [0..31]} | {error, error_reason()}.
parse_data_chars(DataChars) ->
  parse_data_chars(DataChars, []).

-spec parse_data_chars(string(), [0..31]) -> {ok, [0..31]} | {error, error_reason()}.
parse_data_chars([], Acc) ->
  {ok, lists:reverse(Acc)};
parse_data_chars([C | Rest], Acc) ->
  case char_value(C) of
    error -> {error, invalid_character};
    Val -> parse_data_chars(Rest, [Val | Acc])
  end.

-spec create_checksum(string(), [0..31], non_neg_integer()) -> [0..31].
create_checksum(Hrp, Data, Const) ->
  Values = hrp_expand(Hrp) ++ Data ++ [0, 0, 0, 0, 0, 0],
  Polymod = polymod(Values) bxor Const,
  [(Polymod bsr (5 * (5 - I))) band 31 || I <- lists:seq(0, 5)].

-spec hrp_expand(string()) -> [0..31].
hrp_expand(Hrp) ->
  [C bsr 5 || C <- Hrp] ++ [0] ++ [C band 31 || C <- Hrp].

-spec polymod([0..31]) -> non_neg_integer().
polymod(Values) ->
  lists:foldl(fun polymod_step/2, 1, Values).

-spec polymod_step(0..31, non_neg_integer()) -> non_neg_integer().
polymod_step(V, Chk) ->
  Top = Chk bsr 25,
  Chk1 = ((Chk band 16#1ffffff) bsl 5) bxor V,
  Chk2 =
    case (Top band 1) =/= 0 of
      true -> Chk1 bxor 16#3b6a57b2;
      false -> Chk1
    end,
  Chk3 =
    case (Top band 2) =/= 0 of
      true -> Chk2 bxor 16#26508e6d;
      false -> Chk2
    end,
  Chk4 =
    case (Top band 4) =/= 0 of
      true -> Chk3 bxor 16#1ea119fa;
      false -> Chk3
    end,
  Chk5 =
    case (Top band 8) =/= 0 of
      true -> Chk4 bxor 16#3d4233dd;
      false -> Chk4
    end,
  case (Top band 16) =/= 0 of
    true -> Chk5 bxor 16#2a1462b3;
    false -> Chk5
  end.

-spec convert_bits_loop(
  [non_neg_integer()],
  pos_integer(),
  pos_integer(),
  boolean(),
  non_neg_integer(),
  non_neg_integer(),
  [non_neg_integer()]
) -> {ok, binary()} | {error, error_reason()}.
convert_bits_loop([], FromBits, ToBits, Pad, Acc, Bits, Out) ->
  if
    Pad andalso Bits > 0 ->
      Padded = (Acc bsl (ToBits - Bits)) band ((1 bsl ToBits) - 1),
      {ok, list_to_binary(lists:reverse([Padded | Out]))};
    not Pad andalso Bits >= FromBits ->
      {error, invalid_padding};
    not Pad andalso ((Acc bsl (ToBits - Bits)) band ((1 bsl ToBits) - 1)) =/= 0 ->
      {error, invalid_padding};
    true ->
      {ok, list_to_binary(lists:reverse(Out))}
  end;
convert_bits_loop([Val | Rest], FromBits, ToBits, Pad, Acc, Bits, Out) ->
  NewAcc = (Acc bsl FromBits) bor Val,
  NewBits = Bits + FromBits,
  {FinalAcc, FinalBits, Emitted} = drain_bits(NewAcc, NewBits, ToBits, []),
  convert_bits_loop(Rest, FromBits, ToBits, Pad, FinalAcc, FinalBits, Emitted ++ Out).

-spec drain_bits(
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  [non_neg_integer()]
) -> {non_neg_integer(), non_neg_integer(), [non_neg_integer()]}.
drain_bits(Acc, Bits, ToBits, Emitted) when Bits >= ToBits ->
  Shift = Bits - ToBits,
  Chunk = (Acc bsr Shift) band ((1 bsl ToBits) - 1),
  drain_bits(Acc, Shift, ToBits, [Chunk | Emitted]);
drain_bits(Acc, Bits, _ToBits, Emitted) ->
  {Acc, Bits, Emitted}.

-spec alphabet_char(0..31) -> char().
alphabet_char(0) -> $q;
alphabet_char(1) -> $p;
alphabet_char(2) -> $z;
alphabet_char(3) -> $r;
alphabet_char(4) -> $y;
alphabet_char(5) -> $9;
alphabet_char(6) -> $x;
alphabet_char(7) -> $8;
alphabet_char(8) -> $g;
alphabet_char(9) -> $f;
alphabet_char(10) -> $2;
alphabet_char(11) -> $t;
alphabet_char(12) -> $v;
alphabet_char(13) -> $d;
alphabet_char(14) -> $w;
alphabet_char(15) -> $0;
alphabet_char(16) -> $s;
alphabet_char(17) -> $3;
alphabet_char(18) -> $j;
alphabet_char(19) -> $n;
alphabet_char(20) -> $5;
alphabet_char(21) -> $4;
alphabet_char(22) -> $k;
alphabet_char(23) -> $h;
alphabet_char(24) -> $c;
alphabet_char(25) -> $e;
alphabet_char(26) -> $6;
alphabet_char(27) -> $m;
alphabet_char(28) -> $u;
alphabet_char(29) -> $a;
alphabet_char(30) -> $7;
alphabet_char(31) -> $l.

-spec char_value(char()) -> 0..31 | error.
char_value($q) -> 0;
char_value($p) -> 1;
char_value($z) -> 2;
char_value($r) -> 3;
char_value($y) -> 4;
char_value($9) -> 5;
char_value($x) -> 6;
char_value($7) -> 30;
char_value($8) -> 7;
char_value($g) -> 8;
char_value($f) -> 9;
char_value($2) -> 10;
char_value($t) -> 11;
char_value($v) -> 12;
char_value($d) -> 13;
char_value($w) -> 14;
char_value($0) -> 15;
char_value($s) -> 16;
char_value($3) -> 17;
char_value($j) -> 18;
char_value($n) -> 19;
char_value($5) -> 20;
char_value($4) -> 21;
char_value($k) -> 22;
char_value($h) -> 23;
char_value($c) -> 24;
char_value($e) -> 25;
char_value($6) -> 26;
char_value($m) -> 27;
char_value($u) -> 28;
char_value($a) -> 29;
char_value($l) -> 31;
char_value(_) -> error.

-spec to_string(binary() | string()) -> string().
to_string(Bin) when is_binary(Bin) -> binary_to_list(Bin);
to_string(Str) when is_list(Str) -> Str.

-spec to_5bit_list(binary() | [0..31]) -> {ok, [0..31]} | error.
to_5bit_list(Bin) when is_binary(Bin) ->
  List = binary_to_list(Bin),
  case lists:all(fun(B) -> B >= 0 andalso B =< 31 end, List) of
    true -> {ok, List};
    false -> error
  end;
to_5bit_list(List) when is_list(List) ->
  case lists:all(fun(B) -> is_integer(B) andalso B >= 0 andalso B =< 31 end, List) of
    true -> {ok, List};
    false -> error
  end;
to_5bit_list(_) ->
  error.
