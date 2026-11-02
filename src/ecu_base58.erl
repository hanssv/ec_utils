%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang Base58 and Base58Check encoding and decoding.
%%%
%%% Implements high-throughput Radix-$58^{10}$ chunked encoding and decoding
%%% with zero external dependencies, preserving leading zero bytes as '1's.
%%% Base58Check applies double SHA-256 4-byte checksum validation.
%%%
%%% Reference:
%%%   Bitcoin Base58: https://en.bitcoin.it/wiki/Base58Check_encoding
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_base58).

-typing([eqwalizer]).

-export([
  encode/1,
  decode/1,
  encode_check/1,
  decode_check/1
]).

%% 58^10 constant (fits in 60-bit BEAM fixnum: 430804206899405824 < 2^59)
-define(BASE10, 430804206899405824).

%% Base58 alphabet lookup tuple (1-indexed for element/2 BIF)
-define(ENC_TABLE, {
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9,
  $A,
  $B,
  $C,
  $D,
  $E,
  $F,
  $G,
  $H,
  $J,
  $K,
  $L,
  $M,
  $N,
  $P,
  $Q,
  $R,
  $S,
  $T,
  $U,
  $V,
  $W,
  $X,
  $Y,
  $Z,
  $a,
  $b,
  $c,
  $d,
  $e,
  $f,
  $g,
  $h,
  $i,
  $j,
  $k,
  $m,
  $n,
  $o,
  $p,
  $q,
  $r,
  $s,
  $t,
  $u,
  $v,
  $w,
  $x,
  $y,
  $z
}).

%% 256-element reverse decoding table (byte + 1 -> 0..57 or error)
-define(DEC_TABLE, {
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  error,
  17,
  18,
  19,
  20,
  21,
  error,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  32,
  error,
  error,
  error,
  error,
  error,
  error,
  33,
  34,
  35,
  36,
  37,
  38,
  39,
  40,
  41,
  42,
  43,
  error,
  44,
  45,
  46,
  47,
  48,
  49,
  50,
  51,
  52,
  53,
  54,
  55,
  56,
  57,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error,
  error
}).

%% ===================================================================
%% API Functions
%% ===================================================================

-spec encode(binary()) -> binary().
encode(Bin) when is_binary(Bin) ->
  {LeadingZeros, Rest} = count_leading_zeros(Bin, 0),
  ZeroPrefix = binary:copy(<<"1">>, LeadingZeros),
  case Rest of
    <<>> ->
      ZeroPrefix;
    _ ->
      Bits = byte_size(Rest) * 8,
      <<Num:Bits>> = Rest,
      Chars = encode_radix10(Num, []),
      <<ZeroPrefix/binary, (list_to_binary(Chars))/binary>>
  end.

-define(MAX_DECODE_LEN, 4096).

-spec decode(binary() | string()) ->
  {ok, binary()} | {error, bad_char | bad_encoding | input_too_long}.
decode(Input) when is_binary(Input) ->
  if
    byte_size(Input) > ?MAX_DECODE_LEN ->
      {error, input_too_long};
    true ->
      decode_chars(binary_to_list(Input))
  end;
decode(Input) when is_list(Input) ->
  try length(Input) of
    Len when Len > ?MAX_DECODE_LEN ->
      {error, input_too_long};
    _ ->
      decode_chars(Input)
  catch
    _:_ ->
      {error, bad_char}
  end;
decode(_) ->
  {error, bad_char}.

-spec encode_check(binary()) -> binary().
encode_check(Payload) when is_binary(Payload) ->
  Checksum = double_sha256_checksum(Payload),
  encode(<<Payload/binary, Checksum:4/binary>>).

-spec decode_check(binary() | string()) ->
  {ok, binary()} | {error, bad_checksum | bad_char | bad_encoding | input_too_long}.
decode_check(Input) ->
  case decode(Input) of
    {ok, Bin} when byte_size(Bin) >= 4 ->
      PayloadSize = byte_size(Bin) - 4,
      <<Payload:PayloadSize/binary, Checksum:4/binary>> = Bin,
      case double_sha256_checksum(Payload) of
        Checksum ->
          {ok, Payload};
        _ExpectedMismatch ->
          {error, bad_checksum}
      end;
    {ok, _TooShort} ->
      {error, bad_checksum};
    {error, Reason} ->
      {error, Reason}
  end.

%% ===================================================================
%% Internal Helpers: Encoding
%% ===================================================================

-spec count_leading_zeros(binary(), non_neg_integer()) -> {non_neg_integer(), binary()}.
count_leading_zeros(<<0:8, Rest/binary>>, Count) ->
  count_leading_zeros(Rest, Count + 1);
count_leading_zeros(Rest, Count) ->
  {Count, Rest}.

-spec encode_radix10(non_neg_integer(), string()) -> string().
encode_radix10(0, Acc) ->
  Acc;
encode_radix10(X, Acc) ->
  Q = X div ?BASE10,
  R = X rem ?BASE10,
  if
    Q == 0 ->
      encode_remainder(R, Acc);
    true ->
      encode_radix10(Q, extract10(R, Acc))
  end.

-spec encode_remainder(non_neg_integer(), string()) -> string().
encode_remainder(0, Acc) ->
  Acc;
encode_remainder(R, Acc) ->
  T = ?ENC_TABLE,
  encode_remainder(R div 58, [element((R rem 58) + 1, T) | Acc]).

-spec extract10(non_neg_integer(), string()) -> string().
extract10(R, Acc) ->
  R0 = R rem 58,
  Q0 = R div 58,
  R1 = Q0 rem 58,
  Q1 = Q0 div 58,
  R2 = Q1 rem 58,
  Q2 = Q1 div 58,
  R3 = Q2 rem 58,
  Q3 = Q2 div 58,
  R4 = Q3 rem 58,
  Q4 = Q3 div 58,
  R5 = Q4 rem 58,
  Q5 = Q4 div 58,
  R6 = Q5 rem 58,
  Q6 = Q5 div 58,
  R7 = Q6 rem 58,
  Q7 = Q6 div 58,
  R8 = Q7 rem 58,
  R9 = Q7 div 58,
  T = ?ENC_TABLE,
  [
    element(R9 + 1, T),
    element(R8 + 1, T),
    element(R7 + 1, T),
    element(R6 + 1, T),
    element(R5 + 1, T),
    element(R4 + 1, T),
    element(R3 + 1, T),
    element(R2 + 1, T),
    element(R1 + 1, T),
    element(R0 + 1, T)
    | Acc
  ].

%% ===================================================================
%% Internal Helpers: Decoding
%% ===================================================================

-spec decode_chars(string()) -> {ok, binary()} | {error, bad_char | bad_encoding}.
decode_chars(Chars) ->
  {LeadingOnes, RestChars} = count_leading_ones(Chars, 0),
  ZeroPrefix = binary:copy(<<0>>, LeadingOnes),
  case RestChars of
    [] ->
      {ok, ZeroPrefix};
    _ ->
      try decode_bignum(RestChars) of
        {ok, 0} ->
          {ok, ZeroPrefix};
        {ok, Num} ->
          Body = binary:encode_unsigned(Num),
          {ok, <<ZeroPrefix/binary, Body/binary>>};
        {error, Reason} ->
          {error, Reason}
      catch
        error:system_limit ->
          {error, bad_encoding}
      end
  end.

-spec count_leading_ones(string(), non_neg_integer()) -> {non_neg_integer(), string()}.
count_leading_ones([$1 | Rest], Count) ->
  count_leading_ones(Rest, Count + 1);
count_leading_ones(Rest, Count) ->
  {Count, Rest}.

-spec decode_bignum(string()) -> {ok, non_neg_integer()} | {error, bad_char}.
decode_bignum(Chars) ->
  T = ?DEC_TABLE,
  Len = length(Chars),
  RemLen = Len rem 10,
  {Head, Rest} = lists:split(RemLen, Chars),
  case decode_small(Head, 0, T) of
    {ok, InitAcc} ->
      decode_chunks(Rest, InitAcc, T);
    {error, Reason} ->
      {error, Reason}
  end.

-spec decode_small(string(), non_neg_integer(), tuple()) -> {ok, non_neg_integer()} | {error, bad_char}.
decode_small([], Acc, _T) ->
  {ok, Acc};
decode_small([C | Rest], Acc, T) when is_integer(C), C >= 0, C =< 255 ->
  case element(C + 1, T) of
    Val when is_integer(Val) ->
      decode_small(Rest, Acc * 58 + Val, T);
    _Error ->
      {error, bad_char}
  end;
decode_small([_ | _], _Acc, _T) ->
  {error, bad_char}.

-spec decode_chunks(string(), non_neg_integer(), tuple()) -> {ok, non_neg_integer()} | {error, bad_char}.
decode_chunks([], Acc, _T) ->
  {ok, Acc};
decode_chunks([C0, C1, C2, C3, C4, C5, C6, C7, C8, C9 | Rest], Acc, T) when
  is_integer(C0),
  C0 >= 0,
  C0 =< 255,
  is_integer(C1),
  C1 >= 0,
  C1 =< 255,
  is_integer(C2),
  C2 >= 0,
  C2 =< 255,
  is_integer(C3),
  C3 >= 0,
  C3 =< 255,
  is_integer(C4),
  C4 >= 0,
  C4 =< 255,
  is_integer(C5),
  C5 >= 0,
  C5 =< 255,
  is_integer(C6),
  C6 >= 0,
  C6 =< 255,
  is_integer(C7),
  C7 >= 0,
  C7 =< 255,
  is_integer(C8),
  C8 >= 0,
  C8 =< 255,
  is_integer(C9),
  C9 >= 0,
  C9 =< 255
->
  case
    {
      element(C0 + 1, T),
      element(C1 + 1, T),
      element(C2 + 1, T),
      element(C3 + 1, T),
      element(C4 + 1, T),
      element(C5 + 1, T),
      element(C6 + 1, T),
      element(C7 + 1, T),
      element(C8 + 1, T),
      element(C9 + 1, T)
    }
  of
    {V0, V1, V2, V3, V4, V5, V6, V7, V8, V9} when
      is_integer(V0),
      is_integer(V1),
      is_integer(V2),
      is_integer(V3),
      is_integer(V4),
      is_integer(V5),
      is_integer(V6),
      is_integer(V7),
      is_integer(V8),
      is_integer(V9)
    ->
      C10 = V0 * 58 + V1,
      C20 = C10 * 58 + V2,
      C30 = C20 * 58 + V3,
      C40 = C30 * 58 + V4,
      C50 = C40 * 58 + V5,
      C60 = C50 * 58 + V6,
      C70 = C60 * 58 + V7,
      C80 = C70 * 58 + V8,
      Chunk = C80 * 58 + V9,
      decode_chunks(Rest, Acc * ?BASE10 + Chunk, T);
    _Error ->
      {error, bad_char}
  end;
decode_chunks(_, _Acc, _T) ->
  {error, bad_char}.

-spec double_sha256_checksum(binary()) -> <<_:32>>.
double_sha256_checksum(Data) ->
  <<Checksum:4/binary, _/binary>> = crypto:hash(sha256, crypto:hash(sha256, Data)),
  Checksum.
