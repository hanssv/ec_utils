%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang implementation of the BLAKE2b cryptographic hash function
%%% (RFC 7693) with support for arbitrary digest lengths (1-64 bytes),
%%% keying, salt, and personalization.
%%%
%%% Used for Zcash RedJubjub (ZIP 215 / ZIP 216 / spec §5.4.7.1) H* hash.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_blake2b).

-typing([eqwalizer]).

-export([
  hash/1,
  hash/2
]).

-export_type([
  options/0
]).

-define(MASK64, 16#FFFFFFFFFFFFFFFF).

-define(IV0, 16#6a09e667f3bcc908).
-define(IV1, 16#bb67ae8584caa73b).
-define(IV2, 16#3c6ef372fe94f82b).
-define(IV3, 16#a54ff53a5f1d36f1).
-define(IV4, 16#510e527fade682d1).
-define(IV5, 16#9b05688c2b3e6c1f).
-define(IV6, 16#1f83d9abfb41bd6b).
-define(IV7, 16#5be0cd19137e2179).

-type options() :: #{
  outlen => pos_integer(),
  key => binary(),
  salt => binary(),
  personal => binary()
}.

-type state_h() ::
  {
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
  }.

-type msg_block() ::
  {
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
  }.

-type state_v() ::
  {
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
  }.

%% @doc Compute standard unkeyed BLAKE2b-512 (64-byte digest).
-spec hash(binary()) -> binary().
hash(Data) when is_binary(Data) ->
  hash(Data, #{}).

%% @doc Compute BLAKE2b with custom options (outlen, key, salt, personal).
-spec hash(binary(), options()) -> binary().
hash(Data, Options) when is_binary(Data), is_map(Options) ->
  OutLen = maps:get(outlen, Options, 64),
  Key = maps:get(key, Options, <<>>),
  Salt = maps:get(salt, Options, <<0:128>>),
  Personal = maps:get(personal, Options, <<0:128>>),

  if
    OutLen < 1 orelse OutLen > 64 ->
      error(badarg);
    byte_size(Key) > 64 ->
      error(badarg);
    byte_size(Salt) > 16 ->
      error(badarg);
    byte_size(Personal) > 16 ->
      error(badarg);
    true ->
      PaddedSalt = pad_right(Salt, 16),
      PaddedPersonal = pad_right(Personal, 16),
      InitH = init_h(OutLen, byte_size(Key), PaddedSalt, PaddedPersonal),

      case Key of
        <<>> ->
          hash_data(Data, InitH, OutLen);
        _ ->
          KeyBlock = pad_right(Key, 128),
          hash_data(<<KeyBlock/binary, Data/binary>>, InitH, OutLen)
      end
  end;
hash(_, _) ->
  error(badarg).

-spec pad_right(binary(), non_neg_integer()) -> binary().
pad_right(Bin, Len) when byte_size(Bin) < Len ->
  PadBits = (Len - byte_size(Bin)) * 8,
  <<Bin/binary, 0:PadBits>>;
pad_right(Bin, Len) when byte_size(Bin) =:= Len ->
  Bin.

-spec init_h(pos_integer(), non_neg_integer(), binary(), binary()) -> state_h().
init_h(OutLen, KeyLen, Salt16, Personal16) ->
  <<S0:64/little, S1:64/little>> = Salt16,
  <<P0:64/little, P1:64/little>> = Personal16,

  %% Parameter word 0: outlen (byte 0), keylen (byte 1), fanout=1 (byte 2), depth=1 (byte 3)
  Param0 = OutLen bor (KeyLen bsl 8) bor (1 bsl 16) bor (1 bsl 24),
  H0 = ?IV0 bxor Param0,
  H1 = ?IV1,
  H2 = ?IV2,
  H3 = ?IV3,
  H4 = ?IV4 bxor S0,
  H5 = ?IV5 bxor S1,
  H6 = ?IV6 bxor P0,
  H7 = ?IV7 bxor P1,
  {H0, H1, H2, H3, H4, H5, H6, H7}.

-spec hash_data(binary(), state_h(), pos_integer()) -> binary().
hash_data(<<>>, InitH, OutLen) ->
  %% Empty message case: exactly one 128-byte block of zeroes with final flag and count = 0
  ZeroBlock = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  FinH = compress_block(ZeroBlock, InitH, 0, ?MASK64, 0),
  finalize_digest(FinH, OutLen);
hash_data(Data, InitH, OutLen) ->
  TotalBytes = byte_size(Data),
  FinH = process_blocks(Data, InitH, 0, TotalBytes),
  finalize_digest(FinH, OutLen).

-spec process_blocks(binary(), state_h(), non_neg_integer(), non_neg_integer()) -> state_h().
process_blocks(Block128, H, _Count, TotalBytes) when byte_size(Block128) =< 128 ->
  Padded = pad_right(Block128, 128),
  MsgBlock = parse_block(Padded),
  compress_block(MsgBlock, H, TotalBytes, ?MASK64, 0);
process_blocks(<<Block128:128/binary, Rest/binary>>, H, Count, TotalBytes) ->
  NewCount = Count + 128,
  MsgBlock = parse_block(Block128),
  NewH = compress_block(MsgBlock, H, NewCount, 0, 0),
  process_blocks(Rest, NewH, NewCount, TotalBytes).

-spec parse_block(binary()) -> msg_block().
parse_block(<<
  M0:64/little,
  M1:64/little,
  M2:64/little,
  M3:64/little,
  M4:64/little,
  M5:64/little,
  M6:64/little,
  M7:64/little,
  M8:64/little,
  M9:64/little,
  M10:64/little,
  M11:64/little,
  M12:64/little,
  M13:64/little,
  M14:64/little,
  M15:64/little
>>) ->
  {M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15}.

-spec compress_block(
  msg_block(),
  state_h(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer()
) -> state_h().
compress_block(M, {H0, H1, H2, H3, H4, H5, H6, H7}, Count, LastBlock, LastNode) ->
  CountLow = Count band ?MASK64,
  CountHigh = (Count bsr 64) band ?MASK64,

  V0 = H0,
  V1 = H1,
  V2 = H2,
  V3 = H3,
  V4 = H4,
  V5 = H5,
  V6 = H6,
  V7 = H7,
  V8 = ?IV0,
  V9 = ?IV1,
  V10 = ?IV2,
  V11 = ?IV3,
  V12 = ?IV4 bxor CountLow,
  V13 = ?IV5 bxor CountHigh,
  V14 = ?IV6 bxor LastBlock,
  V15 = ?IV7 bxor LastNode,

  InitV = {V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15},
  FinV = rounds(0, M, InitV),

  {FV0, FV1, FV2, FV3, FV4, FV5, FV6, FV7, FV8, FV9, FV10, FV11, FV12, FV13, FV14, FV15} = FinV,
  {
    H0 bxor FV0 bxor FV8,
    H1 bxor FV1 bxor FV9,
    H2 bxor FV2 bxor FV10,
    H3 bxor FV3 bxor FV11,
    H4 bxor FV4 bxor FV12,
    H5 bxor FV5 bxor FV13,
    H6 bxor FV6 bxor FV14,
    H7 bxor FV7 bxor FV15
  }.

-spec rounds(
  non_neg_integer(),
  msg_block(),
  state_v()
) -> state_v().
rounds(12, _M, V) ->
  V;
rounds(R, M, V) ->
  V1 = round_step(R, M, V),
  rounds(R + 1, M, V1).

-compile({inline, [g64/6, rotr64/2, elem/2]}).

-spec rotr64(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
rotr64(X, N) ->
  ((X bsr N) bor (X bsl (64 - N))) band ?MASK64.

-spec g64(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer()
) ->
  {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
g64(A, B, C, D, X, Y) ->
  A1 = (A + B + X) band ?MASK64,
  D1 = rotr64(D bxor A1, 32),
  C1 = (C + D1) band ?MASK64,
  B1 = rotr64(B bxor C1, 24),
  A2 = (A1 + B1 + Y) band ?MASK64,
  D2 = rotr64(D1 bxor A2, 16),
  C2 = (C1 + D2) band ?MASK64,
  B2 = rotr64(B1 bxor C2, 63),
  {A2, B2, C2, D2}.

-spec round_cols(non_neg_integer(), state_v(), msg_block()) -> state_v().
round_cols(R, {V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15}, M) ->
  {S0, S1, S2, S3, S4, S5, S6, S7} = sigma_row(R, 0),
  {NV0, NV4, NV8, NV12} = g64(V0, V4, V8, V12, elem(S0, M), elem(S1, M)),
  {NV1, NV5, NV9, NV13} = g64(V1, V5, V9, V13, elem(S2, M), elem(S3, M)),
  {NV2, NV6, NV10, NV14} = g64(V2, V6, V10, V14, elem(S4, M), elem(S5, M)),
  {NV3, NV7, NV11, NV15} = g64(V3, V7, V11, V15, elem(S6, M), elem(S7, M)),
  {NV0, NV1, NV2, NV3, NV4, NV5, NV6, NV7, NV8, NV9, NV10, NV11, NV12, NV13, NV14, NV15}.

-spec round_diag(non_neg_integer(), state_v(), msg_block()) -> state_v().
round_diag(R, {V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15}, M) ->
  {S8, S9, S10, S11, S12, S13, S14, S15} = sigma_row(R, 1),
  {NV0, NV5, NV10, NV15} = g64(V0, V5, V10, V15, elem(S8, M), elem(S9, M)),
  {NV1, NV6, NV11, NV12} = g64(V1, V6, V11, V12, elem(S10, M), elem(S11, M)),
  {NV2, NV7, NV8, NV13} = g64(V2, V7, V8, V13, elem(S12, M), elem(S13, M)),
  {NV3, NV4, NV9, NV14} = g64(V3, V4, V9, V14, elem(S14, M), elem(S15, M)),
  {NV0, NV1, NV2, NV3, NV4, NV5, NV6, NV7, NV8, NV9, NV10, NV11, NV12, NV13, NV14, NV15}.

-spec round_step(non_neg_integer(), msg_block(), state_v()) -> state_v().
round_step(R, M, V) ->
  V1 = round_cols(R, V, M),
  round_diag(R, V1, M).

-spec sigma_row(non_neg_integer(), 0 | 1) ->
  {
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer(),
    non_neg_integer()
  }.
sigma_row(0, 0) -> {0, 1, 2, 3, 4, 5, 6, 7};
sigma_row(0, 1) -> {8, 9, 10, 11, 12, 13, 14, 15};
sigma_row(1, 0) -> {14, 10, 4, 8, 9, 15, 13, 6};
sigma_row(1, 1) -> {1, 12, 0, 2, 11, 7, 5, 3};
sigma_row(2, 0) -> {11, 8, 12, 0, 5, 2, 15, 13};
sigma_row(2, 1) -> {10, 14, 3, 6, 7, 1, 9, 4};
sigma_row(3, 0) -> {7, 9, 3, 1, 13, 12, 11, 14};
sigma_row(3, 1) -> {2, 6, 5, 10, 4, 0, 15, 8};
sigma_row(4, 0) -> {9, 0, 5, 7, 2, 4, 10, 15};
sigma_row(4, 1) -> {14, 1, 11, 12, 6, 8, 3, 13};
sigma_row(5, 0) -> {2, 12, 6, 10, 0, 11, 8, 3};
sigma_row(5, 1) -> {4, 13, 7, 5, 15, 14, 1, 9};
sigma_row(6, 0) -> {12, 5, 1, 15, 14, 13, 4, 10};
sigma_row(6, 1) -> {0, 7, 6, 3, 9, 2, 8, 11};
sigma_row(7, 0) -> {13, 11, 7, 14, 12, 1, 3, 9};
sigma_row(7, 1) -> {5, 0, 15, 4, 8, 6, 2, 10};
sigma_row(8, 0) -> {6, 15, 14, 9, 11, 3, 0, 8};
sigma_row(8, 1) -> {12, 2, 13, 7, 1, 4, 10, 5};
sigma_row(9, 0) -> {10, 2, 8, 4, 7, 6, 1, 5};
sigma_row(9, 1) -> {15, 11, 9, 14, 3, 12, 13, 0};
sigma_row(10, 0) -> {0, 1, 2, 3, 4, 5, 6, 7};
sigma_row(10, 1) -> {8, 9, 10, 11, 12, 13, 14, 15};
sigma_row(11, 0) -> {14, 10, 4, 8, 9, 15, 13, 6};
sigma_row(11, 1) -> {1, 12, 0, 2, 11, 7, 5, 3}.

-spec elem(non_neg_integer(), msg_block()) -> non_neg_integer().
elem(0, {M0, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _}) -> M0;
elem(1, {_, M1, _, _, _, _, _, _, _, _, _, _, _, _, _, _}) -> M1;
elem(2, {_, _, M2, _, _, _, _, _, _, _, _, _, _, _, _, _}) -> M2;
elem(3, {_, _, _, M3, _, _, _, _, _, _, _, _, _, _, _, _}) -> M3;
elem(4, {_, _, _, _, M4, _, _, _, _, _, _, _, _, _, _, _}) -> M4;
elem(5, {_, _, _, _, _, M5, _, _, _, _, _, _, _, _, _, _}) -> M5;
elem(6, {_, _, _, _, _, _, M6, _, _, _, _, _, _, _, _, _}) -> M6;
elem(7, {_, _, _, _, _, _, _, M7, _, _, _, _, _, _, _, _}) -> M7;
elem(8, {_, _, _, _, _, _, _, _, M8, _, _, _, _, _, _, _}) -> M8;
elem(9, {_, _, _, _, _, _, _, _, _, M9, _, _, _, _, _, _}) -> M9;
elem(10, {_, _, _, _, _, _, _, _, _, _, M10, _, _, _, _, _}) -> M10;
elem(11, {_, _, _, _, _, _, _, _, _, _, _, M11, _, _, _, _}) -> M11;
elem(12, {_, _, _, _, _, _, _, _, _, _, _, _, M12, _, _, _}) -> M12;
elem(13, {_, _, _, _, _, _, _, _, _, _, _, _, _, M13, _, _}) -> M13;
elem(14, {_, _, _, _, _, _, _, _, _, _, _, _, _, _, M14, _}) -> M14;
elem(15, {_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, M15}) -> M15.

-spec finalize_digest(state_h(), pos_integer()) -> binary().
finalize_digest({H0, H1, H2, H3, H4, H5, H6, H7}, OutLen) ->
  FullBin = <<
    H0:64/little,
    H1:64/little,
    H2:64/little,
    H3:64/little,
    H4:64/little,
    H5:64/little,
    H6:64/little,
    H7:64/little
  >>,
  binary:part(FullBin, 0, OutLen).
