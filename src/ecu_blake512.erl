%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang implementation of the BLAKE-512 cryptographic hash function
%%% (NIST SHA-3 competition finalist).
%%%
%%% Used for Circom and BabyJubjub EdDSA private key expansion and nonces.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_blake512).

-typing([eqwalizer]).

-export([
  hash/1
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

-define(C0, 16#243f6a8885a308d3).
-define(C1, 16#13198a2e03707344).
-define(C2, 16#a4093822299f31d0).
-define(C3, 16#082efa98ec4e6c89).
-define(C4, 16#452821e638d01377).
-define(C5, 16#be5466cf34e90c6c).
-define(C6, 16#c0ac29b7c97c50dd).
-define(C7, 16#3f84d5b5b5470917).
-define(C8, 16#9216d5d98979fb1b).
-define(C9, 16#d1310ba698dfb5ac).
-define(C10, 16#2ffd72dbd01adfb7).
-define(C11, 16#b8e1afed6a267e96).
-define(C12, 16#ba7c9045f12c7f99).
-define(C13, 16#24a19947b3916cf7).
-define(C14, 16#0801f2e2858efc16).
-define(C15, 16#636920d871574e69).

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

%% @doc Hash arbitrary binary data with BLAKE-512, returning 64 bytes.
-spec hash(binary()) -> binary().
hash(Data) when is_binary(Data) ->
  InitH = {?IV0, ?IV1, ?IV2, ?IV3, ?IV4, ?IV5, ?IV6, ?IV7},
  BitLen = byte_size(Data) * 8,
  process_message(Data, BitLen, 0, InitH).

-spec process_message(binary(), non_neg_integer(), non_neg_integer(), state_h()) -> binary().
process_message(Data, TotalBitLen, ProcessedBits, H) when byte_size(Data) >= 128 ->
  <<Block:128/binary, Rest/binary>> = Data,
  NextBits = ProcessedBits + 1024,
  NewH = compress(Block, NextBits, false, H),
  process_message(Rest, TotalBitLen, NextBits, NewH);
process_message(Remainder, TotalBitLen, _ProcessedBits, H) ->
  pad_and_finalize(Remainder, TotalBitLen, H).

-spec pad_and_finalize(binary(), non_neg_integer(), state_h()) -> binary().
pad_and_finalize(Data, TotalBitLen, H) ->
  Len = byte_size(Data),
  FinalH =
    if
      Len =:= 111 ->
        %% Special case: exactly 111 bytes, 1 byte left for 0x81 (0x80 | 0x01)
        Padded = <<Data/binary, 16#81:8, TotalBitLen:128/big>>,
        compress(Padded, TotalBitLen, TotalBitLen =:= 0, H);
      Len < 111 ->
        PadZeros = 111 - Len - 1,
        Padded = <<Data/binary, 16#80:8, 0:(PadZeros * 8), 16#01:8, TotalBitLen:128/big>>,
        compress(Padded, TotalBitLen, TotalBitLen =:= 0, H);
      true ->
        %% Len > 111: spills over into 2 blocks
        PadZeros1 = 128 - Len - 1,
        Block1 = <<Data/binary, 16#80:8, 0:(PadZeros1 * 8)>>,
        InterH = compress(Block1, TotalBitLen, false, H),
        Block2 = <<0:(111 * 8), 16#01:8, TotalBitLen:128/big>>,
        compress(Block2, 0, true, InterH)
    end,
  {H0, H1, H2, H3, H4, H5, H6, H7} = FinalH,
  <<H0:64/big, H1:64/big, H2:64/big, H3:64/big, H4:64/big, H5:64/big, H6:64/big, H7:64/big>>.

-spec compress(binary(), non_neg_integer(), boolean(), state_h()) -> state_h().
compress(Block, TBitLen, NullT, {H0, H1, H2, H3, H4, H5, H6, H7}) ->
  <<M0:64/big, M1:64/big, M2:64/big, M3:64/big, M4:64/big, M5:64/big, M6:64/big, M7:64/big, M8:64/big,
    M9:64/big, M10:64/big, M11:64/big, M12:64/big, M13:64/big, M14:64/big, M15:64/big>> = Block,
  M = {M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15},

  T0 = TBitLen band ?MASK64,
  T1 = (TBitLen bsr 64) band ?MASK64,

  {V12, V13, V14, V15} =
    if
      NullT ->
        {?C4, ?C5, ?C6, ?C7};
      true ->
        {T0 bxor ?C4, T0 bxor ?C5, T1 bxor ?C6, T1 bxor ?C7}
    end,

  V0 = H0,
  V1 = H1,
  V2 = H2,
  V3 = H3,
  V4 = H4,
  V5 = H5,
  V6 = H6,
  V7 = H7,
  V8 = ?C0,
  V9 = ?C1,
  V10 = ?C2,
  V11 = ?C3,

  V = {V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15},
  VEnd = rounds(0, V, M),

  {EV0, EV1, EV2, EV3, EV4, EV5, EV6, EV7, EV8, EV9, EV10, EV11, EV12, EV13, EV14, EV15} = VEnd,
  NewH0 = H0 bxor EV0 bxor EV8,
  NewH1 = H1 bxor EV1 bxor EV9,
  NewH2 = H2 bxor EV2 bxor EV10,
  NewH3 = H3 bxor EV3 bxor EV11,
  NewH4 = H4 bxor EV4 bxor EV12,
  NewH5 = H5 bxor EV5 bxor EV13,
  NewH6 = H6 bxor EV6 bxor EV14,
  NewH7 = H7 bxor EV7 bxor EV15,
  {NewH0, NewH1, NewH2, NewH3, NewH4, NewH5, NewH6, NewH7}.

-spec rounds(non_neg_integer(), state_v(), msg_block()) -> state_v().
rounds(16, V, _M) ->
  V;
rounds(R, V, M) ->
  V1 = round_cols(R rem 10, V, M),
  V2 = round_diag(R rem 10, V1, M),
  rounds(R + 1, V2, M).

-compile({inline, [rot64/2, g64/8]}).

-spec rot64(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
rot64(X, N) ->
  ((X bsr N) bor (X bsl (64 - N))) band ?MASK64.

-spec g64(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer()
) ->
  {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
g64(A, B, C, D, M1, C1, M2, C2) ->
  A1 = (A + B + (M1 bxor C1)) band ?MASK64,
  D1 = rot64(D bxor A1, 32),
  C1_val = (C + D1) band ?MASK64,
  B1 = rot64(B bxor C1_val, 25),
  A2 = (A1 + B1 + (M2 bxor C2)) band ?MASK64,
  D2 = rot64(D1 bxor A2, 16),
  C2_val = (C1_val + D2) band ?MASK64,
  B2 = rot64(B1 bxor C2_val, 11),
  {A2, B2, C2_val, D2}.

-spec round_cols(non_neg_integer(), state_v(), msg_block()) -> state_v().
round_cols(SigmaIdx, {V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15}, M) ->
  {S0, S1, S2, S3, S4, S5, S6, S7} = sigma_row(SigmaIdx, 0),
  {NV0, NV4, NV8, NV12} = g64(V0, V4, V8, V12, elem(S0, M), c_elem(S1), elem(S1, M), c_elem(S0)),
  {NV1, NV5, NV9, NV13} = g64(V1, V5, V9, V13, elem(S2, M), c_elem(S3), elem(S3, M), c_elem(S2)),
  {NV2, NV6, NV10, NV14} = g64(V2, V6, V10, V14, elem(S4, M), c_elem(S5), elem(S5, M), c_elem(S4)),
  {NV3, NV7, NV11, NV15} = g64(V3, V7, V11, V15, elem(S6, M), c_elem(S7), elem(S7, M), c_elem(S6)),
  {NV0, NV1, NV2, NV3, NV4, NV5, NV6, NV7, NV8, NV9, NV10, NV11, NV12, NV13, NV14, NV15}.

-spec round_diag(non_neg_integer(), state_v(), msg_block()) -> state_v().
round_diag(SigmaIdx, {V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15}, M) ->
  {S8, S9, S10, S11, S12, S13, S14, S15} = sigma_row(SigmaIdx, 1),
  {NV0, NV5, NV10, NV15} = g64(V0, V5, V10, V15, elem(S8, M), c_elem(S9), elem(S9, M), c_elem(S8)),
  {NV1, NV6, NV11, NV12} = g64(V1, V6, V11, V12, elem(S10, M), c_elem(S11), elem(S11, M), c_elem(S10)),
  {NV2, NV7, NV8, NV13} = g64(V2, V7, V8, V13, elem(S12, M), c_elem(S13), elem(S13, M), c_elem(S12)),
  {NV3, NV4, NV9, NV14} = g64(V3, V4, V9, V14, elem(S14, M), c_elem(S15), elem(S15, M), c_elem(S14)),
  {NV0, NV1, NV2, NV3, NV4, NV5, NV6, NV7, NV8, NV9, NV10, NV11, NV12, NV13, NV14, NV15}.

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
sigma_row(9, 1) -> {15, 11, 9, 14, 3, 12, 13, 0}.

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

-spec c_elem(non_neg_integer()) -> non_neg_integer().
c_elem(0) -> ?C0;
c_elem(1) -> ?C1;
c_elem(2) -> ?C2;
c_elem(3) -> ?C3;
c_elem(4) -> ?C4;
c_elem(5) -> ?C5;
c_elem(6) -> ?C6;
c_elem(7) -> ?C7;
c_elem(8) -> ?C8;
c_elem(9) -> ?C9;
c_elem(10) -> ?C10;
c_elem(11) -> ?C11;
c_elem(12) -> ?C12;
c_elem(13) -> ?C13;
c_elem(14) -> ?C14;
c_elem(15) -> ?C15.
