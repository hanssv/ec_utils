%%% -*- erlang -*-
%%% % @format
%%%
%%%-------------------------------------------------------------------
%%% @doc Pure Erlang Keccak-f[1600] Permutation and SHA-3 Family (FIPS 202)
%%%
%%% Implements the Keccak sponge function family with zero external C/NIF
%%% dependencies, including:
%%%   - Ethereum Keccak-256 (`keccak256/1`)
%%%   - NIST FIPS 202 SHA-3 (`sha3_224/1`, `sha3_256/1`, `sha3_384/1`, `sha3_512/1`)
%%%   - NIST FIPS 202 SHAKE XOF (`shake128/2`, `shake256/2`)
%%%   - Generic Keccak sponge (`keccak/4`)
%%%
%%% Algorithmic optimizations:
%%%   1. State is represented throughout absorption as a 25-tuple of 64-bit uints,
%%%      eliminating all 1600-bit bignum allocations and binary marshalling.
%%%   2. Fast O(1) multi-byte padding path for byte-aligned binary/iodata inputs,
%%%      avoiding bit-by-bit slicing and flipping.
%%%   3. Unrolled 4-round symmetry by Hans Svensson, fusing 4 Keccak rounds into
%%%      a single function pass to eliminate intermediate 25-tuple heap allocations.
%%%   4. Branchless 64-bit uint arithmetic using bitwise operations (`?CAN64`,
%%%      `?ROTL64`) that stay strictly within 64-bit positive integers.
%%%
%%% Note on usage:
%%%   `ecu_keccak` is provided to ensure `ec_utils` remains completely self-contained
%%%   with zero external C dependencies for Ethereum message signing/recovery
%%%   (`ecu_crypto:eth_msg_recover/2`), address derivation, and Ed448/SHAKE256.
%%%   Do NOT use this library if you only require standalone, high-throughput hash
%%%   functions! For bulk or streaming hashing, use OTP's built-in `crypto:hash/2`
%%%   (for NIST SHA-3) or a dedicated native NIF, which are ~40x–70x faster.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_keccak).

-typing([eqwalizer]).

-export([keccak256/1,
         sha3_224/1,
         sha3_256/1,
         sha3_384/1,
         sha3_512/1,
         shake128/2,
         shake256/2,
         keccak/4]).

-define(NIST_SHA3_DELIMITER, <<2#01:2>>).
-define(KECCAK_DELIMITER, <<>>).
-define(SHAKE_DELIMITER, <<2#1111:4>>).

-define(SUFFIX_KECCAK, 16#01).
-define(SUFFIX_SHA3,   16#06).
-define(SUFFIX_SHAKE,  16#1F).

-define(INT64, 16#FFFFFFFFFFFFFFFF).
-define(BSL64(X, N), ((X bsl N) band ?INT64)).
-define(BSR64(X, N), (X bsr N)).
-define(ROTL64(X, N), (?BSL64(X, N) bor ?BSR64(X, (64 - N)))).
-define(CAN64(A, B), ((A bxor B) band A)).

-type state_words() :: {
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()
}.

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Ethereum Keccak-256 (32-byte digest with empty delimiter).
-spec keccak256(Message :: iodata()) -> <<_:256>>.
keccak256(Message) ->
  MsgBin = iolist_to_binary(Message),
  hash_fast(MsgBin, ?SUFFIX_KECCAK, 136, 17, 256).

%% @doc NIST FIPS 202 SHA3-224 (28-byte digest).
-spec sha3_224(Message :: iodata()) -> <<_:224>>.
sha3_224(Message) ->
  MsgBin = iolist_to_binary(Message),
  hash_fast(MsgBin, ?SUFFIX_SHA3, 144, 18, 224).

%% @doc NIST FIPS 202 SHA3-256 (32-byte digest).
-spec sha3_256(Message :: iodata()) -> <<_:256>>.
sha3_256(Message) ->
  MsgBin = iolist_to_binary(Message),
  hash_fast(MsgBin, ?SUFFIX_SHA3, 136, 17, 256).

%% @doc NIST FIPS 202 SHA3-384 (48-byte digest).
-spec sha3_384(Message :: iodata()) -> <<_:384>>.
sha3_384(Message) ->
  MsgBin = iolist_to_binary(Message),
  hash_fast(MsgBin, ?SUFFIX_SHA3, 104, 13, 384).

%% @doc NIST FIPS 202 SHA3-512 (64-byte digest).
-spec sha3_512(Message :: iodata()) -> <<_:512>>.
sha3_512(Message) ->
  MsgBin = iolist_to_binary(Message),
  hash_fast(MsgBin, ?SUFFIX_SHA3, 72, 9, 512).

%% @doc NIST FIPS 202 SHAKE128 extendable-output function.
-spec shake128(Message :: iodata(), OutputBitLength :: pos_integer()) -> bitstring().
shake128(Message, OutputBitLength) ->
  MsgBin = iolist_to_binary(Message),
  hash_fast(MsgBin, ?SUFFIX_SHAKE, 168, 21, OutputBitLength).

%% @doc NIST FIPS 202 SHAKE256 extendable-output function.
-spec shake256(Message :: iodata(), OutputBitLength :: pos_integer()) -> bitstring().
shake256(Message, OutputBitLength) ->
  MsgBin = iolist_to_binary(Message),
  hash_fast(MsgBin, ?SUFFIX_SHAKE, 136, 17, OutputBitLength).

%% @doc Generic Keccak sponge function for arbitrary bitstrings and delimiters.
-spec keccak(Capacity :: pos_integer(),
             Message :: bitstring(),
             Delimiter :: bitstring(),
             OutputBitLength :: pos_integer()) -> bitstring().
keccak(Capacity, Message, Delimiter, OutputBitLength)
  when is_binary(Message) andalso is_binary(Delimiter) andalso byte_size(Delimiter) == 0 ->
  BitRate = 1600 - Capacity,
  hash_fast(Message, ?SUFFIX_KECCAK, BitRate div 8, BitRate div 64, OutputBitLength);
keccak(Capacity, Message, Delimiter, OutputBitLength)
  when is_binary(Message) andalso Delimiter =:= ?NIST_SHA3_DELIMITER ->
  BitRate = 1600 - Capacity,
  hash_fast(Message, ?SUFFIX_SHA3, BitRate div 8, BitRate div 64, OutputBitLength);
keccak(Capacity, Message, Delimiter, OutputBitLength)
  when is_binary(Message) andalso Delimiter =:= ?SHAKE_DELIMITER ->
  BitRate = 1600 - Capacity,
  hash_fast(Message, ?SUFFIX_SHAKE, BitRate div 8, BitRate div 64, OutputBitLength);
keccak(Capacity, Message, Delimiter, OutputBitLength) ->
  %% Generic bitstring fallback for arbitrary non-byte-aligned inputs
  BitRate = 1600 - Capacity,
  PaddedMessage = pad_generic(Message, Delimiter, BitRate),
  InitialSponge = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
  FinalState = absorb_generic(PaddedMessage, BitRate, InitialSponge),
  squeeze(FinalState, OutputBitLength, BitRate div 64).

%% ===================================================================
%% Fast-path Byte Hash Pipeline
%% ===================================================================

-spec hash_fast(binary(), byte(), pos_integer(), pos_integer(), pos_integer()) -> bitstring().
hash_fast(Msg, SuffixByte, RateBytes, RateWords, OutputBitLength) ->
  PadBytes = RateBytes - (byte_size(Msg) rem RateBytes),
  Pad = case PadBytes of
    1 -> <<(SuffixByte bor 16#80)>>;
    2 -> <<SuffixByte, 16#80>>;
    N -> <<SuffixByte, 0:(N - 2)/unit:8, 16#80>>
  end,
  Padded = <<Msg/binary, Pad/binary>>,
  Initial = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
  FinalState = absorb_blocks(Padded, RateBytes, RateWords, Initial),
  squeeze(FinalState, OutputBitLength, RateWords).

%% ===================================================================
%% Block Absorption
%% ===================================================================

-spec absorb_blocks(binary(), pos_integer(), pos_integer(), state_words()) -> state_words().
absorb_blocks(<<>>, _RateBytes, _RateWords, State) ->
  State;
absorb_blocks(<<Block:136/binary, Rest/binary>>, 136, 17, State) ->
  absorb_blocks(Rest, 136, 17, absorb_block17(Block, State));
absorb_blocks(<<Block:72/binary, Rest/binary>>, 72, 9, State) ->
  absorb_blocks(Rest, 72, 9, absorb_block9(Block, State));
absorb_blocks(<<Block:104/binary, Rest/binary>>, 104, 13, State) ->
  absorb_blocks(Rest, 104, 13, absorb_block13(Block, State));
absorb_blocks(<<Block:144/binary, Rest/binary>>, 144, 18, State) ->
  absorb_blocks(Rest, 144, 18, absorb_block18(Block, State));
absorb_blocks(<<Block:168/binary, Rest/binary>>, 168, 21, State) ->
  absorb_blocks(Rest, 168, 21, absorb_block21(Block, State)).

-spec absorb_block17(<<_:1088>>, state_words()) -> state_words().
absorb_block17(<<
  W0:64/little, W1:64/little, W2:64/little, W3:64/little,
  W4:64/little, W5:64/little, W6:64/little, W7:64/little,
  W8:64/little, W9:64/little, W10:64/little, W11:64/little,
  W12:64/little, W13:64/little, W14:64/little, W15:64/little,
  W16:64/little
>>, {
  A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16,
  A17, A18, A19, A20, A21, A22, A23, A24
}) ->
  inner_keccak_fast({
    A0 bxor W0, A1 bxor W1, A2 bxor W2, A3 bxor W3,
    A4 bxor W4, A5 bxor W5, A6 bxor W6, A7 bxor W7,
    A8 bxor W8, A9 bxor W9, A10 bxor W10, A11 bxor W11,
    A12 bxor W12, A13 bxor W13, A14 bxor W14, A15 bxor W15,
    A16 bxor W16,
    A17, A18, A19, A20, A21, A22, A23, A24
  }).

-spec absorb_block9(<<_:576>>, state_words()) -> state_words().
absorb_block9(<<
  W0:64/little, W1:64/little, W2:64/little, W3:64/little,
  W4:64/little, W5:64/little, W6:64/little, W7:64/little,
  W8:64/little
>>, {
  A0, A1, A2, A3, A4, A5, A6, A7, A8,
  A9, A10, A11, A12, A13, A14, A15, A16,
  A17, A18, A19, A20, A21, A22, A23, A24
}) ->
  inner_keccak_fast({
    A0 bxor W0, A1 bxor W1, A2 bxor W2, A3 bxor W3,
    A4 bxor W4, A5 bxor W5, A6 bxor W6, A7 bxor W7,
    A8 bxor W8,
    A9, A10, A11, A12, A13, A14, A15, A16,
    A17, A18, A19, A20, A21, A22, A23, A24
  }).

-spec absorb_block13(<<_:832>>, state_words()) -> state_words().
absorb_block13(<<
  W0:64/little, W1:64/little, W2:64/little, W3:64/little,
  W4:64/little, W5:64/little, W6:64/little, W7:64/little,
  W8:64/little, W9:64/little, W10:64/little, W11:64/little,
  W12:64/little
>>, {
  A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12,
  A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24
}) ->
  inner_keccak_fast({
    A0 bxor W0, A1 bxor W1, A2 bxor W2, A3 bxor W3,
    A4 bxor W4, A5 bxor W5, A6 bxor W6, A7 bxor W7,
    A8 bxor W8, A9 bxor W9, A10 bxor W10, A11 bxor W11,
    A12 bxor W12,
    A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24
  }).

-spec absorb_block18(<<_:1152>>, state_words()) -> state_words().
absorb_block18(<<
  W0:64/little, W1:64/little, W2:64/little, W3:64/little,
  W4:64/little, W5:64/little, W6:64/little, W7:64/little,
  W8:64/little, W9:64/little, W10:64/little, W11:64/little,
  W12:64/little, W13:64/little, W14:64/little, W15:64/little,
  W16:64/little, W17:64/little
>>, {
  A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17,
  A18, A19, A20, A21, A22, A23, A24
}) ->
  inner_keccak_fast({
    A0 bxor W0, A1 bxor W1, A2 bxor W2, A3 bxor W3,
    A4 bxor W4, A5 bxor W5, A6 bxor W6, A7 bxor W7,
    A8 bxor W8, A9 bxor W9, A10 bxor W10, A11 bxor W11,
    A12 bxor W12, A13 bxor W13, A14 bxor W14, A15 bxor W15,
    A16 bxor W16, A17 bxor W17,
    A18, A19, A20, A21, A22, A23, A24
  }).

-spec absorb_block21(<<_:1344>>, state_words()) -> state_words().
absorb_block21(<<
  W0:64/little, W1:64/little, W2:64/little, W3:64/little,
  W4:64/little, W5:64/little, W6:64/little, W7:64/little,
  W8:64/little, W9:64/little, W10:64/little, W11:64/little,
  W12:64/little, W13:64/little, W14:64/little, W15:64/little,
  W16:64/little, W17:64/little, W18:64/little, W19:64/little,
  W20:64/little
>>, {
  A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17,
  A18, A19, A20, A21, A22, A23, A24
}) ->
  inner_keccak_fast({
    A0 bxor W0, A1 bxor W1, A2 bxor W2, A3 bxor W3,
    A4 bxor W4, A5 bxor W5, A6 bxor W6, A7 bxor W7,
    A8 bxor W8, A9 bxor W9, A10 bxor W10, A11 bxor W11,
    A12 bxor W12, A13 bxor W13, A14 bxor W14, A15 bxor W15,
    A16 bxor W16, A17 bxor W17, A18 bxor W18, A19 bxor W19,
    A20 bxor W20,
    A21, A22, A23, A24
  }).

%% ===================================================================
%% Squeeze Phase
%% ===================================================================

-spec squeeze(state_words(), pos_integer(), pos_integer()) -> bitstring().
squeeze({A0, A1, A2, A3, _A4, _A5, _A6, _A7, _A8, _A9, _A10, _A11, _A12, _A13, _A14, _A15, _A16, _A17, _A18, _A19, _A20, _A21, _A22, _A23, _A24}, 256, _RateWords) ->
  <<A0:64/little, A1:64/little, A2:64/little, A3:64/little>>;
squeeze({A0, A1, A2, A3, _A4, _A5, _A6, _A7, _A8, _A9, _A10, _A11, _A12, _A13, _A14, _A15, _A16, _A17, _A18, _A19, _A20, _A21, _A22, _A23, _A24}, 224, _RateWords) ->
  <<A0:64/little, A1:64/little, A2:64/little, A3:32/little>>;
squeeze({A0, A1, A2, A3, A4, A5, _A6, _A7, _A8, _A9, _A10, _A11, _A12, _A13, _A14, _A15, _A16, _A17, _A18, _A19, _A20, _A21, _A22, _A23, _A24}, 384, _RateWords) ->
  <<A0:64/little, A1:64/little, A2:64/little, A3:64/little, A4:64/little, A5:64/little>>;
squeeze({A0, A1, A2, A3, A4, A5, A6, A7, _A8, _A9, _A10, _A11, _A12, _A13, _A14, _A15, _A16, _A17, _A18, _A19, _A20, _A21, _A22, _A23, _A24}, 512, _RateWords) ->
  <<A0:64/little, A1:64/little, A2:64/little, A3:64/little,
    A4:64/little, A5:64/little, A6:64/little, A7:64/little>>;
squeeze(State, OutputBitLength, RateWords) ->
  squeeze_loop(State, OutputBitLength, RateWords, <<>>).

-spec squeeze_loop(state_words(), pos_integer(), pos_integer(), bitstring()) -> bitstring().
squeeze_loop(_State, OutputBitLength, _RateWords, Acc)
  when OutputBitLength =< bit_size(Acc) ->
  <<ResultBits:OutputBitLength, _/bitstring>> = Acc,
  <<ResultBits:OutputBitLength>>;
squeeze_loop(State, OutputBitLength, RateWords, Acc) ->
  RateBin = extract_rate_bin(State, RateWords),
  NewAcc = <<Acc/bitstring, RateBin/binary>>,
  NewState = inner_keccak_fast(State),
  squeeze_loop(NewState, OutputBitLength, RateWords, NewAcc).

-spec extract_rate_bin(state_words(), pos_integer()) -> binary().
extract_rate_bin({
  A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24
}, RateWords) ->
  Full = <<A0:64/little, A1:64/little, A2:64/little, A3:64/little,
           A4:64/little, A5:64/little, A6:64/little, A7:64/little,
           A8:64/little, A9:64/little, A10:64/little, A11:64/little,
           A12:64/little, A13:64/little, A14:64/little, A15:64/little,
           A16:64/little, A17:64/little, A18:64/little, A19:64/little,
           A20:64/little, A21:64/little, A22:64/little, A23:64/little, A24:64/little>>,
  RateBytes = RateWords * 8,
  <<Out:RateBytes/binary, _/binary>> = Full,
  Out.

%% ===================================================================
%% Generic Bitstring Padding and Absorption Fallback
%% ===================================================================

-spec pad_generic(bitstring(), bitstring(), pos_integer()) -> bitstring().
pad_generic(Msg, Delimiter, BitRate) ->
  MsgBits = bit_size(Msg),
  DlmBits = bit_size(Delimiter),
  <<Msg0:(MsgBits div 8)/bytes, Msg1/bitstring>> = Msg,
  case (MsgBits + DlmBits) rem BitRate of
    0 ->
      <<Msg0/binary, (rev_pad(Msg1, Delimiter, BitRate - 2))/bitstring>>;
    N when N == BitRate - 1 ->
      <<Msg0/binary, (rev_pad(Msg1, Delimiter, BitRate - 1))/bitstring>>;
    N ->
      <<Msg0/binary, (rev_pad(Msg1, Delimiter, BitRate - N - 2))/bitstring>>
  end.

-spec rev_pad(bitstring(), bitstring(), non_neg_integer()) -> bitstring().
rev_pad(Msg, Delimiter, PadZeros) ->
  Pad = <<Msg/bitstring, Delimiter/bitstring, 1:1, 0:PadZeros, 1:1>>,
  << (flip_bits(X)) || <<X:8>> <= Pad >>.

-spec flip_bits(byte() | binary()) -> binary().
flip_bits(0) -> <<0:8>>;
flip_bits(<<A:1, B:1, C:1, D:1, E:1, F:1, G:1, H:1>>) ->
  <<H:1, G:1, F:1, E:1, D:1, C:1, B:1, A:1>>;
flip_bits(N) when is_integer(N) -> flip_bits(<<N:8>>).

-spec absorb_generic(bitstring(), pos_integer(), state_words()) -> state_words().
absorb_generic(PaddedBits, BitRate, State) when BitRate =< bit_size(PaddedBits) ->
  RateBytes = BitRate div 8,
  <<ThisRWord:RateBytes/binary, Rest/bitstring>> = PaddedBits,
  RateWords = BitRate div 64,
  NewState = absorb_rate_bits(ThisRWord, RateWords, State),
  absorb_generic(Rest, BitRate, NewState);
absorb_generic(<<>>, _BitRate, State) ->
  State.

-spec absorb_rate_bits(bitstring(), pos_integer(), state_words()) -> state_words().
absorb_rate_bits(Bits, 17, State) -> absorb_block17(Bits, State);
absorb_rate_bits(Bits, 9, State)  -> absorb_block9(Bits, State);
absorb_rate_bits(Bits, 13, State) -> absorb_block13(Bits, State);
absorb_rate_bits(Bits, 18, State) -> absorb_block18(Bits, State);
absorb_rate_bits(Bits, 21, State) -> absorb_block21(Bits, State).

%% ===================================================================
%% Fast Unrolled Keccak-f[1600] (64-bit uints)
%% ===================================================================

-spec inner_keccak_fast(state_words()) -> state_words().
inner_keccak_fast(IntState0) ->
  IntState1 = fast_round(IntState0, {16#0000000000000001, 16#0000000000008082, 16#800000000000808A, 16#8000000080008000}),
  IntState2 = fast_round(IntState1, {16#000000000000808B, 16#0000000080000001, 16#8000000080008081, 16#8000000000008009}),
  IntState3 = fast_round(IntState2, {16#000000000000008A, 16#0000000000000088, 16#0000000080008009, 16#000000008000000A}),
  IntState4 = fast_round(IntState3, {16#000000008000808B, 16#800000000000008B, 16#8000000000008089, 16#8000000000008003}),
  IntState5 = fast_round(IntState4, {16#8000000000008002, 16#8000000000000080, 16#000000000000800A, 16#800000008000000A}),
  fast_round(IntState5, {16#8000000080008081, 16#8000000000008080, 16#0000000080000001, 16#8000000080008008}).

-spec fast_round(state_words(), {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}) -> state_words().
fast_round({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24},
           {RC0, RC1, RC2, RC3}) ->
  %% Round 1

  BC0_0 = A0 bxor A5 bxor A10 bxor A15 bxor A20,
  BC1_0 = A1 bxor A6 bxor A11 bxor A16 bxor A21,
  BC2_0 = A2 bxor A7 bxor A12 bxor A17 bxor A22,
  BC3_0 = A3 bxor A8 bxor A13 bxor A18 bxor A23,
  BC4_0 = A4 bxor A9 bxor A14 bxor A19 bxor A24,
  D0 = BC4_0 bxor ?ROTL64(BC1_0, 1),
  D1 = BC0_0 bxor ?ROTL64(BC2_0, 1),
  D2 = BC1_0 bxor ?ROTL64(BC3_0, 1),
  D3 = BC2_0 bxor ?ROTL64(BC4_0, 1),
  D4 = BC3_0 bxor ?ROTL64(BC0_0, 1),

  BC0_1 = A0 bxor D0,
  BC1_1 = ?ROTL64(A6 bxor D1, 44),
  BC2_1 = ?ROTL64(A12 bxor D2, 43),
  BC3_1 = ?ROTL64(A18 bxor D3, 21),
  BC4_1 = ?ROTL64(A24 bxor D4, 14),
  A0_1  = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC0,
  A6_1  = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A12_1 = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A18_1 = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A24_1 = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A10 bxor D0, 3),
  BC3_2 = ?ROTL64(A16 bxor D1, 45),
  BC4_2 = ?ROTL64(A22 bxor D2, 61),
  BC0_2 = ?ROTL64(A3 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A10_1 = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A16_1 = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A22_1 = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A3_1  = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1  = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A20 bxor D0, 18),
  BC0_3 = ?ROTL64(A1 bxor D1, 1),
  BC1_3 = ?ROTL64(A7 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A19 bxor D4, 8),
  A20_1 = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A1_1  = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A7_1  = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A19_1 = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A5 bxor D0, 36),
  BC2_4 = ?ROTL64(A11 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A23 bxor D3, 56),
  BC0_4 = ?ROTL64(A4 bxor D4, 27),
  A5_1  = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A11_1 = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A23_1 = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A4_1  = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A15 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A2 bxor D2, 62),
  BC1_5 = ?ROTL64(A8 bxor D3, 55),
  BC2_5 = ?ROTL64(A14 bxor D4, 39),
  A15_1 = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A2_1  = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A8_1  = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A14_1 = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  %% Round 2

  BC0_0_r2 = A0_1 bxor A5_1 bxor A10_1 bxor A15_1 bxor A20_1,
  BC1_0_r2 = A1_1 bxor A6_1 bxor A11_1 bxor A16_1 bxor A21_1,
  BC2_0_r2 = A2_1 bxor A7_1 bxor A12_1 bxor A17_1 bxor A22_1,
  BC3_0_r2 = A3_1 bxor A8_1 bxor A13_1 bxor A18_1 bxor A23_1,
  BC4_0_r2 = A4_1 bxor A9_1 bxor A14_1 bxor A19_1 bxor A24_1,
  D0_r2 = BC4_0_r2 bxor ?ROTL64(BC1_0_r2, 1),
  D1_r2 = BC0_0_r2 bxor ?ROTL64(BC2_0_r2, 1),
  D2_r2 = BC1_0_r2 bxor ?ROTL64(BC3_0_r2, 1),
  D3_r2 = BC2_0_r2 bxor ?ROTL64(BC4_0_r2, 1),
  D4_r2 = BC3_0_r2 bxor ?ROTL64(BC0_0_r2, 1),

  BC0_1_r2 = A0_1 bxor D0_r2,
  BC1_1_r2 = ?ROTL64(A16_1 bxor D1_r2, 44),
  BC2_1_r2 = ?ROTL64(A7_1 bxor D2_r2, 43),
  BC3_1_r2 = ?ROTL64(A23_1 bxor D3_r2, 21),
  BC4_1_r2 = ?ROTL64(A14_1 bxor D4_r2, 14),
  A0_2  = BC0_1_r2 bxor ?CAN64(BC2_1_r2, BC1_1_r2) bxor RC1,
  A16_2 = BC1_1_r2 bxor ?CAN64(BC3_1_r2, BC2_1_r2),
  A7_2  = BC2_1_r2 bxor ?CAN64(BC4_1_r2, BC3_1_r2),
  A23_2 = BC3_1_r2 bxor ?CAN64(BC0_1_r2, BC4_1_r2),
  A14_2 = BC4_1_r2 bxor ?CAN64(BC1_1_r2, BC0_1_r2),

  BC2_2_r2 = ?ROTL64(A20_1 bxor D0_r2, 3),
  BC3_2_r2 = ?ROTL64(A11_1 bxor D1_r2, 45),
  BC4_2_r2 = ?ROTL64(A2_1 bxor D2_r2, 61),
  BC0_2_r2 = ?ROTL64(A18_1 bxor D3_r2, 28),
  BC1_2_r2 = ?ROTL64(A9_1 bxor D4_r2, 20),
  A20_2 = BC0_2_r2 bxor ?CAN64(BC2_2_r2, BC1_2_r2),
  A11_2 = BC1_2_r2 bxor ?CAN64(BC3_2_r2, BC2_2_r2),
  A2_2  = BC2_2_r2 bxor ?CAN64(BC4_2_r2, BC3_2_r2),
  A18_2 = BC3_2_r2 bxor ?CAN64(BC0_2_r2, BC4_2_r2),
  A9_2  = BC4_2_r2 bxor ?CAN64(BC1_2_r2, BC0_2_r2),

  BC4_3_r2 = ?ROTL64(A15_1 bxor D0_r2, 18),
  BC0_3_r2 = ?ROTL64(A6_1 bxor D1_r2, 1),
  BC1_3_r2 = ?ROTL64(A22_1 bxor D2_r2, 6),
  BC2_3_r2 = ?ROTL64(A13_1 bxor D3_r2, 25),
  BC3_3_r2 = ?ROTL64(A4_1 bxor D4_r2, 8),
  A15_2 = BC0_3_r2 bxor ?CAN64(BC2_3_r2, BC1_3_r2),
  A6_2  = BC1_3_r2 bxor ?CAN64(BC3_3_r2, BC2_3_r2),
  A22_2 = BC2_3_r2 bxor ?CAN64(BC4_3_r2, BC3_3_r2),
  A13_2 = BC3_3_r2 bxor ?CAN64(BC0_3_r2, BC4_3_r2),
  A4_2  = BC4_3_r2 bxor ?CAN64(BC1_3_r2, BC0_3_r2),

  BC1_4_r2 = ?ROTL64(A10_1 bxor D0_r2, 36),
  BC2_4_r2 = ?ROTL64(A1_1 bxor D1_r2, 10),
  BC3_4_r2 = ?ROTL64(A17_1 bxor D2_r2, 15),
  BC4_4_r2 = ?ROTL64(A8_1 bxor D3_r2, 56),
  BC0_4_r2 = ?ROTL64(A24_1 bxor D4_r2, 27),
  A10_2 = BC0_4_r2 bxor ?CAN64(BC2_4_r2, BC1_4_r2),
  A1_2  = BC1_4_r2 bxor ?CAN64(BC3_4_r2, BC2_4_r2),
  A17_2 = BC2_4_r2 bxor ?CAN64(BC4_4_r2, BC3_4_r2),
  A8_2  = BC3_4_r2 bxor ?CAN64(BC0_4_r2, BC4_4_r2),
  A24_2 = BC4_4_r2 bxor ?CAN64(BC1_4_r2, BC0_4_r2),

  BC3_5_r2 = ?ROTL64(A5_1 bxor D0_r2, 41),
  BC4_5_r2 = ?ROTL64(A21_1 bxor D1_r2, 2),
  BC0_5_r2 = ?ROTL64(A12_1 bxor D2_r2, 62),
  BC1_5_r2 = ?ROTL64(A3_1 bxor D3_r2, 55),
  BC2_5_r2 = ?ROTL64(A19_1 bxor D4_r2, 39),
  A5_2  = BC0_5_r2 bxor ?CAN64(BC2_5_r2, BC1_5_r2),
  A21_2 = BC1_5_r2 bxor ?CAN64(BC3_5_r2, BC2_5_r2),
  A12_2 = BC2_5_r2 bxor ?CAN64(BC4_5_r2, BC3_5_r2),
  A3_2  = BC3_5_r2 bxor ?CAN64(BC0_5_r2, BC4_5_r2),
  A19_2 = BC4_5_r2 bxor ?CAN64(BC1_5_r2, BC0_5_r2),

  %% Round 3

  BC0_0_r3 = A0_2 bxor A5_2 bxor A10_2 bxor A15_2 bxor A20_2,
  BC1_0_r3 = A1_2 bxor A6_2 bxor A11_2 bxor A16_2 bxor A21_2,
  BC2_0_r3 = A2_2 bxor A7_2 bxor A12_2 bxor A17_2 bxor A22_2,
  BC3_0_r3 = A3_2 bxor A8_2 bxor A13_2 bxor A18_2 bxor A23_2,
  BC4_0_r3 = A4_2 bxor A9_2 bxor A14_2 bxor A19_2 bxor A24_2,
  D0_r3 = BC4_0_r3 bxor ?ROTL64(BC1_0_r3, 1),
  D1_r3 = BC0_0_r3 bxor ?ROTL64(BC2_0_r3, 1),
  D2_r3 = BC1_0_r3 bxor ?ROTL64(BC3_0_r3, 1),
  D3_r3 = BC2_0_r3 bxor ?ROTL64(BC4_0_r3, 1),
  D4_r3 = BC3_0_r3 bxor ?ROTL64(BC0_0_r3, 1),

  BC0_1_r3 = A0_2 bxor D0_r3,
  BC1_1_r3 = ?ROTL64(A11_2 bxor D1_r3, 44),
  BC2_1_r3 = ?ROTL64(A22_2 bxor D2_r3, 43),
  BC3_1_r3 = ?ROTL64(A8_2 bxor D3_r3, 21),
  BC4_1_r3 = ?ROTL64(A19_2 bxor D4_r3, 14),
  A0_3  = BC0_1_r3 bxor ?CAN64(BC2_1_r3, BC1_1_r3) bxor RC2,
  A11_3 = BC1_1_r3 bxor ?CAN64(BC3_1_r3, BC2_1_r3),
  A22_3 = BC2_1_r3 bxor ?CAN64(BC4_1_r3, BC3_1_r3),
  A8_3  = BC3_1_r3 bxor ?CAN64(BC0_1_r3, BC4_1_r3),
  A19_3 = BC4_1_r3 bxor ?CAN64(BC1_1_r3, BC0_1_r3),

  BC2_2_r3 = ?ROTL64(A15_2 bxor D0_r3, 3),
  BC3_2_r3 = ?ROTL64(A1_2 bxor D1_r3, 45),
  BC4_2_r3 = ?ROTL64(A12_2 bxor D2_r3, 61),
  BC0_2_r3 = ?ROTL64(A23_2 bxor D3_r3, 28),
  BC1_2_r3 = ?ROTL64(A9_2 bxor D4_r3, 20),
  A15_3 = BC0_2_r3 bxor ?CAN64(BC2_2_r3, BC1_2_r3),
  A1_3  = BC1_2_r3 bxor ?CAN64(BC3_2_r3, BC2_2_r3),
  A12_3 = BC2_2_r3 bxor ?CAN64(BC4_2_r3, BC3_2_r3),
  A23_3 = BC3_2_r3 bxor ?CAN64(BC0_2_r3, BC4_2_r3),
  A9_3  = BC4_2_r3 bxor ?CAN64(BC1_2_r3, BC0_2_r3),

  BC4_3_r3 = ?ROTL64(A5_2 bxor D0_r3, 18),
  BC0_3_r3 = ?ROTL64(A16_2 bxor D1_r3, 1),
  BC1_3_r3 = ?ROTL64(A2_2 bxor D2_r3, 6),
  BC2_3_r3 = ?ROTL64(A13_2 bxor D3_r3, 25),
  BC3_3_r3 = ?ROTL64(A24_2 bxor D4_r3, 8),
  A5_3  = BC0_3_r3 bxor ?CAN64(BC2_3_r3, BC1_3_r3),
  A16_3 = BC1_3_r3 bxor ?CAN64(BC3_3_r3, BC2_3_r3),
  A2_3  = BC2_3_r3 bxor ?CAN64(BC4_3_r3, BC3_3_r3),
  A13_3 = BC3_3_r3 bxor ?CAN64(BC0_3_r3, BC4_3_r3),
  A24_3 = BC4_3_r3 bxor ?CAN64(BC1_3_r3, BC0_3_r3),

  BC1_4_r3 = ?ROTL64(A20_2 bxor D0_r3, 36),
  BC2_4_r3 = ?ROTL64(A6_2 bxor D1_r3, 10),
  BC3_4_r3 = ?ROTL64(A17_2 bxor D2_r3, 15),
  BC4_4_r3 = ?ROTL64(A3_2 bxor D3_r3, 56),
  BC0_4_r3 = ?ROTL64(A14_2 bxor D4_r3, 27),
  A20_3 = BC0_4_r3 bxor ?CAN64(BC2_4_r3, BC1_4_r3),
  A6_3  = BC1_4_r3 bxor ?CAN64(BC3_4_r3, BC2_4_r3),
  A17_3 = BC2_4_r3 bxor ?CAN64(BC4_4_r3, BC3_4_r3),
  A3_3  = BC3_4_r3 bxor ?CAN64(BC0_4_r3, BC4_4_r3),
  A14_3 = BC4_4_r3 bxor ?CAN64(BC1_4_r3, BC0_4_r3),

  BC3_5_r3 = ?ROTL64(A10_2 bxor D0_r3, 41),
  BC4_5_r3 = ?ROTL64(A21_2 bxor D1_r3, 2),
  BC0_5_r3 = ?ROTL64(A7_2 bxor D2_r3, 62),
  BC1_5_r3 = ?ROTL64(A18_2 bxor D3_r3, 55),
  BC2_5_r3 = ?ROTL64(A4_2 bxor D4_r3, 39),
  A10_3 = BC0_5_r3 bxor ?CAN64(BC2_5_r3, BC1_5_r3),
  A21_3 = BC1_5_r3 bxor ?CAN64(BC3_5_r3, BC2_5_r3),
  A7_3  = BC2_5_r3 bxor ?CAN64(BC4_5_r3, BC3_5_r3),
  A18_3 = BC3_5_r3 bxor ?CAN64(BC0_5_r3, BC4_5_r3),
  A4_3  = BC4_5_r3 bxor ?CAN64(BC1_5_r3, BC0_5_r3),

  %% Round 4

  BC0_0_r4 = A0_3 bxor A5_3 bxor A10_3 bxor A15_3 bxor A20_3,
  BC1_0_r4 = A1_3 bxor A6_3 bxor A11_3 bxor A16_3 bxor A21_3,
  BC2_0_r4 = A2_3 bxor A7_3 bxor A12_3 bxor A17_3 bxor A22_3,
  BC3_0_r4 = A3_3 bxor A8_3 bxor A13_3 bxor A18_3 bxor A23_3,
  BC4_0_r4 = A4_3 bxor A9_3 bxor A14_3 bxor A19_3 bxor A24_3,
  D0_r4 = BC4_0_r4 bxor ?ROTL64(BC1_0_r4, 1),
  D1_r4 = BC0_0_r4 bxor ?ROTL64(BC2_0_r4, 1),
  D2_r4 = BC1_0_r4 bxor ?ROTL64(BC3_0_r4, 1),
  D3_r4 = BC2_0_r4 bxor ?ROTL64(BC4_0_r4, 1),
  D4_r4 = BC3_0_r4 bxor ?ROTL64(BC0_0_r4, 1),

  BC0_1_r4 = A0_3 bxor D0_r4,
  BC1_1_r4 = ?ROTL64(A1_3 bxor D1_r4, 44),
  BC2_1_r4 = ?ROTL64(A2_3 bxor D2_r4, 43),
  BC3_1_r4 = ?ROTL64(A3_3 bxor D3_r4, 21),
  BC4_1_r4 = ?ROTL64(A4_3 bxor D4_r4, 14),
  A0_4  = BC0_1_r4 bxor ?CAN64(BC2_1_r4, BC1_1_r4) bxor RC3,
  A1_4  = BC1_1_r4 bxor ?CAN64(BC3_1_r4, BC2_1_r4),
  A2_4  = BC2_1_r4 bxor ?CAN64(BC4_1_r4, BC3_1_r4),
  A3_4  = BC3_1_r4 bxor ?CAN64(BC0_1_r4, BC4_1_r4),
  A4_4  = BC4_1_r4 bxor ?CAN64(BC1_1_r4, BC0_1_r4),

  BC2_2_r4 = ?ROTL64(A5_3 bxor D0_r4, 3),
  BC3_2_r4 = ?ROTL64(A6_3 bxor D1_r4, 45),
  BC4_2_r4 = ?ROTL64(A7_3 bxor D2_r4, 61),
  BC0_2_r4 = ?ROTL64(A8_3 bxor D3_r4, 28),
  BC1_2_r4 = ?ROTL64(A9_3 bxor D4_r4, 20),
  A5_4  = BC0_2_r4 bxor ?CAN64(BC2_2_r4, BC1_2_r4),
  A6_4  = BC1_2_r4 bxor ?CAN64(BC3_2_r4, BC2_2_r4),
  A7_4  = BC2_2_r4 bxor ?CAN64(BC4_2_r4, BC3_2_r4),
  A8_4  = BC3_2_r4 bxor ?CAN64(BC0_2_r4, BC4_2_r4),
  A9_4  = BC4_2_r4 bxor ?CAN64(BC1_2_r4, BC0_2_r4),

  BC4_3_r4 = ?ROTL64(A10_3 bxor D0_r4, 18),
  BC0_3_r4 = ?ROTL64(A11_3 bxor D1_r4, 1),
  BC1_3_r4 = ?ROTL64(A12_3 bxor D2_r4, 6),
  BC2_3_r4 = ?ROTL64(A13_3 bxor D3_r4, 25),
  BC3_3_r4 = ?ROTL64(A14_3 bxor D4_r4, 8),
  A10_4 = BC0_3_r4 bxor ?CAN64(BC2_3_r4, BC1_3_r4),
  A11_4 = BC1_3_r4 bxor ?CAN64(BC3_3_r4, BC2_3_r4),
  A12_4 = BC2_3_r4 bxor ?CAN64(BC4_3_r4, BC3_3_r4),
  A13_4 = BC3_3_r4 bxor ?CAN64(BC0_3_r4, BC4_3_r4),
  A14_4 = BC4_3_r4 bxor ?CAN64(BC1_3_r4, BC0_3_r4),

  BC1_4_r4 = ?ROTL64(A15_3 bxor D0_r4, 36),
  BC2_4_r4 = ?ROTL64(A16_3 bxor D1_r4, 10),
  BC3_4_r4 = ?ROTL64(A17_3 bxor D2_r4, 15),
  BC4_4_r4 = ?ROTL64(A18_3 bxor D3_r4, 56),
  BC0_4_r4 = ?ROTL64(A19_3 bxor D4_r4, 27),
  A15_4 = BC0_4_r4 bxor ?CAN64(BC2_4_r4, BC1_4_r4),
  A16_4 = BC1_4_r4 bxor ?CAN64(BC3_4_r4, BC2_4_r4),
  A17_4 = BC2_4_r4 bxor ?CAN64(BC4_4_r4, BC3_4_r4),
  A18_4 = BC3_4_r4 bxor ?CAN64(BC0_4_r4, BC4_4_r4),
  A19_4 = BC4_4_r4 bxor ?CAN64(BC1_4_r4, BC0_4_r4),

  BC3_5_r4 = ?ROTL64(A20_3 bxor D0_r4, 41),
  BC4_5_r4 = ?ROTL64(A21_3 bxor D1_r4, 2),
  BC0_5_r4 = ?ROTL64(A22_3 bxor D2_r4, 62),
  BC1_5_r4 = ?ROTL64(A23_3 bxor D3_r4, 55),
  BC2_5_r4 = ?ROTL64(A24_3 bxor D4_r4, 39),
  A20_4 = BC0_5_r4 bxor ?CAN64(BC2_5_r4, BC1_5_r4),
  A21_4 = BC1_5_r4 bxor ?CAN64(BC3_5_r4, BC2_5_r4),
  A22_4 = BC2_5_r4 bxor ?CAN64(BC4_5_r4, BC3_5_r4),
  A23_4 = BC3_5_r4 bxor ?CAN64(BC0_5_r4, BC4_5_r4),
  A24_4 = BC4_5_r4 bxor ?CAN64(BC1_5_r4, BC0_5_r4),

  {A0_4, A1_4, A2_4, A3_4, A4_4, A5_4, A6_4, A7_4, A8_4, A9_4, A10_4, A11_4, A12_4, A13_4,
   A14_4, A15_4, A16_4, A17_4, A18_4, A19_4, A20_4, A21_4, A22_4, A23_4, A24_4}.