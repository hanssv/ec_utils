%%% File        : ecu_keccak.erl
%%% Description : Pure Erlang Keccak-f[1600] state permutation and SHA-3 family
%%%
%%% Based on kek_fast.erl by Hans Svensson (unrolled 64-bit uint implementation)
%%% and original implementation by Peter Harpending (ISC License).
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

-define(INT64, 16#FFFFFFFFFFFFFFFF).
-define(BSL64(X, N), ((X bsl N) band ?INT64)).
-define(BSR64(X, N), (X bsr N)).
-define(ROTL64(X, N), (?BSL64(X, N) bor ?BSR64(X, (64 - N)))).
-define(CAN64(A, B), ((A bxor B) band A)).

%% ===================================================================
%% Top-level API
%% ===================================================================

%% @doc Ethereum Keccak-256 (32-byte hash with empty delimiter).
-spec keccak256(Message :: iodata()) -> <<_:256>>.
keccak256(Message) ->
  MsgBin = iolist_to_binary(Message),
  keccak(512, MsgBin, ?KECCAK_DELIMITER, 256).

%% @doc NIST FIPS 202 SHA3-224.
-spec sha3_224(Message :: iodata()) -> <<_:224>>.
sha3_224(Message) ->
  MsgBin = iolist_to_binary(Message),
  keccak(448, MsgBin, ?NIST_SHA3_DELIMITER, 224).

%% @doc NIST FIPS 202 SHA3-256.
-spec sha3_256(Message :: iodata()) -> <<_:256>>.
sha3_256(Message) ->
  MsgBin = iolist_to_binary(Message),
  keccak(512, MsgBin, ?NIST_SHA3_DELIMITER, 256).

%% @doc NIST FIPS 202 SHA3-384.
-spec sha3_384(Message :: iodata()) -> <<_:384>>.
sha3_384(Message) ->
  MsgBin = iolist_to_binary(Message),
  keccak(768, MsgBin, ?NIST_SHA3_DELIMITER, 384).

%% @doc NIST FIPS 202 SHA3-512.
-spec sha3_512(Message :: iodata()) -> <<_:512>>.
sha3_512(Message) ->
  MsgBin = iolist_to_binary(Message),
  keccak(1024, MsgBin, ?NIST_SHA3_DELIMITER, 512).

%% @doc NIST FIPS 202 SHAKE128 variable-length output.
-spec shake128(Message :: iodata(), OutputBitLength :: pos_integer()) -> bitstring().
shake128(Message, OutputBitLength) ->
  MsgBin = iolist_to_binary(Message),
  keccak(256, MsgBin, ?SHAKE_DELIMITER, OutputBitLength).

%% @doc NIST FIPS 202 SHAKE256 variable-length output.
-spec shake256(Message :: iodata(), OutputBitLength :: pos_integer()) -> bitstring().
shake256(Message, OutputBitLength) ->
  MsgBin = iolist_to_binary(Message),
  keccak(512, MsgBin, ?SHAKE_DELIMITER, OutputBitLength).

%% ===================================================================
%% Sponge Implementation
%% ===================================================================

-spec keccak(Capacity :: pos_integer(),
             Message :: bitstring(),
             Delimiter :: bitstring(),
             OutputBitLength :: pos_integer()) -> bitstring().
keccak(Capacity, Message, Delimiter, OutputBitLength) ->
  BitRate       = 1600 - Capacity,
  PaddedMessage = pad(Message, Delimiter, BitRate),
  InitialSponge = <<0:1600>>,
  WetSponge     = absorb(PaddedMessage, BitRate, Capacity, InitialSponge),
  squeeze(WetSponge, OutputBitLength, BitRate).

-spec pad(Message :: bitstring(), Delimiter :: bitstring(), BitRate :: pos_integer()) -> bitstring().
pad(Msg, Delimiter, BitRate) ->
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

-type state_words() :: {
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()
}.

-spec rev_pad(Msg :: bitstring(), Delimiter :: bitstring(), PadZeros :: non_neg_integer()) -> bitstring().
rev_pad(Msg, Delimiter, PadZeros) ->
  Pad = <<Msg/bitstring, Delimiter/bitstring, 1:1, 0:PadZeros, 1:1>>,
  << (flip_bits(X)) || <<X:8>> <= Pad >>.

-spec flip_bits(byte() | binary()) -> binary().
flip_bits(0) -> <<0:8>>;
flip_bits(<<A:1, B:1, C:1, D:1, E:1, F:1, G:1, H:1>>) ->
  <<H:1, G:1, F:1, E:1, D:1, C:1, B:1, A:1>>;
flip_bits(N) when is_integer(N) -> flip_bits(<<N:8>>).

-spec absorb(PaddedMessage :: bitstring(),
             BitRate :: pos_integer(),
             Capacity :: pos_integer(),
             SpongeAcc :: <<_:1600>>) -> <<_:1600>>.
absorb(PaddedMessageBits, BitRate, Capacity, Sponge) when BitRate =< bit_size(PaddedMessageBits) ->
  <<ThisRWord:BitRate, Rest/bitstring>> = PaddedMessageBits,
  <<SpongeInt:1600>> = Sponge,
  <<Foo:1600>>       = <<ThisRWord:BitRate, 0:Capacity>>,
  FInputInt          = SpongeInt bxor Foo,
  FInputBits         = <<FInputInt:1600>>,
  NewSponge          = inner_keccak(FInputBits),
  absorb(Rest, BitRate, Capacity, NewSponge);
absorb(<<>>, _BitRate, _Capacity, FinalSponge) ->
  FinalSponge.

-spec squeeze(WetSponge :: <<_:1600>>,
              OutputBitLength :: pos_integer(),
              BitRate :: pos_integer()) -> bitstring().
squeeze(WetSponge, OutputBitLength, BitRate) ->
  really_squeeze(WetSponge, OutputBitLength, BitRate, <<>>).

-spec really_squeeze(WetSponge :: <<_:1600>>,
                     OutputBitLength :: pos_integer(),
                     BitRate :: pos_integer(),
                     ResultAcc :: bitstring()) -> bitstring().
really_squeeze(_WetSponge, OutputBitLength, _BitRate, FinalAccBits)
  when OutputBitLength =< bit_size(FinalAccBits) ->
  <<ResultBits:OutputBitLength, _/bitstring>> = FinalAccBits,
  <<ResultBits:OutputBitLength>>;
really_squeeze(WetSponge, OutputBitLength, BitRate, ResultAcc) ->
  <<ThisRWord:BitRate, _/bitstring>> = WetSponge,
  NewResultAcc = <<ResultAcc/bitstring, ThisRWord:BitRate>>,
  NewWetSponge = inner_keccak(WetSponge),
  really_squeeze(NewWetSponge, OutputBitLength, BitRate, NewResultAcc).

%% ===================================================================
%% Fast Unrolled Keccak-f[1600] (64-bit uints)
%% ===================================================================

-spec inner_keccak(<<_:1600>>) -> <<_:1600>>.
inner_keccak(<<
  A0:64/little, A1:64/little, A2:64/little, A3:64/little, A4:64/little,
  A5:64/little, A6:64/little, A7:64/little, A8:64/little, A9:64/little,
  A10:64/little, A11:64/little, A12:64/little, A13:64/little, A14:64/little,
  A15:64/little, A16:64/little, A17:64/little, A18:64/little, A19:64/little,
  A20:64/little, A21:64/little, A22:64/little, A23:64/little, A24:64/little
>>) ->
  IntState0 = {A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24},
  {B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15, B16, B17, B18, B19, B20, B21, B22, B23, B24} = inner_keccak_fast(IntState0),
  <<B0:64/little, B1:64/little, B2:64/little, B3:64/little, B4:64/little,
    B5:64/little, B6:64/little, B7:64/little, B8:64/little, B9:64/little,
    B10:64/little, B11:64/little, B12:64/little, B13:64/little, B14:64/little,
    B15:64/little, B16:64/little, B17:64/little, B18:64/little, B19:64/little,
    B20:64/little, B21:64/little, B22:64/little, B23:64/little, B24:64/little>>.

-spec inner_keccak_fast(state_words()) -> state_words().
inner_keccak_fast(IntState0) ->
  IntState1 = fast_round(IntState0, {16#0000000000000001, 16#0000000000008082, 16#800000000000808A, 16#8000000080008000}),
  IntState2 = fast_round(IntState1, {16#000000000000808B, 16#0000000080000001, 16#8000000080008081, 16#8000000000008009}),
  IntState3 = fast_round(IntState2, {16#000000000000008A, 16#0000000000000088, 16#0000000080008009, 16#000000008000000A}),
  IntState4 = fast_round(IntState3, {16#000000008000808B, 16#800000000000008B, 16#8000000000008089, 16#8000000000008003}),
  IntState5 = fast_round(IntState4, {16#8000000000008002, 16#8000000000000080, 16#000000000000800A, 16#800000008000000A}),
  fast_round(IntState5, {16#8000000080008081, 16#8000000000008080, 16#0000000080000001, 16#8000000080008008}).

-spec fast_round(state_words(), {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}) -> state_words().
fast_round(As0, {RC0, RC1, RC2, RC3}) ->
  As1 = fast_round1(As0, RC0),
  As2 = fast_round2(As1, RC1),
  As3 = fast_round3(As2, RC2),
  fast_round4(As3, RC3).

-spec fast_round1(state_words(), non_neg_integer()) -> state_words().
fast_round1({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC0) ->
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

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.

-spec fast_round2(state_words(), non_neg_integer()) -> state_words().
fast_round2({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC1) ->
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
  BC1_1 = ?ROTL64(A16 bxor D1, 44),
  BC2_1 = ?ROTL64(A7 bxor D2, 43),
  BC3_1 = ?ROTL64(A23 bxor D3, 21),
  BC4_1 = ?ROTL64(A14 bxor D4, 14),
  A0_1  = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC1,
  A16_1 = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A7_1  = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A23_1 = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A14_1 = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A20 bxor D0, 3),
  BC3_2 = ?ROTL64(A11 bxor D1, 45),
  BC4_2 = ?ROTL64(A2 bxor D2, 61),
  BC0_2 = ?ROTL64(A18 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A20_1 = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A11_1 = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A2_1  = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A18_1 = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1  = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A15 bxor D0, 18),
  BC0_3 = ?ROTL64(A6 bxor D1, 1),
  BC1_3 = ?ROTL64(A22 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A4 bxor D4, 8),
  A15_1 = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A6_1  = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A22_1 = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A4_1  = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A10 bxor D0, 36),
  BC2_4 = ?ROTL64(A1 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A8 bxor D3, 56),
  BC0_4 = ?ROTL64(A24 bxor D4, 27),
  A10_1 = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A1_1  = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A8_1  = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A24_1 = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A5 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A12 bxor D2, 62),
  BC1_5 = ?ROTL64(A3 bxor D3, 55),
  BC2_5 = ?ROTL64(A19 bxor D4, 39),
  A5_1  = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A12_1 = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A3_1  = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A19_1 = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.

-spec fast_round3(state_words(), non_neg_integer()) -> state_words().
fast_round3({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC2) ->
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
  BC1_1 = ?ROTL64(A11 bxor D1, 44),
  BC2_1 = ?ROTL64(A22 bxor D2, 43),
  BC3_1 = ?ROTL64(A8 bxor D3, 21),
  BC4_1 = ?ROTL64(A19 bxor D4, 14),
  A0_1  = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC2,
  A11_1 = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A22_1 = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A8_1  = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A19_1 = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A15 bxor D0, 3),
  BC3_2 = ?ROTL64(A1 bxor D1, 45),
  BC4_2 = ?ROTL64(A12 bxor D2, 61),
  BC0_2 = ?ROTL64(A23 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A15_1 = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A1_1  = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A12_1 = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A23_1 = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1  = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A5 bxor D0, 18),
  BC0_3 = ?ROTL64(A16 bxor D1, 1),
  BC1_3 = ?ROTL64(A2 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A24 bxor D4, 8),
  A5_1  = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A16_1 = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A2_1  = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A24_1 = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A20 bxor D0, 36),
  BC2_4 = ?ROTL64(A6 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A3 bxor D3, 56),
  BC0_4 = ?ROTL64(A14 bxor D4, 27),
  A20_1 = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A6_1  = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A3_1  = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A14_1 = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A10 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A7 bxor D2, 62),
  BC1_5 = ?ROTL64(A18 bxor D3, 55),
  BC2_5 = ?ROTL64(A4 bxor D4, 39),
  A10_1 = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A7_1  = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A18_1 = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A4_1  = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.

-spec fast_round4(state_words(), non_neg_integer()) -> state_words().
fast_round4({A0, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, A21, A22, A23, A24}, RC3) ->
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
  BC1_1 = ?ROTL64(A1 bxor D1, 44),
  BC2_1 = ?ROTL64(A2 bxor D2, 43),
  BC3_1 = ?ROTL64(A3 bxor D3, 21),
  BC4_1 = ?ROTL64(A4 bxor D4, 14),
  A0_1  = BC0_1 bxor ?CAN64(BC2_1, BC1_1) bxor RC3,
  A1_1  = BC1_1 bxor ?CAN64(BC3_1, BC2_1),
  A2_1  = BC2_1 bxor ?CAN64(BC4_1, BC3_1),
  A3_1  = BC3_1 bxor ?CAN64(BC0_1, BC4_1),
  A4_1  = BC4_1 bxor ?CAN64(BC1_1, BC0_1),

  BC2_2 = ?ROTL64(A5 bxor D0, 3),
  BC3_2 = ?ROTL64(A6 bxor D1, 45),
  BC4_2 = ?ROTL64(A7 bxor D2, 61),
  BC0_2 = ?ROTL64(A8 bxor D3, 28),
  BC1_2 = ?ROTL64(A9 bxor D4, 20),
  A5_1  = BC0_2 bxor ?CAN64(BC2_2, BC1_2),
  A6_1  = BC1_2 bxor ?CAN64(BC3_2, BC2_2),
  A7_1  = BC2_2 bxor ?CAN64(BC4_2, BC3_2),
  A8_1  = BC3_2 bxor ?CAN64(BC0_2, BC4_2),
  A9_1  = BC4_2 bxor ?CAN64(BC1_2, BC0_2),

  BC4_3 = ?ROTL64(A10 bxor D0, 18),
  BC0_3 = ?ROTL64(A11 bxor D1, 1),
  BC1_3 = ?ROTL64(A12 bxor D2, 6),
  BC2_3 = ?ROTL64(A13 bxor D3, 25),
  BC3_3 = ?ROTL64(A14 bxor D4, 8),
  A10_1 = BC0_3 bxor ?CAN64(BC2_3, BC1_3),
  A11_1 = BC1_3 bxor ?CAN64(BC3_3, BC2_3),
  A12_1 = BC2_3 bxor ?CAN64(BC4_3, BC3_3),
  A13_1 = BC3_3 bxor ?CAN64(BC0_3, BC4_3),
  A14_1 = BC4_3 bxor ?CAN64(BC1_3, BC0_3),

  BC1_4 = ?ROTL64(A15 bxor D0, 36),
  BC2_4 = ?ROTL64(A16 bxor D1, 10),
  BC3_4 = ?ROTL64(A17 bxor D2, 15),
  BC4_4 = ?ROTL64(A18 bxor D3, 56),
  BC0_4 = ?ROTL64(A19 bxor D4, 27),
  A15_1 = BC0_4 bxor ?CAN64(BC2_4, BC1_4),
  A16_1 = BC1_4 bxor ?CAN64(BC3_4, BC2_4),
  A17_1 = BC2_4 bxor ?CAN64(BC4_4, BC3_4),
  A18_1 = BC3_4 bxor ?CAN64(BC0_4, BC4_4),
  A19_1 = BC4_4 bxor ?CAN64(BC1_4, BC0_4),

  BC3_5 = ?ROTL64(A20 bxor D0, 41),
  BC4_5 = ?ROTL64(A21 bxor D1, 2),
  BC0_5 = ?ROTL64(A22 bxor D2, 62),
  BC1_5 = ?ROTL64(A23 bxor D3, 55),
  BC2_5 = ?ROTL64(A24 bxor D4, 39),
  A20_1 = BC0_5 bxor ?CAN64(BC2_5, BC1_5),
  A21_1 = BC1_5 bxor ?CAN64(BC3_5, BC2_5),
  A22_1 = BC2_5 bxor ?CAN64(BC4_5, BC3_5),
  A23_1 = BC3_5 bxor ?CAN64(BC0_5, BC4_5),
  A24_1 = BC4_5 bxor ?CAN64(BC1_5, BC0_5),

  {A0_1, A1_1, A2_1, A3_1, A4_1, A5_1, A6_1, A7_1, A8_1, A9_1, A10_1, A11_1, A12_1, A13_1,
   A14_1, A15_1, A16_1, A17_1, A18_1, A19_1, A20_1, A21_1, A22_1, A23_1, A24_1}.
