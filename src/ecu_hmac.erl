%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang Keyed-Hashing for Message Authentication (HMAC, RFC 2104).
%%%
%%% Supports SHA-2 (SHA-224/256/384/512), SHA-3 (SHA3-224/256/384/512),
%%% and RIPEMD-160 hash algorithms without external dependencies.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_hmac).

-typing([eqwalizer]).

-export([
  hmac/3,
  mac/4
]).

-type hash_type() ::
  sha224
  | sha256
  | sha384
  | sha512
  | ripemd160
  | sha3_224
  | sha3_256
  | sha3_384
  | sha3_512.

-export_type([hash_type/0]).

-spec mac(hmac, hash_type(), binary() | iolist(), binary() | iolist()) -> binary().
mac(hmac, HashType, Key, Data) ->
  hmac(HashType, Key, Data).

-spec hmac(hash_type(), binary() | iolist(), binary() | iolist()) -> binary().
hmac(sha512, Key, Data) ->
  KeyBin = to_binary(Key),
  DataBin = to_binary(Data),
  KeyNorm =
    if
      byte_size(KeyBin) > 128 ->
        ecu_sha2:sha512(KeyBin);
      true ->
        KeyBin
    end,
  PadZeros = 128 - byte_size(KeyNorm),
  KeyPad = <<KeyNorm/binary, 0:(PadZeros * 8)>>,
  Ki = xor_pad_128(KeyPad, 16#36),
  Ko = xor_pad_128(KeyPad, 16#5c),
  InitState = ecu_sha2:init_state_512(),
  IState = ecu_sha2:compress_block_512(Ki, InitState),
  OState = ecu_sha2:compress_block_512(Ko, InitState),
  DataSize = byte_size(DataBin),
  {I0, I1, I2, I3, I4, I5, I6, I7} =
    if
      DataSize =:= 64 ->
        <<D0:64, D1:64, D2:64, D3:64, D4:64, D5:64, D6:64, D7:64>> = DataBin,
        ecu_sha2:compress_64b_msg_512(D0, D1, D2, D3, D4, D5, D6, D7, IState);
      DataSize =< 111 ->
        PadLen = 111 - DataSize,
        TotalBits = (128 + DataSize) * 8,
        InnerBlock = <<DataBin/binary, 16#80, 0:(PadLen * 8), TotalBits:128/big>>,
        ecu_sha2:compress_block_512(InnerBlock, IState);
      true ->
        PadLen = (112 - (DataSize + 1) rem 128 + 128) rem 128,
        TotalBits = (128 + DataSize) * 8,
        Padded = <<DataBin/binary, 16#80, 0:(PadLen * 8), TotalBits:128/big>>,
        <<R0:64, R1:64, R2:64, R3:64, R4:64, R5:64, R6:64, R7:64>> =
          ecu_sha2:process_blocks_512(Padded, IState),
        {R0, R1, R2, R3, R4, R5, R6, R7}
    end,
  {O0, O1, O2, O3, O4, O5, O6, O7} =
    ecu_sha2:compress_64b_msg_512(I0, I1, I2, I3, I4, I5, I6, I7, OState),
  <<O0:64, O1:64, O2:64, O3:64, O4:64, O5:64, O6:64, O7:64>>;
hmac(sha256, Key, Data) ->
  KeyBin = to_binary(Key),
  DataBin = to_binary(Data),
  KeyNorm =
    if
      byte_size(KeyBin) > 64 ->
        ecu_sha2:sha256(KeyBin);
      true ->
        KeyBin
    end,
  PadZeros = 64 - byte_size(KeyNorm),
  KeyPad = <<KeyNorm/binary, 0:(PadZeros * 8)>>,
  Ki = xor_pad_64(KeyPad, 16#36),
  Ko = xor_pad_64(KeyPad, 16#5c),
  InitState = ecu_sha2:init_state_256(),
  IState = ecu_sha2:compress_block_256(Ki, InitState),
  OState = ecu_sha2:compress_block_256(Ko, InitState),
  DataSize = byte_size(DataBin),
  {I0, I1, I2, I3, I4, I5, I6, I7} =
    if
      DataSize =:= 32 ->
        <<D0:32, D1:32, D2:32, D3:32, D4:32, D5:32, D6:32, D7:32>> = DataBin,
        ecu_sha2:compress_32b_msg_256(D0, D1, D2, D3, D4, D5, D6, D7, IState);
      DataSize =< 55 ->
        PadLen = 55 - DataSize,
        TotalBits = (64 + DataSize) * 8,
        InnerBlock = <<DataBin/binary, 16#80, 0:(PadLen * 8), TotalBits:64/big>>,
        ecu_sha2:compress_block_256(InnerBlock, IState);
      true ->
        PadLen = (56 - (DataSize + 1) rem 64 + 64) rem 64,
        TotalBits = (64 + DataSize) * 8,
        Padded = <<DataBin/binary, 16#80, 0:(PadLen * 8), TotalBits:64/big>>,
        <<R0:32, R1:32, R2:32, R3:32, R4:32, R5:32, R6:32, R7:32>> =
          ecu_sha2:process_blocks_256(Padded, IState),
        {R0, R1, R2, R3, R4, R5, R6, R7}
    end,
  {O0, O1, O2, O3, O4, O5, O6, O7} =
    ecu_sha2:compress_32b_msg_256(I0, I1, I2, I3, I4, I5, I6, I7, OState),
  <<O0:32, O1:32, O2:32, O3:32, O4:32, O5:32, O6:32, O7:32>>;
hmac(HashType, Key, Data) ->
  KeyBin = to_binary(Key),
  DataBin = to_binary(Data),
  B = block_size(HashType),
  KeyNorm =
    if
      byte_size(KeyBin) > B ->
        hash(HashType, KeyBin);
      true ->
        KeyBin
    end,
  PadZeros = B - byte_size(KeyNorm),
  KeyPad = <<KeyNorm/binary, 0:(PadZeros * 8)>>,
  {Ki, Ko} = xor_key_pad(B, KeyPad),
  Inner = hash(HashType, <<Ki/binary, DataBin/binary>>),
  hash(HashType, <<Ko/binary, Inner/binary>>).

-spec xor_pad_64(binary(), byte()) -> binary().
xor_pad_64(<<K0:64, K1:64, K2:64, K3:64, K4:64, K5:64, K6:64, K7:64>>, Byte) ->
  W = Byte * 16#0101010101010101,
  <<
    (K0 bxor W):64,
    (K1 bxor W):64,
    (K2 bxor W):64,
    (K3 bxor W):64,
    (K4 bxor W):64,
    (K5 bxor W):64,
    (K6 bxor W):64,
    (K7 bxor W):64
  >>.

-spec xor_pad_128(binary(), byte()) -> binary().
xor_pad_128(
  <<K0:64, K1:64, K2:64, K3:64, K4:64, K5:64, K6:64, K7:64, K8:64, K9:64, K10:64, K11:64, K12:64, K13:64,
    K14:64, K15:64>>,
  Byte
) ->
  W = Byte * 16#0101010101010101,
  <<
    (K0 bxor W):64,
    (K1 bxor W):64,
    (K2 bxor W):64,
    (K3 bxor W):64,
    (K4 bxor W):64,
    (K5 bxor W):64,
    (K6 bxor W):64,
    (K7 bxor W):64,
    (K8 bxor W):64,
    (K9 bxor W):64,
    (K10 bxor W):64,
    (K11 bxor W):64,
    (K12 bxor W):64,
    (K13 bxor W):64,
    (K14 bxor W):64,
    (K15 bxor W):64
  >>.

-spec xor_key_pad(pos_integer(), binary()) -> {binary(), binary()}.
xor_key_pad(64, KeyPad) ->
  {xor_pad_64(KeyPad, 16#36), xor_pad_64(KeyPad, 16#5c)};
xor_key_pad(128, KeyPad) ->
  {xor_pad_128(KeyPad, 16#36), xor_pad_128(KeyPad, 16#5c)};
xor_key_pad(B, KeyPad) ->
  Ipad = binary:copy(<<16#36>>, B),
  Opad = binary:copy(<<16#5c>>, B),
  {ecu_entropy:exor(KeyPad, Ipad), ecu_entropy:exor(KeyPad, Opad)}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec to_binary(binary() | iolist()) -> binary().
to_binary(Bin) when is_binary(Bin) -> Bin;
to_binary(List) when is_list(List) -> iolist_to_binary(List).

-spec block_size(hash_type()) -> pos_integer().
block_size(sha224) -> 64;
block_size(sha256) -> 64;
block_size(sha384) -> 128;
block_size(sha512) -> 128;
block_size(ripemd160) -> 64;
block_size(sha3_224) -> 144;
block_size(sha3_256) -> 136;
block_size(sha3_384) -> 104;
block_size(sha3_512) -> 72.

-spec hash(hash_type(), binary()) -> binary().
hash(sha224, Data) -> ecu_sha2:sha224(Data);
hash(sha256, Data) -> ecu_sha2:sha256(Data);
hash(sha384, Data) -> ecu_sha2:sha384(Data);
hash(sha512, Data) -> ecu_sha2:sha512(Data);
hash(ripemd160, Data) -> ecu_ripemd160:ripemd160(Data);
hash(sha3_224, Data) -> ecu_keccak:sha3_224(Data);
hash(sha3_256, Data) -> ecu_keccak:sha3_256(Data);
hash(sha3_384, Data) -> ecu_keccak:sha3_384(Data);
hash(sha3_512, Data) -> ecu_keccak:sha3_512(Data).
