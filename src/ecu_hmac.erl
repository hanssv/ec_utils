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
  Ipad = binary:copy(<<16#36>>, B),
  Opad = binary:copy(<<16#5c>>, B),
  Ki = ecu_entropy:exor(KeyPad, Ipad),
  Ko = ecu_entropy:exor(KeyPad, Opad),
  Inner = hash(HashType, <<Ki/binary, DataBin/binary>>),
  hash(HashType, <<Ko/binary, Inner/binary>>).

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
