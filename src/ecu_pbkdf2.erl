%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang Password-Based Key Derivation Function 2 (PBKDF2, RFC 2898 / PKCS #5).
%%%
%%% Implements PBKDF2 with HMAC-SHA512 (used in BIP-39 seed generation)
%%% and other SHA-2/SHA-3 hash algorithms without external dependencies.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_pbkdf2).

-typing([eqwalizer]).

-export([
  pbkdf2_hmac/5
]).

-type hash_type() :: ecu_hmac:hash_type().

-spec pbkdf2_hmac(
  hash_type(),
  binary() | iolist(),
  binary() | iolist(),
  pos_integer(),
  non_neg_integer()
) -> binary().
pbkdf2_hmac(_Digest, _Password, _Salt, _Iterations, 0) ->
  <<>>;
pbkdf2_hmac(Digest, Password, Salt, Iterations, Length) when
  is_integer(Iterations), Iterations > 0, is_integer(Length), Length > 0
->
  PassBin = to_binary(Password),
  SaltBin = to_binary(Salt),
  HLen = hash_len(Digest),
  TotalBlocks = (Length + HLen - 1) div HLen,
  Derived = pbkdf2_blocks(1, TotalBlocks, Digest, PassBin, SaltBin, Iterations, <<>>),
  binary:part(Derived, 0, Length).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec pbkdf2_blocks(
  pos_integer(),
  non_neg_integer(),
  hash_type(),
  binary(),
  binary(),
  pos_integer(),
  binary()
) -> binary().
pbkdf2_blocks(BlockIndex, TotalBlocks, _Digest, _Password, _Salt, _Iterations, Acc) when
  BlockIndex > TotalBlocks
->
  Acc;
pbkdf2_blocks(BlockIndex, TotalBlocks, Digest, Password, Salt, Iterations, Acc) ->
  U1 = ecu_hmac:hmac(Digest, Password, <<Salt/binary, BlockIndex:32/big>>),
  Block = pbkdf2_f(2, Iterations, Digest, Password, U1, U1),
  pbkdf2_blocks(
    BlockIndex + 1,
    TotalBlocks,
    Digest,
    Password,
    Salt,
    Iterations,
    <<Acc/binary, Block/binary>>
  ).

-spec pbkdf2_f(
  pos_integer(),
  pos_integer(),
  hash_type(),
  binary(),
  binary(),
  binary()
) -> binary().
pbkdf2_f(Iter, Iterations, _Digest, _Password, _PrevU, Acc) when Iter > Iterations ->
  Acc;
pbkdf2_f(Iter, Iterations, Digest, Password, PrevU, Acc) ->
  U = ecu_hmac:hmac(Digest, Password, PrevU),
  NewAcc = ecu_entropy:exor(Acc, U),
  pbkdf2_f(Iter + 1, Iterations, Digest, Password, U, NewAcc).

-spec to_binary(binary() | iolist()) -> binary().
to_binary(Bin) when is_binary(Bin) -> Bin;
to_binary(List) when is_list(List) -> iolist_to_binary(List).

-spec hash_len(hash_type()) -> pos_integer().
hash_len(sha224) -> 28;
hash_len(sha256) -> 32;
hash_len(sha384) -> 48;
hash_len(sha512) -> 64;
hash_len(ripemd160) -> 20;
hash_len(sha3_224) -> 28;
hash_len(sha3_256) -> 32;
hash_len(sha3_384) -> 48;
hash_len(sha3_512) -> 64.
