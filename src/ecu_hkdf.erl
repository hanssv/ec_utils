%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang HMAC-based Extract-and-Expand Key Derivation Function (HKDF, RFC 5869).
%%%
%%% Implements HKDF-Extract, HKDF-Expand, and the combined HKDF function
%%% parameterizable over SHA-2, SHA-3, and RIPEMD-160.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_hkdf).

-typing([eqwalizer]).

-export([
  hkdf/5,
  extract/3,
  expand/4
]).

-type hash_type() :: ecu_hmac:hash_type().

-spec hkdf(
  hash_type(),
  binary() | iolist(),
  binary() | iolist(),
  binary() | iolist(),
  non_neg_integer()
) -> binary().
hkdf(HashType, IKM, Salt, Info, L) ->
  PRK = extract(HashType, Salt, IKM),
  expand(HashType, PRK, Info, L).

-spec extract(hash_type(), binary() | iolist(), binary() | iolist()) -> binary().
extract(HashType, Salt, IKM) ->
  SaltBin = to_binary(Salt),
  IKMBin = to_binary(IKM),
  RealSalt =
    if
      byte_size(SaltBin) =:= 0 ->
        binary:copy(<<0>>, hash_len(HashType));
      true ->
        SaltBin
    end,
  ecu_hmac:hmac(HashType, RealSalt, IKMBin).

-spec expand(hash_type(), binary() | iolist(), binary() | iolist(), non_neg_integer()) ->
  binary().
expand(_HashType, _PRK, _Info, 0) ->
  <<>>;
expand(HashType, PRK, Info, L) when is_integer(L), L > 0 ->
  PRKBin = to_binary(PRK),
  InfoBin = to_binary(Info),
  HLen = hash_len(HashType),
  N = (L + HLen - 1) div HLen,
  if
    N > 255 ->
      erlang:error(badarg);
    true ->
      Blocks = expand_loop(1, N, HashType, PRKBin, InfoBin, <<>>, <<>>),
      binary:part(Blocks, 0, L)
  end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec expand_loop(
  pos_integer(),
  non_neg_integer(),
  hash_type(),
  binary(),
  binary(),
  binary(),
  binary()
) -> binary().
expand_loop(I, N, _HashType, _PRK, _Info, _PrevT, Acc) when I > N ->
  Acc;
expand_loop(I, N, HashType, PRK, Info, PrevT, Acc) ->
  T_i = ecu_hmac:hmac(HashType, PRK, <<PrevT/binary, Info/binary, I:8>>),
  expand_loop(I + 1, N, HashType, PRK, Info, T_i, <<Acc/binary, T_i/binary>>).

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
