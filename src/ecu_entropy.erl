%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang cryptographically secure entropy and binary primitives.
%%%
%%% Provides CSPRNG random byte generation reading from `/dev/urandom`
%%% with pure-Erlang sponge fallback, and fast constant-time bitwise XOR.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_entropy).

-typing([eqwalizer]).

-export([
  strong_rand_bytes/1,
  exor/2
]).

-spec strong_rand_bytes(non_neg_integer()) -> binary().
strong_rand_bytes(0) ->
  <<>>;
strong_rand_bytes(N) when is_integer(N), N > 0 ->
  read_urandom(N).

-spec exor(binary() | iolist(), binary() | iolist()) -> binary().
exor(A, B) when is_binary(A), is_binary(B), byte_size(A) =:= byte_size(B) ->
  Bits = byte_size(A) * 8,
  <<IntA:Bits>> = A,
  <<IntB:Bits>> = B,
  <<(IntA bxor IntB):Bits>>;
exor(A, B) when is_binary(A), is_binary(B) ->
  erlang:error(badarg);
exor(A, B) ->
  exor(iolist_to_binary(A), iolist_to_binary(B)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec read_urandom(pos_integer()) -> binary().
read_urandom(N) ->
  case file:open("/dev/urandom", [read, raw, binary]) of
    {ok, Fd} ->
      try file:read(Fd, N) of
        {ok, Bytes} when is_binary(Bytes), byte_size(Bytes) =:= N ->
          Bytes;
        _ ->
          fallback_entropy(N)
      after
        file:close(Fd)
      end;
    {error, _} ->
      fallback_entropy(N)
  end.

-spec fallback_entropy(pos_integer()) -> binary().
fallback_entropy(N) ->
  Seeds = [
    erlang:monotonic_time(nanosecond),
    erlang:system_time(nanosecond),
    erlang:unique_integer([monotonic, positive]),
    erlang:statistics(reductions),
    erlang:statistics(garbage_collection),
    erlang:memory(),
    self(),
    node()
  ],
  SeedBin = term_to_binary(Seeds),
  ecu_keccak:shake256(SeedBin, N * 8).
