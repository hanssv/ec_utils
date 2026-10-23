%%% File        : ecu_misc.erl
%%% Author      : Hans Svensson
%%% Description : Misc. functionality
%%% Created     : 13 Jan 2022 by Hans Svensson
-module(ecu_misc).

-typing([eqwalizer]).

-export([eea/2, exp_mod/3,
         hex_to_bin/1, bin_to_hex/1]).

%% A^B mod P
-spec exp_mod(integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
exp_mod(_A, 0, P) when is_integer(P), P > 0 -> 1;
exp_mod(A, B, P) when is_integer(P), P > 0, is_integer(B), B >= 0, A rem P == 0 ->
  case B > 0 of
    true  -> 0;
    false -> 1
  end;
exp_mod(A, B, P) when is_integer(P), P > 0, is_integer(B), B >= 0, A > 0 ->
  case crypto:mod_pow(A, B, P) of
    Bin when is_binary(Bin) -> binary:decode_unsigned(Bin);
    error -> error(badarg)
  end;
exp_mod(A, B, P) when is_integer(P), P > 0, is_integer(B), B >= 0 ->
  X = exp_mod(-A, B, P),
  case B rem 2 == 0 orelse X == 0 of
    true  -> X;
    false -> P - X
  end.

%% Extended Euclidean Algorithm
-spec eea(integer(), integer()) -> {integer(), integer(), integer()} | undefined.
eea(A, B) when is_integer(A), is_integer(B), (A < 1 orelse B < 1) ->
  undefined;
eea(A, B) when is_integer(A), is_integer(B) ->
  eea(A, 1, 0, B, 0, 1).

-spec eea(integer(), integer(), integer(), integer(), integer(), integer()) ->
    {integer(), integer(), integer()}.
eea(G, S, T, 0, _, _) ->
  {G, S, T};
eea(G0, S0, T0, G1, S1, T1) ->
  Q = G0 div G1,
  eea(G1, S1, T1, G0 - (Q * G1), S0 - (Q * S1), T0 - (Q * T1)).

%% Hex encode/decode
-spec hex_to_bin(Input :: string()) -> binary().
hex_to_bin(S) when is_list(S), length(S) rem 2 == 0 ->
  try hex_to_bin_acc(S, <<>>)
  catch _:_ -> error(badarg)
  end;
hex_to_bin(_) ->
  error(badarg).

-spec hex_to_bin_acc(string(), binary()) -> binary().
hex_to_bin_acc([], Acc) ->
  Acc;
hex_to_bin_acc([X,Y|T], Acc) ->
  case io_lib:fread("~16u", [X,Y]) of
    {ok, [V], []} when is_integer(V), V >= 0, V =< 255 ->
      hex_to_bin_acc(T, <<Acc/binary, V:8>>);
    _ -> error(badarg)
  end.

-spec bin_to_hex(Input :: binary()) -> string().
bin_to_hex(Bin) when is_binary(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).
