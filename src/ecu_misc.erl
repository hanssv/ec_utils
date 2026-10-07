%%% File        : ecu_misc.erl
%%% Author      : Hans Svensson
%%% Description : Misc. functionality
%%% Created     : 13 Jan 2022 by Hans Svensson
-module(ecu_misc).

-export([eea/2, exp_mod/3,
         hex_to_bin/1, bin_to_hex/1,
         pcomp/1]).

%% A^B mod P
exp_mod(_A, 0, _P) -> 1;
exp_mod(A, B, P) when A rem P == 0 ->
  case B > 0 of
    true  -> 0;
    false -> 1
  end;
exp_mod(A, B, P) when A > 0 ->
  binary:decode_unsigned(crypto:mod_pow(A, B, P));
exp_mod(A, B, P) ->
  X = exp_mod(-A, B, P),
  case B rem 2 == 0 orelse X == 0 of
    true  -> X;
    false -> P - X
  end.

%% Extended Euclidean Algorithm
eea(A, B) when ((A < 1) or (B < 1)) ->
    undefined;
eea(A, B) ->
    eea(A, 1, 0, B, 0, 1).

eea(G, S, T, 0, _, _) ->
    {G, S, T};
eea(G0, S0, T0, G1, S1, T1) ->
    Q = G0 div G1,
    eea(G1, S1, T1, G0 - (Q * G1), S0 - (Q * S1), T0 - (Q * T1)).

%% Rudimentary parallel computation with process monitoring
pcomp(Fs) ->
  Parent = self(),
  Monitors = [ spawn_monitor(fun() -> Parent ! {self(), F()} end) || F <- Fs ],
  try
    [ receive
        {Pid, X} ->
          demonitor(MRef, [flush]),
          X;
        {'DOWN', MRef, process, Pid, normal} ->
          receive
            {Pid, X} -> X
          after 0 ->
            error(premature_exit)
          end;
        {'DOWN', MRef, process, _Pid, Reason} ->
          error(Reason)
      after 5000 ->
        error(timeout)
      end || {Pid, MRef} <- Monitors ]
  catch
    Class:Reason:Stack ->
      [ begin
          exit(Pid, kill),
          demonitor(MRef, [flush])
        end || {Pid, MRef} <- Monitors ],
      erlang:raise(Class, Reason, Stack)
  end.

%% Hex encode/decode
-spec hex_to_bin(Input :: string()) -> binary().
hex_to_bin(S) when is_list(S), length(S) rem 2 == 0 ->
  try hex_to_bin(S, [])
  catch _:_ -> error(badarg)
  end;
hex_to_bin(_) ->
  error(badarg).

hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  case io_lib:fread("~16u", [X,Y]) of
    {ok, [V], []} -> hex_to_bin(T, [V | Acc]);
    _ -> error(badarg)
  end.

-spec bin_to_hex(Input :: binary()) -> string().
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).
