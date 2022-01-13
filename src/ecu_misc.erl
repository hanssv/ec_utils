%%% File        : ecu_misc.erl
%%% Author      : Hans Svensson
%%% Description : Misc. functionality
%%% Created     : 13 Jan 2022 by Hans Svensson
-module(ecu_misc).

-export([eea/2]).

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


