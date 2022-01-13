%%% File        : ecdsa_tests.erl
%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 12 Jan 2022 by Hans Svensson
-module(ecdsa_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

gen_ecdsa_secp256k1_privkey() ->
  <<P0:256>> = crypto:strong_rand_bytes(32),
  P = (P0 rem (ecu_secp256k1:n() - 1)) + 1,
  <<P:256>>.

ecdsa_sign_verify_secp256k1_test() ->
  Data0 = [ {gen_ecdsa_secp256k1_privkey(), crypto:strong_rand_bytes(32)} || _ <- lists:seq(1, 10) ],

  Data = [{Pr, ecu_ecdsa:private_to_public(secp256k1, Pr), M} || {Pr, M} <- Data0],

  Test = fun(PrivK, PubK, MsgHash) ->
             Sig = ecu_ecdsa:sign(secp256k1, MsgHash, PrivK),
             ?assert(ecu_ecdsa:verify(secp256k1, MsgHash, PubK, Sig))
         end,

  {T, _} = timer:tc(fun() -> [ Test(Pr, Pu, M) || {Pr, Pu, M} <- Data ] end),
  ?debugFmt("Average time for sign+verify: ~.3f ms", [(T / 1000) / length(Data)]).
