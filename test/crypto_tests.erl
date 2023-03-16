%%% File        : crypto_tests.erl
%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 12 Jan 2022 by Hans Svensson
-module(crypto_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").


gen_ecdsa_secp256k1_privkey() ->
  <<P0:256>> = crypto:strong_rand_bytes(32),
  P = (P0 rem (ecu_secp256k1:n() - 1)) + 1,
  <<P:256>>.

eth_sign_verify_test() ->
  Data0 = [ {gen_ecdsa_secp256k1_privkey(), crypto:strong_rand_bytes(32)} || _ <- lists:seq(1, 10) ],

  Data = [{Pr, ecu_crypto:private_to_short(ethereum, Pr), M} || {Pr, M} <- Data0],

  Test = fun(PrivK, PubK, MsgHash) ->
             Sig = ecu_crypto:eth_msg_sign(MsgHash, PrivK),
             ?assertEqual(PubK, ecu_crypto:eth_msg_recover(MsgHash, Sig))
         end,

  {T, _} = timer:tc(fun() -> [ Test(Pr, Pu, M) || {Pr, Pu, M} <- Data ] end),
  ?debugFmt("Average time for eth_msg_sign+eth_msg_recovery: ~.3f ms", [(T / 1000) / length(Data)]).

recover_test() ->
  <<R:256, S:256>> = ecu_misc:hex_to_bin("a5f270865420c8595128cf7132dcedb1221abf89286f926d067dff2fa59347c07a0fd06e8b4a567b0628a01d5398480a49c540c0cbd9980abd08cf3818f25e2e"),
%%   <<Priv:256>> = hex_to_bin("9a4a5c038e7ce00f0ad216894afc00de6b41bbca1d4d7742104cb9f078c6d2df"),
%%   <<Z:256>> = hex_to_bin("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95"), %% MsgHash
  ShortPub = ecu_misc:hex_to_bin("E53e2125F377D5c62a1FfbfEEB89A0826E9dE54C"),
  ?assertEqual(ShortPub, ecu_crypto:eth_msg_recover(<<"test">>, <<28:8, R:256, S:256>>)).
