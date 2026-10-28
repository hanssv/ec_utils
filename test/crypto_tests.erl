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

-include("ecu_secp256k1.hrl").

ec_recover_invalid_test() ->
  Msg = crypto:strong_rand_bytes(32),
  %% R = N must return <<0:256>> rather than crashing in s_inv(N)
  ?assertEqual(<<0:256>>, ecu_crypto:ec_recover(Msg, <<27:8, ?N:256, 1:256>>)),
  %% S = N must return <<0:256>>
  ?assertEqual(<<0:256>>, ecu_crypto:ec_recover(Msg, <<27:8, 1:256, ?N:256>>)),
  %% R = 5 is not on the curve, must return <<0:256>> rather than a bogus address
  ?assertEqual(<<0:256>>, ecu_crypto:ec_recover(Msg, <<27:8, 5:256, 1:256>>)).

private_to_short_bitcoin_test() ->
  Priv = <<1:256>>,
  Short = ecu_crypto:private_to_short(bitcoin, Priv),
  ?assertEqual(20, byte_size(Short)),
  ?assertError(badarg, ecu_crypto:private_to_short(bitcoin, <<0:256>>)),
  ?assertError(badarg, ecu_crypto:private_to_short(bitcoin, <<?N:256>>)).

private_to_short_ethereum_test() ->
  Priv = <<1:256>>,
  Short = ecu_crypto:private_to_short(ethereum, Priv),
  ?assertEqual(20, byte_size(Short)),
  ?assertError(badarg, ecu_crypto:private_to_short(ethereum, <<0:256>>)),
  ?assertError(badarg, ecu_crypto:private_to_short(ethereum, <<?N:256>>)).

hex_to_bin_odd_length_test() ->
  ?assertError(badarg, ecu_misc:hex_to_bin("abc")).

eth_sig_rsv_conversion_test() ->
  Priv = gen_ecdsa_secp256k1_privkey(),
  Msg = <<"Hello Ethereum">>,
  SigVRS = ecu_crypto:eth_msg_sign(Msg, Priv),
  <<V:8, R:256, S:256>> = SigVRS,
  SigRSV = ecu_crypto:eth_sig_to_rsv(SigVRS),
  ?assertEqual(<<R:256, S:256, V:8>>, SigRSV),
  ?assertEqual(SigVRS, ecu_crypto:eth_sig_from_rsv(SigRSV)),
  Addr = ecu_crypto:private_to_short(ethereum, Priv),
  ?assertEqual(Addr, ecu_crypto:eth_msg_recover(Msg, ecu_crypto:eth_sig_from_rsv(SigRSV))),
  ?assertError(badarg, ecu_crypto:eth_sig_to_rsv(<<1, 2, 3>>)),
  ?assertError(badarg, ecu_crypto:eth_sig_from_rsv(<<1, 2, 3>>)).
