%%%-------------------------------------------------------------------
%%% @doc
%%% Tests for the optional Falcon / FN-DSA reference NIF.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_fn_dsa_nif_tests).

-include_lib("eunit/include/eunit.hrl").

falcon512_nif_roundtrip_test() ->
  case ecu_fn_dsa_nif:is_available() of
    true ->
      {ok, {PK, SK}} = ecu_fn_dsa_nif:falcon512_keypair(),
      ?assertEqual(897, byte_size(PK)),
      ?assertEqual(1281, byte_size(SK)),
      Msg = <<"FN-DSA-512 test message">>,
      {ok, Sig} = ecu_fn_dsa_nif:falcon512_sign(SK, Msg),
      ?assert(byte_size(Sig) =< 666),
      ?assert(ecu_fn_dsa_nif:falcon512_verify(PK, Msg, Sig)),
      ?assertNot(ecu_fn_dsa_nif:falcon512_verify(PK, <<"Wrong msg">>, Sig));
    false ->
      ok
  end.

falcon1024_nif_roundtrip_test() ->
  case ecu_fn_dsa_nif:is_available() of
    true ->
      {ok, {PK, SK}} = ecu_fn_dsa_nif:falcon1024_keypair(),
      ?assertEqual(1793, byte_size(PK)),
      ?assertEqual(2305, byte_size(SK)),
      Msg = <<"FN-DSA-1024 test message">>,
      {ok, Sig} = ecu_fn_dsa_nif:falcon1024_sign(SK, Msg),
      ?assert(byte_size(Sig) =< 1280),
      ?assert(ecu_fn_dsa_nif:falcon1024_verify(PK, Msg, Sig)),
      ?assertNot(ecu_fn_dsa_nif:falcon1024_verify(PK, <<"Wrong msg">>, Sig));
    false ->
      ok
  end.
