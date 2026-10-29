%%% File        : ecu_schnorr_nif.erl
%%% Description : Backward compatibility forwarder to ecu_rustcrypto_nif
-module(ecu_schnorr_nif).

-export([is_available/0, sign/3, verify/3, public_key/1]).

is_available() ->
  ecu_rustcrypto_nif:is_available().

sign(Priv, Msg, Aux) ->
  ecu_rustcrypto_nif:sign(Priv, Msg, Aux).

verify(Sig, Msg, Pub) ->
  ecu_rustcrypto_nif:verify(Sig, Msg, Pub).

public_key(Priv) ->
  ecu_rustcrypto_nif:public_key(Priv).
