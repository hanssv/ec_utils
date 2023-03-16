%%% File        : ecu_crypto_eqc.erl
%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 7 Jan 2023 by Hans Svensson
-module(ecu_crypto_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

gen_ecdsa_secp256k1_privkey() ->
  <<P0:256>> = crypto:strong_rand_bytes(32),
  P = (P0 rem (ecu_secp256k1:n() - 1)) + 1,
  return(<<P:256>>).

prop_recover() ->
  ?FORALL(PK, gen_ecdsa_secp256k1_privkey(),
  begin
    MsgHash = sha3:hash(256, PK),
    Sig = ecu_crypto:eth_sign(MsgHash, PK),
    Pub1 = ecrecover:recover(MsgHash, Sig),
    Pub2 = ecu_crypto:ec_recover(MsgHash, Sig),
    equals(Pub1, Pub2)
  end).

