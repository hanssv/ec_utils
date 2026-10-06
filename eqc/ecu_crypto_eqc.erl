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

-include("ecu_secp256k1.hrl").

gen_boundary_scalar() ->
  elements([0, 1, 2, ?N - 1, ?N, ?N + 1, (1 bsl 256) - 1]).

gen_large_scalar() ->
  ?LET(X, choose(0, (1 bsl 256) - ?N), ?N + X).

gen_recover_scalar() ->
  frequency([
    {2, gen_boundary_scalar()},
    {3, gen_large_scalar()},
    {5, ?LET(<<X:256>>, binary(32), X)}
  ]).

gen_v() ->
  frequency([
    {8, elements([27, 28])},
    {2, choose(0, 255)}
  ]).

gen_sig() ->
  frequency([
    {4, ?LET(PK, gen_ecdsa_secp256k1_privkey(),
             ecu_crypto:eth_sign(crypto:strong_rand_bytes(32), PK))},
    {6, ?LET({V, R, S}, {gen_v(), gen_recover_scalar(), gen_recover_scalar()},
             <<V:8, R:256, S:256>>)}
  ]).

prop_ec_recover_vs_rust() ->
  ?FORALL({MsgHash, Sig}, {noshrink(binary(32)), gen_sig()},
  begin
    Rust = ecrecover:recover(MsgHash, Sig),
    ECU  = try ecu_crypto:ec_recover(MsgHash, Sig) catch _:_ -> error end,
    equals(Rust, ECU)
  end).
