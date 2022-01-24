%%% File        : benchmark_tests.erl
%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 20 Jan 2022 by Hans Svensson
-module(benchmark_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

gen_scalar() ->
  <<X:256>> = crypto:strong_rand_bytes(32),
  1 + X rem (ecu_ed25519:n() - 1).

bench_point_add_test() ->
  Pts = [ enacl:crypto_ed25519_scalarmult_base(<<(gen_scalar()):256/little>>) || _ <- lists:seq(1, 100) ],

  PtsEnacl0   = lists:zip(Pts, tl(Pts) ++ [hd(Pts)]),
  PtsEd255190 = [ {ecu_ed25519:to_ext_hom(P1), ecu_ed25519:to_ext_hom(P2)} || {P1, P2} <- lists:zip(Pts, tl(Pts) ++ [hd(Pts)]) ],
%%   PtsEd255190 = lists:zip(Pts, tl(Pts) ++ [hd(Pts)]),

  PtsEnacl   = lists:append(lists:duplicate(1000, PtsEnacl0)),
  PtsEd25519 = lists:append(lists:duplicate(100, PtsEd255190)),

  {TimeEnacl,   _} = timer:tc(fun() -> [enacl:crypto_ed25519_add(P1, P2) || {P1, P2} <- PtsEnacl], ok end),
  {TimeEd25519, _} = timer:tc(fun() -> [ecu_ed25519:p_add(P1, P2) || {P1, P2} <- PtsEd25519], ok end),
%%   {TimeEd25519, _} = timer:tc(fun() -> [ecu_ed25519:compress(ecu_ed25519:p_add(P1, P2)) || {P1, P2} <- PtsEd25519], ok end),

  ?debugFmt("", []),
  stats("Point add", "enacl/libsodium", length(PtsEnacl), TimeEnacl),
  stats("Point add", "ecu_ed25519    ", length(PtsEd25519), TimeEd25519),
  diff(TimeEnacl / length(PtsEnacl), TimeEd25519 / length(PtsEd25519)),
  ok.

bench_scalar_mul_base_test() ->
  Scalars0 = [ <<(gen_scalar()):256/little>> || _ <- lists:seq(1, 100) ],
  ScalarsSecp    = lists:append(lists:duplicate(1, Scalars0)),
  ScalarsEnacl   = lists:append(lists:duplicate(100, Scalars0)),
  ScalarsEd25519 = lists:append(lists:duplicate(30, Scalars0)),

  {TimeSecp,    _} = timer:tc(fun() -> [ecu_secp256k1:scalar_mul_base(S)        || S <- ScalarsSecp], ok end),
  {TimeEnacl,   _} = timer:tc(fun() -> [enacl:crypto_ed25519_scalarmult_base(S) || S <- ScalarsEnacl], ok end),
  {TimeEd25519, _} = timer:tc(fun() -> [ecu_ed25519:scalar_mul_base(S)          || S <- ScalarsEd25519], ok end),

  ?debugFmt("", []),
  stats("Scalar mul base", "ecu_secp256k1  ", length(ScalarsSecp), TimeSecp),
  stats("Scalar mul base", "enacl/libsodium", length(ScalarsEnacl), TimeEnacl),
  stats("Scalar mul base", "ecu_ed25519    ", length(ScalarsEd25519), TimeEd25519),
  diff(TimeEnacl / length(ScalarsEnacl), TimeEd25519 / length(ScalarsEd25519)),
  ok.

bench_scalar_mul_test() ->
  Scalars0 = [ <<(gen_scalar()):256/little>> || _ <- lists:seq(1, 100) ],
  ScalarsSecp    = lists:append(lists:duplicate(1, Scalars0)),
  ScalarsEnacl   = lists:append(lists:duplicate(100, Scalars0)),
  ScalarsEd25519 = lists:append(lists:duplicate(10, Scalars0)),

  Test = fun(F, P0, Ss) -> lists:foldl(fun(S, P) -> F(S, P) end, P0, Ss) end,

  {TimeSecp,    _} = timer:tc(fun() -> Test(fun ecu_secp256k1:scalar_mul/2,        ecu_secp256k1:scalar_mul_base(hd(ScalarsSecp)),         tl(ScalarsSecp)) end),
  {TimeEnacl,   _} = timer:tc(fun() -> Test(fun enacl:crypto_ed25519_scalarmult/2, enacl:crypto_ed25519_scalarmult_base(hd(ScalarsEnacl)), tl(ScalarsEnacl)) end),
  {TimeEd25519, _} = timer:tc(fun() -> Test(fun ecu_ed25519:scalar_mul/2,          ecu_ed25519:scalar_mul_base(hd(ScalarsEd25519)),        tl(ScalarsEd25519)) end),

  ?debugFmt("", []),
  stats("Scalar mul", "ecu_secp256k1  ", length(ScalarsSecp), TimeSecp),
  stats("Scalar mul", "enacl/libsodium", length(ScalarsEnacl), TimeEnacl),
  stats("Scalar mul", "ecu_ed25519    ", length(ScalarsEd25519), TimeEd25519),
  diff(TimeEnacl / length(ScalarsEnacl), TimeEd25519 / length(ScalarsEd25519)),
  ok.

bench_sign_test() ->
  KeyPairs = [ enacl:sign_keypair() || _ <- lists:seq(1, 10) ],
  Messages = [ crypto:strong_rand_bytes(X) || X <- lists:seq(20, 49) ],

  Data = [ {K, Msg} || {Msg, K} <- lists:zip(Messages, lists:append(lists:duplicate(3, KeyPairs))) ],

  DataEnacl   = lists:append(lists:duplicate(1000, Data)),
  DataEd25519 = lists:append(lists:duplicate(20, Data)),

  {TimeEnacl,   _} = timer:tc(fun() -> [enacl:sign_detached(Msg, maps:get(secret, K))     || {K, Msg} <- DataEnacl], ok end),
  {TimeEd25519, _} = timer:tc(fun() -> [ecu_eddsa:sign_detached(Msg, maps:get(secret, K)) || {K, Msg} <- DataEd25519], ok end),


  ?debugFmt("", []),
  stats("Message sign", "enacl/libsodium", length(DataEnacl), TimeEnacl),
  stats("Message sign", "ecu_ed25519    ", length(DataEd25519), TimeEd25519),
  diff(TimeEnacl / length(DataEnacl), TimeEd25519 / length(DataEd25519)),
  ok.

bench_verify_test() ->
  KeyPairs = [ enacl:sign_keypair() || _ <- lists:seq(1, 10) ],
  Messages = [ crypto:strong_rand_bytes(X) || X <- lists:seq(20, 49) ],

  Data = [ {K, Msg, enacl:sign_detached(Msg, maps:get(secret, K))}
           || {Msg, K} <- lists:zip(Messages, lists:append(lists:duplicate(3, KeyPairs))) ],

  DataEnacl   = lists:append(lists:duplicate(1000, Data)),
  DataEd25519 = lists:append(lists:duplicate(20, Data)),

  {TimeEnacl,   _} = timer:tc(fun() -> [enacl:sign_verify_detached(Sig, Msg, maps:get(public, K))     || {K, Msg, Sig} <- DataEnacl], ok end),
  {TimeEd25519, _} = timer:tc(fun() -> [ecu_eddsa:sign_verify_detached(Sig, Msg, maps:get(public, K)) || {K, Msg, Sig} <- DataEd25519], ok end),


  ?debugFmt("", []),
  stats("Message verify", "enacl/libsodium", length(DataEnacl), TimeEnacl),
  stats("Message verify", "ecu_ed25519    ", length(DataEd25519), TimeEd25519),
  diff(TimeEnacl / length(DataEnacl), TimeEd25519 / length(DataEd25519)),
  ok.

gen_ecdsa_secp256k1_privkey() ->
  <<P0:256>> = crypto:strong_rand_bytes(32),
  P = (P0 rem (ecu_secp256k1:n() - 1)) + 1,
  <<P:256>>.

bench_ecverify_test() ->
  Data0 = [ {gen_ecdsa_secp256k1_privkey(), crypto:strong_rand_bytes(32)} || _ <- lists:seq(1, 10) ],
  Data1  = [ {Pr, Msg, ecu_crypto:private_to_short(ethereum, Pr), ecu_crypto:eth_sign(Msg, Pr)} || {Pr, Msg} <- Data0 ],

  RustData = lists:append(lists:duplicate(100, Data1)),
  ECUData  = lists:append(lists:duplicate(5, Data1)),

  %% ensure loading
  ecrecover:recover(<<0:256>>, <<123:520>>),

  {TimeRust, _} = timer:tc(fun() -> [ ecrecover:recover(Msg, Sig) || {_, Msg, _, Sig} <- RustData ], ok end),
  {TimeECU,  _} = timer:tc(fun() -> [ ecu_crypto:eth_recover(Msg, Sig) || {_, Msg, _, Sig} <- ECUData ], ok end),

  ?debugFmt("", []),
  stats("Message verify", "ecrecover (Rust)", length(RustData), TimeRust),
  stats("Message verify", "ecu_crypto      ", length(ECUData), TimeECU),
  diff(TimeRust / length(RustData), TimeECU / length(ECUData)),
  ok.

stats(What, Who, N, T) ->
  ?debugFmt("~s with ~s ~.2f us/op", [What, Who, T / N]).

diff(T1, T2) when T1 > T2 ->
  diff(T2, T1);
diff(T1, T2) ->
  ?debugFmt("Speed difference x~.2f", [T2 / T1]).
