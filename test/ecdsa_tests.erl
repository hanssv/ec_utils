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

%% --- Input validation (S2, S8)

-include("ecu_secp256k1.hrl").

pubkey() ->
  ecu_ecdsa:private_to_public(secp256k1, <<5:256>>).

%% With z = 0 and s = 1, both u1 = z/s and u2 = r/s are 0, so the verifier adds
%% two points at infinity, gets x = 0 and accepts r = 0. Works for any pubkey.
verify_zero_r_forgery_test() ->
  ?assertNot(ecu_ecdsa:verify(secp256k1, <<0:256>>, pubkey(), <<0:256, 1:256>>)),
  ?assertNot(ecu_ecdsa:verify(secp256k1, <<?N:256>>, pubkey(), <<0:256, 1:256>>)).

verify_zero_s_test() ->
  %% s_inv(0) used to crash with a badmatch
  ?assertNot(ecu_ecdsa:verify(secp256k1, <<1:256>>, pubkey(), <<1:256, 0:256>>)).

verify_out_of_range_test() ->
  Bad = [0, ?N, ?N + 1, (1 bsl 256) - 1],
  [ ?assertNot(ecu_ecdsa:verify(secp256k1, <<1:256>>, pubkey(), <<R:256, 1:256>>))
    || R <- Bad ],
  [ ?assertNot(ecu_ecdsa:verify(secp256k1, <<1:256>>, pubkey(), <<1:256, S:256>>))
    || S <- Bad ].

%% Anyone can forge a signature for the point at infinity: pick k, set
%% r = x(kG) mod n and s = z / k.
verify_infinity_pubkey_test() ->
  K = 12345, Z = 99,
  {X, _} = ecu_secp256k1:scalar_mul_base(K),
  R = X rem ?N,
  S = ecu_secp256k1:s_mul(Z, ecu_secp256k1:s_inv(K)),
  ?assertNot(ecu_ecdsa:verify(secp256k1, <<Z:256>>, {0, 0}, <<R:256, S:256>>)).

verify_off_curve_pubkey_test() ->
  ?assertNot(ecu_ecdsa:verify(secp256k1, <<1:256>>, {1, 1}, <<1:256, 1:256>>)).

invalid_private_key_test() ->
  Bad = [0, ?N, ?N + 1, (1 bsl 256) - 1],
  [ ?assertError(_, ecu_ecdsa:private_to_public(secp256k1, <<K:256>>)) || K <- Bad ],
  [ ?assertError(_, ecu_ecdsa:sign(secp256k1, <<1:256>>, <<K:256>>)) || K <- Bad ],
  [ ?assertError(_, ecu_ecdsa:sign_secp256k1(<<1:256>>, <<K:256>>)) || K <- Bad ].

valid_private_key_boundaries_test() ->
  %% 1 and n - 1 are the extreme valid keys
  [ begin
      Pub = ecu_ecdsa:private_to_public(secp256k1, <<K:256>>),
      Sig = ecu_ecdsa:sign(secp256k1, <<7:256>>, <<K:256>>),
      ?assert(ecu_ecdsa:verify(secp256k1, <<7:256>>, Pub, Sig))
    end || K <- [1, ?N - 1] ].

sign_secp256k1_return_type_test() ->
  MsgHash = crypto:hash(sha256, <<"test">>),
  Priv = <<123:256>>,
  Res = ecu_ecdsa:sign_secp256k1(MsgHash, Priv),
  ?assertMatch({<<_:64/binary>>, Y} when is_integer(Y), Res).

