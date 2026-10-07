%%% File        : ecdsa_eqc.erl
%%% Description : Properties for ecu_ecdsa (input validation + round trips)
-module(ecdsa_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_secp256k1.hrl").
-define(MAX256, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).

%% Scalar in range
gen_valid_scalar() ->
  weighted_default({1, elements([1, 2, ?N - 2, ?N - 1])},
                   {9, choose(1, ?N)}).

%% Scalar not in range (outside field)
gen_invalid_scalar() ->
  weighted_default({1, elements([0, ?N, ?N + 1, ?MAX256 - 1, ?MAX256])},
                   {9, ?LET(X, choose(0, ?MAX256 - ?N), ?N + X)}).

%% Valid private keys, biased towards the boundaries.
gen_privkey() ->
  ?LET(X, gen_valid_scalar(), <<X:256>>).

%% Any 256 bit value, biased towards "extreme" values.
gen_tagged_scalar(Valid, Invalid) ->
  frequency([{Valid, {valid, gen_valid_scalar()}}, {Invalid, {invalid, gen_invalid_scalar()}}]).

%% A random message its content doesn't matter, so don't shrink.
gen_msg() ->
  noshrink(binary(32)).

in_range(X) -> X >= 1 andalso X < ?N.

%% Signing then verifying works, also for extreme keys.
prop_sign_verify() ->
  ?FORALL({Priv, Msg}, {gen_privkey(), gen_msg()},
  begin
    Pub = ecu_ecdsa:private_to_public(secp256k1, Priv),
    Sig = ecu_ecdsa:sign(secp256k1, Msg, Priv),
    equals(true, ecu_ecdsa:verify(secp256k1, Msg, Pub, Sig))
  end).

%% A signature doesn't verify for a different message.
prop_verify_wrong_msg() ->
  ?FORALL({Priv, Msg1, Msg2}, {gen_privkey(), gen_msg(), gen_msg()},
  ?IMPLIES(Msg1 /= Msg2,
  begin
    Pub = ecu_ecdsa:private_to_public(secp256k1, Priv),
    Sig = ecu_ecdsa:sign(secp256k1, Msg1, Priv),
    equals(false, ecu_ecdsa:verify(secp256k1, Msg2, Pub, Sig))
  end)).


gen_forged_msg() ->
  weighted_default({1, elements([<<0:256>>, <<?N:256>>])}, {3, gen_msg()}).

%% verify/4 never crashes on well-sized input, and never accepts a signature
%% where r or s is out of range (regardless of message and public key).
prop_verify_total() ->
  ?FORALL({Priv, Msg, {ValidR, R}, {ValidS, S}},
          {gen_privkey(), gen_forged_msg(), gen_tagged_scalar(1, 1), gen_tagged_scalar(1, 1)},
  begin
    Pub = ecu_ecdsa:private_to_public(secp256k1, Priv),
    Res =
      try
        ecu_ecdsa:verify(secp256k1, Msg, Pub, <<R:256, S:256>>)
      catch _:_:_ ->
        error
      end,
    BothValid = ValidR == valid andalso ValidS == valid,
    ?WHENFAIL(eqc:format("r = ~p\ns = ~p\n", [R, S]),
              is_boolean(Res) andalso (Res == false orelse BothValid))
  end).

%% Private keys outside 1..n-1 are rejected.
prop_invalid_privkey() ->
  ?FORALL({K, Msg}, {gen_invalid_scalar(), gen_msg()},
  begin
    Priv = <<K:256>>,
    conjunction([{private_to_public, catches(fun() -> ecu_ecdsa:private_to_public(secp256k1, Priv) end)},
                 {sign,              catches(fun() -> ecu_ecdsa:sign(secp256k1, Msg, Priv) end)}])
  end).

catches(F) ->
  try F(), false catch error:_ -> true end.

prop_secp256k1_p_add_unreduced() ->
  ?FORALL({K1, K2, M1, M2}, {choose(1, ?N - 1), choose(1, ?N - 1), choose(0, 3), choose(0, 3)},
  begin
    P1 = ecu_secp256k1:scalar_mul_base(K1),
    P2 = ecu_secp256k1:scalar_mul_base(K2),
    {X1, Y1} = P1,
    {X2, Y2} = P2,
    P1_unreduced = {X1 + M1 * ?P, Y1 + M1 * ?P},
    P2_unreduced = {X2 + M2 * ?P, Y2 + M2 * ?P},
    Expected = ecu_secp256k1:p_add(P1, P2),
    Actual   = try ecu_secp256k1:p_add(P1_unreduced, P2_unreduced)
               catch _:_ -> crash
               end,
    equals(Expected, Actual)
  end).

