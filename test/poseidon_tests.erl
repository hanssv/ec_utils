%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit test suite for Poseidon hash function (ecu_poseidon).
%%% Covers:
%%% - FATE VM / Aeternity known-answer tests (BLS12-381)
%%% - Circomlib official test vectors (BN254)
%%% - Cross-verification against Rust reference oracle (ecu_poseidon_nif)
%%% - Strict domain and range validation (scalars >= prime, bad lengths)
%%% @end
%%%-------------------------------------------------------------------
-module(poseidon_tests).

-include_lib("eunit/include/eunit.hrl").

-define(BLS_Q, 16#73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001).
-define(BN_Q, 16#30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001).

fate_known_answer_test() ->
  %% aeu_poseidon:hash3(1, 2)
  Expected = 16#28ce19420fc246a05553ad1e8c98f5c9d67166be2c18e9e4cb4b4e317dd2a78a,
  ?assertEqual(Expected, ecu_poseidon:hash3(1, 2)),
  ?assertEqual(Expected, ecu_poseidon:hash3(bls12_381, 1, 2)),
  ?assertEqual(Expected, ecu_poseidon:hash([1, 2])),
  ?assertEqual(Expected, ecu_poseidon:hash(bls12_381, [1, 2])),
  ?assertEqual(<<Expected:256/big>>, ecu_poseidon:hash_binary([<<1:256>>, <<2:256>>])),
  ?assertEqual(<<Expected:256/big>>, ecu_poseidon:hash_binary(bls12_381, [<<1:256>>, <<2:256>>])).

circomlib_known_answer_test() ->
  %% Circomlib poseidon([1, 2]) over BN254
  Expected12 = 16#115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a,
  ?assertEqual(Expected12, ecu_poseidon:hash3(bn254, 1, 2)),
  ?assertEqual(Expected12, ecu_poseidon:hash(bn254, [1, 2])),
  ?assertEqual(<<Expected12:256/big>>, ecu_poseidon:hash_binary(bn254, [<<1:256>>, <<2:256>>])),

  %% Circomlib poseidon([1])
  Expected1 = 16#29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133,
  ?assertEqual(Expected1, ecu_poseidon:hash(bn254, [1])),

  %% Circomlib poseidon([1, 1])
  Expected11 = 16#007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81,
  ?assertEqual(Expected11, ecu_poseidon:hash(bn254, [1, 1])),
  ?assertEqual(Expected11, ecu_poseidon:hash3(bn254, 1, 1)).

differential_rust_oracle_test() ->
  case ecu_poseidon_nif:is_available() of
    true ->
      %% BLS12-381 differential
      A = 12345678901234567890,
      B = 98765432109876543210,
      ExpBls = ecu_poseidon:hash3(bls12_381, A, B),
      {ok, <<NifBls:256/big>>} = ecu_poseidon_nif:hash3(bls12_381, <<A:256>>, <<B:256>>),
      ?assertEqual(ExpBls, NifBls),

      %% BN254 differential
      ExpBn = ecu_poseidon:hash3(bn254, A, B),
      {ok, <<NifBn:256/big>>} = ecu_poseidon_nif:hash3(bn254, <<A:256>>, <<B:256>>),
      ?assertEqual(ExpBn, NifBn),

      %% Multi-element differential (3 inputs -> T=4)
      Inputs = [A, B, A + B],
      InputsBin = [<<X:256>> || X <- Inputs],
      ExpMultiBls = ecu_poseidon:hash(bls12_381, Inputs),
      {ok, <<NifMultiBls:256/big>>} = ecu_poseidon_nif:hash(bls12_381, InputsBin),
      ?assertEqual(ExpMultiBls, NifMultiBls),

      ExpMultiBn = ecu_poseidon:hash(bn254, Inputs),
      {ok, <<NifMultiBn:256/big>>} = ecu_poseidon_nif:hash(bn254, InputsBin),
      ?assertEqual(ExpMultiBn, NifMultiBn);
    false ->
      ok
  end.

domain_validation_test() ->
  %% Rejection of inputs >= modulus (BLS12-381)
  ?assertError(badarg, ecu_poseidon:hash3(bls12_381, ?BLS_Q, 1)),
  ?assertError(badarg, ecu_poseidon:hash3(bls12_381, 1, ?BLS_Q + 5)),
  ?assertError(badarg, ecu_poseidon:hash(bls12_381, [?BLS_Q, 1])),
  ?assertError(badarg, ecu_poseidon:hash_binary(bls12_381, [<<?BLS_Q:256>>, <<1:256>>])),

  %% Rejection of inputs >= modulus (BN254)
  ?assertError(badarg, ecu_poseidon:hash3(bn254, ?BN_Q, 1)),
  ?assertError(badarg, ecu_poseidon:hash3(bn254, 1, ?BN_Q + 5)),
  ?assertError(badarg, ecu_poseidon:hash(bn254, [?BN_Q, 1])),
  ?assertError(badarg, ecu_poseidon:hash_binary(bn254, [<<?BN_Q:256>>, <<1:256>>])),

  %% Rejection of negative numbers
  ?assertError(badarg, ecu_poseidon:hash3(bls12_381, -1, 1)),
  ?assertError(badarg, ecu_poseidon:hash(bls12_381, [-1])),

  %% Rejection of invalid lengths (empty or > 8 inputs)
  ?assertError(badarg, ecu_poseidon:hash(bls12_381, [])),
  ?assertError(badarg, ecu_poseidon:hash(bls12_381, [1, 2, 3, 4, 5, 6, 7, 8, 9])),

  %% Rejection of bad binary lengths
  ?assertError(badarg, ecu_poseidon:hash_binary(bls12_381, [<<1>>])),
  ?assertError(badarg, ecu_poseidon:hash_binary(bls12_381, [<<1:264>>])).

permute_properties_test() ->
  State0 = [0, 1, 2, 3],
  State1 = ecu_poseidon:permute(bls12_381, State0),
  ?assertEqual(4, length(State1)),
  lists:foreach(fun(X) -> ?assert(X >= 0 andalso X < ?BLS_Q) end, State1),

  StateBn = ecu_poseidon:permute(bn254, State0),
  ?assertEqual(4, length(StateBn)),
  lists:foreach(fun(X) -> ?assert(X >= 0 andalso X < ?BN_Q) end, StateBn).
