%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit test suite for IETF BLS Signatures and Aggregation on BLS12-381.
%%% Validates `min_pk' and `min_sig' schemes against:
%%%   - Supranational blst differential oracle (NIF)
%%%   - KeyGen, Sign, Verify roundtrips
%%%   - Signature & Public Key Aggregation
%%%   - Fast Aggregate Verify (common message)
%%%   - Core Aggregate Verify (distinct messages)
%%%   - Malicious/tampered inputs and negative cases
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_sig_tests).

-include_lib("eunit/include/eunit.hrl").

-define(BLS, ecu_bls12_381).
-define(SIG, ecu_bls12_381_sig).
-define(NIF, ecu_bls12_381_nif).

min_pk_sign_verify_differential_test() ->
  case ?NIF:is_available() of
    false ->
      ok;
    true ->
      lists:foreach(
        fun(Seed) ->
          IKM = crypto:hash(sha256, Seed),
          {ok, {PK_nif, SK_nif}} = ?NIF:min_pk_keygen(IKM),
          {ok, {PK_erl, SK_erl}} = ?SIG:min_pk_keygen(IKM),
          ?assertEqual(SK_nif, SK_erl),
          ?assertEqual(PK_nif, PK_erl),

          Msg = <<"Differential BLS test payload: ", Seed/binary>>,
          DST = ?SIG:min_pk_dst_basic(),

          {ok, Sig_nif} = ?NIF:min_pk_sign(SK_nif, Msg, DST),
          Sig_erl = ?SIG:min_pk_sign(SK_erl, Msg, DST),
          ?assertEqual(Sig_nif, Sig_erl),

          ?assert(?SIG:min_pk_verify(PK_erl, Msg, Sig_erl, DST)),
          ?assert(?NIF:min_pk_verify(PK_erl, Msg, Sig_erl, DST)),

          %% Negative tests
          ?assertNot(?SIG:min_pk_verify(PK_erl, <<"tampered">>, Sig_erl, DST)),
          ?assertNot(?NIF:min_pk_verify(PK_erl, <<"tampered">>, Sig_erl, DST)),

          WrongPK = ?BLS:g1_compress(?BLS:g1_generator()),
          ?assertNot(?SIG:min_pk_verify(WrongPK, Msg, Sig_erl, DST))
        end,
        [<<"seed_1">>, <<"seed_2">>, <<"seed_3">>]
      )
  end.

min_sig_sign_verify_differential_test() ->
  case ?NIF:is_available() of
    false ->
      ok;
    true ->
      lists:foreach(
        fun(Seed) ->
          IKM = crypto:hash(sha256, Seed),
          {ok, {PK_nif, SK_nif}} = ?NIF:min_sig_keygen(IKM),
          {ok, {PK_erl, SK_erl}} = ?SIG:min_sig_keygen(IKM),
          ?assertEqual(SK_nif, SK_erl),
          ?assertEqual(PK_nif, PK_erl),

          Msg = <<"Differential min_sig test payload: ", Seed/binary>>,
          DST = ?SIG:min_sig_dst_basic(),

          {ok, Sig_nif} = ?NIF:min_sig_sign(SK_nif, Msg, DST),
          Sig_erl = ?SIG:min_sig_sign(SK_erl, Msg, DST),
          ?assertEqual(Sig_nif, Sig_erl),

          ?assert(?SIG:min_sig_verify(PK_erl, Msg, Sig_erl, DST)),
          ?assert(?NIF:min_sig_verify(PK_erl, Msg, Sig_erl, DST)),

          ?assertNot(?SIG:min_sig_verify(PK_erl, <<"tampered">>, Sig_erl, DST)),
          ?assertNot(?NIF:min_sig_verify(PK_erl, <<"tampered">>, Sig_erl, DST))
        end,
        [<<"seed_a">>, <<"seed_b">>, <<"seed_c">>]
      )
  end.

min_pk_aggregation_test() ->
  Seeds = [<<"agg_1">>, <<"agg_2">>, <<"agg_3">>, <<"agg_4">>],
  KeyPairs = [
    begin
      IKM = crypto:hash(sha256, S),
      {ok, {PK, SK}} = ?SIG:min_pk_keygen(IKM),
      {PK, SK}
    end
   || S <- Seeds
  ],
  PKs = [PK || {PK, _} <- KeyPairs],
  SKs = [SK || {_, SK} <- KeyPairs],

  MsgCommon = <<"Shared consensus message">>,
  DST = ?SIG:min_pk_dst_basic(),

  Sigs = [?SIG:min_pk_sign(SK, MsgCommon, DST) || SK <- SKs],

  {ok, SigAgg} = ?SIG:min_pk_aggregate_signatures(Sigs),
  {ok, PKAgg} = ?SIG:min_pk_aggregate_public_keys(PKs),

  case ?NIF:is_available() of
    true ->
      {ok, NifSigAgg} = ?NIF:min_pk_aggregate(Sigs),
      ?assertEqual(NifSigAgg, SigAgg),
      ?assert(?NIF:min_pk_fast_aggregate_verify(PKs, MsgCommon, SigAgg, DST));
    false ->
      ok
  end,

  %% Verify using fast_aggregate_verify
  ?assert(?SIG:min_pk_fast_aggregate_verify(PKs, MsgCommon, SigAgg, DST)),
  ?assert(?SIG:min_pk_verify(PKAgg, MsgCommon, SigAgg, DST)),

  %% Tampered message fails
  ?assertNot(?SIG:min_pk_fast_aggregate_verify(PKs, <<"tampered">>, SigAgg, DST)),

  %% Missing signer fails
  [_FirstPK | RestPKs] = PKs,
  ?assertNot(?SIG:min_pk_fast_aggregate_verify(RestPKs, MsgCommon, SigAgg, DST)).

min_sig_aggregation_test() ->
  Seeds = [<<"ms_agg_1">>, <<"ms_agg_2">>, <<"ms_agg_3">>],
  KeyPairs = [
    begin
      IKM = crypto:hash(sha256, S),
      {ok, {PK, SK}} = ?SIG:min_sig_keygen(IKM),
      {PK, SK}
    end
   || S <- Seeds
  ],
  PKs = [PK || {PK, _} <- KeyPairs],
  SKs = [SK || {_, SK} <- KeyPairs],

  MsgCommon = <<"Min_sig shared message">>,
  DST = ?SIG:min_sig_dst_basic(),

  Sigs = [?SIG:min_sig_sign(SK, MsgCommon, DST) || SK <- SKs],

  {ok, SigAgg} = ?SIG:min_sig_aggregate_signatures(Sigs),
  {ok, PKAgg} = ?SIG:min_sig_aggregate_public_keys(PKs),

  ?assert(?SIG:min_sig_fast_aggregate_verify(PKs, MsgCommon, SigAgg, DST)),
  ?assert(?SIG:min_sig_verify(PKAgg, MsgCommon, SigAgg, DST)),
  ?assertNot(?SIG:min_sig_fast_aggregate_verify(PKs, <<"wrong">>, SigAgg, DST)).

min_pk_core_aggregate_verify_test() ->
  Seeds = [<<"multi_1">>, <<"multi_2">>, <<"multi_3">>],
  Msgs = [<<"order_100">>, <<"order_200">>, <<"order_300">>],
  DST = ?SIG:min_pk_dst_basic(),

  Triples = [
    begin
      IKM = crypto:hash(sha256, S),
      {ok, {PK, SK}} = ?SIG:min_pk_keygen(IKM),
      Sig = ?SIG:min_pk_sign(SK, M, DST),
      {PK, M, Sig}
    end
   || {S, M} <- lists:zip(Seeds, Msgs)
  ],

  Pairs = [{PK, M} || {PK, M, _} <- Triples],
  Sigs = [Sig || {_, _, Sig} <- Triples],

  {ok, SigAgg} = ?SIG:min_pk_aggregate_signatures(Sigs),

  ?assert(?SIG:min_pk_aggregate_verify(Pairs, SigAgg, DST)),

  %% Permuted messages must fail
  [{PK1, M1}, {PK2, M2} | Rest] = Pairs,
  BadPairs = [{PK1, M2}, {PK2, M1} | Rest],
  ?assertNot(?SIG:min_pk_aggregate_verify(BadPairs, SigAgg, DST)),

  %% Tampered signature must fail
  BadSig = binary:copy(<<0>>, 96),
  ?assertNot(?SIG:min_pk_aggregate_verify(Pairs, BadSig, DST)).

min_sig_core_aggregate_verify_test() ->
  Seeds = [<<"multi_s1">>, <<"multi_s2">>, <<"multi_s3">>],
  Msgs = [<<"vote_A">>, <<"vote_B">>, <<"vote_C">>],
  DST = ?SIG:min_sig_dst_basic(),

  Triples = [
    begin
      IKM = crypto:hash(sha256, S),
      {ok, {PK, SK}} = ?SIG:min_sig_keygen(IKM),
      Sig = ?SIG:min_sig_sign(SK, M, DST),
      {PK, M, Sig}
    end
   || {S, M} <- lists:zip(Seeds, Msgs)
  ],

  Pairs = [{PK, M} || {PK, M, _} <- Triples],
  Sigs = [Sig || {_, _, Sig} <- Triples],

  {ok, SigAgg} = ?SIG:min_sig_aggregate_signatures(Sigs),

  ?assert(?SIG:min_sig_aggregate_verify(Pairs, SigAgg, DST)),

  %% Mismatched pairs fail
  [{PK1, M1}, {PK2, M2} | Rest] = Pairs,
  ?assertNot(?SIG:min_sig_aggregate_verify([{PK1, M2}, {PK2, M1} | Rest], SigAgg, DST)).

generic_api_test() ->
  IKM = crypto:hash(sha256, <<"generic_scheme_seed">>),
  Msg = <<"Test generic dispatch">>,

  %% min_pk
  {ok, {PK_pk, SK_pk}} = ?SIG:min_pk_keygen(IKM),
  Sig_pk = ?SIG:sign(min_pk, SK_pk, Msg),
  ?assert(?SIG:verify(min_pk, PK_pk, Msg, Sig_pk)),

  %% min_sig
  {ok, {PK_sig, SK_sig}} = ?SIG:min_sig_keygen(IKM),
  Sig_sig = ?SIG:sign(min_sig, SK_sig, Msg),
  ?assert(?SIG:verify(min_sig, PK_sig, Msg, Sig_sig)),

  %% Top-level ecu_bls12_381 exports
  ?assert(?BLS:min_pk_verify(PK_pk, Msg, Sig_pk)),
  ?assert(?BLS:min_sig_verify(PK_sig, Msg, Sig_sig)).

invalid_inputs_test() ->
  %% Short IKM
  ?assertEqual({error, ikm_too_short}, ?SIG:min_pk_keygen(<<"too_short">>)),
  ?assertEqual({error, ikm_too_short}, ?SIG:min_sig_keygen(<<"too_short">>)),

  %% Empty aggregation lists
  ?assertEqual({error, empty_signatures}, ?SIG:min_pk_aggregate_signatures([])),
  ?assertEqual({error, empty_public_keys}, ?SIG:min_pk_aggregate_public_keys([])),
  ?assertEqual({error, empty_signatures}, ?SIG:min_sig_aggregate_signatures([])),
  ?assertEqual({error, empty_public_keys}, ?SIG:min_sig_aggregate_public_keys([])),

  %% Empty aggregate verify
  ?assertNot(?SIG:min_pk_fast_aggregate_verify([], <<"msg">>, binary:copy(<<0>>, 96))),
  ?assertNot(?SIG:min_pk_aggregate_verify([], binary:copy(<<0>>, 96))),
  ?assertNot(?SIG:min_sig_fast_aggregate_verify([], <<"msg">>, binary:copy(<<0>>, 48))),
  ?assertNot(?SIG:min_sig_aggregate_verify([], binary:copy(<<0>>, 48))).
