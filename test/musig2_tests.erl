%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for ecu_musig2 (BIP-327 secp256k1 & Ed25519) and
%%% cross-verification against reference NIF (ecu_musig2_nif).
%%% @end
%%%-------------------------------------------------------------------
-module(musig2_tests).

-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% BIP-327 (secp256k1 / BIP-340) Tests
%% ===================================================================

bip327_2party_test() ->
  lists:foreach(
    fun(_) ->
      SK1 = crypto:strong_rand_bytes(32),
      SK2 = crypto:strong_rand_bytes(32),
      PK1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK1)),
      PK2 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK2)),
      Msg = crypto:strong_rand_bytes(32),

      {ok, Ctx} = ecu_musig2:key_agg([PK1, PK2]),
      AggPk = ecu_musig2:key_agg_pubkey(Ctx),
      ?assertEqual(32, byte_size(AggPk)),

      {SecN1, <<_R1a:33/binary, _R2a:33/binary>> = PubN1} = ecu_musig2:nonce_gen(bip340, SK1),
      {SecN2, <<_R1b:33/binary, _R2b:33/binary>> = PubN2} = ecu_musig2:nonce_gen(bip340, SK2),
      {ok, <<_AggR1:33/binary, _AggR2:33/binary>> = AggN} = ecu_musig2:nonce_agg([PubN1, PubN2]),

      {ok, Psig1} = ecu_musig2:sign_partial(Ctx, SK1, SecN1, AggN, Msg),
      {ok, Psig2} = ecu_musig2:sign_partial(Ctx, SK2, SecN2, AggN, Msg),

      ?assert(ecu_musig2:verify_partial(Ctx, Psig1, PubN1, PK1, AggN, Msg)),
      ?assert(ecu_musig2:verify_partial(Ctx, Psig2, PubN2, PK2, AggN, Msg)),

      {ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, [Psig1, Psig2]),
      ?assertEqual(64, byte_size(Sig)),
      ?assert(ecu_schnorr:verify(Sig, Msg, AggPk)),

      %% If NIF is available, cross-verify
      case ecu_musig2_nif:is_available() of
        true ->
          {ok, {NifAggPk, NifCtx}} = ecu_musig2_nif:key_agg([PK1, PK2]),
          ?assertEqual(AggPk, NifAggPk),
          ?assert(ecu_musig2_nif:verify(NifCtx, Psig1, PubN1, PK1, AggN, Msg)),
          ?assert(ecu_musig2_nif:verify(NifCtx, Psig2, PubN2, PK2, AggN, Msg)),
          {ok, NifSig} = ecu_musig2_nif:aggregate(NifCtx, AggN, Msg, [Psig1, Psig2]),
          ?assertEqual(Sig, NifSig);
        false ->
          ok
      end
    end,
    lists:seq(1, 5)
  ).

bip327_3party_test() ->
  lists:foreach(
    fun(_) ->
      SKs = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 3)],
      PKs = [ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK)) || SK <- SKs],
      Msg = crypto:strong_rand_bytes(32),

      {ok, Ctx} = ecu_musig2:key_agg(PKs),
      AggPk = ecu_musig2:key_agg_pubkey(Ctx),

      Nonces = [ecu_musig2:nonce_gen(SK) || SK <- SKs],
      PubNonces = [PN || {_, <<_:33/binary, _:33/binary>> = PN} <- Nonces],
      SecNonces = [SN || {SN, _} <- Nonces],

      {ok, <<_:33/binary, _:33/binary>> = AggN} = ecu_musig2:nonce_agg(PubNonces),

      Psigs = [
        begin
          {ok, Psig} = ecu_musig2:sign_partial(Ctx, SK, SN, AggN, Msg),
          ?assert(ecu_musig2:verify_partial(Ctx, Psig, PN, PK, AggN, Msg)),
          Psig
        end
       || {SK, SN, PN, PK} <- zip4(SKs, SecNonces, PubNonces, PKs)
      ],

      {ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, Psigs),
      ?assert(ecu_schnorr:verify(Sig, Msg, AggPk)),

      case ecu_musig2_nif:is_available() of
        true ->
          {ok, {NifAggPk, NifCtx}} = ecu_musig2_nif:key_agg(PKs),
          ?assertEqual(AggPk, NifAggPk),
          lists:foreach(
            fun({Psig, PN, PK}) ->
              ?assert(ecu_musig2_nif:verify(NifCtx, Psig, PN, PK, AggN, Msg))
            end,
            lists:zip3(Psigs, PubNonces, PKs)
          ),
          {ok, NifSig} = ecu_musig2_nif:aggregate(NifCtx, AggN, Msg, Psigs),
          ?assertEqual(Sig, NifSig);
        false ->
          ok
      end
    end,
    lists:seq(1, 5)
  ).

bip327_duplicate_key_test() ->
  SK1 = crypto:strong_rand_bytes(32),
  PK1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK1)),
  SK2 = crypto:strong_rand_bytes(32),
  PK2 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK2)),
  Msg = <<"Duplicate Key Test">>,

  %% 3 keys where PK1 appears twice: [PK1, PK2, PK1]
  PKs = [PK1, PK2, PK1],
  {ok, Ctx} = ecu_musig2:key_agg(PKs),
  AggPk = ecu_musig2:key_agg_pubkey(Ctx),

  {SN1_a, <<_:33/binary, _:33/binary>> = PN1_a} = ecu_musig2:nonce_gen(SK1),
  {SN2, <<_:33/binary, _:33/binary>> = PN2} = ecu_musig2:nonce_gen(SK2),
  {SN1_b, <<_:33/binary, _:33/binary>> = PN1_b} = ecu_musig2:nonce_gen(SK1),

  PubNonces = [PN1_a, PN2, PN1_b],
  {ok, <<_:33/binary, _:33/binary>> = AggN} = ecu_musig2:nonce_agg(PubNonces),

  %% Occurrence 1 for PK1
  {ok, Psig1_a} = ecu_musig2:sign_partial(Ctx, SK1, SN1_a, AggN, Msg, 1),
  ?assert(ecu_musig2:verify_partial(Ctx, Psig1_a, PN1_a, PK1, AggN, Msg, 1)),

  %% Occurrence 1 for PK2
  {ok, Psig2} = ecu_musig2:sign_partial(Ctx, SK2, SN2, AggN, Msg, 1),
  ?assert(ecu_musig2:verify_partial(Ctx, Psig2, PN2, PK2, AggN, Msg, 1)),

  %% Occurrence 2 for PK1
  {ok, Psig1_b} = ecu_musig2:sign_partial(Ctx, SK1, SN1_b, AggN, Msg, 2),
  ?assert(ecu_musig2:verify_partial(Ctx, Psig1_b, PN1_b, PK1, AggN, Msg, 2)),

  {ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, [Psig1_a, Psig2, Psig1_b]),
  ?assert(ecu_schnorr:verify(Sig, Msg, AggPk)),

  case ecu_musig2_nif:is_available() of
    true ->
      {ok, {NifAggPk, NifCtx}} = ecu_musig2_nif:key_agg(PKs),
      ?assertEqual(AggPk, NifAggPk),
      ?assert(ecu_musig2_nif:verify(NifCtx, Psig1_a, PN1_a, PK1, AggN, Msg)),
      ?assert(ecu_musig2_nif:verify(NifCtx, Psig2, PN2, PK2, AggN, Msg)),
      ?assert(ecu_musig2_nif:verify(NifCtx, Psig1_b, PN1_b, PK1, AggN, Msg)),
      {ok, NifSig} = ecu_musig2_nif:aggregate(NifCtx, AggN, Msg, [Psig1_a, Psig2, Psig1_b]),
      ?assertEqual(Sig, NifSig);
    false ->
      ok
  end.

%% ===================================================================
%% Ed25519 MuSig2 Tests
%% ===================================================================

ed25519_2party_test() ->
  lists:foreach(
    fun(_) ->
      SK1 = crypto:strong_rand_bytes(32),
      SK2 = crypto:strong_rand_bytes(32),
      #{public := PK1} = ecu_eddsa:sign_seed_keypair(SK1),
      #{public := PK2} = ecu_eddsa:sign_seed_keypair(SK2),
      Msg = crypto:strong_rand_bytes(32),

      {ok, Ctx} = ecu_musig2:key_agg(ed25519, [PK1, PK2]),
      AggPk = ecu_musig2:key_agg_pubkey(Ctx),
      ?assertEqual(32, byte_size(AggPk)),

      {SecN1, PubN1} = ecu_musig2:nonce_gen(ed25519),
      {SecN2, PubN2} = ecu_musig2:nonce_gen(ed25519),
      {ok, AggN} = ecu_musig2:nonce_agg(ed25519, [PubN1, PubN2]),

      {ok, Psig1} = ecu_musig2:sign_partial(Ctx, SK1, SecN1, AggN, Msg),
      {ok, Psig2} = ecu_musig2:sign_partial(Ctx, SK2, SecN2, AggN, Msg),

      ?assert(ecu_musig2:verify_partial(Ctx, Psig1, PubN1, PK1, AggN, Msg)),
      ?assert(ecu_musig2:verify_partial(Ctx, Psig2, PubN2, PK2, AggN, Msg)),

      {ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, [Psig1, Psig2]),
      ?assertEqual(64, byte_size(Sig)),
      ?assert(ecu_eddsa:sign_verify_detached(Sig, Msg, AggPk))
    end,
    lists:seq(1, 5)
  ).

ed25519_3party_test() ->
  lists:foreach(
    fun(_) ->
      SKs = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 3)],
      PKs = [
        begin
          #{public := PK} = ecu_eddsa:sign_seed_keypair(SK),
          PK
        end
       || SK <- SKs
      ],
      Msg = crypto:strong_rand_bytes(32),

      {ok, Ctx} = ecu_musig2:key_agg(ed25519, PKs),
      AggPk = ecu_musig2:key_agg_pubkey(Ctx),

      Nonces = [ecu_musig2:nonce_gen(ed25519) || _ <- lists:seq(1, 3)],
      PubNonces = [PN || {_, PN} <- Nonces],
      SecNonces = [SN || {SN, _} <- Nonces],

      {ok, AggN} = ecu_musig2:nonce_agg(ed25519, PubNonces),

      Psigs = [
        begin
          {ok, Psig} = ecu_musig2:sign_partial(Ctx, SK, SN, AggN, Msg),
          ?assert(ecu_musig2:verify_partial(Ctx, Psig, PN, PK, AggN, Msg)),
          Psig
        end
       || {SK, SN, PN, PK} <- zip4(SKs, SecNonces, PubNonces, PKs)
      ],

      {ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, Psigs),
      ?assert(ecu_eddsa:sign_verify_detached(Sig, Msg, AggPk))
    end,
    lists:seq(1, 5)
  ).

zip4([A | As], [B | Bs], [C | Cs], [D | Ds]) ->
  [{A, B, C, D} | zip4(As, Bs, Cs, Ds)];
zip4([], [], [], []) ->
  [].
