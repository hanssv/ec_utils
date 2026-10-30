%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for MuSig2 (BIP-327 secp256k1 & Ed25519).
%%% @end
%%%-------------------------------------------------------------------
-module(musig2_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

gen_num_signers() ->
  choose(2, 5).

gen_msg() ->
  ?LET(
    Len,
    choose(1, 64),
    binary(Len)
  ).

gen_secp_keypair() ->
  ?LET(
    Seed,
    binary(32),
    begin
      N = ecu_secp256k1:n(),
      SKVal = binary:decode_unsigned(Seed) rem (N - 1) + 1,
      SK = <<SKVal:256>>,
      PK = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SKVal)),
      {SK, PK}
    end
  ).

gen_ed25519_keypair() ->
  ?LET(
    SK,
    binary(32),
    begin
      #{public := PK} = ecu_eddsa:sign_seed_keypair(SK),
      {SK, PK}
    end
  ).

prop_bip327_multisig() ->
  ?FORALL(
    {NumSigners, Msg},
    {gen_num_signers(), gen_msg()},
    begin
      Keypairs = [
        begin
          Seed = crypto:strong_rand_bytes(32),
          N = ecu_secp256k1:n(),
          SKVal = binary:decode_unsigned(Seed) rem (N - 1) + 1,
          SK = <<SKVal:256>>,
          PK = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SKVal)),
          {SK, PK}
        end
       || _ <- lists:seq(1, NumSigners)
      ],
      {SKs, PKs} = lists:unzip(Keypairs),

      {ok, Ctx} = ecu_musig2:key_agg(PKs),
      AggPk = ecu_musig2:key_agg_pubkey(Ctx),

      Nonces = [ecu_musig2:nonce_gen(SK) || SK <- SKs],
      {SecNonces, PubNonces} = lists:unzip(Nonces),

      {ok, AggN} = ecu_musig2:nonce_agg(PubNonces),

      Psigs = [
        begin
          {ok, Psig} = ecu_musig2:sign_partial(Ctx, SK, SN, AggN, Msg),
          true = ecu_musig2:verify_partial(Ctx, Psig, PN, PK, AggN, Msg),
          Psig
        end
       || {SK, SN, PN, PK} <- zip4(SKs, SecNonces, PubNonces, PKs)
      ],

      {ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, Psigs),
      ValidPure = ecu_schnorr:verify(Sig, Msg, AggPk),

      ValidNif =
        case ecu_musig2_nif:is_available() of
          true ->
            {ok, {NifAggPk, NifCtx}} = ecu_musig2_nif:key_agg(PKs),
            AggPk == NifAggPk andalso
              lists:all(
                fun({Psig, PN, PK}) ->
                  ecu_musig2_nif:verify(NifCtx, Psig, PN, PK, AggN, Msg)
                end,
                lists:zip3(Psigs, PubNonces, PKs)
              ) andalso
              begin
                {ok, NifSig} = ecu_musig2_nif:aggregate(NifCtx, AggN, Msg, Psigs),
                Sig == NifSig
              end;
          false ->
            true
        end,

      ValidPure andalso ValidNif
    end
  ).

prop_ed25519_multisig() ->
  ?FORALL(
    {NumSigners, Msg},
    {gen_num_signers(), gen_msg()},
    begin
      Keypairs = [
        begin
          SK = crypto:strong_rand_bytes(32),
          #{public := PK} = ecu_eddsa:sign_seed_keypair(SK),
          {SK, PK}
        end
       || _ <- lists:seq(1, NumSigners)
      ],
      {SKs, PKs} = lists:unzip(Keypairs),

      {ok, Ctx} = ecu_musig2:key_agg(ed25519, PKs),
      AggPk = ecu_musig2:key_agg_pubkey(Ctx),

      Nonces = [ecu_musig2:nonce_gen(ed25519) || _ <- lists:seq(1, NumSigners)],
      {SecNonces, PubNonces} = lists:unzip(Nonces),

      {ok, AggN} = ecu_musig2:nonce_agg(ed25519, PubNonces),

      Psigs = [
        begin
          {ok, Psig} = ecu_musig2:sign_partial(Ctx, SK, SN, AggN, Msg),
          true = ecu_musig2:verify_partial(Ctx, Psig, PN, PK, AggN, Msg),
          Psig
        end
       || {SK, SN, PN, PK} <- zip4(SKs, SecNonces, PubNonces, PKs)
      ],

      {ok, Sig} = ecu_musig2:aggregate_partial(Ctx, AggN, Msg, Psigs),
      ecu_eddsa:sign_verify_detached(Sig, Msg, AggPk)
    end
  ).

zip4([A | As], [B | Bs], [C | Cs], [D | Ds]) ->
  [{A, B, C, D} | zip4(As, Bs, Cs, Ds)];
zip4([], [], [], []) ->
  [].
