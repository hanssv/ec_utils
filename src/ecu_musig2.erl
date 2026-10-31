%%%-------------------------------------------------------------------
%%% @doc
%%% MuSig2: Two-Round Schnorr Multi-Signatures.
%%% Supports BIP-327 (secp256k1 / BIP-340) and Ed25519.
%%%
%%% Reference:
%%%   BIP-327: https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_musig2).

-typing([eqwalizer]).

-include("ecu_secp256k1.hrl").

-export([
  key_agg/1, key_agg/2,
  key_agg_pubkey/1, key_agg_pubkey/2,
  key_agg_coeff/2, key_agg_coeff/3,
  nonce_gen/0, nonce_gen/1, nonce_gen/2,
  nonce_agg/1, nonce_agg/2,
  sign_partial/5, sign_partial/6,
  verify_partial/6, verify_partial/7,
  aggregate_partial/4, aggregate_partial/5
]).

-type ciphersuite() :: bip340 | ed25519.
-type pubkey() :: binary().
-type seckey() :: binary() | non_neg_integer().
-type secnonce() :: [binary()] | binary().
-type pubnonce() :: binary() | [binary()].
-type aggnonce() :: binary() | [binary()].
-type partial_sig() :: binary().

-record(key_agg_ctx, {
  ciphersuite :: ciphersuite(),
  agg_pk_point :: {non_neg_integer(), non_neg_integer()} | term(),
  agg_pk_bin :: binary(),
  ordered_pks :: [pubkey()],
  coeffs :: [non_neg_integer()],
  pk2 :: pubkey() | undefined
}).

-opaque key_agg_ctx() :: #key_agg_ctx{}.
-export_type([ciphersuite/0, key_agg_ctx/0, secnonce/0, pubnonce/0, aggnonce/0, partial_sig/0]).

%% Tagged hash tags for BIP-327
-define(TAG_KEYAGG_LIST, <<"KeyAgg list">>).
-define(TAG_KEYAGG_COEFF, <<"KeyAgg coefficient">>).
-define(TAG_NONCECOEF, <<"MuSig/noncecoef">>).

%% ====================================================================
%% API Functions
%% ====================================================================

%% @doc Aggregate public keys using the default 'bip340' (secp256k1) ciphersuite.
-spec key_agg([pubkey()]) -> {ok, key_agg_ctx()} | {error, term()}.
key_agg(Pubkeys) ->
  key_agg(bip340, Pubkeys).

%% @doc Aggregate public keys using the specified ciphersuite ('bip340' or 'ed25519').
-spec key_agg(ciphersuite(), [pubkey()]) -> {ok, key_agg_ctx()} | {error, term()}.
key_agg(bip340, Pubkeys) when is_list(Pubkeys), Pubkeys =/= [] ->
  try
    OrderedNormPks = [norm_secp_pubkey(PK) || PK <- Pubkeys],
    L = crypto:hash(sha256, [tagged_hash_prefix(?TAG_KEYAGG_LIST) | OrderedNormPks]),
    Pk1 = hd(OrderedNormPks),
    Pk2 = find_second_unique_pk(OrderedNormPks, Pk1),
    Coeffs = [compute_secp_coeff(L, PK, Pk2) || PK <- OrderedNormPks],
    Points = [ecu_secp256k1:decompress(PK) || PK <- OrderedNormPks],
    ScaledPoints = [ecu_secp256k1:scalar_mul(C, Pt) || {C, Pt} <- lists:zip(Coeffs, Points)],
    AggPt = lists:foldl(
      fun(Pt, Acc) -> ecu_secp256k1:p_add(Acc, Pt) end, hd(ScaledPoints), tl(ScaledPoints)
    ),
    case AggPt of
      {0, 0} ->
        {error, point_at_infinity};
      _ ->
        CompAggPk = ecu_secp256k1:compress(AggPt),
        Ctx = #key_agg_ctx{
          ciphersuite = bip340,
          agg_pk_point = AggPt,
          agg_pk_bin = CompAggPk,
          ordered_pks = OrderedNormPks,
          coeffs = Coeffs,
          pk2 = Pk2
        },
        {ok, Ctx}
    end
  catch
    _:Reason -> {error, Reason}
  end;
key_agg(ed25519, Pubkeys) when is_list(Pubkeys), Pubkeys =/= [] ->
  try
    lists:foreach(
      fun(PK) ->
        case ecu_ed25519:is_small_order(PK) of
          true -> throw(invalid_pubkey);
          false -> ok
        end
      end,
      Pubkeys
    ),
    SortedPks = lists:sort(Pubkeys),
    AllPks = iolist_to_binary(SortedPks),
    Coeffs = [compute_ed25519_coeff(AllPks, PK) || PK <- SortedPks],
    ScaledPts = [ecu_ed25519:scalar_mul_noclamp(C, PK) || {C, PK} <- lists:zip(Coeffs, SortedPks)],
    AggPt = lists:foldl(fun(Pt, Acc) -> ecu_ed25519:p_add(Acc, Pt) end, hd(ScaledPts), tl(ScaledPts)),
    CompAggPk = ecu_ed25519:compress(AggPt),
    case CompAggPk =:= <<1:256/little>> orelse ecu_ed25519:is_small_order(CompAggPk) of
      true -> throw(invalid_agg_pk);
      false -> ok
    end,
    Ctx = #key_agg_ctx{
      ciphersuite = ed25519,
      agg_pk_point = AggPt,
      agg_pk_bin = CompAggPk,
      ordered_pks = SortedPks,
      coeffs = Coeffs,
      pk2 = undefined
    },
    {ok, Ctx}
  catch
    _:Reason -> {error, Reason}
  end;
key_agg(_, _) ->
  {error, badarg}.

%% @doc Retrieve the aggregated public key from context.
%% For 'bip340', returns the 32-byte BIP-340 x-only public key.
%% For 'ed25519', returns the 32-byte Ed25519 compressed public key.
-spec key_agg_pubkey(key_agg_ctx()) -> pubkey().
key_agg_pubkey(#key_agg_ctx{ciphersuite = bip340, agg_pk_bin = <<_:8, X:32/binary>>}) ->
  X;
key_agg_pubkey(#key_agg_ctx{ciphersuite = ed25519, agg_pk_bin = AggPk}) ->
  AggPk.

%% @doc Retrieve plain (compressed 33-byte for secp256k1) or x-only (32-byte) public key.
-spec key_agg_pubkey(key_agg_ctx(), plain | xonly) -> pubkey().
key_agg_pubkey(#key_agg_ctx{ciphersuite = bip340, agg_pk_bin = CompPk}, plain) ->
  CompPk;
key_agg_pubkey(#key_agg_ctx{ciphersuite = bip340, agg_pk_bin = <<_:8, X:32/binary>>}, xonly) ->
  X;
key_agg_pubkey(#key_agg_ctx{ciphersuite = ed25519, agg_pk_bin = AggPk}, _) ->
  AggPk.

%% @doc Retrieve the key aggregation coefficient for an individual public key.
-spec key_agg_coeff(key_agg_ctx(), pubkey()) -> {ok, non_neg_integer()} | {error, not_found}.
key_agg_coeff(Ctx, PubKey) ->
  key_agg_coeff(Ctx, PubKey, 1).

-spec key_agg_coeff(key_agg_ctx(), pubkey(), pos_integer()) ->
  {ok, non_neg_integer()} | {error, not_found}.
key_agg_coeff(
  #key_agg_ctx{ciphersuite = bip340, ordered_pks = Pks, coeffs = Coeffs}, PubKey, Occurrence
) ->
  NormPK = norm_secp_pubkey(PubKey),
  find_nth_coeff(NormPK, Pks, Coeffs, Occurrence, 1);
key_agg_coeff(
  #key_agg_ctx{ciphersuite = ed25519, ordered_pks = Pks, coeffs = Coeffs}, PubKey, Occurrence
) ->
  find_nth_coeff(PubKey, Pks, Coeffs, Occurrence, 1).

-spec find_nth_coeff(pubkey(), [pubkey()], [non_neg_integer()], pos_integer(), pos_integer()) ->
  {ok, non_neg_integer()} | {error, not_found}.
find_nth_coeff(_PK, [], [], _Target, _Curr) ->
  {error, not_found};
find_nth_coeff(PK, [PK | _], [C | _], Target, Target) ->
  {ok, C};
find_nth_coeff(PK, [PK | RestPks], [_ | RestCs], Target, Curr) ->
  find_nth_coeff(PK, RestPks, RestCs, Target, Curr + 1);
find_nth_coeff(PK, [_ | RestPks], [_ | RestCs], Target, Curr) ->
  find_nth_coeff(PK, RestPks, RestCs, Target, Curr).

%% @doc Generate a fresh secret nonce and public nonce.
-spec nonce_gen() -> {secnonce(), pubnonce()}.
nonce_gen() ->
  nonce_gen(bip340).

-spec nonce_gen(ciphersuite() | seckey()) -> {secnonce(), pubnonce()}.
nonce_gen(bip340) ->
  K1 = rand_scalar_secp(),
  K2 = rand_scalar_secp(),
  R1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(K1)),
  R2 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(K2)),
  {<<K1:256, K2:256>>, <<R1/binary, R2/binary>>};
nonce_gen(ed25519) ->
  N1 = clamp_ed25519(crypto:strong_rand_bytes(32)),
  N2 = clamp_ed25519(crypto:strong_rand_bytes(32)),
  R1 = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(N1)),
  R2 = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(N2)),
  {[N1, N2], [R1, R2]};
nonce_gen(SecKey) when is_binary(SecKey), byte_size(SecKey) =:= 32 ->
  nonce_gen(bip340, SecKey).

-spec nonce_gen(ciphersuite(), seckey()) -> {secnonce(), pubnonce()}.
nonce_gen(bip340, SecKey) when is_binary(SecKey), byte_size(SecKey) =:= 32 ->
  Rand = crypto:strong_rand_bytes(32),
  K1 = rand_scalar_secp_aux(Rand, SecKey, 1),
  K2 = rand_scalar_secp_aux(Rand, SecKey, 2),
  R1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(K1)),
  R2 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(K2)),
  <<SK:256>> = SecKey,
  SignerPub = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK)),
  {<<K1:256, K2:256, SignerPub/binary>>, <<R1/binary, R2/binary>>};
nonce_gen(ed25519, _SecKey) ->
  nonce_gen(ed25519).

%% @doc Aggregate public nonces into an aggregate nonce.
-spec nonce_agg([pubnonce()]) -> {ok, aggnonce()} | {error, term()}.
nonce_agg(PubNonces) ->
  nonce_agg(bip340, PubNonces).

-spec nonce_agg(ciphersuite(), [pubnonce()]) -> {ok, aggnonce()} | {error, term()}.
nonce_agg(bip340, PubNonces) when is_list(PubNonces), PubNonces =/= [] ->
  try
    Pairs = [
      case PN of
        <<R1:33/binary, R2:33/binary>> ->
          {decode_secp_pub_or_infinity(R1), decode_secp_pub_or_infinity(R2)};
        [R1, R2] ->
          {decode_secp_pub_or_infinity(R1), decode_secp_pub_or_infinity(R2)}
      end
     || PN <- PubNonces
    ],
    {R1s, R2s} = lists:unzip(Pairs),
    SumR1 = lists:foldl(fun(Pt, Acc) -> ecu_secp256k1:p_add(Acc, Pt) end, hd(R1s), tl(R1s)),
    SumR2 = lists:foldl(fun(Pt, Acc) -> ecu_secp256k1:p_add(Acc, Pt) end, hd(R2s), tl(R2s)),
    CompR1 = encode_secp_pub_or_infinity(SumR1),
    CompR2 = encode_secp_pub_or_infinity(SumR2),
    {ok, <<CompR1/binary, CompR2/binary>>}
  catch
    _:Reason -> {error, Reason}
  end;
nonce_agg(ed25519, PubNonces) when is_list(PubNonces), PubNonces =/= [] ->
  try
    Pairs = [
      case PN of
        <<R1:32/binary, R2:32/binary>> -> [R1, R2];
        [R1, R2] -> [R1, R2]
      end
     || PN <- PubNonces
    ],
    AccN1 = lists:foldl(
      fun(Pt, Acc) -> ecu_ed25519:p_add(Acc, Pt) end,
      hd([hd(P) || P <- Pairs]),
      tl([hd(P) || P <- Pairs])
    ),
    AccN2 = lists:foldl(
      fun(Pt, Acc) -> ecu_ed25519:p_add(Acc, Pt) end,
      hd([lists:nth(2, P) || P <- Pairs]),
      tl([lists:nth(2, P) || P <- Pairs])
    ),
    {ok, [ecu_ed25519:compress(AccN1), ecu_ed25519:compress(AccN2)]}
  catch
    _:Reason -> {error, Reason}
  end;
nonce_agg(_, _) ->
  {error, badarg}.

%% @doc Compute a partial signature.
-spec sign_partial(key_agg_ctx(), seckey(), secnonce(), aggnonce(), binary()) ->
  {ok, partial_sig()} | {error, term()}.
sign_partial(Ctx, SecKey, SecNonce, AggNonce, Msg) ->
  sign_partial(Ctx, SecKey, SecNonce, AggNonce, Msg, 1).

-spec sign_partial(key_agg_ctx(), seckey(), secnonce(), aggnonce(), binary(), pos_integer()) ->
  {ok, partial_sig()} | {error, term()}.
sign_partial(
  Ctx = #key_agg_ctx{ciphersuite = bip340},
  SecKey,
  SecNonce,
  <<AggR1Bin:33/binary, AggR2Bin:33/binary>>,
  Msg,
  Occurrence
) when is_binary(SecNonce) ->
  try
    {K1, K2, StoredPubOpt} =
      case SecNonce of
        <<K1Int:256, K2Int:256, StoredPub:33/binary>> ->
          {K1Int, K2Int, {ok, StoredPub}};
        <<K1Int:256, K2Int:256>> ->
          {K1Int, K2Int, undefined}
      end,
    N = ecu_secp256k1:n(),
    SK =
      case SecKey of
        <<SKInt:256>> -> SKInt;
        _ when is_integer(SecKey) -> SecKey
      end,
    PubPt = ecu_secp256k1:scalar_mul_base(SK),
    PubKeyComp = ecu_secp256k1:compress(PubPt),
    case StoredPubOpt of
      {ok, ExpectedPub} when ExpectedPub =/= PubKeyComp ->
        {error, public_key_mismatch};
      _ ->
        {ok, KeyCoeff} = key_agg_coeff(Ctx, PubKeyComp, Occurrence),

        AggPt = Ctx#key_agg_ctx.agg_pk_point,
        AggXonly = key_agg_pubkey(Ctx),

        AggR1 = decode_secp_pub_or_infinity(AggR1Bin),
        AggR2 = decode_secp_pub_or_infinity(AggR2Bin),

        B = compute_secp_noncecoef(AggR1Bin, AggR2Bin, AggXonly, Msg),
        FinalNoncePt =
          case ecu_secp256k1:p_add(AggR1, ecu_secp256k1:scalar_mul(B, AggR2)) of
            {0, 0} -> {?X, ?Y};
            Pt -> Pt
          end,

        {_Rx, Ry} = FinalNoncePt,
        KSign =
          case Ry rem 2 of
            0 -> 1;
            1 -> N - 1
          end,

        {_Qx, Qy} = AggPt,
        DSign =
          case is_integer(Qy) andalso (Qy rem 2 =:= 0) of
            true -> 1;
            false -> N - 1
          end,

        RxOnly = <<(element(1, FinalNoncePt)):256>>,
        E = ecu_schnorr:tagged_hash(
          <<"BIP0340/challenge">>, <<RxOnly/binary, AggXonly/binary, Msg/binary>>
        ),
        EInt = binary:decode_unsigned(E),

        K_eff = (KSign * (K1 + (B * K2) rem N)) rem N,
        K_eff_pos = (K_eff + N) rem N,

        D_eff = (DSign * SK) rem N,
        D_eff_pos = (D_eff + N) rem N,

        S_part = (K_eff_pos + (EInt * KeyCoeff rem N) * D_eff_pos) rem N,
        {ok, <<S_part:256>>}
    end
  catch
    _:Reason -> {error, Reason}
  end;
sign_partial(
  Ctx = #key_agg_ctx{ciphersuite = ed25519}, SecKey, [N1s, N2s], [AccN1, AccN2], Msg, Occurrence
) ->
  try
    SecKeyBin =
      case SecKey of
        <<_:256>> -> SecKey;
        _ when is_integer(SecKey) -> <<SecKey:256>>
      end,
    <<Seed0:32/bytes, _/binary>> = crypto:hash(sha512, SecKeyBin),
    Seed = clamp_ed25519(Seed0),
    MyPK = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Seed)),
    {ok, MyExpBin} = key_agg_coeff(Ctx, MyPK, Occurrence),
    AggPK = Ctx#key_agg_ctx.agg_pk_bin,

    Exp1 = <<1:256/little>>,
    Exp2 = ecu_ed25519:scalar_reduce(
      crypto:hash(sha512, <<AggPK/binary, AccN1/binary, AccN2/binary, Msg/binary>>)
    ),

    AggN = ecu_ed25519:compress(
      ecu_ed25519:p_add(
        ecu_ed25519:scalar_mul_noclamp(Exp1, AccN1),
        ecu_ed25519:scalar_mul_noclamp(Exp2, AccN2)
      )
    ),

    Challenge = ecu_ed25519:scalar_reduce(
      crypto:hash(sha512, <<AggN/binary, AggPK/binary, Msg/binary>>)
    ),
    Ns = ecu_ed25519:s_add(ecu_ed25519:s_mul(Exp1, N1s), ecu_ed25519:s_mul(Exp2, N2s)),
    S = ecu_ed25519:s_add(
      ecu_ed25519:s_mul(Challenge, ecu_ed25519:s_mul(<<MyExpBin:256/little>>, Seed)), Ns
    ),
    {ok, S}
  catch
    _:Reason -> {error, Reason}
  end;
sign_partial(_, _, _, _, _, _) ->
  {error, badarg}.

%% @doc Verify a partial signature.
-spec verify_partial(key_agg_ctx(), partial_sig(), pubnonce(), pubkey(), aggnonce(), binary()) ->
  boolean().
verify_partial(Ctx, PartSig, PubNonce, SignerPk, AggNonce, Msg) ->
  verify_partial(Ctx, PartSig, PubNonce, SignerPk, AggNonce, Msg, 1).

-spec verify_partial(
  key_agg_ctx(), partial_sig(), pubnonce(), pubkey(), aggnonce(), binary(), pos_integer()
) -> boolean().
verify_partial(
  Ctx = #key_agg_ctx{ciphersuite = bip340},
  <<S:256>>,
  <<R1Bin:33/binary, R2Bin:33/binary>>,
  SignerPk,
  <<AggR1Bin:33/binary, AggR2Bin:33/binary>>,
  Msg,
  Occurrence
) ->
  try
    N = ecu_secp256k1:n(),
    if
      S >= N ->
        false;
      true ->
        NormPK = norm_secp_pubkey(SignerPk),
        case key_agg_coeff(Ctx, NormPK, Occurrence) of
          {ok, KeyCoeff} ->
            AggPt = Ctx#key_agg_ctx.agg_pk_point,
            AggXonly = key_agg_pubkey(Ctx),

            AggR1 = decode_secp_pub_or_infinity(AggR1Bin),
            AggR2 = decode_secp_pub_or_infinity(AggR2Bin),
            B = compute_secp_noncecoef(AggR1Bin, AggR2Bin, AggXonly, Msg),
            FinalNoncePt =
              case ecu_secp256k1:p_add(AggR1, ecu_secp256k1:scalar_mul(B, AggR2)) of
                {0, 0} -> {?X, ?Y};
                Pt -> Pt
              end,

            R1 = ecu_secp256k1:decompress(R1Bin),
            R2 = ecu_secp256k1:decompress(R2Bin),
            Reff0 = ecu_secp256k1:p_add(R1, ecu_secp256k1:scalar_mul(B, R2)),
            {_, Ry} = FinalNoncePt,
            Reff =
              case Ry rem 2 of
                0 -> Reff0;
                1 -> ecu_secp256k1:p_neg(Reff0)
              end,

            RxOnly = <<(element(1, FinalNoncePt)):256>>,
            E = ecu_schnorr:tagged_hash(
              <<"BIP0340/challenge">>, <<RxOnly/binary, AggXonly/binary, Msg/binary>>
            ),
            EInt = binary:decode_unsigned(E),

            SignerPt = ecu_secp256k1:decompress(NormPK),
            {_, Qy} = AggPt,
            Peff =
              case is_integer(Qy) andalso (Qy rem 2 =:= 0) of
                true -> SignerPt;
                false -> ecu_secp256k1:p_neg(SignerPt)
              end,

            SG = ecu_secp256k1:scalar_mul_base(S),
            Rhs = ecu_secp256k1:p_add(Reff, ecu_secp256k1:scalar_mul((EInt * KeyCoeff) rem N, Peff)),
            SG =:= Rhs;
          _ ->
            false
        end
    end
  catch
    _:_ -> false
  end;
verify_partial(
  Ctx = #key_agg_ctx{ciphersuite = ed25519}, PartSig, [R1, R2], SignerPk, [AccN1, AccN2], Msg, Occurrence
) ->
  try
    case key_agg_coeff(Ctx, SignerPk, Occurrence) of
      {ok, KeyExpBin} ->
        AggPK = Ctx#key_agg_ctx.agg_pk_bin,
        Exp1 = <<1:256/little>>,
        Exp2 = ecu_ed25519:scalar_reduce(
          crypto:hash(sha512, <<AggPK/binary, AccN1/binary, AccN2/binary, Msg/binary>>)
        ),

        AggN = ecu_ed25519:compress(
          ecu_ed25519:p_add(
            ecu_ed25519:scalar_mul_noclamp(Exp1, AccN1),
            ecu_ed25519:scalar_mul_noclamp(Exp2, AccN2)
          )
        ),

        Challenge = ecu_ed25519:scalar_reduce(
          crypto:hash(sha512, <<AggN/binary, AggPK/binary, Msg/binary>>)
        ),
        Reff = ecu_ed25519:p_add(
          ecu_ed25519:scalar_mul_noclamp(Exp1, R1),
          ecu_ed25519:scalar_mul_noclamp(Exp2, R2)
        ),
        Lhs = ecu_ed25519:scalar_mul_base_noclamp(PartSig),
        Rhs = ecu_ed25519:p_add(
          Reff,
          ecu_ed25519:scalar_mul_noclamp(
            ecu_ed25519:s_mul(Challenge, <<KeyExpBin:256/little>>),
            SignerPk
          )
        ),
        ecu_ed25519:compress(Lhs) =:= ecu_ed25519:compress(Rhs);
      _ ->
        false
    end
  catch
    _:_ -> false
  end;
verify_partial(_, _, _, _, _, _, _) ->
  false.

%% @doc Aggregate partial signatures into a final Schnorr signature.
-spec aggregate_partial(key_agg_ctx(), aggnonce(), binary(), [partial_sig()]) ->
  {ok, binary()} | {error, term()}.
aggregate_partial(Ctx, AggNonce, Msg, PartSigs) ->
  aggregate_partial(Ctx, AggNonce, Msg, PartSigs, 0).

-spec aggregate_partial(key_agg_ctx(), aggnonce(), binary(), [partial_sig()], non_neg_integer()) ->
  {ok, binary()} | {error, term()}.
aggregate_partial(
  #key_agg_ctx{ciphersuite = bip340, agg_pk_point = AggPt, agg_pk_bin = AggPkComp},
  <<AggR1Bin:33/binary, AggR2Bin:33/binary>>,
  Msg,
  PartSigs,
  TweakAcc
) ->
  try
    N = ecu_secp256k1:n(),
    <<_:8, AggXonly:32/binary>> = AggPkComp,
    AggR1 = decode_secp_pub_or_infinity(AggR1Bin),
    AggR2 = decode_secp_pub_or_infinity(AggR2Bin),
    B = compute_secp_noncecoef(AggR1Bin, AggR2Bin, AggXonly, Msg),
    FinalNoncePt =
      case ecu_secp256k1:p_add(AggR1, ecu_secp256k1:scalar_mul(B, AggR2)) of
        {0, 0} -> {?X, ?Y};
        Pt -> Pt
      end,

    RxOnly = <<(element(1, FinalNoncePt)):256>>,
    E = ecu_schnorr:tagged_hash(<<"BIP0340/challenge">>, <<RxOnly/binary, AggXonly/binary, Msg/binary>>),
    EInt = binary:decode_unsigned(E),

    SumS0 = lists:foldl(fun(<<S:256>>, Acc) -> (Acc + S) rem N end, 0, PartSigs),
    {_, Qy} = AggPt,
    TweakTerm =
      case is_integer(Qy) andalso (Qy rem 2 =:= 0) of
        true -> (EInt * (TweakAcc rem N)) rem N;
        false -> (N - ((EInt * (TweakAcc rem N)) rem N)) rem N
      end,

    FinalS = (SumS0 + TweakTerm) rem N,
    Sig = <<RxOnly/binary, FinalS:256>>,
    case ecu_schnorr:verify(Sig, Msg, AggXonly) of
      true -> {ok, Sig};
      false -> {error, invalid_signature}
    end
  catch
    _:Reason -> {error, Reason}
  end;
aggregate_partial(
  #key_agg_ctx{ciphersuite = ed25519, agg_pk_bin = AggPK}, [AccN1, AccN2], Msg, PartSigs, _TweakAcc
) ->
  try
    Exp1 = <<1:256/little>>,
    Exp2 = ecu_ed25519:scalar_reduce(
      crypto:hash(sha512, <<AggPK/binary, AccN1/binary, AccN2/binary, Msg/binary>>)
    ),
    AggN = ecu_ed25519:compress(
      ecu_ed25519:p_add(
        ecu_ed25519:scalar_mul_noclamp(Exp1, AccN1),
        ecu_ed25519:scalar_mul_noclamp(Exp2, AccN2)
      )
    ),
    TotalS = lists:foldl(fun(S, Acc) -> ecu_ed25519:s_add(Acc, S) end, <<0:256>>, PartSigs),
    Sig = <<AggN:32/bytes, TotalS:32/bytes>>,
    case ecu_eddsa:sign_verify_detached(Sig, Msg, AggPK) of
      true -> {ok, Sig};
      false -> {error, invalid_signature}
    end
  catch
    _:Reason -> {error, Reason}
  end;
aggregate_partial(_, _, _, _, _) ->
  {error, badarg}.

%% ====================================================================
%% Internal Helpers
%% ====================================================================

-spec norm_secp_pubkey(pubkey()) -> pubkey().
norm_secp_pubkey(<<_:8, _:32/binary>> = Comp) ->
  Comp;
norm_secp_pubkey(<<X:32/binary>>) ->
  case ecu_schnorr:lift_x(X) of
    {ok, Pt} -> ecu_secp256k1:compress(Pt);
    error -> error({bad_xonly_pubkey, X})
  end.

-spec find_second_unique_pk([pubkey()], pubkey()) -> pubkey() | undefined.
find_second_unique_pk([], _Pk1) ->
  undefined;
find_second_unique_pk([PK | Rest], Pk1) ->
  if
    PK =/= Pk1 -> PK;
    true -> find_second_unique_pk(Rest, Pk1)
  end.

-spec compute_secp_coeff(binary(), pubkey(), pubkey() | undefined) -> non_neg_integer().
compute_secp_coeff(_L, Pk2, Pk2) when Pk2 =/= undefined ->
  1;
compute_secp_coeff(L, PK, _Pk2) ->
  Hash = crypto:hash(sha256, [tagged_hash_prefix(?TAG_KEYAGG_COEFF), L, PK]),
  binary:decode_unsigned(Hash) rem ecu_secp256k1:n().

-spec compute_secp_noncecoef(binary(), binary(), binary(), binary()) -> non_neg_integer().
compute_secp_noncecoef(AggR1, AggR2, AggXonly, Msg) ->
  Hash = crypto:hash(sha256, [tagged_hash_prefix(?TAG_NONCECOEF), AggR1, AggR2, AggXonly, Msg]),
  binary:decode_unsigned(Hash) rem ecu_secp256k1:n().

-spec compute_ed25519_coeff(binary(), pubkey()) -> non_neg_integer().
compute_ed25519_coeff(AllPks, PK) ->
  Hash = crypto:hash(sha512, <<AllPks/binary, PK/binary>>),
  <<Val:256/little>> = ecu_ed25519:scalar_reduce(Hash),
  Val.

-spec rand_scalar_secp() -> non_neg_integer().
rand_scalar_secp() ->
  N = ecu_secp256k1:n(),
  Bytes = crypto:strong_rand_bytes(32),
  binary:decode_unsigned(Bytes) rem (N - 1) + 1.

-spec rand_scalar_secp_aux(binary(), seckey(), non_neg_integer()) -> non_neg_integer().
rand_scalar_secp_aux(Rand, SecKey, Index) ->
  N = ecu_secp256k1:n(),
  TagAux = crypto:hash(sha256, [tagged_hash_prefix(<<"MuSig/aux">>), Rand, SecKey, <<Index:8>>]),
  binary:decode_unsigned(TagAux) rem (N - 1) + 1.

-spec clamp_ed25519(binary()) -> binary().
clamp_ed25519(<<B0:8, B1_30:30/bytes, B31:8>>) ->
  <<(B0 band 16#f8):8, B1_30/bytes, ((B31 band 16#7f) bor 16#40):8>>.

-spec tagged_hash_prefix(binary()) -> binary().
tagged_hash_prefix(Tag) ->
  TagHash = crypto:hash(sha256, Tag),
  <<TagHash/binary, TagHash/binary>>.

-spec encode_secp_pub_or_infinity({non_neg_integer(), non_neg_integer()}) -> binary().
encode_secp_pub_or_infinity({0, 0}) ->
  binary:copy(<<0>>, 33);
encode_secp_pub_or_infinity(Pt) ->
  ecu_secp256k1:compress(Pt).

-spec decode_secp_pub_or_infinity(binary()) -> {non_neg_integer(), non_neg_integer()}.
decode_secp_pub_or_infinity(<<0:264>>) ->
  {0, 0};
decode_secp_pub_or_infinity(Bin) ->
  ecu_secp256k1:decompress(Bin).
