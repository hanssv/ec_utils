%%%-------------------------------------------------------------------
%%% @doc
%%% IETF BLS Signatures and Non-Interactive Aggregation for BLS12-381.
%%%
%%% Implements:
%%%   - `min_pk`: Minimal Public Key Size
%%%       PK in G1 (48 bytes compressed), Signature in G2 (96 bytes compressed)
%%%       Default DST: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'
%%%   - `min_sig`: Minimal Signature Size
%%%       PK in G2 (96 bytes compressed), Signature in G1 (48 bytes compressed)
%%%       Default DST: `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_'
%%%   - KeyGen (v4 / EIP-2333 and v5 per draft-irtf-cfrg-bls-signature)
%%%   - Non-interactive signature and public key aggregation
%%%   - Fast aggregate verification (single message, 2 pairings)
%%%   - Core aggregate verification (distinct messages, N+1 pairings)
%%%
%%% Reference:
%%%   - draft-irtf-cfrg-bls-signature:
%%%     https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05
%%%   - EIP-2333: https://eips.ethereum.org/EIPS/eip-2333
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_sig).

-typing([eqwalizer]).

-include("ecu_bls12_381.hrl").

-define(BLS, ecu_bls12_381).
-define(H2C, ecu_bls12_381_h2c).

-type privkey() :: <<_:256>> | pos_integer().

-type min_pk_pubkey() :: ?BLS:g1_compressed() | ?BLS:g1_affine().
-type min_pk_sig() :: ?BLS:g2_compressed() | ?BLS:g2_affine().

-type min_sig_pubkey() :: ?BLS:g2_compressed() | ?BLS:g2_affine().
-type min_sig_sig() :: ?BLS:g1_compressed() | ?BLS:g1_affine().

-type scheme() :: min_pk | min_sig.
-type dst() :: binary().
-type keygen_opt() ::
  {salt, binary()}
  | {info, binary()}
  | {version, v4 | v5}.

-export_type([
  privkey/0,
  min_pk_pubkey/0,
  min_pk_sig/0,
  min_sig_pubkey/0,
  min_sig_sig/0,
  scheme/0,
  dst/0,
  keygen_opt/0
]).

%% Default DSTs
-export([
  min_pk_dst_basic/0,
  min_pk_dst_aug/0,
  min_pk_dst_pop/0,
  min_sig_dst_basic/0,
  min_sig_dst_aug/0,
  min_sig_dst_pop/0
]).

%% Key generation & derivation
-export([
  keygen/1,
  keygen/2,
  min_pk_keygen/1,
  min_pk_keygen/2,
  min_sig_keygen/1,
  min_sig_keygen/2,
  sk_to_min_pk/1,
  sk_to_min_sig/1
]).

%% min_pk Operations
-export([
  min_pk_sign/2,
  min_pk_sign/3,
  min_pk_verify/3,
  min_pk_verify/4,
  min_pk_aggregate_signatures/1,
  min_pk_aggregate_public_keys/1,
  min_pk_fast_aggregate_verify/3,
  min_pk_fast_aggregate_verify/4,
  min_pk_aggregate_verify/2,
  min_pk_aggregate_verify/3
]).

%% min_sig Operations
-export([
  min_sig_sign/2,
  min_sig_sign/3,
  min_sig_verify/3,
  min_sig_verify/4,
  min_sig_aggregate_signatures/1,
  min_sig_aggregate_public_keys/1,
  min_sig_fast_aggregate_verify/3,
  min_sig_fast_aggregate_verify/4,
  min_sig_aggregate_verify/2,
  min_sig_aggregate_verify/3
]).

%% Generic Scheme API
-export([
  sign/3,
  sign/4,
  verify/4,
  verify/5,
  aggregate_signatures/2,
  aggregate_public_keys/2
]).

%%%-------------------------------------------------------------------
%%% Default DSTs per draft-irtf-cfrg-bls-signature Section 4
%%%-------------------------------------------------------------------

-spec min_pk_dst_basic() -> dst().
min_pk_dst_basic() -> <<"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_">>.

-spec min_pk_dst_aug() -> dst().
min_pk_dst_aug() -> <<"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_">>.

-spec min_pk_dst_pop() -> dst().
min_pk_dst_pop() -> <<"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_">>.

-spec min_sig_dst_basic() -> dst().
min_sig_dst_basic() -> <<"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_">>.

-spec min_sig_dst_aug() -> dst().
min_sig_dst_aug() -> <<"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_">>.

-spec min_sig_dst_pop() -> dst().
min_sig_dst_pop() -> <<"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_">>.

%%%-------------------------------------------------------------------
%%% Key Generation & Derivation
%%%-------------------------------------------------------------------

-spec keygen(binary()) -> {ok, <<_:256>>} | {error, term()}.
keygen(IKM) ->
  keygen(IKM, []).

-spec keygen(binary(), [keygen_opt()]) -> {ok, <<_:256>>} | {error, term()}.
keygen(IKM, _Opts) when not is_binary(IKM) orelse byte_size(IKM) < 32 ->
  {error, ikm_too_short};
keygen(IKM, Opts) ->
  Version = proplists:get_value(version, Opts, v4),
  Info = proplists:get_value(info, Opts, <<>>),
  InitialSalt =
    case proplists:get_value(salt, Opts) of
      undefined ->
        SaltPrime = <<"BLS-SIG-KEYGEN-SALT-">>,
        case Version of
          v4 -> ecu_compat:hash(sha256, SaltPrime);
          v5 -> SaltPrime
        end;
      ExplicitSalt when is_binary(ExplicitSalt) ->
        case Version of
          v4 -> ecu_compat:hash(sha256, ExplicitSalt);
          v5 -> ExplicitSalt
        end
    end,
  keygen_loop(IKM, Info, InitialSalt).

-spec keygen_loop(binary(), binary(), binary()) -> {ok, <<_:256>>}.
keygen_loop(IKM, Info, Salt) ->
  L = 48,
  PRK = ecu_compat:mac(hmac, sha256, Salt, <<IKM/binary, 0:8>>),
  InfoBytes = <<Info/binary, L:16/big>>,
  T1 = ecu_compat:mac(hmac, sha256, PRK, <<InfoBytes/binary, 1:8>>),
  T2 = ecu_compat:mac(hmac, sha256, PRK, <<T1/binary, InfoBytes/binary, 2:8>>),
  OKM = binary:part(<<T1/binary, T2/binary>>, 0, L),
  SK_int = binary:decode_unsigned(OKM) rem ?BLS12_381_R,
  case SK_int of
    0 ->
      NextSalt = ecu_compat:hash(sha256, Salt),
      keygen_loop(IKM, Info, NextSalt);
    _ ->
      {ok, <<SK_int:256/big>>}
  end.

-spec min_pk_keygen(binary()) -> {ok, {?BLS:g1_compressed(), <<_:256>>}} | {error, term()}.
min_pk_keygen(IKM) ->
  min_pk_keygen(IKM, []).

-spec min_pk_keygen(binary(), [keygen_opt()]) ->
  {ok, {?BLS:g1_compressed(), <<_:256>>}} | {error, term()}.
min_pk_keygen(IKM, Opts) ->
  case keygen(IKM, Opts) of
    {ok, SK} ->
      PK = sk_to_min_pk(SK),
      {ok, {PK, SK}};
    {error, Reason} ->
      {error, Reason}
  end.

-spec min_sig_keygen(binary()) -> {ok, {?BLS:g2_compressed(), <<_:256>>}} | {error, term()}.
min_sig_keygen(IKM) ->
  min_sig_keygen(IKM, []).

-spec min_sig_keygen(binary(), [keygen_opt()]) ->
  {ok, {?BLS:g2_compressed(), <<_:256>>}} | {error, term()}.
min_sig_keygen(IKM, Opts) ->
  case keygen(IKM, Opts) of
    {ok, SK} ->
      PK = sk_to_min_sig(SK),
      {ok, {PK, SK}};
    {error, Reason} ->
      {error, Reason}
  end.

-spec sk_to_min_pk(privkey()) -> ?BLS:g1_compressed().
sk_to_min_pk(SK) ->
  SK_int = to_scalar_int(SK),
  PK_point = ?BLS:g1_scalar_mul_base(SK_int),
  ?BLS:g1_compress(PK_point).

-spec sk_to_min_sig(privkey()) -> ?BLS:g2_compressed().
sk_to_min_sig(SK) ->
  SK_int = to_scalar_int(SK),
  PK_point = ?BLS:g2_scalar_mul_base(SK_int),
  ?BLS:g2_compress(PK_point).

%%%-------------------------------------------------------------------
%%% min_pk Operations (PK in G1, Sig in G2)
%%%-------------------------------------------------------------------

-spec min_pk_sign(privkey(), binary()) -> ?BLS:g2_compressed().
min_pk_sign(SK, Msg) ->
  min_pk_sign(SK, Msg, min_pk_dst_basic()).

-spec min_pk_sign(privkey(), binary(), dst()) -> ?BLS:g2_compressed().
min_pk_sign(SK, Msg, DST) when is_binary(Msg), is_binary(DST) ->
  SK_int = to_scalar_int(SK),
  Q = ?H2C:hash_to_curve_g2(Msg, DST),
  SigPt = ?BLS:g2_scalar_mul(Q, SK_int),
  ?BLS:g2_compress(SigPt).

-spec min_pk_verify(min_pk_pubkey(), binary(), min_pk_sig()) -> boolean().
min_pk_verify(PK, Msg, Sig) ->
  min_pk_verify(PK, Msg, Sig, min_pk_dst_basic()).

-spec min_pk_verify(min_pk_pubkey(), binary(), min_pk_sig(), dst()) -> boolean().
min_pk_verify(PK, Msg, Sig, DST) when is_binary(Msg), is_binary(DST) ->
  case {to_g1_point(PK), to_g2_point(Sig)} of
    {{ok, PKPt}, {ok, SigPt}} ->
      case is_valid_pk_g1(PKPt) andalso is_valid_sig_g2(SigPt) of
        true ->
          Q = ?H2C:hash_to_curve_g2(Msg, DST),
          NegG1 = ?BLS:g1_neg(?BLS:g1_generator()),
          ?BLS:pairing_check([
            {PKPt, Q},
            {NegG1, SigPt}
          ]);
        false ->
          false
      end;
    _ ->
      false
  end.

-spec min_pk_aggregate_signatures([min_pk_sig()]) ->
  {ok, ?BLS:g2_compressed()} | {error, term()}.
min_pk_aggregate_signatures([]) ->
  {error, empty_signatures};
min_pk_aggregate_signatures(Sigs) ->
  aggregate_g2_points(Sigs, ?BLS:g2_infinity()).

-spec min_pk_aggregate_public_keys([min_pk_pubkey()]) ->
  {ok, ?BLS:g1_compressed()} | {error, term()}.
min_pk_aggregate_public_keys([]) ->
  {error, empty_public_keys};
min_pk_aggregate_public_keys(PKs) ->
  aggregate_g1_points(PKs, ?BLS:g1_infinity()).

-spec min_pk_fast_aggregate_verify([min_pk_pubkey()], binary(), min_pk_sig()) -> boolean().
min_pk_fast_aggregate_verify(PKs, Msg, SigAgg) ->
  min_pk_fast_aggregate_verify(PKs, Msg, SigAgg, min_pk_dst_basic()).

-spec min_pk_fast_aggregate_verify([min_pk_pubkey()], binary(), min_pk_sig(), dst()) ->
  boolean().
min_pk_fast_aggregate_verify([], _Msg, _SigAgg, _DST) ->
  false;
min_pk_fast_aggregate_verify(PKs, Msg, SigAgg, DST) when is_binary(Msg), is_binary(DST) ->
  case min_pk_aggregate_public_keys(PKs) of
    {ok, AggPK} ->
      min_pk_verify(AggPK, Msg, SigAgg, DST);
    {error, _} ->
      false
  end.

-spec min_pk_aggregate_verify([{min_pk_pubkey(), binary()}], min_pk_sig()) -> boolean().
min_pk_aggregate_verify(Pairs, SigAgg) ->
  min_pk_aggregate_verify(Pairs, SigAgg, min_pk_dst_basic()).

-spec min_pk_aggregate_verify([{min_pk_pubkey(), binary()}], min_pk_sig(), dst()) ->
  boolean().
min_pk_aggregate_verify([], _SigAgg, _DST) ->
  false;
min_pk_aggregate_verify(Pairs, SigAgg, DST) when is_binary(DST) ->
  case to_g2_point(SigAgg) of
    {ok, SigPt} ->
      case is_valid_sig_g2(SigPt) of
        true ->
          min_pk_aggregate_verify_pairs(Pairs, DST, SigPt);
        false ->
          false
      end;
    _ ->
      false
  end.

-spec min_pk_aggregate_verify_pairs(
  [{min_pk_pubkey(), binary()}],
  dst(),
  ?BLS:g2_affine()
) -> boolean().
min_pk_aggregate_verify_pairs(Pairs, DST, SigPt) ->
  PairList =
    lists:foldl(
      fun
        ({PK, Msg}, Acc) when is_list(Acc), is_binary(Msg) ->
          case to_g1_point(PK) of
            {ok, PKPt} ->
              case is_valid_pk_g1(PKPt) of
                true ->
                  Q = ?H2C:hash_to_curve_g2(Msg, DST),
                  [{PKPt, Q} | Acc];
                false ->
                  error
              end;
            _ ->
              error
          end;
        (_, _Acc) ->
          error
      end,
      [],
      Pairs
    ),
  case PairList of
    error ->
      false;
    PairsAcc when is_list(PairsAcc) ->
      NegG1 = ?BLS:g1_neg(?BLS:g1_generator()),
      ?BLS:pairing_check([{NegG1, SigPt} | PairsAcc])
  end.

%%%-------------------------------------------------------------------
%%% min_sig Operations (PK in G2, Sig in G1)
%%%-------------------------------------------------------------------

-spec min_sig_sign(privkey(), binary()) -> ?BLS:g1_compressed().
min_sig_sign(SK, Msg) ->
  min_sig_sign(SK, Msg, min_sig_dst_basic()).

-spec min_sig_sign(privkey(), binary(), dst()) -> ?BLS:g1_compressed().
min_sig_sign(SK, Msg, DST) when is_binary(Msg), is_binary(DST) ->
  SK_int = to_scalar_int(SK),
  P = ?H2C:hash_to_curve_g1(Msg, DST),
  SigPt = ?BLS:g1_scalar_mul(P, SK_int),
  ?BLS:g1_compress(SigPt).

-spec min_sig_verify(min_sig_pubkey(), binary(), min_sig_sig()) -> boolean().
min_sig_verify(PK, Msg, Sig) ->
  min_sig_verify(PK, Msg, Sig, min_sig_dst_basic()).

-spec min_sig_verify(min_sig_pubkey(), binary(), min_sig_sig(), dst()) -> boolean().
min_sig_verify(PK, Msg, Sig, DST) when is_binary(Msg), is_binary(DST) ->
  case {to_g2_point(PK), to_g1_point(Sig)} of
    {{ok, PKPt}, {ok, SigPt}} ->
      case is_valid_pk_g2(PKPt) andalso is_valid_sig_g1(SigPt) of
        true ->
          P = ?H2C:hash_to_curve_g1(Msg, DST),
          NegG2 = ?BLS:g2_neg(?BLS:g2_generator()),
          ?BLS:pairing_check([
            {SigPt, NegG2},
            {P, PKPt}
          ]);
        false ->
          false
      end;
    _ ->
      false
  end.

-spec min_sig_aggregate_signatures([min_sig_sig()]) ->
  {ok, ?BLS:g1_compressed()} | {error, term()}.
min_sig_aggregate_signatures([]) ->
  {error, empty_signatures};
min_sig_aggregate_signatures(Sigs) ->
  aggregate_g1_points(Sigs, ?BLS:g1_infinity()).

-spec min_sig_aggregate_public_keys([min_sig_pubkey()]) ->
  {ok, ?BLS:g2_compressed()} | {error, term()}.
min_sig_aggregate_public_keys([]) ->
  {error, empty_public_keys};
min_sig_aggregate_public_keys(PKs) ->
  aggregate_g2_points(PKs, ?BLS:g2_infinity()).

-spec min_sig_fast_aggregate_verify([min_sig_pubkey()], binary(), min_sig_sig()) -> boolean().
min_sig_fast_aggregate_verify(PKs, Msg, SigAgg) ->
  min_sig_fast_aggregate_verify(PKs, Msg, SigAgg, min_sig_dst_basic()).

-spec min_sig_fast_aggregate_verify([min_sig_pubkey()], binary(), min_sig_sig(), dst()) ->
  boolean().
min_sig_fast_aggregate_verify([], _Msg, _SigAgg, _DST) ->
  false;
min_sig_fast_aggregate_verify(PKs, Msg, SigAgg, DST) when is_binary(Msg), is_binary(DST) ->
  case min_sig_aggregate_public_keys(PKs) of
    {ok, AggPK} ->
      min_sig_verify(AggPK, Msg, SigAgg, DST);
    {error, _} ->
      false
  end.

-spec min_sig_aggregate_verify([{min_sig_pubkey(), binary()}], min_sig_sig()) -> boolean().
min_sig_aggregate_verify(Pairs, SigAgg) ->
  min_sig_aggregate_verify(Pairs, SigAgg, min_sig_dst_basic()).

-spec min_sig_aggregate_verify([{min_sig_pubkey(), binary()}], min_sig_sig(), dst()) ->
  boolean().
min_sig_aggregate_verify([], _SigAgg, _DST) ->
  false;
min_sig_aggregate_verify(Pairs, SigAgg, DST) when is_binary(DST) ->
  case to_g1_point(SigAgg) of
    {ok, SigPt} ->
      case is_valid_sig_g1(SigPt) of
        true ->
          min_sig_aggregate_verify_pairs(Pairs, DST, SigPt);
        false ->
          false
      end;
    _ ->
      false
  end.

-spec min_sig_aggregate_verify_pairs(
  [{min_sig_pubkey(), binary()}],
  dst(),
  ?BLS:g1_affine()
) -> boolean().
min_sig_aggregate_verify_pairs(Pairs, DST, SigPt) ->
  PairList =
    lists:foldl(
      fun
        ({PK, Msg}, Acc) when is_list(Acc), is_binary(Msg) ->
          case to_g2_point(PK) of
            {ok, PKPt} ->
              case is_valid_pk_g2(PKPt) of
                true ->
                  P = ?H2C:hash_to_curve_g1(Msg, DST),
                  [{P, PKPt} | Acc];
                false ->
                  error
              end;
            _ ->
              error
          end;
        (_, _Acc) ->
          error
      end,
      [],
      Pairs
    ),
  case PairList of
    error ->
      false;
    PairsAcc when is_list(PairsAcc) ->
      NegG2 = ?BLS:g2_neg(?BLS:g2_generator()),
      ?BLS:pairing_check([{SigPt, NegG2} | PairsAcc])
  end.

%%%-------------------------------------------------------------------
%%% Generic Scheme API
%%%-------------------------------------------------------------------

-spec sign
  (min_pk, privkey(), binary()) -> ?BLS:g2_compressed();
  (min_sig, privkey(), binary()) -> ?BLS:g1_compressed().
sign(min_pk, SK, Msg) ->
  min_pk_sign(SK, Msg);
sign(min_sig, SK, Msg) ->
  min_sig_sign(SK, Msg).

-spec sign
  (min_pk, privkey(), binary(), dst()) -> ?BLS:g2_compressed();
  (min_sig, privkey(), binary(), dst()) -> ?BLS:g1_compressed().
sign(min_pk, SK, Msg, DST) ->
  min_pk_sign(SK, Msg, DST);
sign(min_sig, SK, Msg, DST) ->
  min_sig_sign(SK, Msg, DST).

-spec verify
  (min_pk, min_pk_pubkey(), binary(), min_pk_sig()) -> boolean();
  (min_sig, min_sig_pubkey(), binary(), min_sig_sig()) -> boolean().
verify(min_pk, PK, Msg, Sig) ->
  min_pk_verify(PK, Msg, Sig);
verify(min_sig, PK, Msg, Sig) ->
  min_sig_verify(PK, Msg, Sig).

-spec verify
  (min_pk, min_pk_pubkey(), binary(), min_pk_sig(), dst()) -> boolean();
  (min_sig, min_sig_pubkey(), binary(), min_sig_sig(), dst()) -> boolean().
verify(min_pk, PK, Msg, Sig, DST) ->
  min_pk_verify(PK, Msg, Sig, DST);
verify(min_sig, PK, Msg, Sig, DST) ->
  min_sig_verify(PK, Msg, Sig, DST).

-spec aggregate_signatures
  (min_pk, [min_pk_sig()]) ->
    {ok, ?BLS:g2_compressed()} | {error, term()};
  (min_sig, [min_sig_sig()]) ->
    {ok, ?BLS:g1_compressed()} | {error, term()}.
aggregate_signatures(min_pk, Sigs) ->
  min_pk_aggregate_signatures(Sigs);
aggregate_signatures(min_sig, Sigs) ->
  min_sig_aggregate_signatures(Sigs).

-spec aggregate_public_keys
  (min_pk, [min_pk_pubkey()]) ->
    {ok, ?BLS:g1_compressed()} | {error, term()};
  (min_sig, [min_sig_pubkey()]) ->
    {ok, ?BLS:g2_compressed()} | {error, term()}.
aggregate_public_keys(min_pk, PKs) ->
  min_pk_aggregate_public_keys(PKs);
aggregate_public_keys(min_sig, PKs) ->
  min_sig_aggregate_public_keys(PKs).

%%%-------------------------------------------------------------------
%%% Internal Helpers
%%%-------------------------------------------------------------------

-spec to_scalar_int(privkey()) -> pos_integer().
to_scalar_int(SK) when is_binary(SK) ->
  Val = binary:decode_unsigned(SK),
  case Val > 0 andalso Val < ?BLS12_381_R of
    true -> Val;
    false -> error({invalid_scalar, SK})
  end;
to_scalar_int(SK) when is_integer(SK), SK > 0, SK < ?BLS12_381_R ->
  SK;
to_scalar_int(SK) ->
  error({invalid_scalar, SK}).

-spec to_g1_point(?BLS:g1_compressed() | ?BLS:g1_affine()) ->
  {ok, ?BLS:g1_affine()} | {error, term()}.
to_g1_point(Bin) when is_binary(Bin), byte_size(Bin) =:= 48 ->
  ?BLS:g1_decompress(Bin);
to_g1_point({X, Y}) when is_integer(X), is_integer(Y) ->
  Pt = {X, Y},
  case ?BLS:g1_on_curve(Pt) of
    true -> {ok, Pt};
    false -> {error, not_on_curve}
  end;
to_g1_point(infinity) ->
  {ok, infinity};
to_g1_point(_) ->
  {error, invalid_g1_point}.

-spec to_g2_point(?BLS:g2_compressed() | ?BLS:g2_affine()) ->
  {ok, ?BLS:g2_affine()} | {error, term()}.
to_g2_point(Bin) when is_binary(Bin), byte_size(Bin) =:= 96 ->
  ?BLS:g2_decompress(Bin);
to_g2_point({X, Y}) when is_tuple(X), is_tuple(Y) ->
  Pt = {X, Y},
  case ?BLS:g2_on_curve(Pt) of
    true -> {ok, Pt};
    false -> {error, not_on_curve}
  end;
to_g2_point(infinity) ->
  {ok, infinity};
to_g2_point(_) ->
  {error, invalid_g2_point}.

-spec is_valid_pk_g1(?BLS:g1_affine()) -> boolean().
is_valid_pk_g1(infinity) ->
  false;
is_valid_pk_g1(Pt) ->
  ?BLS:g1_is_in_subgroup(Pt).

-spec is_valid_pk_g2(?BLS:g2_affine()) -> boolean().
is_valid_pk_g2(infinity) ->
  false;
is_valid_pk_g2(Pt) ->
  ?BLS:g2_is_in_subgroup(Pt).

-spec is_valid_sig_g1(?BLS:g1_affine()) -> boolean().
is_valid_sig_g1(Pt) ->
  ?BLS:g1_is_in_subgroup(Pt).

-spec is_valid_sig_g2(?BLS:g2_affine()) -> boolean().
is_valid_sig_g2(Pt) ->
  ?BLS:g2_is_in_subgroup(Pt).

-spec aggregate_g1_points([min_pk_pubkey()], ?BLS:g1_affine()) ->
  {ok, ?BLS:g1_compressed()} | {error, term()}.
aggregate_g1_points([], AccPt) ->
  {ok, ?BLS:g1_compress(AccPt)};
aggregate_g1_points([Item | Rest], AccPt) ->
  case to_g1_point(Item) of
    {ok, Pt} ->
      case is_valid_sig_g1(Pt) of
        true ->
          NewAcc = ?BLS:g1_add(AccPt, Pt),
          aggregate_g1_points(Rest, NewAcc);
        false ->
          {error, not_in_subgroup}
      end;
    {error, Reason} ->
      {error, Reason}
  end.

-spec aggregate_g2_points([min_pk_sig()], ?BLS:g2_affine()) ->
  {ok, ?BLS:g2_compressed()} | {error, term()}.
aggregate_g2_points([], AccPt) ->
  {ok, ?BLS:g2_compress(AccPt)};
aggregate_g2_points([Item | Rest], AccPt) ->
  case to_g2_point(Item) of
    {ok, Pt} ->
      case is_valid_sig_g2(Pt) of
        true ->
          NewAcc = ?BLS:g2_add(AccPt, Pt),
          aggregate_g2_points(Rest, NewAcc);
        false ->
          {error, not_in_subgroup}
      end;
    {error, Reason} ->
      {error, Reason}
  end.
