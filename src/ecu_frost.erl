%%%-------------------------------------------------------------------
%%% @doc
%%% FROST: Flexible Round-Optimized Schnorr Threshold Signatures
%%% Implements RFC 9591 for both FROST(Ed25519, SHA-512) and
%%% FROST(secp256k1, SHA-256) ciphersuites.
%%% Defaults to 'ed25519' when no ciphersuite is specified.
%%%
%%% Reference:
%%%   RFC 9591: https://datatracker.ietf.org/doc/html/rfc9591
%%%   RFC 9380: https://datatracker.ietf.org/doc/html/rfc9380 (Hash-to-Curve)
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_frost).

%% Protocol operations (RFC 9591 §5)
-export([commit/1, commit/2, commit/3,
         sign/6, sign/7,
         verify_signature_share/7, verify_signature_share/8,
         aggregate/4, aggregate/5,
         verify/3, verify/4]).

%% Protocol subroutines (RFC 9591 §4)
-export([compute_binding_factors/3, compute_binding_factors/4,
         compute_group_commitment/2, compute_group_commitment/3,
         compute_challenge/3, compute_challenge/4,
         derive_lagrange_coefficient/2, derive_lagrange_coefficient/3,
         encode_group_commitment_list/1, encode_group_commitment_list/2,
         nonce_generate/1, nonce_generate/2, nonce_generate/3]).

%% Trusted Dealer & Polynomial operations (RFC 9591 Appendix C)
-export([trusted_dealer_keygen/2, trusted_dealer_keygen/3, trusted_dealer_keygen/4,
         vss_verify/3, vss_verify/4,
         secret_share_combine/1, secret_share_combine/2,
         polynomial_evaluate/2, polynomial_evaluate/3,
         derive_interpolating_value/2, derive_interpolating_value/3]).

%% Types
-type ciphersuite() :: ed25519 | secp256k1.
-type participant_id() :: pos_integer().
-type scalar() :: <<_:256>>.
-type compressed_pt() :: <<_:256>> | <<_:264>>.
-type nonce_pair() :: {HidingNonce :: scalar(), BindingNonce :: scalar()}.
-type nonce_commitment_pair() :: {HidingNonceComm :: compressed_pt(), BindingNonceComm :: compressed_pt()}.
-type commitment_tuple() :: {participant_id(), HidingNonceComm :: compressed_pt(), BindingNonceComm :: compressed_pt()}.
-type commitment_list() :: [commitment_tuple()].
-type binding_factor_tuple() :: {participant_id(), scalar()}.
-type binding_factor_list() :: [binding_factor_tuple()].
-type sig_share() :: scalar().
-type signature() :: <<_:512>> | <<_:520>>.

-export_type([ciphersuite/0, participant_id/0, scalar/0, compressed_pt/0,
              nonce_pair/0, nonce_commitment_pair/0,
              commitment_tuple/0, commitment_list/0,
              binding_factor_tuple/0, binding_factor_list/0,
              sig_share/0, signature/0]).

-define(ED25519_CTX, <<"FROST-ED25519-SHA512-v1"/utf8>>).
-define(SECP256K1_CTX, <<"FROST-secp256k1-SHA256-v1"/utf8>>).
-define(SECP256K1_N, 16#fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141).

%% ===================================================================
%% Protocol Operations (RFC 9591 §5)
%% ===================================================================

-spec commit(Secret :: scalar()) -> {nonce_pair(), nonce_commitment_pair()}.
commit(Secret) ->
  commit(ed25519, Secret).

-spec commit(ciphersuite() | scalar(), scalar() | {binary(), binary()}) ->
  {nonce_pair(), nonce_commitment_pair()}.
commit(Suite, Secret) when is_atom(Suite), is_binary(Secret) ->
  Rand1 = crypto:strong_rand_bytes(32),
  Rand2 = crypto:strong_rand_bytes(32),
  commit(Suite, Secret, {Rand1, Rand2});
commit(Secret, {Rand1, Rand2}) when is_binary(Secret), is_binary(Rand1), is_binary(Rand2) ->
  commit(ed25519, Secret, {Rand1, Rand2}).

-spec commit(Suite :: ciphersuite(),
             Secret :: scalar(),
             RandPair :: {binary(), binary()}) ->
  {nonce_pair(), nonce_commitment_pair()}.
commit(ed25519, Secret, {RandHiding, RandBinding}) ->
  HidingNonce  = nonce_generate(ed25519, Secret, RandHiding),
  BindingNonce = nonce_generate(ed25519, Secret, RandBinding),
  HidingNonceComm  = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(HidingNonce)),
  BindingNonceComm = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(BindingNonce)),
  {{HidingNonce, BindingNonce}, {HidingNonceComm, BindingNonceComm}};
commit(secp256k1, Secret, {RandHiding, RandBinding}) ->
  HidingNonce  = nonce_generate(secp256k1, Secret, RandHiding),
  BindingNonce = nonce_generate(secp256k1, Secret, RandBinding),
  <<H_int:256>> = HidingNonce,
  <<B_int:256>> = BindingNonce,
  HidingNonceComm  = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(H_int)),
  BindingNonceComm = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(B_int)),
  {{HidingNonce, BindingNonce}, {HidingNonceComm, BindingNonceComm}}.

-spec sign(Id :: participant_id(),
           SecretShare :: scalar(),
           GroupPublicKey :: compressed_pt(),
           NoncePair :: nonce_pair(),
           Msg :: binary(),
           CommitmentList :: commitment_list()) -> sig_share().
sign(Id, SecretShare, GroupPublicKey, NoncePair, Msg, CommitmentList) ->
  sign(ed25519, Id, SecretShare, GroupPublicKey, NoncePair, Msg, CommitmentList).

-spec sign(Suite :: ciphersuite(),
           Id :: participant_id(),
           SecretShare :: scalar(),
           GroupPublicKey :: compressed_pt(),
           NoncePair :: nonce_pair(),
           Msg :: binary(),
           CommitmentList :: commitment_list()) -> sig_share().
sign(ed25519, Id, SecretShare, GroupPublicKey, {HidingNonce, BindingNonce}, Msg, CommitmentList) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(ed25519, GroupPublicKey, SortedList, Msg),
  BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
  GroupCommitment = compute_group_commitment(ed25519, SortedList, BindingFactorList),
  ParticipantList = participants_from_commitment_list(SortedList),
  LambdaId = derive_lagrange_coefficient(ed25519, Id, ParticipantList),
  Challenge = compute_challenge(ed25519, GroupCommitment, GroupPublicKey, Msg),

  Term1 = ecu_ed25519:s_mul(BindingNonce, BindingFactor),
  Term2 = ecu_ed25519:s_mul(LambdaId, ecu_ed25519:s_mul(SecretShare, Challenge)),
  ecu_ed25519:s_add(HidingNonce, ecu_ed25519:s_add(Term1, Term2));
sign(secp256k1, Id, SecretShare, GroupPublicKey, {HidingNonce, BindingNonce}, Msg, CommitmentList) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(secp256k1, GroupPublicKey, SortedList, Msg),
  BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
  GroupCommitment = compute_group_commitment(secp256k1, SortedList, BindingFactorList),
  ParticipantList = participants_from_commitment_list(SortedList),
  LambdaId = derive_lagrange_coefficient(secp256k1, Id, ParticipantList),
  Challenge = compute_challenge(secp256k1, GroupCommitment, GroupPublicKey, Msg),

  <<D:256>> = HidingNonce,
  <<E:256>> = BindingNonce,
  <<Rho:256>> = BindingFactor,
  <<Lambda:256>> = LambdaId,
  <<S:256>> = SecretShare,
  <<C:256>> = Challenge,

  Term1 = (E * Rho) rem ?SECP256K1_N,
  Term2 = (Lambda * ((S * C) rem ?SECP256K1_N)) rem ?SECP256K1_N,
  Z = (D + Term1 + Term2) rem ?SECP256K1_N,
  <<Z:256>>.

-spec verify_signature_share(Id :: participant_id(),
                             PublicKeyShare :: compressed_pt(),
                             CommitmentPair :: nonce_commitment_pair(),
                             SigShare :: sig_share(),
                             CommitmentList :: commitment_list(),
                             GroupPublicKey :: compressed_pt(),
                             Msg :: binary()) -> boolean().
verify_signature_share(Id, PublicKeyShare, CommitmentPair,
                       SigShare, CommitmentList, GroupPublicKey, Msg) ->
  verify_signature_share(ed25519, Id, PublicKeyShare, CommitmentPair,
                         SigShare, CommitmentList, GroupPublicKey, Msg).

-spec verify_signature_share(Suite :: ciphersuite(),
                             Id :: participant_id(),
                             PublicKeyShare :: compressed_pt(),
                             CommitmentPair :: nonce_commitment_pair(),
                             SigShare :: sig_share(),
                             CommitmentList :: commitment_list(),
                             GroupPublicKey :: compressed_pt(),
                             Msg :: binary()) -> boolean().
verify_signature_share(ed25519, Id, PublicKeyShare, {HidingNonceComm, BindingNonceComm},
                       SigShare, CommitmentList, GroupPublicKey, Msg) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(ed25519, GroupPublicKey, SortedList, Msg),
  BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
  GroupCommitment = compute_group_commitment(ed25519, SortedList, BindingFactorList),
  Challenge = compute_challenge(ed25519, GroupCommitment, GroupPublicKey, Msg),
  ParticipantList = participants_from_commitment_list(SortedList),
  LambdaId = derive_lagrange_coefficient(ed25519, Id, ParticipantList),

  PtHiding = ecu_ed25519:decompress(HidingNonceComm),
  PtBinding = ecu_ed25519:decompress(BindingNonceComm),
  CommShare = ecu_ed25519:p_add(PtHiding, ecu_ed25519:scalar_mul_noclamp(BindingFactor, PtBinding)),

  LHS = ecu_ed25519:scalar_mul_base_noclamp(SigShare),
  PtPub = ecu_ed25519:decompress(PublicKeyShare),
  RHS = ecu_ed25519:p_add(CommShare, ecu_ed25519:scalar_mul_noclamp(ecu_ed25519:s_mul(Challenge, LambdaId), PtPub)),

  ecu_ed25519:pt_eq(LHS, RHS);
verify_signature_share(secp256k1, Id, PublicKeyShare, {HidingNonceComm, BindingNonceComm},
                       SigShare, CommitmentList, GroupPublicKey, Msg) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(secp256k1, GroupPublicKey, SortedList, Msg),
  BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
  GroupCommitment = compute_group_commitment(secp256k1, SortedList, BindingFactorList),
  Challenge = compute_challenge(secp256k1, GroupCommitment, GroupPublicKey, Msg),
  ParticipantList = participants_from_commitment_list(SortedList),
  LambdaId = derive_lagrange_coefficient(secp256k1, Id, ParticipantList),

  PtHiding = ecu_secp256k1:decompress(HidingNonceComm),
  PtBinding = ecu_secp256k1:decompress(BindingNonceComm),
  <<BF_int:256>> = BindingFactor,
  CommShare = ecu_secp256k1:p_add(PtHiding, ecu_secp256k1:scalar_mul(BF_int, PtBinding)),

  <<Z_int:256>> = SigShare,
  LHS = ecu_secp256k1:scalar_mul_base(Z_int),

  <<C_int:256>> = Challenge,
  <<L_int:256>> = LambdaId,
  Factor = (C_int * L_int) rem ?SECP256K1_N,
  PtPub = ecu_secp256k1:decompress(PublicKeyShare),
  RHS = ecu_secp256k1:p_add(CommShare, ecu_secp256k1:scalar_mul(Factor, PtPub)),

  LHS =:= RHS.

-spec aggregate(CommitmentList :: commitment_list(),
                Msg :: binary(),
                GroupPublicKey :: compressed_pt(),
                SigShares :: [sig_share()]) -> signature().
aggregate(CommitmentList, Msg, GroupPublicKey, SigShares) ->
  aggregate(ed25519, CommitmentList, Msg, GroupPublicKey, SigShares).

-spec aggregate(Suite :: ciphersuite(),
                CommitmentList :: commitment_list(),
                Msg :: binary(),
                GroupPublicKey :: compressed_pt(),
                SigShares :: [sig_share()]) -> signature().
aggregate(ed25519, CommitmentList, Msg, GroupPublicKey, SigShares) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(ed25519, GroupPublicKey, SortedList, Msg),
  GroupCommitment = compute_group_commitment(ed25519, SortedList, BindingFactorList),
  Z = lists:foldl(fun(Share, Acc) -> ecu_ed25519:s_add(Acc, Share) end, <<0:256>>, SigShares),
  <<GroupCommitment:32/binary, Z:32/binary>>;
aggregate(secp256k1, CommitmentList, Msg, GroupPublicKey, SigShares) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(secp256k1, GroupPublicKey, SortedList, Msg),
  GroupCommitment = compute_group_commitment(secp256k1, SortedList, BindingFactorList),
  Z = lists:foldl(fun(<<S:256>>, Acc) -> (Acc + S) rem ?SECP256K1_N end, 0, SigShares),
  <<GroupCommitment:33/binary, Z:256/big>>.

-spec verify(Signature :: signature(),
             Msg :: binary(),
             GroupPublicKey :: compressed_pt()) -> boolean().
verify(Signature, Msg, GroupPublicKey) ->
  verify(ed25519, Signature, Msg, GroupPublicKey).

-spec verify(Suite :: ciphersuite(),
             Signature :: signature(),
             Msg :: binary(),
             GroupPublicKey :: compressed_pt()) -> boolean().
verify(ed25519, <<Sig:64/binary>>, Msg, GroupPublicKey) ->
  ecu_eddsa:sign_verify_detached(Sig, Msg, GroupPublicKey);
verify(secp256k1, <<R_enc:33/binary, Z_bin:32/binary>>, Msg, PK_enc) ->
  try
    Challenge = compute_challenge(secp256k1, R_enc, PK_enc, Msg),
    <<C_int:256>> = Challenge,
    <<Z_int:256>> = Z_bin,
    PtR = ecu_secp256k1:decompress(R_enc),
    PtPK = ecu_secp256k1:decompress(PK_enc),
    LHS = ecu_secp256k1:scalar_mul_base(Z_int),
    RHS = ecu_secp256k1:p_add(PtR, ecu_secp256k1:scalar_mul(C_int, PtPK)),
    LHS =:= RHS
  catch
    _:_ ->
      false
  end;
verify(_, _, _, _) ->
  false.

%% ===================================================================
%% Protocol Subroutines (RFC 9591 §4)
%% ===================================================================

-spec nonce_generate(Secret :: scalar()) -> scalar().
nonce_generate(Secret) ->
  nonce_generate(ed25519, Secret).

-spec nonce_generate(ciphersuite() | scalar(), scalar() | binary()) -> scalar().
nonce_generate(Suite, Secret) when is_atom(Suite), is_binary(Secret) ->
  Rand = crypto:strong_rand_bytes(32),
  nonce_generate(Suite, Secret, Rand);
nonce_generate(Secret, Rand) when is_binary(Secret), is_binary(Rand) ->
  nonce_generate(ed25519, Secret, Rand).

-spec nonce_generate(Suite :: ciphersuite(),
                     Secret :: scalar(),
                     RandomBytes :: binary()) -> scalar().
nonce_generate(ed25519, Secret, RandomBytes) ->
  ecu_ed25519:scalar_reduce(crypto:hash(sha512, <<?ED25519_CTX/binary, "nonce", RandomBytes/binary, Secret/binary>>));
nonce_generate(secp256k1, Secret, RandomBytes) ->
  hash_to_field_secp256k1(<<RandomBytes/binary, Secret/binary>>, <<?SECP256K1_CTX/binary, "nonce">>).

-spec compute_binding_factors(GroupPublicKey :: compressed_pt(),
                              CommitmentList :: commitment_list(),
                              Msg :: binary()) -> binding_factor_list().
compute_binding_factors(GroupPublicKey, CommitmentList, Msg) ->
  compute_binding_factors(ed25519, GroupPublicKey, CommitmentList, Msg).

-spec compute_binding_factors(Suite :: ciphersuite(),
                              GroupPublicKey :: compressed_pt(),
                              CommitmentList :: commitment_list(),
                              Msg :: binary()) -> binding_factor_list().
compute_binding_factors(ed25519, GroupPublicKey, CommitmentList, Msg) ->
  SortedList = sort_commitment_list(CommitmentList),
  MsgHash = crypto:hash(sha512, <<?ED25519_CTX/binary, "msg", Msg/binary>>),
  EncodedCommitmentHash = crypto:hash(sha512, <<?ED25519_CTX/binary, "com", (encode_group_commitment_list(ed25519, SortedList))/binary>>),
  RhoInputPrefix = <<GroupPublicKey:32/binary, MsgHash/binary, EncodedCommitmentHash/binary>>,
  [ {Id, ecu_ed25519:scalar_reduce(crypto:hash(sha512, <<?ED25519_CTX/binary, "rho", RhoInputPrefix/binary, Id:256/little>>))}
    || {Id, _, _} <- SortedList ];
compute_binding_factors(secp256k1, GroupPublicKey, CommitmentList, Msg) ->
  SortedList = sort_commitment_list(CommitmentList),
  MsgHash = crypto:hash(sha256, <<?SECP256K1_CTX/binary, "msg", Msg/binary>>),
  EncodedCommitmentHash = crypto:hash(sha256, <<?SECP256K1_CTX/binary, "com", (encode_group_commitment_list(secp256k1, SortedList))/binary>>),
  RhoInputPrefix = <<GroupPublicKey:33/binary, MsgHash/binary, EncodedCommitmentHash/binary>>,
  [ {Id, hash_to_field_secp256k1(<<RhoInputPrefix/binary, Id:256/big>>, <<?SECP256K1_CTX/binary, "rho">>)}
    || {Id, _, _} <- SortedList ].

-spec compute_group_commitment(CommitmentList :: commitment_list(),
                               BindingFactorList :: binding_factor_list()) -> compressed_pt().
compute_group_commitment(CommitmentList, BindingFactorList) ->
  compute_group_commitment(ed25519, CommitmentList, BindingFactorList).

-spec compute_group_commitment(Suite :: ciphersuite(),
                               CommitmentList :: commitment_list(),
                               BindingFactorList :: binding_factor_list()) -> compressed_pt().
compute_group_commitment(ed25519, CommitmentList, BindingFactorList) ->
  SortedList = sort_commitment_list(CommitmentList),
  Pts = [ begin
            PtHiding = ecu_ed25519:decompress(HidingComm),
            PtBinding = ecu_ed25519:decompress(BindingComm),
            BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
            ecu_ed25519:p_add(PtHiding, ecu_ed25519:scalar_mul_noclamp(BindingFactor, PtBinding))
          end || {Id, HidingComm, BindingComm} <- SortedList ],
  ecu_ed25519:compress(fold_pts_ed25519(Pts));
compute_group_commitment(secp256k1, CommitmentList, BindingFactorList) ->
  SortedList = sort_commitment_list(CommitmentList),
  Pts = [ begin
            PtHiding = ecu_secp256k1:decompress(HidingComm),
            PtBinding = ecu_secp256k1:decompress(BindingComm),
            BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
            <<BF_int:256>> = BindingFactor,
            ecu_secp256k1:p_add(PtHiding, ecu_secp256k1:scalar_mul(BF_int, PtBinding))
          end || {Id, HidingComm, BindingComm} <- SortedList ],
  ecu_secp256k1:compress(fold_pts_secp256k1(Pts)).

-spec compute_challenge(GroupCommitment :: compressed_pt(),
                        GroupPublicKey :: compressed_pt(),
                        Msg :: binary()) -> scalar().
compute_challenge(GroupCommitment, GroupPublicKey, Msg) ->
  compute_challenge(ed25519, GroupCommitment, GroupPublicKey, Msg).

-spec compute_challenge(Suite :: ciphersuite(),
                        GroupCommitment :: compressed_pt(),
                        GroupPublicKey :: compressed_pt(),
                        Msg :: binary()) -> scalar().
compute_challenge(ed25519, GroupCommitment, GroupPublicKey, Msg) ->
  ecu_ed25519:scalar_reduce(crypto:hash(sha512, <<GroupCommitment:32/binary, GroupPublicKey:32/binary, Msg/binary>>));
compute_challenge(secp256k1, GroupCommitment, GroupPublicKey, Msg) ->
  hash_to_field_secp256k1(<<GroupCommitment:33/binary, GroupPublicKey:33/binary, Msg/binary>>, <<?SECP256K1_CTX/binary, "chal">>).

-spec encode_group_commitment_list(CommitmentList :: commitment_list()) -> binary().
encode_group_commitment_list(CommitmentList) ->
  encode_group_commitment_list(ed25519, CommitmentList).

-spec encode_group_commitment_list(Suite :: ciphersuite(),
                                   CommitmentList :: commitment_list()) -> binary().
encode_group_commitment_list(ed25519, CommitmentList) ->
  SortedList = sort_commitment_list(CommitmentList),
  << <<Id:256/little, HidingComm:32/binary, BindingComm:32/binary>>
     || {Id, HidingComm, BindingComm} <- SortedList >>;
encode_group_commitment_list(secp256k1, CommitmentList) ->
  SortedList = sort_commitment_list(CommitmentList),
  << <<Id:256/big, HidingComm:33/binary, BindingComm:33/binary>>
     || {Id, HidingComm, BindingComm} <- SortedList >>.

-spec derive_lagrange_coefficient(Id :: participant_id(),
                                  ParticipantList :: [participant_id()]) -> scalar().
derive_lagrange_coefficient(Id, ParticipantList) ->
  derive_lagrange_coefficient(ed25519, Id, ParticipantList).

-spec derive_lagrange_coefficient(Suite :: ciphersuite(),
                                  Id :: participant_id(),
                                  ParticipantList :: [participant_id()]) -> scalar().
derive_lagrange_coefficient(ed25519, Id, ParticipantList) ->
  derive_lagrange_ed25519(Id, ParticipantList, <<1:256/little>>, <<1:256/little>>);
derive_lagrange_coefficient(secp256k1, Id, ParticipantList) ->
  derive_lagrange_secp256k1(Id, ParticipantList, 1, 1).

-spec derive_lagrange_ed25519(Id :: participant_id(),
                              Rest :: [participant_id()],
                              Num :: scalar(),
                              Den :: scalar()) -> scalar().
derive_lagrange_ed25519(_, [], Num, Den) ->
  ecu_ed25519:s_mul(Num, ecu_ed25519:s_inv(Den));
derive_lagrange_ed25519(Id, [Id | Js], Num, Den) ->
  derive_lagrange_ed25519(Id, Js, Num, Den);
derive_lagrange_ed25519(Id, [J | Js], Num, Den) ->
  derive_lagrange_ed25519(Id, Js,
                          ecu_ed25519:s_mul(Num, <<J:256/little>>),
                          ecu_ed25519:s_mul(Den, ecu_ed25519:s_sub(<<J:256/little>>, <<Id:256/little>>))).

-spec derive_lagrange_secp256k1(Id :: participant_id(),
                                Rest :: [participant_id()],
                                Num :: non_neg_integer(),
                                Den :: non_neg_integer()) -> scalar().
derive_lagrange_secp256k1(_, [], Num, Den) ->
  InvDen = ecu_secp256k1:s_inv(Den),
  Res = (Num * InvDen) rem ?SECP256K1_N,
  <<Res:256/big>>;
derive_lagrange_secp256k1(Id, [Id | Js], Num, Den) ->
  derive_lagrange_secp256k1(Id, Js, Num, Den);
derive_lagrange_secp256k1(Id, [J | Js], Num, Den) ->
  Diff = (J - Id + ?SECP256K1_N) rem ?SECP256K1_N,
  derive_lagrange_secp256k1(Id, Js,
                            (Num * J) rem ?SECP256K1_N,
                            (Den * Diff) rem ?SECP256K1_N).

-spec derive_interpolating_value(ParticipantList :: [participant_id()],
                                 Id :: participant_id()) -> scalar().
derive_interpolating_value(ParticipantList, Id) ->
  derive_lagrange_coefficient(ed25519, Id, ParticipantList).

-spec derive_interpolating_value(Suite :: ciphersuite(),
                                 ParticipantList :: [participant_id()],
                                 Id :: participant_id()) -> scalar().
derive_interpolating_value(Suite, ParticipantList, Id) ->
  derive_lagrange_coefficient(Suite, Id, ParticipantList).

%% ===================================================================
%% Trusted Dealer Key Generation (RFC 9591 Appendix C)
%% ===================================================================

-spec trusted_dealer_keygen(MinParticipants :: pos_integer(),
                            MaxParticipants :: pos_integer()) ->
  {[{participant_id(), scalar()}], compressed_pt(), [compressed_pt()]}.
trusted_dealer_keygen(MinParticipants, MaxParticipants) ->
  trusted_dealer_keygen(ed25519, MinParticipants, MaxParticipants).

-spec trusted_dealer_keygen(ciphersuite() | scalar(),
                            pos_integer() | scalar(),
                            pos_integer()) ->
  {[{participant_id(), scalar()}], compressed_pt(), [compressed_pt()]}.
trusted_dealer_keygen(Suite, MinParticipants, MaxParticipants)
    when is_atom(Suite), is_integer(MinParticipants), is_integer(MaxParticipants) ->
  SecretKey = rnd_scalar(Suite),
  trusted_dealer_keygen(Suite, SecretKey, MinParticipants, MaxParticipants);
trusted_dealer_keygen(SecretKey, MinParticipants, MaxParticipants)
    when is_binary(SecretKey), is_integer(MinParticipants), is_integer(MaxParticipants) ->
  trusted_dealer_keygen(ed25519, SecretKey, MinParticipants, MaxParticipants).

-spec trusted_dealer_keygen(Suite :: ciphersuite(),
                            SecretKey :: scalar(),
                            MinParticipants :: pos_integer(),
                            MaxParticipants :: pos_integer()) ->
  {[{participant_id(), scalar()}], compressed_pt(), [compressed_pt()]}.
trusted_dealer_keygen(ed25519, SecretKey, MinParticipants, MaxParticipants)
    when MinParticipants >= 1, MaxParticipants >= MinParticipants ->
  RandomCoeffs = [ rnd_scalar(ed25519) || _ <- lists:seq(1, MinParticipants - 1) ],
  Coeffs = [SecretKey | RandomCoeffs],
  Shares = [ {I, polynomial_evaluate(ed25519, I, Coeffs)} || I <- lists:seq(1, MaxParticipants) ],
  VSSCommitment = [ ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(C)) || C <- Coeffs ],
  GroupPublicKey = hd(VSSCommitment),
  {Shares, GroupPublicKey, VSSCommitment};
trusted_dealer_keygen(secp256k1, SecretKey, MinParticipants, MaxParticipants)
    when MinParticipants >= 1, MaxParticipants >= MinParticipants ->
  RandomCoeffs = [ rnd_scalar(secp256k1) || _ <- lists:seq(1, MinParticipants - 1) ],
  Coeffs = [SecretKey | RandomCoeffs],
  Shares = [ {I, polynomial_evaluate(secp256k1, I, Coeffs)} || I <- lists:seq(1, MaxParticipants) ],
  VSSCommitment = [ begin
                      <<C_int:256>> = C,
                      ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(C_int))
                    end || C <- Coeffs ],
  GroupPublicKey = hd(VSSCommitment),
  {Shares, GroupPublicKey, VSSCommitment}.

-spec vss_verify(Id :: participant_id(),
                 Share :: scalar(),
                 VSSCommitment :: [compressed_pt()]) -> boolean().
vss_verify(Id, Share, VSSCommitment) ->
  vss_verify(ed25519, Id, Share, VSSCommitment).

-spec vss_verify(Suite :: ciphersuite(),
                 Id :: participant_id(),
                 Share :: scalar(),
                 VSSCommitment :: [compressed_pt()]) -> boolean().
vss_verify(ed25519, Id, Share, VSSCommitment) ->
  LHS = ecu_ed25519:scalar_mul_base_noclamp(Share),
  Terms = [ begin
              Exp = pow_scalar_ed25519(<<Id:256/little>>, K),
              Pt = ecu_ed25519:decompress(Comm),
              ecu_ed25519:scalar_mul_noclamp(Exp, Pt)
            end || {K, Comm} <- lists:zip(lists:seq(0, length(VSSCommitment) - 1), VSSCommitment) ],
  RHS = fold_pts_ed25519(Terms),
  ecu_ed25519:pt_eq(LHS, RHS);
vss_verify(secp256k1, Id, Share, VSSCommitment) ->
  <<S_int:256>> = Share,
  LHS = ecu_secp256k1:scalar_mul_base(S_int),
  Terms = [ begin
              Exp = pow_int(Id, K, ?SECP256K1_N),
              Pt = ecu_secp256k1:decompress(Comm),
              ecu_secp256k1:scalar_mul(Exp, Pt)
            end || {K, Comm} <- lists:zip(lists:seq(0, length(VSSCommitment) - 1), VSSCommitment) ],
  RHS = fold_pts_secp256k1(Terms),
  LHS =:= RHS.

-spec secret_share_combine(Shares :: [{participant_id(), scalar()}]) -> scalar().
secret_share_combine(Shares) ->
  secret_share_combine(ed25519, Shares).

-spec secret_share_combine(Suite :: ciphersuite(),
                           Shares :: [{participant_id(), scalar()}]) -> scalar().
secret_share_combine(ed25519, Shares) when length(Shares) >= 1 ->
  Ids = [ Id || {Id, _} <- Shares ],
  Terms = [ ecu_ed25519:s_mul(Share, derive_lagrange_coefficient(ed25519, Id, Ids)) || {Id, Share} <- Shares ],
  lists:foldl(fun(T, Acc) -> ecu_ed25519:s_add(Acc, T) end, <<0:256>>, Terms);
secret_share_combine(secp256k1, Shares) when length(Shares) >= 1 ->
  Ids = [ Id || {Id, _} <- Shares ],
  Terms = [ begin
              <<S_int:256>> = Share,
              <<L_int:256>> = derive_lagrange_coefficient(secp256k1, Id, Ids),
              (S_int * L_int) rem ?SECP256K1_N
            end || {Id, Share} <- Shares ],
  Total = lists:foldl(fun(T, Acc) -> (Acc + T) rem ?SECP256K1_N end, 0, Terms),
  <<Total:256/big>>.

-spec polynomial_evaluate(X :: participant_id() | scalar(), Coeffs :: [scalar()]) -> scalar().
polynomial_evaluate(X, Coeffs) ->
  polynomial_evaluate(ed25519, X, Coeffs).

-spec polynomial_evaluate(Suite :: ciphersuite(),
                          X :: participant_id() | scalar(),
                          Coeffs :: [scalar()]) -> scalar().
polynomial_evaluate(ed25519, X, Coeffs) ->
  X_bin = case is_integer(X) of true -> <<X:256/little>>; false -> X end,
  polynomial_evaluate_horner_ed25519(X_bin, lists:reverse(Coeffs), <<0:256>>);
polynomial_evaluate(secp256k1, X, Coeffs) ->
  X_int = case is_integer(X) of true -> X; false -> <<Val:256>> = X, Val end,
  CoeffsInt = [ begin <<C:256>> = Coeff, C end || Coeff <- lists:reverse(Coeffs) ],
  Res = lists:foldl(fun(Coeff, Acc) -> (Coeff + Acc * X_int) rem ?SECP256K1_N end, 0, CoeffsInt),
  <<Res:256/big>>.

-spec polynomial_evaluate_horner_ed25519(X :: scalar(), RevCoeffs :: [scalar()], Acc :: scalar()) -> scalar().
polynomial_evaluate_horner_ed25519(_, [], Acc) ->
  Acc;
polynomial_evaluate_horner_ed25519(X, [Coeff | Rest], Acc) ->
  NextAcc = ecu_ed25519:s_add(Coeff, ecu_ed25519:s_mul(Acc, X)),
  polynomial_evaluate_horner_ed25519(X, Rest, NextAcc).

%% ===================================================================
%% Hash to Field (RFC 9380 §5.3) for secp256k1
%% ===================================================================

-spec hash_to_field_secp256k1(Msg :: binary(), DST :: binary()) -> scalar().
hash_to_field_secp256k1(Msg, DST) ->
  UniformBytes = expand_message_xmd(Msg, DST, 48),
  <<Val:384>> = UniformBytes,
  Order = ?SECP256K1_N,
  <<(Val rem Order):256/big>>.

-spec expand_message_xmd(Msg :: binary(), DST :: binary(), LenInBytes :: non_neg_integer()) -> binary().
expand_message_xmd(Msg, DST, LenInBytes) ->
  DST_prime = case byte_size(DST) > 255 of
                true ->
                  Oversize = crypto:hash(sha256, [<<"H2C-OVERSIZE-DST-">>, DST]),
                  <<Oversize/binary, (byte_size(Oversize)):8>>;
                false ->
                  <<DST/binary, (byte_size(DST)):8>>
              end,
  Z_pad = <<0:512>>,
  L_bytes = <<LenInBytes:16>>,
  Msg_prime = <<Z_pad/binary, Msg/binary, L_bytes/binary, 0:8, DST_prime/binary>>,
  B0 = crypto:hash(sha256, Msg_prime),
  B1 = crypto:hash(sha256, <<B0/binary, 1:8, DST_prime/binary>>),
  XOR1 = crypto:exor(B0, B1),
  B2 = crypto:hash(sha256, <<XOR1/binary, 2:8, DST_prime/binary>>),
  binary:part(<<B1/binary, B2/binary>>, 0, LenInBytes).

%% ===================================================================
%% Internal Helpers
%% ===================================================================

-spec rnd_scalar(ciphersuite()) -> scalar().
rnd_scalar(ed25519) ->
  ecu_ed25519:scalar_reduce(crypto:strong_rand_bytes(64));
rnd_scalar(secp256k1) ->
  Val = binary:decode_unsigned(crypto:strong_rand_bytes(48)) rem ?SECP256K1_N,
  case Val of
    0 -> rnd_scalar(secp256k1);
    _ -> <<Val:256/big>>
  end.

-spec pow_scalar_ed25519(scalar(), non_neg_integer()) -> scalar().
pow_scalar_ed25519(_, 0) ->
  <<1:256/little>>;
pow_scalar_ed25519(Base, 1) ->
  Base;
pow_scalar_ed25519(Base, Exp) when Exp > 1 ->
  pow_scalar_ed25519(Base, Exp, <<1:256/little>>).

-spec pow_scalar_ed25519(scalar(), non_neg_integer(), scalar()) -> scalar().
pow_scalar_ed25519(_, 0, Acc) ->
  Acc;
pow_scalar_ed25519(Base, Exp, Acc) when Exp rem 2 =:= 1 ->
  pow_scalar_ed25519(ecu_ed25519:s_mul(Base, Base), Exp div 2, ecu_ed25519:s_mul(Acc, Base));
pow_scalar_ed25519(Base, Exp, Acc) ->
  pow_scalar_ed25519(ecu_ed25519:s_mul(Base, Base), Exp div 2, Acc).

-spec pow_int(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
pow_int(_, 0, _) ->
  1;
pow_int(Base, Exp, Mod) ->
  pow_int(Base rem Mod, Exp, Mod, 1).

-spec pow_int(non_neg_integer(), non_neg_integer(), pos_integer(), non_neg_integer()) -> non_neg_integer().
pow_int(_, 0, _, Acc) ->
  Acc;
pow_int(Base, Exp, Mod, Acc) when Exp rem 2 =:= 1 ->
  pow_int((Base * Base) rem Mod, Exp div 2, Mod, (Acc * Base) rem Mod);
pow_int(Base, Exp, Mod, Acc) ->
  pow_int((Base * Base) rem Mod, Exp div 2, Mod, Acc).

-spec fold_pts_ed25519([ecu_ed25519:pt()]) -> ecu_ed25519:pt().
fold_pts_ed25519([]) ->
  ecu_ed25519:decompress(<<1:8, 0:248>>);
fold_pts_ed25519([P | Pts]) ->
  lists:foldl(fun(Pt, Acc) -> ecu_ed25519:p_add(Acc, Pt) end, P, Pts).

-spec fold_pts_secp256k1([ecu_secp256k1:pt_affine()]) -> ecu_secp256k1:pt_affine().
fold_pts_secp256k1([]) ->
  {0, 0};
fold_pts_secp256k1([P | Pts]) ->
  lists:foldl(fun(Pt, Acc) -> ecu_secp256k1:p_add(Acc, Pt) end, P, Pts).

-spec binding_factor_for_participant(binding_factor_list(), participant_id()) -> scalar().
binding_factor_for_participant(BindingFactorList, Id) ->
  case lists:keyfind(Id, 1, BindingFactorList) of
    {Id, Factor} -> Factor;
    false -> error({participant_not_found, Id})
  end.

-spec participants_from_commitment_list(commitment_list()) -> [participant_id()].
participants_from_commitment_list(CommitmentList) ->
  [ Id || {Id, _, _} <- CommitmentList ].

-spec sort_commitment_list(commitment_list()) -> commitment_list().
sort_commitment_list(CommitmentList) ->
  lists:sort(fun({IdA, _, _}, {IdB, _, _}) -> IdA =< IdB end, CommitmentList).
