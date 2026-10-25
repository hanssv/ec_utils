%%%-------------------------------------------------------------------
%%% @doc
%%% FROST: Flexible Round-Optimized Schnorr Threshold Signatures
%%% Implements RFC 9591 for the FROST(Ed25519, SHA-512) ciphersuite.
%%%
%%% Reference:
%%%   RFC 9591: https://datatracker.ietf.org/doc/html/rfc9591
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_frost).

%% Protocol operations (RFC 9591 §5)
-export([commit/1, commit/2,
         sign/6,
         verify_signature_share/7,
         aggregate/4]).

%% Protocol subroutines (RFC 9591 §4)
-export([compute_binding_factors/3,
         compute_group_commitment/2,
         compute_challenge/3,
         derive_lagrange_coefficient/2,
         encode_group_commitment_list/1,
         nonce_generate/1, nonce_generate/2]).

%% Trusted Dealer & Polynomial operations (RFC 9591 Appendix C)
-export([trusted_dealer_keygen/2, trusted_dealer_keygen/3,
         vss_verify/3,
         secret_share_combine/1,
         polynomial_evaluate/2,
         derive_interpolating_value/2]).

%% Types
-type participant_id() :: pos_integer().
-type scalar() :: <<_:256>>.
-type compressed_pt() :: <<_:256>>.
-type nonce_pair() :: {HidingNonce :: scalar(), BindingNonce :: scalar()}.
-type nonce_commitment_pair() :: {HidingNonceComm :: compressed_pt(), BindingNonceComm :: compressed_pt()}.
-type commitment_tuple() :: {participant_id(), HidingNonceComm :: compressed_pt(), BindingNonceComm :: compressed_pt()}.
-type commitment_list() :: [commitment_tuple()].
-type binding_factor_tuple() :: {participant_id(), scalar()}.
-type binding_factor_list() :: [binding_factor_tuple()].
-type sig_share() :: scalar().
-type signature() :: <<_:512>>.

-export_type([participant_id/0, scalar/0, compressed_pt/0,
              nonce_pair/0, nonce_commitment_pair/0,
              commitment_tuple/0, commitment_list/0,
              binding_factor_tuple/0, binding_factor_list/0,
              sig_share/0, signature/0]).

-define(CTX_STRING, <<"FROST-ED25519-SHA512-v1"/utf8>>).

%% ===================================================================
%% Protocol Operations (RFC 9591 §5)
%% ===================================================================

-spec commit(Secret :: scalar()) -> {nonce_pair(), nonce_commitment_pair()}.
commit(Secret) ->
  Rand1 = crypto:strong_rand_bytes(32),
  Rand2 = crypto:strong_rand_bytes(32),
  commit(Secret, {Rand1, Rand2}).

-spec commit(Secret :: scalar(), {RandHiding :: binary(), RandBinding :: binary()}) ->
  {nonce_pair(), nonce_commitment_pair()}.
commit(Secret, {RandHiding, RandBinding}) ->
  HidingNonce  = nonce_generate(Secret, RandHiding),
  BindingNonce = nonce_generate(Secret, RandBinding),
  HidingNonceComm  = compress_scalar_mul(HidingNonce),
  BindingNonceComm = compress_scalar_mul(BindingNonce),
  {{HidingNonce, BindingNonce}, {HidingNonceComm, BindingNonceComm}}.

-spec sign(Id :: participant_id(),
           SecretShare :: scalar(),
           GroupPublicKey :: compressed_pt(),
           NoncePair :: nonce_pair(),
           Msg :: binary(),
           CommitmentList :: commitment_list()) -> sig_share().
sign(Id, SecretShare, GroupPublicKey, {HidingNonce, BindingNonce}, Msg, CommitmentList) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(GroupPublicKey, SortedList, Msg),
  BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
  GroupCommitment = compute_group_commitment(SortedList, BindingFactorList),
  ParticipantList = participants_from_commitment_list(SortedList),
  LambdaId = derive_lagrange_coefficient(Id, ParticipantList),
  Challenge = compute_challenge(GroupCommitment, GroupPublicKey, Msg),

  %% z_i = d_i + (e_i * rho_i) + (lambda_i * s_i * c)
  Term1 = mul_sc(BindingNonce, BindingFactor),
  Term2 = mul_sc(LambdaId, mul_sc(SecretShare, Challenge)),
  add_sc(HidingNonce, add_sc(Term1, Term2)).

-spec verify_signature_share(Id :: participant_id(),
                             PublicKeyShare :: compressed_pt(),
                             CommitmentPair :: nonce_commitment_pair(),
                             SigShare :: sig_share(),
                             CommitmentList :: commitment_list(),
                             GroupPublicKey :: compressed_pt(),
                             Msg :: binary()) -> boolean().
verify_signature_share(Id, PublicKeyShare, {HidingNonceComm, BindingNonceComm},
                       SigShare, CommitmentList, GroupPublicKey, Msg) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(GroupPublicKey, SortedList, Msg),
  BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
  GroupCommitment = compute_group_commitment(SortedList, BindingFactorList),
  Challenge = compute_challenge(GroupCommitment, GroupPublicKey, Msg),
  ParticipantList = participants_from_commitment_list(SortedList),
  LambdaId = derive_lagrange_coefficient(Id, ParticipantList),

  %% CommShare = HidingNonceComm + BindingFactor * BindingNonceComm
  PtHiding = ecu_ed25519:decompress(HidingNonceComm),
  PtBinding = ecu_ed25519:decompress(BindingNonceComm),
  CommShare = ecu_ed25519:p_add(PtHiding, ecu_ed25519:scalar_mul_noclamp(BindingFactor, PtBinding)),

  %% LHS = SigShare * G
  LHS = ecu_ed25519:scalar_mul_base_noclamp(SigShare),

  %% RHS = CommShare + (Challenge * LambdaId) * PublicKeyShare
  PtPub = ecu_ed25519:decompress(PublicKeyShare),
  RHS = ecu_ed25519:p_add(CommShare, ecu_ed25519:scalar_mul_noclamp(mul_sc(Challenge, LambdaId), PtPub)),

  ecu_ed25519:pt_eq(LHS, RHS).

-spec aggregate(CommitmentList :: commitment_list(),
                Msg :: binary(),
                GroupPublicKey :: compressed_pt(),
                SigShares :: [sig_share()]) -> signature().
aggregate(CommitmentList, Msg, GroupPublicKey, SigShares) ->
  SortedList = sort_commitment_list(CommitmentList),
  BindingFactorList = compute_binding_factors(GroupPublicKey, SortedList, Msg),
  GroupCommitment = compute_group_commitment(SortedList, BindingFactorList),
  Z = lists:foldl(fun(Share, Acc) -> add_sc(Acc, Share) end, <<0:256>>, SigShares),
  <<GroupCommitment:32/binary, Z:32/binary>>.

%% ===================================================================
%% Protocol Subroutines (RFC 9591 §4)
%% ===================================================================

-spec nonce_generate(Secret :: scalar()) -> scalar().
nonce_generate(Secret) ->
  Rand = crypto:strong_rand_bytes(32),
  nonce_generate(Secret, Rand).

-spec nonce_generate(Secret :: scalar(), RandomBytes :: binary()) -> scalar().
nonce_generate(Secret, RandomBytes) ->
  hash_3(<<RandomBytes/binary, Secret/binary>>).

-spec compute_binding_factors(GroupPublicKey :: compressed_pt(),
                              CommitmentList :: commitment_list(),
                              Msg :: binary()) -> binding_factor_list().
compute_binding_factors(GroupPublicKey, CommitmentList, Msg) ->
  SortedList = sort_commitment_list(CommitmentList),
  MsgHash = hash_4(Msg),
  EncodedCommitmentHash = hash_5(encode_group_commitment_list(SortedList)),
  RhoInputPrefix = <<GroupPublicKey:32/binary, MsgHash/binary, EncodedCommitmentHash/binary>>,
  [ {Id, hash_1(<<RhoInputPrefix/binary, (sc(Id)):32/binary>>)} || {Id, _, _} <- SortedList ].

-spec compute_group_commitment(CommitmentList :: commitment_list(),
                               BindingFactorList :: binding_factor_list()) -> compressed_pt().
compute_group_commitment(CommitmentList, BindingFactorList) ->
  SortedList = sort_commitment_list(CommitmentList),
  Pts = [ begin
            PtHiding = ecu_ed25519:decompress(HidingComm),
            PtBinding = ecu_ed25519:decompress(BindingComm),
            BindingFactor = binding_factor_for_participant(BindingFactorList, Id),
            ecu_ed25519:p_add(PtHiding, ecu_ed25519:scalar_mul_noclamp(BindingFactor, PtBinding))
          end || {Id, HidingComm, BindingComm} <- SortedList ],
  ecu_ed25519:compress(fold_pts(Pts)).

-spec compute_challenge(GroupCommitment :: compressed_pt(),
                        GroupPublicKey :: compressed_pt(),
                        Msg :: binary()) -> scalar().
compute_challenge(GroupCommitment, GroupPublicKey, Msg) ->
  hash_2(<<GroupCommitment:32/binary, GroupPublicKey:32/binary, Msg/binary>>).

-spec encode_group_commitment_list(CommitmentList :: commitment_list()) -> binary().
encode_group_commitment_list(CommitmentList) ->
  SortedList = sort_commitment_list(CommitmentList),
  << <<(sc(Id)):32/binary, HidingComm:32/binary, BindingComm:32/binary>>
     || {Id, HidingComm, BindingComm} <- SortedList >>.

-spec derive_lagrange_coefficient(Id :: participant_id(),
                                  ParticipantList :: [participant_id()]) -> scalar().
derive_lagrange_coefficient(Id, ParticipantList) ->
  derive_lagrange_coefficient(Id, ParticipantList, sc(1), sc(1)).

-spec derive_lagrange_coefficient(Id :: participant_id(),
                                  Rest :: [participant_id()],
                                  Num :: scalar(),
                                  Den :: scalar()) -> scalar().
derive_lagrange_coefficient(_, [], Num, Den) ->
  mul_sc(Num, inv_sc(Den));
derive_lagrange_coefficient(Id, [Id | Js], Num, Den) ->
  derive_lagrange_coefficient(Id, Js, Num, Den);
derive_lagrange_coefficient(Id, [J | Js], Num, Den) ->
  derive_lagrange_coefficient(Id, Js, mul_sc(Num, sc(J)), mul_sc(Den, sub_sc(sc(J), sc(Id)))).

-spec derive_interpolating_value(ParticipantList :: [participant_id()],
                                 Id :: participant_id()) -> scalar().
derive_interpolating_value(ParticipantList, Id) ->
  derive_lagrange_coefficient(Id, ParticipantList).

%% ===================================================================
%% Trusted Dealer Key Generation (RFC 9591 Appendix C)
%% ===================================================================

-spec trusted_dealer_keygen(MinParticipants :: pos_integer(),
                            MaxParticipants :: pos_integer()) ->
  {[{participant_id(), scalar()}], compressed_pt(), [compressed_pt()]}.
trusted_dealer_keygen(MinParticipants, MaxParticipants) ->
  SecretKey = rnd_scalar(),
  trusted_dealer_keygen(SecretKey, MinParticipants, MaxParticipants).

-spec trusted_dealer_keygen(SecretKey :: scalar(),
                            MinParticipants :: pos_integer(),
                            MaxParticipants :: pos_integer()) ->
  {[{participant_id(), scalar()}], compressed_pt(), [compressed_pt()]}.
trusted_dealer_keygen(SecretKey, MinParticipants, MaxParticipants)
    when MinParticipants >= 1, MaxParticipants >= MinParticipants ->
  RandomCoeffs = [ rnd_scalar() || _ <- lists:seq(1, MinParticipants - 1) ],
  Coeffs = [SecretKey | RandomCoeffs],
  Shares = [ {I, polynomial_evaluate(I, Coeffs)} || I <- lists:seq(1, MaxParticipants) ],
  VSSCommitment = [ compress_scalar_mul(C) || C <- Coeffs ],
  GroupPublicKey = hd(VSSCommitment),
  {Shares, GroupPublicKey, VSSCommitment}.

-spec vss_verify(Id :: participant_id(),
                 Share :: scalar(),
                 VSSCommitment :: [compressed_pt()]) -> boolean().
vss_verify(Id, Share, VSSCommitment) ->
  LHS = ecu_ed25519:scalar_mul_base_noclamp(Share),
  Terms = [ begin
              Exp = pow_scalar(sc(Id), K),
              Pt = ecu_ed25519:decompress(Comm),
              ecu_ed25519:scalar_mul_noclamp(Exp, Pt)
            end || {K, Comm} <- lists:zip(lists:seq(0, length(VSSCommitment) - 1), VSSCommitment) ],
  RHS = fold_pts(Terms),
  ecu_ed25519:pt_eq(LHS, RHS).

-spec secret_share_combine(Shares :: [{participant_id(), scalar()}]) -> scalar().
secret_share_combine(Shares) when length(Shares) >= 1 ->
  Ids = [ Id || {Id, _} <- Shares ],
  Terms = [ mul_sc(Share, derive_lagrange_coefficient(Id, Ids)) || {Id, Share} <- Shares ],
  lists:foldl(fun(T, Acc) -> add_sc(Acc, T) end, <<0:256>>, Terms).

-spec polynomial_evaluate(X :: participant_id() | scalar(), Coeffs :: [scalar()]) -> scalar().
polynomial_evaluate(X, Coeffs) ->
  polynomial_evaluate_horner(sc(X), lists:reverse(Coeffs), <<0:256>>).

-spec polynomial_evaluate_horner(X :: scalar(), RevCoeffs :: [scalar()], Acc :: scalar()) -> scalar().
polynomial_evaluate_horner(_, [], Acc) ->
  Acc;
polynomial_evaluate_horner(X, [Coeff | Rest], Acc) ->
  NextAcc = add_sc(Coeff, mul_sc(Acc, X)),
  polynomial_evaluate_horner(X, Rest, NextAcc).

%% ===================================================================
%% Internal Helpers
%% ===================================================================

-spec hash_x(Infix :: binary(), Binary :: binary()) -> binary().
hash_x(Infix, Binary) ->
  crypto:hash(sha512, <<?CTX_STRING/binary, Infix/binary, Binary/binary>>).

-spec hash_1(Binary :: binary()) -> scalar().
hash_1(Binary) ->
  ecu_ed25519:scalar_reduce(hash_x(<<"rho">>, Binary)).

-spec hash_2(Binary :: binary()) -> scalar().
hash_2(Binary) ->
  ecu_ed25519:scalar_reduce(crypto:hash(sha512, Binary)).

-spec hash_3(Binary :: binary()) -> scalar().
hash_3(Binary) ->
  ecu_ed25519:scalar_reduce(hash_x(<<"nonce">>, Binary)).

-spec hash_4(Binary :: binary()) -> binary().
hash_4(Binary) ->
  hash_x(<<"msg">>, Binary).

-spec hash_5(Binary :: binary()) -> binary().
hash_5(Binary) ->
  hash_x(<<"com">>, Binary).

-spec rnd_scalar() -> scalar().
rnd_scalar() ->
  ecu_ed25519:scalar_reduce(crypto:strong_rand_bytes(64)).

-spec compress_scalar_mul(S :: scalar()) -> compressed_pt().
compress_scalar_mul(S) ->
  ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(S)).

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

-spec fold_pts([ecu_ed25519:pt()]) -> ecu_ed25519:pt().
fold_pts([]) ->
  ecu_ed25519:decompress(<<1:8, 0:248>>); %% Identity (0, 1) in compressed Ed25519
fold_pts([P | Pts]) ->
  lists:foldl(fun(Pt, Acc) -> ecu_ed25519:p_add(Acc, Pt) end, P, Pts).

-spec sc(integer() | binary()) -> scalar().
sc(X) when is_integer(X) -> <<X:256/little>>;
sc(X) when is_binary(X), byte_size(X) =:= 32 -> X.

-spec add_sc(scalar(), scalar()) -> scalar().
add_sc(A, B) ->
  ecu_ed25519:s_add(A, B).

-spec sub_sc(scalar(), scalar()) -> scalar().
sub_sc(A, B) ->
  ecu_ed25519:s_sub(A, B).

-spec mul_sc(scalar(), scalar()) -> scalar().
mul_sc(A, B) ->
  ecu_ed25519:s_mul(A, B).

-spec inv_sc(scalar()) -> scalar().
inv_sc(A) ->
  ecu_ed25519:s_inv(A).

-spec pow_scalar(scalar(), non_neg_integer()) -> scalar().
pow_scalar(_, 0) ->
  sc(1);
pow_scalar(Base, 1) ->
  Base;
pow_scalar(Base, Exp) when Exp > 1 ->
  pow_scalar(Base, Exp, sc(1)).

-spec pow_scalar(scalar(), non_neg_integer(), scalar()) -> scalar().
pow_scalar(_, 0, Acc) ->
  Acc;
pow_scalar(Base, Exp, Acc) when Exp rem 2 =:= 1 ->
  pow_scalar(mul_sc(Base, Base), Exp div 2, mul_sc(Acc, Base));
pow_scalar(Base, Exp, Acc) ->
  pow_scalar(mul_sc(Base, Base), Exp div 2, Acc).
