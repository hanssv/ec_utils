%%%-------------------------------------------------------------------
%%% @doc
%%% FROST: Distributed Key Generation (DKG)
%%% Two-round Distributed Key Generation with Schnorr Proof of Knowledge
%%% for the FROST threshold signing scheme.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_frost_dkg).

-export([round1/3, round1_check/4,
         round2/2, round2_check/3,
         compute_private_sign_share/1,
         compute_public_verification_share/1,
         compute_public_verification_share/2,
         compute_public_key/1]).

%% Types
-type participant_id() :: pos_integer().
-type scalar() :: <<_:256>>.
-type compressed_pt() :: <<_:256>>.
-type pok() :: <<_:512>>.
-type polynomial() :: [scalar()].

-export_type([participant_id/0, scalar/0, compressed_pt/0, pok/0, polynomial/0]).

%% ===================================================================
%% Round 1: Polynomial commitment and Proof of Knowledge
%% ===================================================================

-spec round1(Id :: participant_id(),
             T :: pos_integer(),
             CtxString :: binary()) ->
  {polynomial(), pok(), [compressed_pt()]}.
round1(Id, T, CtxString) when T >= 1 ->
  Cs = [C0 | _] = [ rnd_scalar() || _ <- lists:seq(1, T) ],

  %% Proof of knowledge of C0
  K   = rnd_scalar(),
  R   = compress(sc_mul(K)),
  GC0 = compress(sc_mul(C0)),
  C   = hash_to_scalar(<<(sc(Id)):32/binary, CtxString/binary, GC0:32/binary, R:32/binary>>),
  Mu  = add_sc(K, mul_sc(C0, C)),
  C0Prf = <<R:32/binary, Mu:32/binary>>,

  %% Public commitments to coefficients
  PubC = [ compress(sc_mul(Coeff)) || Coeff <- Cs ],

  {Cs, C0Prf, PubC}.

-spec round1_check(Id :: participant_id(),
                   CtxString :: binary(),
                   C0Prf :: pok(),
                   PubC :: [compressed_pt()]) -> boolean().
round1_check(Id, CtxString, <<R:32/binary, Mu:32/binary>>, [C0 | _]) ->
  C = hash_to_scalar(<<(sc(Id)):32/binary, CtxString/binary, C0:32/binary, R:32/binary>>),
  LHS = sc_mul(Mu),
  PtR = ecu_ed25519:decompress(R),
  PtC0 = ecu_ed25519:decompress(C0),
  RHS = ecu_ed25519:p_add(PtR, ecu_ed25519:scalar_mul_noclamp(C, PtC0)),
  ecu_ed25519:pt_eq(LHS, RHS);
round1_check(_, _, _, _) ->
  false.

%% ===================================================================
%% Round 2: Share distribution and verification
%% ===================================================================

-spec round2(N :: pos_integer(), Cs :: polynomial()) ->
  [{participant_id(), scalar()}].
round2(N, Cs) when N >= 1 ->
  [ {I, ecu_frost:polynomial_evaluate(I, Cs)} || I <- lists:seq(1, N) ].

-spec round2_check(Id :: participant_id(),
                   ShareVal :: scalar(),
                   PubC :: [compressed_pt()]) -> boolean().
round2_check(Id, ShareVal, PubC) ->
  LHS = sc_mul(ShareVal),
  Exponents = pows(sc(Id), length(PubC)),
  Ps = [ ecu_ed25519:scalar_mul_noclamp(E, ecu_ed25519:decompress(C))
         || {E, C} <- lists:zip(Exponents, PubC) ],
  RHS = add_pts(Ps),
  ecu_ed25519:pt_eq(LHS, RHS).

%% ===================================================================
%% Key & Share Derivation
%% ===================================================================

-spec compute_private_sign_share([{participant_id(), scalar()}]) -> scalar().
compute_private_sign_share(Shares) when length(Shares) >= 1 ->
  lists:foldl(fun({_, S}, Acc) -> add_sc(Acc, S) end, <<0:256>>, Shares).

-spec compute_public_verification_share([{participant_id(), scalar()}]) -> compressed_pt().
compute_public_verification_share(Shares) ->
  compress(sc_mul(compute_private_sign_share(Shares))).

-spec compute_public_verification_share(Id :: participant_id(),
                                        PubCs :: [[compressed_pt()]]) -> compressed_pt().
compute_public_verification_share(Id, [PubC1 | _] = PubCs) ->
  Exponents = pows(sc(Id), length(PubC1)),
  Pts = [ ecu_ed25519:scalar_mul_noclamp(E, ecu_ed25519:decompress(C))
          || PubC <- PubCs, {E, C} <- lists:zip(Exponents, PubC) ],
  compress(add_pts(Pts)).

-spec compute_public_key(PubCs :: [[compressed_pt()]]) -> compressed_pt().
compute_public_key(PubCs) when length(PubCs) >= 1 ->
  Pts = [ ecu_ed25519:decompress(C0) || [C0 | _] <- PubCs ],
  compress(add_pts(Pts)).

%% ===================================================================
%% Internal Helpers
%% ===================================================================

-spec pows(scalar(), non_neg_integer()) -> [scalar()].
pows(X, N) ->
  pows(sc(1), X, N).

-spec pows(scalar(), scalar(), non_neg_integer()) -> [scalar()].
pows(_, _, 0) ->
  [];
pows(X, X0, N) ->
  [X | pows(mul_sc(X, X0), X0, N - 1)].

-spec hash_to_scalar(binary()) -> scalar().
hash_to_scalar(Binary) ->
  ecu_ed25519:scalar_reduce(crypto:hash(sha512, Binary)).

-spec rnd_scalar() -> scalar().
rnd_scalar() ->
  ecu_ed25519:scalar_reduce(crypto:strong_rand_bytes(64)).

-spec sc_mul(scalar()) -> ecu_ed25519:pt().
sc_mul(S) ->
  ecu_ed25519:scalar_mul_base_noclamp(S).

-spec add_sc(scalar(), scalar()) -> scalar().
add_sc(A, B) ->
  ecu_ed25519:s_add(A, B).

-spec mul_sc(scalar(), scalar()) -> scalar().
mul_sc(A, B) ->
  ecu_ed25519:s_mul(A, B).

-spec compress(ecu_ed25519:pt()) -> compressed_pt().
compress(P) ->
  ecu_ed25519:compress(P).

-spec add_pts([ecu_ed25519:pt()]) -> ecu_ed25519:pt().
add_pts([]) ->
  ecu_ed25519:decompress(<<1:8, 0:248>>); %% Identity
add_pts([P | Pts]) ->
  lists:foldl(fun(Pt, Acc) -> ecu_ed25519:p_add(Acc, Pt) end, P, Pts).

-spec sc(integer() | binary()) -> scalar().
sc(X) when is_integer(X) -> <<X:256/little>>;
sc(X) when is_binary(X), byte_size(X) =:= 32 -> X.
