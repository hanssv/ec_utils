%%%-------------------------------------------------------------------
%%% @doc
%%% FROST: Distributed Key Generation (DKG)
%%% Two-round Distributed Key Generation with Schnorr Proof of Knowledge
%%% for the FROST threshold signing scheme.
%%% Ciphersuite-aware supporting both 'ed25519' (default) and 'secp256k1'.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_frost_dkg).

-export([round1/3, round1/4,
         round1_check/4, round1_check/5,
         round2/2, round2/3,
         round2_check/3, round2_check/4,
         compute_private_sign_share/1, compute_private_sign_share/2,
         compute_private_sign_share/3,
         compute_public_verification_share/1, compute_public_verification_share/2,
         compute_public_verification_share/3,
         compute_public_key/1, compute_public_key/2]).

%% Types
-type ciphersuite() :: ecu_frost:ciphersuite().
-type participant_id() :: ecu_frost:participant_id().
-type scalar() :: ecu_frost:scalar().
-type compressed_pt() :: ecu_frost:compressed_pt().
-type pok() :: <<_:512>> | <<_:520>> | <<_:912>>.
-type polynomial() :: [scalar()].

-export_type([ciphersuite/0, participant_id/0, scalar/0, compressed_pt/0, pok/0, polynomial/0]).

-define(SECP256K1_N, 16#fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141).

%% ===================================================================
%% Round 1: Polynomial commitment and Proof of Knowledge
%% ===================================================================

-spec round1(Id :: participant_id(),
             T :: pos_integer(),
             CtxString :: binary()) ->
  {polynomial(), pok(), [compressed_pt()]}.
round1(Id, T, CtxString) ->
  round1(ed25519, Id, T, CtxString).

-spec round1(Suite :: ciphersuite(),
             Id :: participant_id(),
             T :: pos_integer(),
             CtxString :: binary()) ->
  {polynomial(), pok(), [compressed_pt()]}.
round1(ed25519, Id, T, CtxString) when T >= 1 ->
  Cs = [C0 | _] = [ ecu_ed25519:scalar_reduce(crypto:strong_rand_bytes(64)) || _ <- lists:seq(1, T) ],
  K   = ecu_ed25519:scalar_reduce(crypto:strong_rand_bytes(64)),
  R   = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(K)),
  GC0 = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(C0)),
  C   = ecu_ed25519:scalar_reduce(crypto:hash(sha512, <<Id:256/little, CtxString/binary, GC0/binary, R/binary>>)),
  Mu  = ecu_ed25519:s_add(K, ecu_ed25519:s_mul(C0, C)),
  C0Prf = <<R:32/binary, Mu:32/binary>>,
  PubC = [ ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Coeff)) || Coeff <- Cs ],
  {Cs, C0Prf, PubC};
round1(ed448, Id, T, CtxString) when T >= 1 ->
  Cs = [C0 | _] = [ ecu_ed448:scalar_reduce(crypto:strong_rand_bytes(114)) || _ <- lists:seq(1, T) ],
  K   = ecu_ed448:scalar_reduce(crypto:strong_rand_bytes(114)),
  R   = ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(K)),
  GC0 = ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(C0)),
  C   = ecu_ed448:scalar_reduce(crypto:hash_xof(shake256, <<Id:456/little, CtxString/binary, GC0/binary, R/binary>>, 114 * 8)),
  Mu  = ecu_ed448:s_add(K, ecu_ed448:s_mul(C0, C)),
  C0Prf = <<R:57/binary, Mu:57/binary>>,
  PubC = [ ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(Coeff)) || Coeff <- Cs ],
  {Cs, C0Prf, PubC};
round1(secp256k1, Id, T, CtxString) when T >= 1 ->
  Cs = [C0 | _] = [ rnd_scalar_secp256k1() || _ <- lists:seq(1, T) ],
  K   = rnd_scalar_secp256k1(),
  <<K_int:256>> = K,
  <<C0_int:256>> = C0,
  R   = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(K_int)),
  GC0 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(C0_int)),
  C   = ecu_frost:compute_challenge(secp256k1, GC0, R, <<Id:256/big, CtxString/binary>>),
  <<C_int:256>> = C,
  Mu_int = (K_int + C0_int * C_int) rem ?SECP256K1_N,
  C0Prf = <<R:33/binary, Mu_int:256/big>>,
  PubC = [ begin
             <<Coeff_int:256>> = Coeff,
              ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(Coeff_int))
           end || Coeff <- Cs ],
  {Cs, C0Prf, PubC};
round1(bip340, Id, T, CtxString) ->
  round1(secp256k1, Id, T, CtxString).

-spec round1_check(Id :: participant_id(),
                   CtxString :: binary(),
                   C0Prf :: pok(),
                   PubC :: [compressed_pt()]) -> boolean().
round1_check(Id, CtxString, C0Prf, PubC) ->
  round1_check(ed25519, Id, CtxString, C0Prf, PubC).

-spec round1_check(Suite :: ciphersuite(),
                   Id :: participant_id(),
                   CtxString :: binary(),
                   C0Prf :: pok(),
                   PubC :: [compressed_pt()]) -> boolean().
round1_check(ed25519, Id, CtxString, <<R:32/binary, Mu:32/binary>>, [C0 | _]) ->
  C = ecu_ed25519:scalar_reduce(crypto:hash(sha512, <<Id:256/little, CtxString/binary, C0/binary, R/binary>>)),
  LHS = ecu_ed25519:scalar_mul_base_noclamp(Mu),
  PtR = ecu_ed25519:decompress(R),
  PtC0 = ecu_ed25519:decompress(C0),
  RHS = ecu_ed25519:p_add(PtR, ecu_ed25519:scalar_mul_noclamp(C, PtC0)),
  ecu_ed25519:pt_eq(LHS, RHS);
round1_check(ed448, Id, CtxString, <<R:57/binary, Mu:57/binary>>, [C0 | _]) ->
  C = ecu_ed448:scalar_reduce(crypto:hash_xof(shake256, <<Id:456/little, CtxString/binary, C0/binary, R/binary>>, 114 * 8)),
  LHS = ecu_ed448:scalar_mul_base_noclamp(Mu),
  PtR = ecu_ed448:decompress(R),
  PtC0 = ecu_ed448:decompress(C0),
  RHS = ecu_ed448:p_add(PtR, ecu_ed448:scalar_mul_noclamp(C, PtC0)),
  ecu_ed448:pt_eq(LHS, RHS);
round1_check(bip340, Id, CtxString, C0Prf, PubC) ->
  round1_check(secp256k1, Id, CtxString, C0Prf, PubC);
round1_check(secp256k1, Id, CtxString, <<R:33/binary, Mu:32/binary>>, [C0 | _]) ->
  C = ecu_frost:compute_challenge(secp256k1, C0, R, <<Id:256/big, CtxString/binary>>),
  <<Mu_int:256>> = Mu,
  <<C_int:256>> = C,
  LHS = ecu_secp256k1:scalar_mul_base(Mu_int),
  PtR = ecu_secp256k1:decompress(R),
  PtC0 = ecu_secp256k1:decompress(C0),
  RHS = ecu_secp256k1:p_add(PtR, ecu_secp256k1:scalar_mul(C_int, PtC0)),
  LHS =:= RHS;
round1_check(_, _, _, _, _) ->
  false.

%% ===================================================================
%% Round 2: Share distribution and verification
%% ===================================================================

-spec round2(N :: pos_integer(), Cs :: polynomial()) ->
  [{participant_id(), scalar()}].
round2(N, Cs) ->
  round2(ed25519, N, Cs).

-spec round2(Suite :: ciphersuite(), N :: pos_integer(), Cs :: polynomial()) ->
  [{participant_id(), scalar()}].
round2(Suite, N, Cs) when N >= 1 ->
  [ {I, ecu_frost:polynomial_evaluate(Suite, I, Cs)} || I <- lists:seq(1, N) ].

-spec round2_check(Id :: participant_id(),
                   ShareVal :: scalar(),
                   PubC :: [compressed_pt()]) -> boolean().
round2_check(Id, ShareVal, PubC) ->
  round2_check(ed25519, Id, ShareVal, PubC).

-spec round2_check(Suite :: ciphersuite(),
                   Id :: participant_id(),
                   ShareVal :: scalar(),
                   PubC :: [compressed_pt()]) -> boolean().
round2_check(ed25519, Id, ShareVal, PubC) ->
  LHS = ecu_ed25519:scalar_mul_base_noclamp(ShareVal),
  Exponents = pows_ed25519(<<Id:256/little>>, length(PubC)),
  Ps = [ ecu_ed25519:scalar_mul_noclamp(E, ecu_ed25519:decompress(C))
         || {E, C} <- lists:zip(Exponents, PubC) ],
  RHS = fold_pts_ed25519(Ps),
  ecu_ed25519:pt_eq(LHS, RHS);
round2_check(ed448, Id, ShareVal, PubC) ->
  LHS = ecu_ed448:scalar_mul_base_noclamp(ShareVal),
  Exponents = pows_ed448(<<Id:456/little>>, length(PubC)),
  Ps = [ ecu_ed448:scalar_mul_noclamp(E, ecu_ed448:decompress(C))
         || {E, C} <- lists:zip(Exponents, PubC) ],
  RHS = fold_pts_ed448(Ps),
  ecu_ed448:pt_eq(LHS, RHS);
round2_check(bip340, Id, ShareVal, PubC) ->
  round2_check(secp256k1, Id, ShareVal, PubC);
round2_check(secp256k1, Id, ShareVal, PubC) ->
  <<S_int:256>> = ShareVal,
  LHS = ecu_secp256k1:scalar_mul_base(S_int),
  Exponents = pows_secp256k1(Id, length(PubC)),
  Ps = [ ecu_secp256k1:scalar_mul(E, ecu_secp256k1:decompress(C))
         || {E, C} <- lists:zip(Exponents, PubC) ],
  RHS = fold_pts_secp256k1(Ps),
  LHS =:= RHS.

%% ===================================================================
%% Key & Share Derivation
%% ===================================================================

-spec compute_private_sign_share([{participant_id(), scalar()}]) -> scalar().
compute_private_sign_share(Shares) ->
  compute_private_sign_share(ed25519, Shares).

-spec compute_private_sign_share(Suite :: ciphersuite(),
                                 Shares :: [{participant_id(), scalar()}]) -> scalar().
compute_private_sign_share(ed25519, Shares) when length(Shares) >= 1 ->
  lists:foldl(fun({_, S}, Acc) -> ecu_ed25519:s_add(Acc, S) end, <<0:256>>, Shares);
compute_private_sign_share(ed448, Shares) when length(Shares) >= 1 ->
  lists:foldl(fun({_, S}, Acc) -> ecu_ed448:s_add(Acc, S) end, <<0:456>>, Shares);
compute_private_sign_share(bip340, Shares) when length(Shares) >= 1 ->
  compute_private_sign_share(secp256k1, Shares);
compute_private_sign_share(secp256k1, Shares) when length(Shares) >= 1 ->
  Sum = lists:foldl(fun({_, <<S:256>>}, Acc) -> (Acc + S) rem ?SECP256K1_N end, 0, Shares),
  <<Sum:256/big>>.

-spec compute_private_sign_share(Suite :: ciphersuite(),
                                 Shares :: [{participant_id(), scalar()}],
                                 PubCs :: [[compressed_pt()]]) -> scalar().
compute_private_sign_share(bip340, Shares, PubCs) ->
  RawShare = compute_private_sign_share(secp256k1, Shares),
  GroupPubKey = compute_public_key(secp256k1, PubCs),
  case GroupPubKey of
    <<2:8, _:32/binary>> ->
      RawShare;
    <<3:8, _:32/binary>> ->
      <<S_int:256>> = RawShare,
      NegS = (?SECP256K1_N - S_int) rem ?SECP256K1_N,
      <<NegS:256/big>>
  end;
compute_private_sign_share(Suite, Shares, _PubCs) ->
  compute_private_sign_share(Suite, Shares).

-spec compute_public_verification_share([{participant_id(), scalar()}]) -> compressed_pt().
compute_public_verification_share(Shares) ->
  compute_public_verification_share(ed25519, Shares).

-spec compute_public_verification_share(ciphersuite(), [{participant_id(), scalar()}]) -> compressed_pt();
                                       (participant_id(), [[compressed_pt()]]) -> compressed_pt().
compute_public_verification_share(ed25519, Shares) when is_list(Shares) ->
  ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(compute_private_sign_share(ed25519, Shares)));
compute_public_verification_share(ed448, Shares) when is_list(Shares) ->
  ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(compute_private_sign_share(ed448, Shares)));
compute_public_verification_share(bip340, Shares) when is_list(Shares) ->
  compute_public_verification_share(secp256k1, Shares);
compute_public_verification_share(secp256k1, Shares) when is_list(Shares) ->
  <<S_int:256>> = compute_private_sign_share(secp256k1, Shares),
  ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(S_int));
compute_public_verification_share(Id, PubCs) when is_integer(Id), is_list(PubCs) ->
  compute_public_verification_share(ed25519, Id, PubCs).

-spec compute_public_verification_share(Suite :: ciphersuite(),
                                        IdOrShares :: participant_id() | [{participant_id(), scalar()}],
                                        PubCs :: [[compressed_pt()]]) -> compressed_pt().
compute_public_verification_share(bip340, Shares, PubCs) when is_list(Shares) ->
  PrivShare = compute_private_sign_share(bip340, Shares, PubCs),
  <<S_int:256>> = PrivShare,
  ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(S_int));
compute_public_verification_share(Suite, Shares, _PubCs) when is_list(Shares) ->
  compute_public_verification_share(Suite, Shares);
compute_public_verification_share(ed25519, Id, [PubC1 | _] = PubCs) when is_integer(Id) ->
  Exponents = pows_ed25519(<<Id:256/little>>, length(PubC1)),
  Pts = [ ecu_ed25519:scalar_mul_noclamp(E, ecu_ed25519:decompress(C))
          || PubC <- PubCs, {E, C} <- lists:zip(Exponents, PubC) ],
  ecu_ed25519:compress(fold_pts_ed25519(Pts));
compute_public_verification_share(ed448, Id, [PubC1 | _] = PubCs) when is_integer(Id) ->
  Exponents = pows_ed448(<<Id:456/little>>, length(PubC1)),
  Pts = [ ecu_ed448:scalar_mul_noclamp(E, ecu_ed448:decompress(C))
          || PubC <- PubCs, {E, C} <- lists:zip(Exponents, PubC) ],
  ecu_ed448:compress(fold_pts_ed448(Pts));
compute_public_verification_share(bip340, Id, PubCs) when is_integer(Id) ->
  RawShare = compute_public_verification_share(secp256k1, Id, PubCs),
  GroupPubKey = compute_public_key(secp256k1, PubCs),
  case GroupPubKey of
    <<2:8, _:32/binary>> -> RawShare;
    <<3:8, _:32/binary>> ->
      Pt = ecu_secp256k1:decompress(RawShare),
      ecu_secp256k1:compress(ecu_secp256k1:p_neg(Pt))
  end;
compute_public_verification_share(secp256k1, Id, [PubC1 | _] = PubCs) when is_integer(Id) ->
  Exponents = pows_secp256k1(Id, length(PubC1)),
  Pts = [ ecu_secp256k1:scalar_mul(E, ecu_secp256k1:decompress(C))
          || PubC <- PubCs, {E, C} <- lists:zip(Exponents, PubC) ],
  ecu_secp256k1:compress(fold_pts_secp256k1(Pts)).

-spec compute_public_key(PubCs :: [[compressed_pt()]]) -> compressed_pt().
compute_public_key(PubCs) ->
  compute_public_key(ed25519, PubCs).

-spec compute_public_key(Suite :: ciphersuite(),
                         PubCs :: [[compressed_pt()]]) -> compressed_pt().
compute_public_key(ed25519, PubCs) when length(PubCs) >= 1 ->
  Pts = [ ecu_ed25519:decompress(C0) || [C0 | _] <- PubCs ],
  ecu_ed25519:compress(fold_pts_ed25519(Pts));
compute_public_key(ed448, PubCs) when length(PubCs) >= 1 ->
  Pts = [ ecu_ed448:decompress(C0) || [C0 | _] <- PubCs ],
  ecu_ed448:compress(fold_pts_ed448(Pts));
compute_public_key(bip340, PubCs) when length(PubCs) >= 1 ->
  Pts = [ ecu_secp256k1:decompress(C0) || [C0 | _] <- PubCs ],
  {X, _Y} = fold_pts_secp256k1(Pts),
  <<X:256/big>>;
compute_public_key(secp256k1, PubCs) when length(PubCs) >= 1 ->
  Pts = [ ecu_secp256k1:decompress(C0) || [C0 | _] <- PubCs ],
  ecu_secp256k1:compress(fold_pts_secp256k1(Pts)).

%% ===================================================================
%% Internal Helpers
%% ===================================================================

-spec rnd_scalar_secp256k1() -> scalar().
rnd_scalar_secp256k1() ->
  Val = binary:decode_unsigned(crypto:strong_rand_bytes(48)) rem ?SECP256K1_N,
  case Val of
    0 -> rnd_scalar_secp256k1();
    _ -> <<Val:256/big>>
  end.

-spec pows_ed25519(scalar(), non_neg_integer()) -> [scalar()].
pows_ed25519(X, N) ->
  pows_ed25519(<<1:256/little>>, X, N).

-spec pows_ed25519(scalar(), scalar(), non_neg_integer()) -> [scalar()].
pows_ed25519(_, _, 0) ->
  [];
pows_ed25519(X, X0, N) ->
  [X | pows_ed25519(ecu_ed25519:s_mul(X, X0), X0, N - 1)].

-spec pows_ed448(scalar(), non_neg_integer()) -> [scalar()].
pows_ed448(X, N) ->
  pows_ed448(<<1:456/little>>, X, N).

-spec pows_ed448(scalar(), scalar(), non_neg_integer()) -> [scalar()].
pows_ed448(_, _, 0) ->
  [];
pows_ed448(X, X0, N) ->
  [X | pows_ed448(ecu_ed448:s_mul(X, X0), X0, N - 1)].

-spec pows_secp256k1(non_neg_integer(), non_neg_integer()) -> [non_neg_integer()].
pows_secp256k1(X, N) ->
  pows_secp256k1(1, X rem ?SECP256K1_N, N).

-spec pows_secp256k1(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> [non_neg_integer()].
pows_secp256k1(_, _, 0) ->
  [];
pows_secp256k1(X, X0, N) ->
  [X | pows_secp256k1((X * X0) rem ?SECP256K1_N, X0, N - 1)].

-spec fold_pts_ed25519([ecu_ed25519:pt()]) -> ecu_ed25519:pt().
fold_pts_ed25519([]) ->
  ecu_ed25519:decompress(<<1:8, 0:248>>);
fold_pts_ed25519([P | Pts]) ->
  lists:foldl(fun(Pt, Acc) -> ecu_ed25519:p_add(Acc, Pt) end, P, Pts).

-spec fold_pts_ed448([ecu_ed448:pt()]) -> ecu_ed448:pt().
fold_pts_ed448([]) ->
  ecu_ed448:decompress(<<1:8, 0:448>>);
fold_pts_ed448([P | Pts]) ->
  lists:foldl(fun(Pt, Acc) -> ecu_ed448:p_add(Acc, Pt) end, P, Pts).

-spec fold_pts_secp256k1([ecu_secp256k1:pt_affine()]) -> ecu_secp256k1:pt_affine().
fold_pts_secp256k1([]) ->
  {0, 0};
fold_pts_secp256k1([P | Pts]) ->
  lists:foldl(fun(Pt, Acc) -> ecu_secp256k1:p_add(Acc, Pt) end, P, Pts).
