%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang BLS12-381 pairing-friendly cryptography:
%%%   - G1 and G2 curve arithmetic and compression roundtrips
%%%   - Subgroup membership invariants
%%%   - Optimal Ate pairing bilinearity and pairing check
%%%   - Hash-to-curve group properties (RFC 9380)
%%%   - IETF BLS signatures (min_pk and min_sig) and aggregation
%%%   - Differential equivalence against Supranational blst oracle
%%% @end
%%%-------------------------------------------------------------------
-module(bls12_381_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

-include("ecu_bls12_381.hrl").

-define(BLS, ecu_bls12_381).
-define(SIG, ecu_bls12_381_sig).
-define(NIF, ecu_bls12_381_nif).

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_scalar() ->
  ?LET(K, choose(1, ?BLS12_381_R - 1), K).

gen_small_scalar() ->
  choose(1, 1000).

gen_g1_point() ->
  ?LET(K, gen_scalar(), ?BLS:g1_scalar_mul_base(K)).

gen_g2_point() ->
  ?LET(K, gen_scalar(), ?BLS:g2_scalar_mul_base(K)).

gen_ikm() ->
  ?LET(Bytes, choose(32, 64), binary(Bytes)).

%%%-------------------------------------------------------------------
%%% Group Properties
%%%-------------------------------------------------------------------

prop_g1_compress_decompress() ->
  ?FORALL(
    K,
    gen_scalar(),
    begin
      P = ?BLS:g1_scalar_mul_base(K),
      Comp = ?BLS:g1_compress(P),
      case ?BLS:g1_decompress(Comp) of
        {ok, P2} ->
          P2 =:= P andalso ?BLS:g1_is_in_subgroup(P2);
        _ ->
          false
      end
    end
  ).

prop_g2_compress_decompress() ->
  ?FORALL(
    K,
    gen_scalar(),
    begin
      Q = ?BLS:g2_scalar_mul_base(K),
      Comp = ?BLS:g2_compress(Q),
      case ?BLS:g2_decompress(Comp) of
        {ok, Q2} ->
          Q2 =:= Q andalso ?BLS:g2_is_in_subgroup(Q2);
        _ ->
          false
      end
    end
  ).

prop_g1_add_homomorphism() ->
  ?FORALL(
    {K1, K2},
    {gen_small_scalar(), gen_small_scalar()},
    begin
      P1 = ?BLS:g1_scalar_mul_base(K1),
      P2 = ?BLS:g1_scalar_mul_base(K2),
      SumP = ?BLS:g1_add(P1, P2),
      ExpectedP = ?BLS:g1_scalar_mul_base((K1 + K2) rem ?BLS12_381_R),
      SumP =:= ExpectedP
    end
  ).

prop_g2_add_homomorphism() ->
  ?FORALL(
    {K1, K2},
    {gen_small_scalar(), gen_small_scalar()},
    begin
      Q1 = ?BLS:g2_scalar_mul_base(K1),
      Q2 = ?BLS:g2_scalar_mul_base(K2),
      SumQ = ?BLS:g2_add(Q1, Q2),
      ExpectedQ = ?BLS:g2_scalar_mul_base((K1 + K2) rem ?BLS12_381_R),
      SumQ =:= ExpectedQ
    end
  ).

%%%-------------------------------------------------------------------
%%% Pairing Properties
%%%-------------------------------------------------------------------

prop_pairing_bilinearity() ->
  ?FORALL(
    K,
    choose(1, 20),
    begin
      P = ?BLS:g1_scalar_mul_base(K),
      Q = ?BLS:g2_scalar_mul_base(K),
      E1 = ?BLS:pairing(P, ?BLS:g2_generator()),
      E2 = ?BLS:pairing(?BLS:g1_generator(), Q),
      E1 =:= E2
    end
  ).

prop_pairing_check_cancellation() ->
  ?FORALL(
    K,
    choose(1, 50),
    begin
      P = ?BLS:g1_scalar_mul_base(K),
      Q = ?BLS:g2_scalar_mul_base(K),
      NegP = ?BLS:g1_neg(P),
      ?BLS:pairing_check([
        {P, Q},
        {NegP, Q}
      ])
    end
  ).

%%%-------------------------------------------------------------------
%%% Hash-to-Curve Properties
%%%-------------------------------------------------------------------

prop_g1_h2c_subgroup() ->
  ?FORALL(
    Msg,
    binary(),
    begin
      P = ?BLS:g1_hash_to_curve(Msg),
      ?BLS:g1_on_curve(P) andalso ?BLS:g1_is_in_subgroup(P)
    end
  ).

prop_g2_h2c_subgroup() ->
  ?FORALL(
    Msg,
    binary(),
    begin
      Q = ?BLS:g2_hash_to_curve(Msg),
      ?BLS:g2_on_curve(Q) andalso ?BLS:g2_is_in_subgroup(Q)
    end
  ).

%%%-------------------------------------------------------------------
%%% BLS Signature Schemes (min_pk & min_sig)
%%%-------------------------------------------------------------------

prop_min_pk_sign_verify() ->
  ?FORALL(
    {IKM, Msg},
    {gen_ikm(), binary()},
    begin
      {ok, {PK, SK}} = ?SIG:min_pk_keygen(IKM),
      Sig = ?SIG:min_pk_sign(SK, Msg),
      ?SIG:min_pk_verify(PK, Msg, Sig)
    end
  ).

prop_min_sig_sign_verify() ->
  ?FORALL(
    {IKM, Msg},
    {gen_ikm(), binary()},
    begin
      {ok, {PK, SK}} = ?SIG:min_sig_keygen(IKM),
      Sig = ?SIG:min_sig_sign(SK, Msg),
      ?SIG:min_sig_verify(PK, Msg, Sig)
    end
  ).

prop_min_pk_fast_aggregate() ->
  ?FORALL(
    {IKMs, Msg},
    {vector(3, gen_ikm()), binary()},
    begin
      KeyPairs = [
        begin
          {ok, {PK, SK}} = ?SIG:min_pk_keygen(IKM),
          {PK, SK}
        end
       || IKM <- IKMs
      ],
      PKs = [PK || {PK, _} <- KeyPairs],
      SKs = [SK || {_, SK} <- KeyPairs],
      Sigs = [?SIG:min_pk_sign(SK, Msg) || SK <- SKs],
      {ok, SigAgg} = ?SIG:min_pk_aggregate_signatures(Sigs),
      ?SIG:min_pk_fast_aggregate_verify(PKs, Msg, SigAgg)
    end
  ).

prop_min_sig_fast_aggregate() ->
  ?FORALL(
    {IKMs, Msg},
    {vector(3, gen_ikm()), binary()},
    begin
      KeyPairs = [
        begin
          {ok, {PK, SK}} = ?SIG:min_sig_keygen(IKM),
          {PK, SK}
        end
       || IKM <- IKMs
      ],
      PKs = [PK || {PK, _} <- KeyPairs],
      SKs = [SK || {_, SK} <- KeyPairs],
      Sigs = [?SIG:min_sig_sign(SK, Msg) || SK <- SKs],
      {ok, SigAgg} = ?SIG:min_sig_aggregate_signatures(Sigs),
      ?SIG:min_sig_fast_aggregate_verify(PKs, Msg, SigAgg)
    end
  ).

%%%-------------------------------------------------------------------
%%% Differential Oracle Properties vs blst NIF
%%%-------------------------------------------------------------------

prop_differential_g1_mult() ->
  ?FORALL(
    K,
    choose(1, 1000000),
    begin
      case ?NIF:is_available() of
        true ->
          P = ?BLS:g1_scalar_mul_base(K),
          Comp = ?BLS:g1_compress(P),
          G1_nif = ?NIF:g1_generator(),
          {ok, ExpectedComp} = ?NIF:g1_mult(G1_nif, <<K:256/little>>),
          Comp =:= ExpectedComp;
        false ->
          true
      end
    end
  ).

prop_differential_min_pk_sign() ->
  ?FORALL(
    {IKM, Msg},
    {gen_ikm(), binary()},
    begin
      case ?NIF:is_available() of
        true ->
          {ok, {PK_nif, SK_nif}} = ?NIF:min_pk_keygen(IKM),
          {ok, {PK_erl, SK_erl}} = ?SIG:min_pk_keygen(IKM),
          SK_nif =:= SK_erl andalso
            PK_nif =:= PK_erl andalso
            begin
              DST = ?SIG:min_pk_dst_basic(),
              {ok, Sig_nif} = ?NIF:min_pk_sign(SK_nif, Msg, DST),
              Sig_erl = ?SIG:min_pk_sign(SK_erl, Msg, DST),
              Sig_nif =:= Sig_erl
            end;
        false ->
          true
      end
    end
  ).
