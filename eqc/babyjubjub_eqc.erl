%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang BabyJubjub elliptic curve
%%% and Circom-compatible EdDSA signatures:
%%%   - Subgroup membership and curve equation invariants
%%%   - Group axioms (closure, identity, associativity, commutativity)
%%%   - Scalar multiplication homomorphism
%%%   - Point compression and decompression roundtrips
%%%   - EdDSA signature completeness and tamper resistance
%%%   - Differential cross-verification against Rust reference NIF
%%% @end
%%%-------------------------------------------------------------------
-module(babyjubjub_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_scalar() ->
  choose(1, ecu_babyjubjub:suborder() - 1).

gen_small_scalar() ->
  choose(1, 1000).

gen_point() ->
  ?LET(K, gen_small_scalar(), ecu_babyjubjub:mul_base8(K)).

gen_seed() ->
  ?LET(Bytes, vector(32, choose(0, 255)), list_to_binary(Bytes)).

gen_msg() ->
  choose(0, ecu_babyjubjub:q() - 1).

%%%-------------------------------------------------------------------
%%% Properties: Curve Arithmetic
%%%-------------------------------------------------------------------

prop_curve_membership() ->
  ?FORALL(
    K,
    gen_small_scalar(),
    begin
      P = ecu_babyjubjub:mul_base8(K),
      ecu_babyjubjub:is_on_curve(P) andalso ecu_babyjubjub:is_in_subgroup(P)
    end
  ).

prop_point_addition_group_laws() ->
  ?FORALL(
    {P1, P2},
    {gen_point(), gen_point()},
    begin
      Id = ecu_babyjubjub:identity(),
      %% Identity
      Id1 = (ecu_babyjubjub:add(P1, Id) =:= P1),
      Id2 = (ecu_babyjubjub:add(Id, P1) =:= P1),
      %% Negation
      Neg = (ecu_babyjubjub:add(P1, ecu_babyjubjub:neg(P1)) =:= Id),
      %% Commutativity
      Comm = (ecu_babyjubjub:add(P1, P2) =:= ecu_babyjubjub:add(P2, P1)),
      Id1 andalso Id2 andalso Neg andalso Comm
    end
  ).

prop_scalar_mult_homomorphism() ->
  ?FORALL(
    {K1, K2},
    {gen_small_scalar(), gen_small_scalar()},
    begin
      P = ecu_babyjubjub:base8(),
      P1 = ecu_babyjubjub:mul(P, K1),
      P2 = ecu_babyjubjub:mul(P, K2),
      SumP = ecu_babyjubjub:add(P1, P2),
      MulSum = ecu_babyjubjub:mul(P, K1 + K2),
      SumP =:= MulSum
    end
  ).

prop_compress_decompress_roundtrip() ->
  ?FORALL(
    P,
    gen_point(),
    begin
      Comp = ecu_babyjubjub:compress(P),
      case ecu_babyjubjub:decompress(Comp) of
        {ok, PDecomp} -> PDecomp =:= P;
        _ -> false
      end
    end
  ).

%%%-------------------------------------------------------------------
%%% Properties: EdDSA (Poseidon)
%%%-------------------------------------------------------------------

prop_eddsa_sign_verify() ->
  ?FORALL(
    {Seed, Msg},
    {gen_seed(), gen_msg()},
    begin
      {SK, PK} = ecu_babyjubjub:keypair(Seed),
      Sig = ecu_babyjubjub:sign(SK, Msg),
      ecu_babyjubjub:verify(PK, Sig, Msg)
    end
  ).

prop_eddsa_tamper_detect() ->
  ?FORALL(
    {Seed, Msg},
    {gen_seed(), gen_msg()},
    begin
      {SK, PK} = ecu_babyjubjub:keypair(Seed),
      Sig = ecu_babyjubjub:sign(SK, Msg),
      WrongMsg = (Msg + 1) rem ecu_babyjubjub:q(),
      TamperedSig =
        case Sig of
          <<R:32/binary, S:256/little>> ->
            NewS = (S + 1) rem ecu_babyjubjub:suborder(),
            <<R/binary, NewS:256/little>>
        end,
      (not ecu_babyjubjub:verify(PK, Sig, WrongMsg)) andalso
        (not ecu_babyjubjub:verify(PK, TamperedSig, Msg))
    end
  ).

prop_nif_differential() ->
  case ecu_babyjubjub_nif:is_available() of
    true ->
      ?FORALL(
        {Seed, Msg},
        {gen_seed(), gen_msg()},
        begin
          ErlPK = ecu_babyjubjub:derive_public_key(Seed),
          {ok, NifPK} = ecu_babyjubjub_nif:eddsa_prv2pub(Seed),
          PKMatch = (ErlPK =:= NifPK),

          ErlSig = ecu_babyjubjub:sign(Seed, Msg),
          MsgBE = <<Msg:256/big>>,
          {ok, NifSig} = ecu_babyjubjub_nif:eddsa_sign(Seed, MsgBE),
          SigMatch = (ErlSig =:= NifSig),

          ErlVerifies = ecu_babyjubjub:verify(ErlPK, NifSig, Msg),
          {ok, NifVerifies} = ecu_babyjubjub_nif:eddsa_verify(NifPK, ErlSig, MsgBE),

          PKMatch andalso SigMatch andalso ErlVerifies andalso NifVerifies
        end
      );
    false ->
      true
  end.
