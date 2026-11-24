%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang Jubjub elliptic curve (BLS12-381)
%%% and RedJubjub signatures (ZIP 215 / ZIP 216 / Zcash Spec §5.4.7.1):
%%%   - Curve invariants and subgroup membership
%%%   - Projective Twisted Edwards group axioms
%%%   - Full 255-bit Montgomery ladder consistency
%%%   - RedJubjub SpendAuth and Binding sign/verify roundtrip
%%%   - RedJubjub public key and keypair re-randomization
%%%   - Adversarial rejection of non-canonical scalars, identity/torsion keys
%%%   - Differential cross-verification against Rust `redjubjub` reference NIF
%%% @end
%%%-------------------------------------------------------------------
-module(jubjub_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_scalar() ->
  choose(1, ecu_jubjub:suborder() - 1).

gen_small_scalar() ->
  choose(1, 1000).

gen_large_scalar() ->
  choose(ecu_jubjub:q() - 5000, ecu_jubjub:q() - 1).

gen_point() ->
  ?LET(K, gen_small_scalar(), ecu_jubjub:mul(ecu_jubjub:generator(), K)).

gen_sig_type() ->
  oneof([spend_auth, binding]).

gen_sk() ->
  ?LET(S, gen_scalar(), <<S:256/little>>).

gen_msg_bin() ->
  ?LET(Bytes, binary(), Bytes).

%%%-------------------------------------------------------------------
%%% Properties: Curve Arithmetic
%%%-------------------------------------------------------------------

prop_curve_membership() ->
  ?FORALL(
    K,
    gen_small_scalar(),
    begin
      P = ecu_jubjub:mul(ecu_jubjub:generator(), K),
      ecu_jubjub:is_on_curve(P) andalso ecu_jubjub:is_in_subgroup(P)
    end
  ).

prop_point_addition_group_laws() ->
  ?FORALL(
    {P1, P2},
    {gen_point(), gen_point()},
    begin
      Id = ecu_jubjub:identity(),
      Id1 = (ecu_jubjub:add(P1, Id) =:= P1),
      Id2 = (ecu_jubjub:add(Id, P1) =:= P1),
      Neg = (ecu_jubjub:add(P1, ecu_jubjub:neg(P1)) =:= Id),
      Comm = (ecu_jubjub:add(P1, P2) =:= ecu_jubjub:add(P2, P1)),
      Id1 andalso Id2 andalso Neg andalso Comm
    end
  ).

prop_scalar_mult_homomorphism() ->
  ?FORALL(
    {K1, K2},
    {gen_small_scalar(), gen_small_scalar()},
    begin
      P = ecu_jubjub:generator(),
      P1 = ecu_jubjub:mul(P, K1),
      P2 = ecu_jubjub:mul(P, K2),
      SumP = ecu_jubjub:add(P1, P2),
      MulSum = ecu_jubjub:mul(P, K1 + K2),
      SumP =:= MulSum
    end
  ).

prop_compress_decompress_roundtrip() ->
  ?FORALL(
    P,
    gen_point(),
    begin
      Comp = ecu_jubjub:compress(P),
      case ecu_jubjub:decompress(Comp) of
        {ok, PDecomp} -> PDecomp =:= P;
        _ -> false
      end
    end
  ).

prop_montgomery_ladder_full_range() ->
  Gen = ecu_jubjub:generator(),
  MGen = ecu_jubjub:edwards_to_montgomery(Gen),
  {UGen, _} = MGen,
  ?FORALL(
    K,
    gen_large_scalar(),
    begin
      EdK = ecu_jubjub:mul(Gen, K),
      case ecu_jubjub:edwards_to_montgomery(EdK) of
        infinity ->
          ecu_jubjub:montgomery_ladder(K, UGen) =:= 0;
        {ExpectedU, _} ->
          ecu_jubjub:montgomery_ladder(K, UGen) =:= ExpectedU
      end
    end
  ).

%%%-------------------------------------------------------------------
%%% Properties: RedJubjub Signatures
%%%-------------------------------------------------------------------

prop_redjubjub_sign_verify() ->
  ?FORALL(
    {SK, Msg, SigType},
    {gen_sk(), gen_msg_bin(), gen_sig_type()},
    begin
      PK = ecu_jubjub:redjubjub_derive_public_key(SK, SigType),
      Sig = ecu_jubjub:redjubjub_sign(SK, Msg, SigType),
      ecu_jubjub:redjubjub_verify(PK, Msg, Sig, SigType)
    end
  ).

prop_redjubjub_tamper_detect() ->
  ?FORALL(
    {SK, Msg, SigType},
    {gen_sk(), gen_msg_bin(), gen_sig_type()},
    begin
      PK = ecu_jubjub:redjubjub_derive_public_key(SK, SigType),
      Sig = ecu_jubjub:redjubjub_sign(SK, Msg, SigType),
      WrongMsg = <<Msg/binary, 1>>,
      TamperedSig =
        case Sig of
          <<R:32/binary, S:256/little>> ->
            NewS = (S + 1) rem ecu_jubjub:suborder(),
            <<R/binary, NewS:256/little>>
        end,
      (not ecu_jubjub:redjubjub_verify(PK, WrongMsg, Sig, SigType)) andalso
        (not ecu_jubjub:redjubjub_verify(PK, Msg, TamperedSig, SigType))
    end
  ).

prop_redjubjub_rerandomize() ->
  ?FORALL(
    {SK, Msg, AlphaInt},
    {gen_sk(), gen_msg_bin(), gen_scalar()},
    begin
      Alpha = <<AlphaInt:256/little>>,
      PK = ecu_jubjub:redjubjub_derive_public_key(SK, spend_auth),
      RandPK = ecu_jubjub:redjubjub_rerandomize_public_key(PK, Alpha),
      {RandSK, RandDerivedPK} = ecu_jubjub:redjubjub_rerandomize_keypair(SK, Alpha),
      RandSig = ecu_jubjub:redjubjub_sign(RandSK, Msg, spend_auth),

      (RandPK =:= RandDerivedPK) andalso
        ecu_jubjub:redjubjub_verify(RandPK, Msg, RandSig, spend_auth)
    end
  ).

prop_redjubjub_adversarial_rejections() ->
  Id = ecu_jubjub:identity(),
  Order2Pt = {0, ecu_jubjub:q() - 1},
  IdComp = ecu_jubjub:compress(Id),
  Order2Comp = ecu_jubjub:compress(Order2Pt),
  Suborder = ecu_jubjub:suborder(),

  ?FORALL(
    {SK, Msg, SigType},
    {gen_sk(), gen_msg_bin(), gen_sig_type()},
    begin
      PK = ecu_jubjub:redjubjub_derive_public_key(SK, SigType),
      Sig = ecu_jubjub:redjubjub_sign(SK, Msg, SigType),
      <<RComp:32/binary, _S:256/little>> = Sig,

      %% 1. Rejection of identity and order-2 public keys
      V1 = (not ecu_jubjub:redjubjub_verify(Id, Msg, Sig, SigType)),
      V2 = (not ecu_jubjub:redjubjub_verify(Order2Pt, Msg, Sig, SigType)),
      V3 = (not ecu_jubjub:redjubjub_verify(IdComp, Msg, Sig, SigType)),
      V4 = (not ecu_jubjub:redjubjub_verify(Order2Comp, Msg, Sig, SigType)),

      %% 2. Rejection of non-canonical scalar S >= SUBORDER
      BadSSig = <<RComp:32/binary, (Suborder + 1):256/little>>,
      V5 = (not ecu_jubjub:redjubjub_verify(PK, Msg, BadSSig, SigType)),

      V1 andalso V2 andalso V3 andalso V4 andalso V5
    end
  ).

prop_redjubjub_nif_differential() ->
  case ecu_jubjub_nif:is_available() of
    true ->
      ?FORALL(
        {SK, Msg, SigType},
        {gen_sk(), gen_msg_bin(), gen_sig_type()},
        begin
          ErlPK = ecu_jubjub:redjubjub_derive_public_key(SK, SigType),
          {ok, NifPK} = ecu_jubjub_nif:redjubjub_derive_public_key(SK, SigType),
          PKMatch = (ErlPK =:= NifPK),

          ErlSig = ecu_jubjub:redjubjub_sign(SK, Msg, SigType),
          {ok, NifSig} = ecu_jubjub_nif:redjubjub_sign(SK, Msg, SigType),

          ErlVerifiesNif = ecu_jubjub:redjubjub_verify(ErlPK, Msg, NifSig, SigType),
          NifVerifiesErl = ecu_jubjub_nif:redjubjub_verify(NifPK, Msg, ErlSig, SigType),

          PKMatch andalso ErlVerifiesNif andalso NifVerifiesErl
        end
      );
    false ->
      true
  end.
