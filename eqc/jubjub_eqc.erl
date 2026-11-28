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

      %% 3. Rejection of malformed / truncated inputs
      V6 = (not ecu_jubjub:redjubjub_verify(<<"bad_pk">>, Msg, Sig, SigType)),
      V7 = (not ecu_jubjub:redjubjub_verify(PK, Msg, <<"bad_sig">>, SigType)),

      V1 andalso V2 andalso V3 andalso V4 andalso V5 andalso V6 andalso V7
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

prop_point_arithmetic_differential() ->
  case ecu_jubjub_nif:is_available() of
    true ->
      ?FORALL(
        {K1, K2, S},
        {gen_small_scalar(), gen_small_scalar(), gen_scalar()},
        begin
          P1 = ecu_jubjub:mul(ecu_jubjub:generator(), K1),
          P2 = ecu_jubjub:mul(ecu_jubjub:generator(), K2),
          P1Comp = ecu_jubjub:compress(P1),
          P2Comp = ecu_jubjub:compress(P2),

          %% Point addition
          ErlAdd = ecu_jubjub:compress(ecu_jubjub:add(P1, P2)),
          {ok, NifAdd} = ecu_jubjub_nif:point_add(P1Comp, P2Comp),
          AddMatch = (ErlAdd =:= NifAdd),

          %% Point doubling
          ErlDbl = ecu_jubjub:compress(ecu_jubjub:double(P1)),
          {ok, NifDbl} = ecu_jubjub_nif:point_double(P1Comp),
          DblMatch = (ErlDbl =:= NifDbl),

          %% Scalar multiplication
          ErlMul = ecu_jubjub:compress(ecu_jubjub:mul(P1, S)),
          ScalarLE = <<S:256/little>>,
          {ok, NifMul} = ecu_jubjub_nif:point_mul(P1Comp, ScalarLE),
          MulMatch = (ErlMul =:= NifMul),

          AddMatch andalso DblMatch andalso MulMatch
        end
      );
    false ->
      true
  end.

prop_montgomery_differential() ->
  case ecu_jubjub_nif:is_available() of
    true ->
      Gen = ecu_jubjub:generator(),
      {UGen, _} = ecu_jubjub:edwards_to_montgomery(Gen),
      ?FORALL(
        K,
        gen_large_scalar(),
        begin
          K_bin = <<K:256/little>>,
          U_bin = <<UGen:256/little>>,
          ErlRes = ecu_jubjub:montgomery_ladder(K_bin, U_bin),
          {ok, NifRes} = ecu_jubjub_nif:montgomery_ladder(K_bin, U_bin),
          ErlRes =:= NifRes
        end
      );
    false ->
      true
  end.

prop_subgroup_differential() ->
  case ecu_jubjub_nif:is_available() of
    true ->
      ?FORALL(
        K,
        gen_small_scalar(),
        begin
          P = ecu_jubjub:mul(ecu_jubjub:generator(), K),
          PComp = ecu_jubjub:compress(P),
          ErlOnCurve = ecu_jubjub:is_on_curve(P),
          NifOnCurve = ecu_jubjub_nif:is_on_curve(PComp),
          ErlSubgroup = ecu_jubjub:is_in_subgroup(P),
          NifSubgroup = ecu_jubjub_nif:is_in_subgroup(PComp),

          %% Also check order-2 point
          Order2Pt = {0, ecu_jubjub:q() - 1},
          Order2Comp = ecu_jubjub:compress(Order2Pt),
          ErlOrder2OnCurve = ecu_jubjub:is_on_curve(Order2Pt),
          NifOrder2OnCurve = ecu_jubjub_nif:is_on_curve(Order2Comp),
          ErlOrder2Subgroup = ecu_jubjub:is_in_subgroup(Order2Pt),
          NifOrder2Subgroup = ecu_jubjub_nif:is_in_subgroup(Order2Comp),

          (ErlOnCurve =:= NifOnCurve) andalso (ErlSubgroup =:= NifSubgroup) andalso
            (ErlOrder2OnCurve =:= NifOrder2OnCurve) andalso
            (ErlOrder2Subgroup =:= false) andalso (NifOrder2Subgroup =:= false)
        end
      );
    false ->
      true
  end.
