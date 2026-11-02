%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for RFC 9380 Hash-to-Curve (`ecu_h2c').
%%% @end
%%%-------------------------------------------------------------------
-module(h2c_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_msg() ->
  ?LET(Len, choose(0, 128), binary(Len)).

gen_dst() ->
  ?LET(Len, choose(1, 48), binary(Len)).

gen_suite() ->
  elements([
    secp256k1_xmd_sha256_sswu_ro,
    secp256k1_xmd_sha256_sswu_nu,
    edwards25519_xmd_sha512_ell2_ro,
    edwards25519_xmd_sha512_ell2_nu,
    edwards448_xof_shake256_ell2_ro,
    edwards448_xof_shake256_ell2_nu
  ]).

%% ===================================================================
%% Properties: secp256k1
%% ===================================================================

prop_secp256k1_on_curve_and_subgroup() ->
  ?FORALL(
    {Msg, DST},
    {gen_msg(), gen_dst()},
    begin
      PtRO = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, DST),
      PtNU = ecu_h2c:encode_to_curve(secp256k1_xmd_sha256_sswu_nu, Msg, DST),

      OnCurveRO = ecu_secp256k1:on_curve(PtRO),
      OnCurveNU = ecu_secp256k1:on_curve(PtNU),

      SubgroupRO = (ecu_secp256k1:scalar_mul(ecu_secp256k1:n(), PtRO) =:= {0, 0}),
      SubgroupNU = (ecu_secp256k1:scalar_mul(ecu_secp256k1:n(), PtNU) =:= {0, 0}),

      OnCurveRO andalso OnCurveNU andalso SubgroupRO andalso SubgroupNU
    end
  ).

prop_secp256k1_differential_rustcrypto() ->
  case ecu_rustcrypto_nif:is_available() of
    false ->
      true;
    true ->
      ?FORALL(
        {Msg, DST},
        {gen_msg(), gen_dst()},
        begin
          {ROx, ROy} = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, DST),
          UncompressedRO = <<4:8, ROx:256, ROy:256>>,
          RustPtRO = ecu_rustcrypto_nif:secp256k1_hash_to_curve(Msg, DST),

          {NUx, NUy} = ecu_h2c:encode_to_curve(secp256k1_xmd_sha256_sswu_nu, Msg, DST),
          UncompressedNU = <<4:8, NUx:256, NUy:256>>,
          RustPtNU = ecu_rustcrypto_nif:secp256k1_encode_to_curve(Msg, DST),

          (UncompressedRO =:= RustPtRO) andalso (UncompressedNU =:= RustPtNU)
        end
      )
  end.

%% ===================================================================
%% Properties: edwards25519
%% ===================================================================

prop_edwards25519_on_curve_and_subgroup() ->
  ?FORALL(
    {Msg, DST},
    {gen_msg(), gen_dst()},
    begin
      PtRO = ecu_h2c:hash_to_curve(edwards25519_xmd_sha512_ell2_ro, Msg, DST),
      PtNU = ecu_h2c:encode_to_curve(edwards25519_xmd_sha512_ell2_nu, Msg, DST),

      OnCurveRO = ecu_ed25519:on_curve(PtRO),
      OnCurveNU = ecu_ed25519:on_curve(PtNU),

      SubgroupRO =
        (ecu_ed25519:to_affine(ecu_ed25519:scalar_mul_noclamp(ecu_ed25519:n(), PtRO)) =:= {0, 1}),
      SubgroupNU =
        (ecu_ed25519:to_affine(ecu_ed25519:scalar_mul_noclamp(ecu_ed25519:n(), PtNU)) =:= {0, 1}),

      OnCurveRO andalso OnCurveNU andalso SubgroupRO andalso SubgroupNU
    end
  ).

%% ===================================================================
%% Properties: edwards448
%% ===================================================================

prop_edwards448_on_curve_and_subgroup() ->
  ?FORALL(
    {Msg, DST},
    {gen_msg(), gen_dst()},
    begin
      PtRO = ecu_h2c:hash_to_curve(edwards448_xof_shake256_ell2_ro, Msg, DST),
      PtNU = ecu_h2c:encode_to_curve(edwards448_xof_shake256_ell2_nu, Msg, DST),

      OnCurveRO = ecu_ed448:on_curve(PtRO),
      OnCurveNU = ecu_ed448:on_curve(PtNU),

      SubgroupRO =
        (ecu_ed448:to_affine(ecu_ed448:scalar_mul_noclamp(ecu_ed448:n(), PtRO)) =:= {0, 1}),
      SubgroupNU =
        (ecu_ed448:to_affine(ecu_ed448:scalar_mul_noclamp(ecu_ed448:n(), PtNU)) =:= {0, 1}),

      OnCurveRO andalso OnCurveNU andalso SubgroupRO andalso SubgroupNU
    end
  ).

%% ===================================================================
%% Properties: Domain Separation and RO vs NU
%% ===================================================================

prop_domain_separation() ->
  ?FORALL(
    {Msg, DST1, Suffix},
    {gen_msg(), gen_dst(), ?LET(S, choose(1, 10), binary(S))},
    begin
      DST2 = <<DST1/binary, Suffix/binary>>,
      Pt1 = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, DST1),
      Pt2 = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, DST2),
      Pt1 =/= Pt2
    end
  ).

prop_ro_vs_nu_distinct() ->
  ?FORALL(
    {Msg, DST},
    {gen_msg(), gen_dst()},
    begin
      PtRO = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, DST),
      PtNU = ecu_h2c:encode_to_curve(secp256k1_xmd_sha256_sswu_nu, Msg, DST),
      PtRO =/= PtNU
    end
  ).

prop_oversize_dst() ->
  ?FORALL(
    {Msg, Len},
    {gen_msg(), choose(256, 350)},
    begin
      LongDST = binary:copy(<<"D">>, Len),
      PtSecp = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, LongDST),
      PtEd25519 = ecu_h2c:hash_to_curve(edwards25519_xmd_sha512_ell2_ro, Msg, LongDST),
      PtEd448 = ecu_h2c:hash_to_curve(edwards448_xof_shake256_ell2_ro, Msg, LongDST),

      ecu_secp256k1:on_curve(PtSecp) andalso
        ecu_ed25519:on_curve(PtEd25519) andalso
        ecu_ed448:on_curve(PtEd448)
    end
  ).
