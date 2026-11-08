%%%-------------------------------------------------------------------
%%% @doc
%%% RFC 9380 Hash-to-Curve algorithms for BLS12-381 G1 and G2:
%%%   - BLS12381G1_XMD:SHA-256_SSWU_RO_ (Simplified SWU + 11-isogeny map)
%%%   - BLS12381G2_XMD:SHA-256_SSWU_RO_ (Simplified SWU over Fp2 + 3-isogeny map)
%%%   - Cofactor clearing for G1 and G2
%%%
%%% Reference:
%%%   - RFC 9380 Section 8.8: https://www.rfc-editor.org/rfc/rfc9380.html#section-8.8
%%%   - RFC 9380 Appendix E.2 (11-Isogeny Map for BLS12-381 G1)
%%%   - RFC 9380 Appendix E.3 (3-Isogeny Map for BLS12-381 G2)
%%%   - RFC 9380 Appendix G.3 (Cofactor Clearing for BLS12-381 G2)
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_h2c).

-typing([eqwalizer]).

-include("ecu_bls12_381.hrl").

-define(FP, ecu_bls12_381_fp).
-define(BLS, ecu_bls12_381).

-type fp() :: non_neg_integer().
-type fp2() :: {fp(), fp()}.

-type g1_affine() :: ?BLS:g1_affine().
-type g2_affine() :: ?BLS:g2_affine().

-export([
  hash_to_curve_g1/1,
  hash_to_curve_g1/2,
  hash_to_curve_g1/3,
  encode_to_curve_g1/1,
  encode_to_curve_g1/2,
  encode_to_curve_g1/3,
  hash_to_curve_g2/1,
  hash_to_curve_g2/2,
  hash_to_curve_g2/3,
  encode_to_curve_g2/1,
  encode_to_curve_g2/2,
  encode_to_curve_g2/3,
  map_to_curve_g1/1,
  map_to_curve_g2/1,
  clear_cofactor_g1/1,
  clear_cofactor_g2/1,
  hash_to_field_g1/3,
  hash_to_field_g2/3,
  default_dst_g1_ro/0,
  default_dst_g1_nu/0,
  default_dst_g2_ro/0,
  default_dst_g2_nu/0
]).

%%%-------------------------------------------------------------------
%%% Default DSTs per RFC 9380 Section 8.8
%%%-------------------------------------------------------------------

-spec default_dst_g1_ro() -> binary().
default_dst_g1_ro() -> <<"BLS12381G1_XMD:SHA-256_SSWU_RO_">>.

-spec default_dst_g1_nu() -> binary().
default_dst_g1_nu() -> <<"BLS12381G1_XMD:SHA-256_SSWU_NU_">>.

-spec default_dst_g2_ro() -> binary().
default_dst_g2_ro() -> <<"BLS12381G2_XMD:SHA-256_SSWU_RO_">>.

-spec default_dst_g2_nu() -> binary().
default_dst_g2_nu() -> <<"BLS12381G2_XMD:SHA-256_SSWU_NU_">>.

%%%-------------------------------------------------------------------
%%% Public H2C API
%%%-------------------------------------------------------------------

-spec hash_to_curve_g1(binary()) -> g1_affine().
hash_to_curve_g1(Msg) ->
  hash_to_curve_g1(Msg, default_dst_g1_ro()).

-spec hash_to_curve_g1(binary(), binary()) -> g1_affine().
hash_to_curve_g1(Msg, DST) ->
  [U0, U1] = hash_to_field_g1(Msg, DST, 2),
  Q0 = map_to_curve_g1(U0),
  Q1 = map_to_curve_g1(U1),
  R = ?BLS:g1_add(Q0, Q1),
  clear_cofactor_g1(R).

-spec hash_to_curve_g1(binary(), binary(), binary()) -> g1_affine().
hash_to_curve_g1(Msg, DST, Aug) ->
  hash_to_curve_g1(<<Aug/binary, Msg/binary>>, DST).

-spec encode_to_curve_g1(binary()) -> g1_affine().
encode_to_curve_g1(Msg) ->
  encode_to_curve_g1(Msg, default_dst_g1_nu()).

-spec encode_to_curve_g1(binary(), binary()) -> g1_affine().
encode_to_curve_g1(Msg, DST) ->
  [U0] = hash_to_field_g1(Msg, DST, 1),
  Q = map_to_curve_g1(U0),
  clear_cofactor_g1(Q).

-spec encode_to_curve_g1(binary(), binary(), binary()) -> g1_affine().
encode_to_curve_g1(Msg, DST, Aug) ->
  encode_to_curve_g1(<<Aug/binary, Msg/binary>>, DST).

-spec hash_to_curve_g2(binary()) -> g2_affine().
hash_to_curve_g2(Msg) ->
  hash_to_curve_g2(Msg, default_dst_g2_ro()).

-spec hash_to_curve_g2(binary(), binary()) -> g2_affine().
hash_to_curve_g2(Msg, DST) ->
  [U0, U1] = hash_to_field_g2(Msg, DST, 2),
  Q0 = map_to_curve_g2(U0),
  Q1 = map_to_curve_g2(U1),
  R = ?BLS:g2_add(Q0, Q1),
  clear_cofactor_g2(R).

-spec hash_to_curve_g2(binary(), binary(), binary()) -> g2_affine().
hash_to_curve_g2(Msg, DST, Aug) ->
  hash_to_curve_g2(<<Aug/binary, Msg/binary>>, DST).

-spec encode_to_curve_g2(binary()) -> g2_affine().
encode_to_curve_g2(Msg) ->
  encode_to_curve_g2(Msg, default_dst_g2_nu()).

-spec encode_to_curve_g2(binary(), binary()) -> g2_affine().
encode_to_curve_g2(Msg, DST) ->
  [U0] = hash_to_field_g2(Msg, DST, 1),
  Q = map_to_curve_g2(U0),
  clear_cofactor_g2(Q).

-spec encode_to_curve_g2(binary(), binary(), binary()) -> g2_affine().
encode_to_curve_g2(Msg, DST, Aug) ->
  encode_to_curve_g2(<<Aug/binary, Msg/binary>>, DST).

%%%-------------------------------------------------------------------
%%% hash_to_field for G1 and G2
%%%-------------------------------------------------------------------

-spec hash_to_field_g1(binary(), binary(), pos_integer()) -> [fp()].
hash_to_field_g1(Msg, DST, Count) ->
  LenInBytes = Count * 64,
  UniformBytes = ecu_h2c:expand_message_xmd(Msg, DST, LenInBytes, sha256),
  unpack_fp_elements(UniformBytes, Count, []).

-spec unpack_fp_elements(binary(), non_neg_integer(), [fp()]) -> [fp()].
unpack_fp_elements(_Bytes, 0, Acc) ->
  lists:reverse(Acc);
unpack_fp_elements(<<Chunk:64/binary, Rest/binary>>, Count, Acc) ->
  Val = binary:decode_unsigned(Chunk) rem ?BLS12_381_P,
  unpack_fp_elements(Rest, Count - 1, [Val | Acc]).

-spec hash_to_field_g2(binary(), binary(), pos_integer()) -> [fp2()].
hash_to_field_g2(Msg, DST, Count) ->
  %% For G2, m = 2, so 2 * 64 = 128 bytes per Fp2 element
  LenInBytes = Count * 128,
  UniformBytes = ecu_h2c:expand_message_xmd(Msg, DST, LenInBytes, sha256),
  unpack_fp2_elements(UniformBytes, Count, []).

-spec unpack_fp2_elements(binary(), non_neg_integer(), [fp2()]) -> [fp2()].
unpack_fp2_elements(_Bytes, 0, Acc) ->
  lists:reverse(Acc);
unpack_fp2_elements(<<Chunk0:64/binary, Chunk1:64/binary, Rest/binary>>, Count, Acc) ->
  E0 = binary:decode_unsigned(Chunk0) rem ?BLS12_381_P,
  E1 = binary:decode_unsigned(Chunk1) rem ?BLS12_381_P,
  unpack_fp2_elements(Rest, Count - 1, [{E0, E1} | Acc]).

%%%-------------------------------------------------------------------
%%% G1 Map to Curve & Cofactor Clearing
%%%-------------------------------------------------------------------

-spec map_to_curve_g1(fp()) -> g1_affine().
map_to_curve_g1(U) ->
  {Xprime, Yprime} = sswu_g1(U),
  isogeny_11(Xprime, Yprime).

-spec clear_cofactor_g1(g1_affine()) -> g1_affine().
clear_cofactor_g1(P) ->
  %% h_eff = 1 - z = 0xd201000000010001
  ?BLS:g1_scalar_mul(P, 16#d201000000010001).

%%% G1 Simplified SWU on isogenous curve E': y'^2 = x'^3 + A'*x' + B'
%%% Z = 11
-define(G1_Z, 11).
-define(G1_APRIME,
  16#144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d
).
-define(G1_BPRIME,
  16#12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0
).
-define(G1_C2,
  16#4610e003bd3ac94dfa9246c390d7a78942602029175a4ca366d601f33f3946e3ed39794735c38315d874bc1d70637c3
).

-spec sswu_g1(fp()) -> {fp(), fp()}.
sswu_g1(U) ->
  Tv1_0 = ?FP:fp_sqr(U),
  Tv1 = ?FP:fp_mul(?G1_Z, Tv1_0),
  Tv2_0 = ?FP:fp_sqr(Tv1),
  Tv2 = ?FP:fp_add(Tv2_0, Tv1),
  Tv3_0 = ?FP:fp_add(Tv2, 1),
  Tv3 = ?FP:fp_mul(?G1_BPRIME, Tv3_0),
  Tv4_0 =
    case Tv2 =/= 0 of
      true -> ?FP:fp_neg(Tv2);
      false -> ?G1_Z
    end,
  Tv4 = ?FP:fp_mul(?G1_APRIME, Tv4_0),
  Tv2_1 = ?FP:fp_sqr(Tv3),
  Tv6_0 = ?FP:fp_sqr(Tv4),
  Tv5_0 = ?FP:fp_mul(?G1_APRIME, Tv6_0),
  Tv2_2 = ?FP:fp_mul(?FP:fp_add(Tv2_1, Tv5_0), Tv3),
  Tv6 = ?FP:fp_mul(Tv6_0, Tv4),
  Tv5 = ?FP:fp_mul(?G1_BPRIME, Tv6),
  Tv2_3 = ?FP:fp_add(Tv2_2, Tv5),
  X_cand = ?FP:fp_mul(Tv1, Tv3),
  {IsSquare, Y1} = sqrt_ratio_g1(Tv2_3, Tv6),
  Y_cand = ?FP:fp_mul(?FP:fp_mul(Tv1, U), Y1),
  X =
    case IsSquare of
      true -> Tv3;
      false -> X_cand
    end,
  Y =
    case IsSquare of
      true -> Y1;
      false -> Y_cand
    end,
  E1 = (U rem 2 =:= Y rem 2),
  Y_final =
    case E1 of
      true -> Y;
      false -> ?FP:fp_neg(Y)
    end,
  X_final = ?FP:fp_mul(X, ?FP:fp_inv(Tv4)),
  {X_final, Y_final}.

-spec sqrt_ratio_g1(fp(), fp()) -> {boolean(), fp()}.
sqrt_ratio_g1(U, V) ->
  C1 = (?BLS12_381_P - 3) div 4,
  Tv1 = ?FP:fp_sqr(V),
  Tv2 = ?FP:fp_mul(U, V),
  Tv1_1 = ?FP:fp_mul(Tv1, Tv2),
  Y1 = ?FP:fp_mul(?FP:fp_pow(Tv1_1, C1), Tv2),
  Y2 = ?FP:fp_mul(Y1, ?G1_C2),
  case ?FP:fp_mul(?FP:fp_sqr(Y1), V) =:= U of
    true -> {true, Y1};
    false -> {false, Y2}
  end.

%%% G1 11-isogeny map per RFC 9380 Appendix E.2
-spec isogeny_11(fp(), fp()) -> {fp(), fp()}.
isogeny_11(X, Y) ->
  X_num = eval_poly_fp(iso_g1_x_num(), X),
  X_den = eval_poly_monic_fp(iso_g1_x_den(), X),
  Y_num = eval_poly_fp(iso_g1_y_num(), X),
  Y_den = eval_poly_monic_fp(iso_g1_y_den(), X),

  X_out = ?FP:fp_mul(X_num, ?FP:fp_inv(X_den)),
  Y_frac = ?FP:fp_mul(Y_num, ?FP:fp_inv(Y_den)),
  Y_out = ?FP:fp_mul(Y, Y_frac),
  {X_out, Y_out}.

-spec eval_poly_fp([fp()], fp()) -> fp().
eval_poly_fp([C | Rest], X) ->
  lists:foldl(fun(Coeff, Acc) -> ?FP:fp_add(?FP:fp_mul(Acc, X), Coeff) end, C, Rest).

-spec eval_poly_monic_fp([fp()], fp()) -> fp().
eval_poly_monic_fp(Coeffs, X) ->
  eval_poly_fp([1 | Coeffs], X).

%%% 11-Isogeny Polynomial Coefficients (highest degree first)
-spec iso_g1_x_num() -> [fp()].
iso_g1_x_num() ->
  [
    16#6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229,
    16#10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b,
    16#169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e,
    16#80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317,
    16#17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e,
    16#d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84,
    16#1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983,
    16#e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9,
    16#1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861,
    16#d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0,
    16#17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb,
    16#11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7
  ].

-spec iso_g1_x_den() -> [fp()].
iso_g1_x_den() ->
  [
    16#95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a,
    16#a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641,
    16#14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e,
    16#772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a,
    16#e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5,
    16#13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e,
    16#3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8,
    16#b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19,
    16#12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff,
    16#8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c
  ].

-spec iso_g1_y_num() -> [fp()].
iso_g1_y_num() ->
  [
    16#15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604,
    16#5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b,
    16#245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133,
    16#b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8,
    16#18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e,
    16#19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132,
    16#e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30,
    16#9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587,
    16#987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29,
    16#4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2,
    16#16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0,
    16#8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb,
    16#1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb,
    16#cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6,
    16#134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696,
    16#90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33
  ].

-spec iso_g1_y_den() -> [fp()].
iso_g1_y_den() ->
  [
    16#e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f,
    16#2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7,
    16#ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc,
    16#accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092,
    16#4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8,
    16#167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55,
    16#1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a,
    16#16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9,
    16#166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c,
    16#8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac,
    16#be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d,
    16#16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416,
    16#58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2,
    16#1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d,
    16#16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1
  ].

%%%-------------------------------------------------------------------
%%% G2 Map to Curve & Cofactor Clearing
%%%-------------------------------------------------------------------

-spec map_to_curve_g2(fp2()) -> g2_affine().
map_to_curve_g2(U) ->
  {Xprime, Yprime} = sswu_g2(U),
  isogeny_3(Xprime, Yprime).

%%% G2 Simplified SWU on isogenous curve E': y'^2 = x'^3 + A'*x' + B' over Fp2
%%% Z = -(2 + u) = {-2, -1}
-define(G2_Z, {?BLS12_381_P - 2, ?BLS12_381_P - 1}).
-define(G2_APRIME, {0, 240}).
-define(G2_BPRIME, {1012, 1012}).

-spec sswu_g2(fp2()) -> {fp2(), fp2()}.
sswu_g2(U) ->
  Tv1_0 = ?FP:fp2_sqr(U),
  Tv1 = ?FP:fp2_mul(?G2_Z, Tv1_0),
  Tv2_0 = ?FP:fp2_sqr(Tv1),
  Tv2 = ?FP:fp2_add(Tv2_0, Tv1),
  Tv3_0 = ?FP:fp2_add(Tv2, ?FP:fp2_one()),
  Tv3 = ?FP:fp2_mul(?G2_BPRIME, Tv3_0),
  Tv4_0 =
    case ?FP:fp2_is_zero(Tv2) of
      false -> ?FP:fp2_neg(Tv2);
      true -> ?G2_Z
    end,
  Tv4 = ?FP:fp2_mul(?G2_APRIME, Tv4_0),
  Tv2_1 = ?FP:fp2_sqr(Tv3),
  Tv6_0 = ?FP:fp2_sqr(Tv4),
  Tv5_0 = ?FP:fp2_mul(?G2_APRIME, Tv6_0),
  Tv2_2 = ?FP:fp2_mul(?FP:fp2_add(Tv2_1, Tv5_0), Tv3),
  Tv6 = ?FP:fp2_mul(Tv6_0, Tv4),
  Tv5 = ?FP:fp2_mul(?G2_BPRIME, Tv6),
  Tv2_3 = ?FP:fp2_add(Tv2_2, Tv5),
  X_cand = ?FP:fp2_mul(Tv1, Tv3),
  {IsSquare, Y1} = sqrt_ratio_g2(Tv2_3, Tv6),
  Y_cand = ?FP:fp2_mul(?FP:fp2_mul(Tv1, U), Y1),
  X =
    case IsSquare of
      true -> Tv3;
      false -> X_cand
    end,
  Y =
    case IsSquare of
      true -> Y1;
      false -> Y_cand
    end,
  E1 = (?FP:fp2_sgn0(U) =:= ?FP:fp2_sgn0(Y)),
  Y_final =
    case E1 of
      true -> Y;
      false -> ?FP:fp2_neg(Y)
    end,
  X_final = ?FP:fp2_mul(X, ?FP:fp2_inv(Tv4)),
  {X_final, Y_final}.

-spec sqrt_ratio_g2(fp2(), fp2()) -> {boolean(), fp2()}.
sqrt_ratio_g2(U, V) ->
  Ratio = ?FP:fp2_mul(U, ?FP:fp2_inv(V)),
  case ?FP:fp2_sqrt(Ratio) of
    {ok, Y1} ->
      {true, Y1};
    error ->
      {ok, Y1} = ?FP:fp2_sqrt(?FP:fp2_mul(?G2_Z, Ratio)),
      {false, Y1}
  end.

%%% G2 3-isogeny map per RFC 9380 Appendix E.3
-spec isogeny_3(fp2(), fp2()) -> {fp2(), fp2()}.
isogeny_3(X, Y) ->
  X_num = eval_poly_fp2(iso_g2_x_num(), X),
  X_den = eval_poly_monic_fp2(iso_g2_x_den(), X),
  Y_num = eval_poly_fp2(iso_g2_y_num(), X),
  Y_den = eval_poly_monic_fp2(iso_g2_y_den(), X),

  X_out = ?FP:fp2_mul(X_num, ?FP:fp2_inv(X_den)),
  Y_frac = ?FP:fp2_mul(Y_num, ?FP:fp2_inv(Y_den)),
  Y_out = ?FP:fp2_mul(Y, Y_frac),
  {X_out, Y_out}.

-spec eval_poly_fp2([fp2()], fp2()) -> fp2().
eval_poly_fp2([C | Rest], X) ->
  lists:foldl(fun(Coeff, Acc) -> ?FP:fp2_add(?FP:fp2_mul(Acc, X), Coeff) end, C, Rest).

-spec eval_poly_monic_fp2([fp2()], fp2()) -> fp2().
eval_poly_monic_fp2(Coeffs, X) ->
  eval_poly_fp2([?FP:fp2_one() | Coeffs], X).

%%% 3-Isogeny Polynomial Coefficients (highest degree first)
-spec iso_g2_x_num() -> [fp2()].
iso_g2_x_num() ->
  [
    {16#171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1,
      0},
    {
      16#11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e,
      16#8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d
    },
    {0,
      16#11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a},
    {
      16#5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6,
      16#5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6
    }
  ].

-spec iso_g2_x_den() -> [fp2()].
iso_g2_x_den() ->
  [
    {12,
      16#1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f},
    {0,
      16#1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63}
  ].

-spec iso_g2_y_num() -> [fp2()].
iso_g2_y_num() ->
  [
    {16#124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10,
      0},
    {
      16#11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c,
      16#8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f
    },
    {0,
      16#5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be},
    {
      16#1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706,
      16#1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706
    }
  ].

-spec iso_g2_y_den() -> [fp2()].
iso_g2_y_den() ->
  [
    {18,
      16#1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99},
    {0,
      16#1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3},
    {
      16#1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb,
      16#1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb
    }
  ].

%%% G2 Cofactor Clearing per RFC 9380 Appendix G.3
-spec clear_cofactor_g2(g2_affine()) -> g2_affine().
clear_cofactor_g2(P) ->
  %% c1 = -0xd201000000010000 (negative)
  %% Since points on E'(Fp2) outside G2 do not have order r,
  %% we must not reduce c1 modulo r.
  %% Multiplication by c1 is -(|c1| * Pt).
  AbsX = 16#d201000000010000,
  MulC1 = fun(Pt) -> ?BLS:g2_neg(?BLS:g2_scalar_mul(Pt, AbsX)) end,
  %% 1. t1 = c1 * P
  T1 = MulC1(P),
  %% 2. t2 = psi(P)
  T2 = psi(P),
  %% 3. t3 = 2 * P
  T3_0 = ?BLS:g2_double(P),
  %% 4. t3 = psi2(t3)
  T3_1 = psi2(T3_0),
  %% 5. t3 = t3 - t2
  T3_2 = ?BLS:g2_sub(T3_1, T2),
  %% 6. t2 = t1 + t2
  T2_1 = ?BLS:g2_add(T1, T2),
  %% 7. t2 = c1 * t2
  T2_2 = MulC1(T2_1),
  %% 8. t3 = t3 + t2
  T3_3 = ?BLS:g2_add(T3_2, T2_2),
  %% 9. t3 = t3 - t1
  T3_4 = ?BLS:g2_sub(T3_3, T1),
  %% 10. Q = t3 - P
  ?BLS:g2_sub(T3_4, P).

%% Frobenius endomorphism psi on G2:
%% psi(x, y) = (c1 * conj(x), c2 * conj(y))
%% c1 = 1 / (1 + u)^((p - 1) / 3)
%% c2 = 1 / (1 + u)^((p - 1) / 2)
-define(PSI_C1,
  {0,
    16#1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad}
).
-define(PSI_C2, {
  16#135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2,
  16#06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09
}).

-spec psi(g2_affine()) -> g2_affine().
psi(infinity) ->
  infinity;
psi({X, Y}) ->
  QX = ?FP:fp2_mul(?PSI_C1, ?FP:fp2_conj(X)),
  QY = ?FP:fp2_mul(?PSI_C2, ?FP:fp2_conj(Y)),
  {QX, QY}.

%% psi2(P) = psi(psi(P))
%% psi2(x, y) = (c1 * x, -y)
%% c1 = 1 / 2^((p - 1) / 3) in Fp
-define(PSI2_C1,
  16#1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac
).

-spec psi2(g2_affine()) -> g2_affine().
psi2(infinity) ->
  infinity;
psi2({X, Y}) ->
  QX = ?FP:fp2_mul_fp(X, ?PSI2_C1),
  QY = ?FP:fp2_neg(Y),
  {QX, QY}.
