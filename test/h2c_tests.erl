%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for RFC 9380 Hash-to-Curve (`ecu_h2c').
%%%
%%% Includes official test vectors from RFC 9380 Appendix J:
%%%   - secp256k1 (Appendix J.8.1 and J.8.2)
%%%   - edwards25519 (Appendix J.5.1 and J.5.2)
%%%   - edwards448 (Appendix J.7.1 and J.7.2)
%%% as well as differential testing against RustCrypto reference NIF.
%%% @end
%%%-------------------------------------------------------------------
-module(h2c_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% RFC 9380 Appendix J.8: secp256k1 Test Vectors
%%====================================================================

secp256k1_ro_vectors_test() ->
  Suite = secp256k1_xmd_sha256_sswu_ro,
  DST = <<"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_RO_">>,

  %% 1. msg = ""
  P1_exp =
    {16#c1cae290e291aee617ebaef1be6d73861479c48b841eaba9b7b5852ddfeb1346,
      16#64fa678e07ae116126f08b022a94af6de15985c996c3a91b64c406a960e51067},
  ?assertEqual(P1_exp, ecu_h2c:hash_to_curve(Suite, <<>>, DST)),

  %% 2. msg = "abc"
  P2_exp =
    {16#3377e01eab42db296b512293120c6cee72b6ecf9f9205760bd9ff11fb3cb2c4b,
      16#7f95890f33efebd1044d382a01b1bee0900fb6116f94688d487c6c7b9c8371f6},
  ?assertEqual(P2_exp, ecu_h2c:hash_to_curve(Suite, <<"abc">>, DST)),

  %% 3. msg = "abcdef0123456789"
  P3_exp =
    {16#bac54083f293f1fe08e4a70137260aa90783a5cb84d3f35848b324d0674b0e3a,
      16#4436476085d4c3c4508b60fcf4389c40176adce756b398bdee27bca19758d828},
  ?assertEqual(P3_exp, ecu_h2c:hash_to_curve(Suite, <<"abcdef0123456789">>, DST)),

  %% 4. msg = "q128_" || 128 'q's
  Msg4 = <<"q128_", (binary:copy(<<"q">>, 128))/binary>>,
  P4_exp =
    {16#e2167bc785333a37aa562f021f1e881defb853839babf52a7f72b102e41890e9,
      16#f2401dd95cc35867ffed4f367cd564763719fbc6a53e969fb8496a1e6685d873},
  ?assertEqual(P4_exp, ecu_h2c:hash_to_curve(Suite, Msg4, DST)),

  %% 5. msg = "a512_" || 512 'a's
  Msg5 = <<"a512_", (binary:copy(<<"a">>, 512))/binary>>,
  P5_exp =
    {16#e3c8d35aaaf0b9b647e88a0a0a7ee5d5bed5ad38238152e4e6fd8c1f8cb7c998,
      16#8446eeb6181bf12f56a9d24e262221cc2f0c4725c7e3803024b5888ee5823aa6},
  ?assertEqual(P5_exp, ecu_h2c:hash_to_curve(Suite, Msg5, DST)).

secp256k1_nu_vectors_test() ->
  Suite = secp256k1_xmd_sha256_sswu_nu,
  DST = <<"QUUX-V01-CS02-with-secp256k1_XMD:SHA-256_SSWU_NU_">>,

  %% 1. msg = ""
  P1_exp =
    {16#a4792346075feae77ac3b30026f99c1441b4ecf666ded19b7522cf65c4c55c5b,
      16#62c59e2a6aeed1b23be5883e833912b08ba06be7f57c0e9cdc663f31639ff3a7},
  ?assertEqual(P1_exp, ecu_h2c:encode_to_curve(Suite, <<>>, DST)),

  %% 2. msg = "abc"
  P2_exp =
    {16#3f3b5842033fff837d504bb4ce2a372bfeadbdbd84a1d2b678b6e1d7ee426b9d,
      16#902910d1fef15d8ae2006fc84f2a5a7bda0e0407dc913062c3a493c4f5d876a5},
  ?assertEqual(P2_exp, ecu_h2c:encode_to_curve(Suite, <<"abc">>, DST)).

%%====================================================================
%% RFC 9380 Appendix J.5: edwards25519 Test Vectors
%%====================================================================

edwards25519_ro_vectors_test() ->
  Suite = edwards25519_xmd_sha512_ell2_ro,
  DST = <<"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_">>,

  %% 1. msg = ""
  P1_exp =
    {16#3c3da6925a3c3c268448dcabb47ccde5439559d9599646a8260e47b1e4822fc6,
      16#09a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21},
  ?assertEqual(P1_exp, ecu_h2c:hash_to_curve(Suite, <<>>, DST)),

  %% 2. msg = "abc"
  P2_exp =
    {16#608040b42285cc0d72cbb3985c6b04c935370c7361f4b7fbdb1ae7f8c1a8ecad,
      16#1a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531},
  ?assertEqual(P2_exp, ecu_h2c:hash_to_curve(Suite, <<"abc">>, DST)),

  %% 3. msg = "abcdef0123456789"
  P3_exp =
    {16#6d7fabf47a2dc03fe7d47f7dddd21082c5fb8f86743cd020f3fb147d57161472,
      16#53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6},
  ?assertEqual(P3_exp, ecu_h2c:hash_to_curve(Suite, <<"abcdef0123456789">>, DST)).

edwards25519_nu_vectors_test() ->
  Suite = edwards25519_xmd_sha512_ell2_nu,
  DST = <<"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_NU_">>,

  %% 1. msg = ""
  P1_exp =
    {16#1ff2b70ecf862799e11b7ae744e3489aa058ce805dd323a936375a84695e76da,
      16#222e314d04a4d5725e9f2aff9fb2a6b69ef375a1214eb19021ceab2d687f0f9b},
  ?assertEqual(P1_exp, ecu_h2c:encode_to_curve(Suite, <<>>, DST)),

  %% 2. msg = "abc"
  P2_exp =
    {16#5f13cc69c891d86927eb37bd4afc6672360007c63f68a33ab423a3aa040fd2a8,
      16#67732d50f9a26f73111dd1ed5dba225614e538599db58ba30aaea1f5c827fa42},
  ?assertEqual(P2_exp, ecu_h2c:encode_to_curve(Suite, <<"abc">>, DST)),

  %% 3. msg = "abcdef0123456789"
  P3_exp =
    {16#1dd2fefce934ecfd7aae6ec998de088d7dd03316aa1847198aecf699ba6613f1,
      16#2f8a6c24dd1adde73909cada6a4a137577b0f179d336685c4a955a0a8e1a86fb},
  ?assertEqual(P3_exp, ecu_h2c:encode_to_curve(Suite, <<"abcdef0123456789">>, DST)).

%%====================================================================
%% RFC 9380 Appendix J.7: edwards448 Test Vectors
%%====================================================================

edwards448_ro_vectors_test() ->
  Suite = edwards448_xof_shake256_ell2_ro,
  DST = <<"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_RO_">>,

  %% 1. msg = ""
  P1_exp =
    {16#73036d4a88949c032f01507005c133884e2f0d81f9a950826245dda9e844fc78186c39daaa7147ead3e462cff60e9c6340b58134480b4d17,
      16#94c1d61b43728e5d784ef4fcb1f38e1075f3aef5e99866911de5a234f1aafdc26b554344742e6ba0420b71b298671bbeb2b7736618634610},
  ?assertEqual(P1_exp, ecu_h2c:hash_to_curve(Suite, <<>>, DST)),

  %% 2. msg = "abc"
  P2_exp =
    {16#4e0158acacffa545adb818a6ed8e0b870e6abc24dfc1dc45cf9a052e98469275d9ff0c168d6a5ac7ec05b742412ee090581f12aa398f9f8c,
      16#894d3fa437b2d2e28cdc3bfaade035430f350ec5239b6b406b5501da6f6d6210ff26719cad83b63e97ab26a12df6dec851d6bf38e294af9a},
  ?assertEqual(P2_exp, ecu_h2c:hash_to_curve(Suite, <<"abc">>, DST)).

edwards448_nu_vectors_test() ->
  Suite = edwards448_xof_shake256_ell2_nu,
  DST = <<"QUUX-V01-CS02-with-edwards448_XOF:SHAKE256_ELL2_NU_">>,

  %% 1. msg = ""
  P1_exp =
    {16#eb5a1fc376fd73230af2de0f3374087cc7f279f0460114cf0a6c12d6d044c16de34ec2350c34b26bf110377655ab77936869d085406af71e,
      16#df5dcea6d42e8f494b279a500d09e895d26ac703d75ca6d118e8ca58bf6f608a2a383f292fce1563ff995dce75aede1fdc8e7c0c737ae9ad},
  ?assertEqual(P1_exp, ecu_h2c:encode_to_curve(Suite, <<>>, DST)),

  %% 2. msg = "abc"
  P2_exp =
    {16#4623a64bceaba3202df76cd8b6e3daf70164f3fcbda6d6e340f7fab5cdf89140d955f722524f5fe4d968fef6ba2853ff4ea086c2f67d8110,
      16#abaac321a169761a8802ab5b5d10061fec1a83c670ac6bc95954700317ee5f82870120e0e2c5a21b12a0c7ad17ebd343363604c4bcecafd1},
  ?assertEqual(P2_exp, ecu_h2c:encode_to_curve(Suite, <<"abc">>, DST)),

  %% 3. msg = "abcdef0123456789"
  P3_exp =
    {16#e9eb562e76db093baa43a31b7edd04ec4aadcef3389a7b9c58a19cf87f8ae3d154e134b6b3ed45847a741e33df51903da681629a4b8bcc2e,
      16#0cf6606927ad7eb15dbc193993bc7e4dda744b311a8ec4274c8f738f74f605934582474c79260f60280fe35bd37d4347e59184cbfa12cbc4},
  ?assertEqual(P3_exp, ecu_h2c:encode_to_curve(Suite, <<"abcdef0123456789">>, DST)).

%%====================================================================
%% Differential Testing Against RustCrypto NIF
%%====================================================================

secp256k1_rustcrypto_differential_test() ->
  case ecu_rustcrypto_nif:is_available() of
    false ->
      ok;
    true ->
      TestCases = [
        {<<>>, <<"DST_1">>},
        {<<"test message">>, <<"custom_secp256k1_dst">>},
        {crypto:strong_rand_bytes(32), <<"random_dst_abc">>},
        {crypto:strong_rand_bytes(100), <<"DST_LONG_1234567890">>}
      ],
      lists:foreach(
        fun({Msg, DST}) ->
          %% Test hash_to_curve
          {Px, Py} = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, DST),
          Uncompressed = <<4:8, Px:256, Py:256>>,
          RustPt = ecu_rustcrypto_nif:secp256k1_hash_to_curve(Msg, DST),
          ?assertEqual(Uncompressed, RustPt),

          %% Test encode_to_curve
          {NUx, NUy} = ecu_h2c:encode_to_curve(secp256k1_xmd_sha256_sswu_nu, Msg, DST),
          UncompressedNU = <<4:8, NUx:256, NUy:256>>,
          RustPtNU = ecu_rustcrypto_nif:secp256k1_encode_to_curve(Msg, DST),
          ?assertEqual(UncompressedNU, RustPtNU)
        end,
        TestCases
      )
  end.

%%====================================================================
%% Edge Cases and Security Constraints
%%====================================================================

oversize_dst_test() ->
  %% DST > 255 bytes must be hashed using H("H2C-OVERSIZE-DST-" || DST)
  LongDST = binary:copy(<<"D">>, 300),
  Msg = <<"oversize dst test message">>,
  Pt1 = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, LongDST),
  ?assert(ecu_secp256k1:on_curve(Pt1)),

  Pt2 = ecu_h2c:hash_to_curve(edwards25519_xmd_sha512_ell2_ro, Msg, LongDST),
  ?assert(ecu_ed25519:on_curve(Pt2)),

  Pt3 = ecu_h2c:hash_to_curve(edwards448_xof_shake256_ell2_ro, Msg, LongDST),
  ?assert(ecu_ed448:on_curve(Pt3)).

empty_dst_error_test() ->
  %% RFC 9380 Section 3.1: DST MUST NOT be empty
  ?assertError(badarg, ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, <<"msg">>, <<>>)),
  ?assertError(badarg, ecu_h2c:encode_to_curve(secp256k1_xmd_sha256_sswu_nu, <<"msg">>, <<>>)),
  ?assertError(badarg, ecu_h2c:hash_to_curve(edwards25519_xmd_sha512_ell2_ro, <<"msg">>, <<>>)),
  ?assertError(badarg, ecu_h2c:hash_to_curve(edwards448_xof_shake256_ell2_ro, <<"msg">>, <<>>)).

default_dst_test() ->
  %% Calling without DST uses canonical suite ID as DST
  Msg = <<"test default dst">>,
  Pt1 = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg),
  Pt1_exp = ecu_h2c:hash_to_curve(
    secp256k1_xmd_sha256_sswu_ro, Msg, <<"secp256k1_XMD:SHA-256_SSWU_RO_">>
  ),
  ?assertEqual(Pt1_exp, Pt1),

  Pt2 = ecu_h2c:hash_to_curve(edwards25519_xmd_sha512_ell2_ro, Msg),
  Pt2_exp = ecu_h2c:hash_to_curve(
    edwards25519_xmd_sha512_ell2_ro, Msg, <<"edwards25519_XMD:SHA-512_ELL2_RO_">>
  ),
  ?assertEqual(Pt2_exp, Pt2).

subgroup_membership_test() ->
  %% Verifies that cleared points belong to the prime-order subgroup
  Msg = <<"subgroup test">>,
  DST = <<"TEST_DST">>,

  %% secp256k1 has h=1, n*P = infinity
  PtSecp = ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, Msg, DST),
  ?assertEqual({0, 0}, ecu_secp256k1:scalar_mul(ecu_secp256k1:n(), PtSecp)),

  %% edwards25519: n*P = neutral point (0, 1)
  PtEd25519 = ecu_h2c:hash_to_curve(edwards25519_xmd_sha512_ell2_ro, Msg, DST),
  P25519_mul = ecu_ed25519:scalar_mul_noclamp(ecu_ed25519:n(), PtEd25519),
  ?assertEqual({0, 1}, ecu_ed25519:to_affine(P25519_mul)),

  %% edwards448: n*P = neutral point (0, 1)
  PtEd448 = ecu_h2c:hash_to_curve(edwards448_xof_shake256_ell2_ro, Msg, DST),
  P448_mul = ecu_ed448:scalar_mul_noclamp(ecu_ed448:n(), PtEd448),
  ?assertEqual({0, 1}, ecu_ed448:to_affine(P448_mul)).
