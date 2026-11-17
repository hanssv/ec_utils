%%%-------------------------------------------------------------------
%%% @doc Unit tests for ecu_vrf (RFC 9381 Verifiable Random Functions).
%%%
%%% Tests official RFC 9381 Appendix B test vectors:
%%%   - Appendix B.3 (Examples 16-18): ECVRF-EDWARDS25519-SHA512-TAI
%%%   - Appendix B.4 (Examples 19-21): ECVRF-EDWARDS25519-SHA512-ELL2
%%% Plus secp256k1 TAI and SSWU roundtrips and negative/tamper test cases.
%%% @end
%%%-------------------------------------------------------------------
-module(vrf_tests).

-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% RFC 9381 Appendix B.3: ECVRF-EDWARDS25519-SHA512-TAI Test Vectors
%%%===================================================================

rfc9381_b3_example_16_test() ->
  %% Example 16: alpha = empty string
  SK = binary:decode_hex(<<"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60">>),
  ExpectedPK =
    binary:decode_hex(<<"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a">>),
  ExpectedPi =
    binary:decode_hex(
      <<
        "8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f"
        "26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab12"
        "68a1b0db10836d9826a528ca76567805"
      >>
    ),
  ExpectedBeta =
    binary:decode_hex(
      <<
        "90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff"
        "66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"
      >>
    ),
  Alpha = <<>>,
  Suite = edwards25519_sha512_tai,

  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(ExpectedPK, PK),

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(ExpectedPi, Pi),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(ExpectedBeta, Beta),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(ExpectedBeta, BetaFromProof).

rfc9381_b3_example_17_test() ->
  %% Example 17: alpha = 0x72
  SK = binary:decode_hex(<<"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb">>),
  ExpectedPK =
    binary:decode_hex(<<"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c">>),
  ExpectedPi =
    binary:decode_hex(
      <<
        "f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed593"
        "3bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926d"
        "a3ef39226bbc355bdc9850112c8f4b02"
      >>
    ),
  ExpectedBeta =
    binary:decode_hex(
      <<
        "eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb"
        "5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"
      >>
    ),
  Alpha = <<16#72>>,
  Suite = edwards25519_sha512_tai,

  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(ExpectedPK, PK),

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(ExpectedPi, Pi),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(ExpectedBeta, Beta),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(ExpectedBeta, BetaFromProof).

rfc9381_b3_example_18_test() ->
  %% Example 18: alpha = 0xaf82
  SK = binary:decode_hex(<<"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7">>),
  ExpectedPK =
    binary:decode_hex(<<"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025">>),
  ExpectedPi =
    binary:decode_hex(
      <<
        "9bc0f79119cc5604bf02d23b4caede71393cedfbb191434dd016d30177ccbf80"
        "96bb474e53895c362d8628ee9f9ea3c0e52c7a5c691b6c18c9979866568add7a"
        "2d41b00b05081ed0f58ee5e31b3a970e"
      >>
    ),
  ExpectedBeta =
    binary:decode_hex(
      <<
        "645427e5d00c62a23fb703732fa5d892940935942101e456ecca7bb217c61c45"
        "2118fec1219202a0edcf038bb6373241578be7217ba85a2687f7a0310b2df19f"
      >>
    ),
  Alpha = <<16#af, 16#82>>,
  Suite = edwards25519_sha512_tai,

  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(ExpectedPK, PK),

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(ExpectedPi, Pi),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(ExpectedBeta, Beta),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(ExpectedBeta, BetaFromProof).

%%%===================================================================
%%% RFC 9381 Appendix B.4: ECVRF-EDWARDS25519-SHA512-ELL2 Test Vectors
%%%===================================================================

rfc9381_b4_example_19_test() ->
  %% Example 19: alpha = empty string
  SK = binary:decode_hex(<<"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60">>),
  ExpectedPK =
    binary:decode_hex(<<"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a">>),
  ExpectedPi =
    binary:decode_hex(
      <<
        "7d9c633ffeee27349264cf5c667579fc583b4bda63ab71d001f89c10003ab46f"
        "14adf9a3cd8b8412d9038531e865c341cafa73589b023d14311c331a9ad15ff2"
        "fb37831e00f0acaa6d73bc9997b06501"
      >>
    ),
  ExpectedBeta =
    binary:decode_hex(
      <<
        "9d574bf9b8302ec0fc1e21c3ec5368269527b87b462ce36dab2d14ccf80c53cc"
        "cf6758f058c5b1c856b116388152bbe509ee3b9ecfe63d93c3b4346c1fbc6c54"
      >>
    ),
  Alpha = <<>>,
  Suite = edwards25519_sha512_ell2,

  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(ExpectedPK, PK),

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(ExpectedPi, Pi),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(ExpectedBeta, Beta),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(ExpectedBeta, BetaFromProof).

rfc9381_b4_example_20_test() ->
  %% Example 20: alpha = 0x72
  SK = binary:decode_hex(<<"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb">>),
  ExpectedPK =
    binary:decode_hex(<<"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c">>),
  ExpectedPi =
    binary:decode_hex(
      <<
        "47b327393ff2dd81336f8a2ef10339112401253b3c714eeda879f12c509072ef"
        "055b48372bb82efbdce8e10c8cb9a2f9d60e93908f93df1623ad78a86a028d6b"
        "c064dbfc75a6a57379ef855dc6733801"
      >>
    ),
  ExpectedBeta =
    binary:decode_hex(
      <<
        "38561d6b77b71d30eb97a062168ae12b667ce5c28caccdf76bc88e093e463598"
        "7cd96814ce55b4689b3dd2947f80e59aac7b7675f8083865b46c89b2ce9cc735"
      >>
    ),
  Alpha = <<16#72>>,
  Suite = edwards25519_sha512_ell2,

  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(ExpectedPK, PK),

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(ExpectedPi, Pi),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(ExpectedBeta, Beta),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(ExpectedBeta, BetaFromProof).

rfc9381_b4_example_21_test() ->
  %% Example 21: alpha = 0xaf82
  SK = binary:decode_hex(<<"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7">>),
  ExpectedPK =
    binary:decode_hex(<<"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025">>),
  ExpectedPi =
    binary:decode_hex(
      <<
        "926e895d308f5e328e7aa159c06eddbe56d06846abf5d98c2512235eaa57fdce"
        "35b46edfc655bc828d44ad09d1150f31374e7ef73027e14760d42e77341fe054"
        "67bb286cc2c9d7fde29120a0b2320d04"
      >>
    ),
  ExpectedBeta =
    binary:decode_hex(
      <<
        "121b7f9b9aaaa29099fc04a94ba52784d44eac976dd1a3cca458733be5cd090a"
        "7b5fbd148444f17f8daf1fb55cb04b1ae85a626e30a54b4b0f8abf4a43314a58"
      >>
    ),
  Alpha = <<16#af, 16#82>>,
  Suite = edwards25519_sha512_ell2,

  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(ExpectedPK, PK),

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(ExpectedPi, Pi),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(ExpectedBeta, Beta),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(ExpectedBeta, BetaFromProof).

%%%===================================================================
%%% Secp256k1 VRF Tests (TAI and SSWU)
%%%===================================================================

secp256k1_tai_roundtrip_test() ->
  SK = <<16#1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef:256>>,
  Suite = secp256k1_sha256_tai,
  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(33, byte_size(PK)),
  Alpha = <<"test message for secp256k1 vrf tai">>,

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(81, byte_size(Pi)),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(32, byte_size(Beta)),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(Beta, BetaFromProof).

secp256k1_sswu_roundtrip_test() ->
  SK = <<16#fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321:256>>,
  Suite = secp256k1_sha256_sswu,
  PK = ecu_vrf:derive_public_key(Suite, SK),
  ?assertEqual(33, byte_size(PK)),
  Alpha = <<"test message for secp256k1 vrf sswu">>,

  {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
  ?assertEqual(81, byte_size(Pi)),

  {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
  ?assertEqual(32, byte_size(Beta)),

  {ok, BetaFromProof} = ecu_vrf:proof_to_hash(Suite, Pi),
  ?assertEqual(Beta, BetaFromProof).

keypair_generation_test() ->
  lists:foreach(
    fun(Suite) ->
      {PK, SK} = ecu_vrf:keypair(Suite),
      ?assertEqual(PK, ecu_vrf:derive_public_key(Suite, SK)),
      Alpha = <<"random keypair test message">>,
      {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
      {ok, Beta} = ecu_vrf:verify(Suite, PK, Pi, Alpha),
      ?assert(is_binary(Beta))
    end,
    [
      edwards25519_sha512_ell2,
      edwards25519_sha512_tai,
      secp256k1_sha256_tai,
      secp256k1_sha256_sswu
    ]
  ).

%%%===================================================================
%%% Negative & Tamper Tests
%%%===================================================================

tampered_alpha_fails_test() ->
  lists:foreach(
    fun(Suite) ->
      {PK, SK} = ecu_vrf:keypair(Suite),
      Alpha = <<"correct message">>,
      {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
      TamperedAlpha = <<"tampered message">>,
      ?assertEqual({error, invalid_proof}, ecu_vrf:verify(Suite, PK, Pi, TamperedAlpha))
    end,
    [
      edwards25519_sha512_ell2,
      edwards25519_sha512_tai,
      secp256k1_sha256_tai,
      secp256k1_sha256_sswu
    ]
  ).

tampered_proof_fails_test() ->
  lists:foreach(
    fun(Suite) ->
      {PK, SK} = ecu_vrf:keypair(Suite),
      Alpha = <<"valid message">>,
      {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
      <<Byte0:8, Rest/binary>> = Pi,
      TamperedPi = <<(Byte0 bxor 1):8, Rest/binary>>,
      ?assertEqual({error, invalid_proof}, ecu_vrf:verify(Suite, PK, TamperedPi, Alpha))
    end,
    [
      edwards25519_sha512_ell2,
      edwards25519_sha512_tai,
      secp256k1_sha256_tai,
      secp256k1_sha256_sswu
    ]
  ).

tampered_public_key_fails_test() ->
  lists:foreach(
    fun(Suite) ->
      {_PK1, SK1} = ecu_vrf:keypair(Suite),
      {PK2, _SK2} = ecu_vrf:keypair(Suite),
      Alpha = <<"valid message">>,
      {ok, Pi} = ecu_vrf:prove(Suite, SK1, Alpha),
      ?assertEqual({error, invalid_proof}, ecu_vrf:verify(Suite, PK2, Pi, Alpha))
    end,
    [
      edwards25519_sha512_ell2,
      edwards25519_sha512_tai,
      secp256k1_sha256_tai,
      secp256k1_sha256_sswu
    ]
  ).

invalid_length_proof_fails_test() ->
  lists:foreach(
    fun(Suite) ->
      {PK, _SK} = ecu_vrf:keypair(Suite),
      Alpha = <<"valid message">>,
      ?assertEqual({error, invalid_proof}, ecu_vrf:verify(Suite, PK, <<>>, Alpha)),
      ?assertEqual({error, invalid_proof}, ecu_vrf:verify(Suite, PK, <<1, 2, 3>>, Alpha)),
      ?assertEqual({error, invalid_proof}, ecu_vrf:proof_to_hash(Suite, <<>>)),
      ?assertEqual({error, invalid_proof}, ecu_vrf:proof_to_hash(Suite, <<1, 2, 3>>))
    end,
    [
      edwards25519_sha512_ell2,
      edwards25519_sha512_tai,
      secp256k1_sha256_tai,
      secp256k1_sha256_sswu
    ]
  ).

small_order_public_key_rejected_test() ->
  %% Identity point on Ed25519 is compressed as <<1, 0...0>> (order 1)
  IdentityEd = <<1:8, 0:248>>,
  ProofEd = crypto:strong_rand_bytes(80),
  ?assertEqual(
    {error, small_order_public_key},
    ecu_vrf:verify(edwards25519_sha512_ell2, IdentityEd, ProofEd, <<>>)
  ),
  ?assertEqual(
    {error, small_order_public_key},
    ecu_vrf:verify(edwards25519_sha512_tai, IdentityEd, ProofEd, <<>>)
  ).

%%%===================================================================
%%% Reference NIF Differential Tests
%%%===================================================================

nif_cross_verification_test() ->
  case ecu_vrf_nif:is_available() of
    false ->
      ok;
    true ->
      Suites = [
        edwards25519_sha512_ell2,
        edwards25519_sha512_tai,
        secp256k1_sha256_tai
      ],
      lists:foreach(
        fun(Suite) ->
          {PK, SK} = ecu_vrf:keypair(Suite),
          Alpha = <<"differential test message with ecu_vrf_nif">>,

          %% 1. Prove in pure Erlang, verify in both Erlang and NIF
          {ok, ErlPi} = ecu_vrf:prove(Suite, SK, Alpha),
          {ok, ErlBeta} = ecu_vrf:verify(Suite, PK, ErlPi, Alpha),
          {ok, NifBetaFromErlPi} = ecu_vrf_nif:verify(Suite, PK, ErlPi, Alpha),
          ?assertEqual(ErlBeta, NifBetaFromErlPi),

          %% 2. Prove in NIF, verify in both NIF and Erlang
          {ok, NifPi} = ecu_vrf_nif:prove(Suite, SK, Alpha),
          {ok, NifBeta} = ecu_vrf_nif:verify(Suite, PK, NifPi, Alpha),
          {ok, ErlBetaFromNifPi} = ecu_vrf:verify(Suite, PK, NifPi, Alpha),
          ?assertEqual(NifBeta, ErlBetaFromNifPi),
          ?assertEqual(ErlBeta, NifBeta),

          %% 3. Verify proof_to_hash consistency
          {ok, ErlHashFromNifPi} = ecu_vrf:proof_to_hash(Suite, NifPi),
          {ok, NifHashFromErlPi} = ecu_vrf_nif:proof_to_hash(Suite, ErlPi),
          ?assertEqual(ErlBeta, ErlHashFromNifPi),
          ?assertEqual(ErlBeta, NifHashFromErlPi)
        end,
        Suites
      )
  end.
