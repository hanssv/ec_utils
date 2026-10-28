-module(ed448_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").
-include("ecu_ed448.hrl").

rfc8032_test_vectors() ->
  [
   %% Vector 1: empty message
   {
    "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
    "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
    <<>>,
    <<>>,
    "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"
   },
   %% Vector 2: 1 octet (empty context)
   {
    "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
    "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
    binary:decode_hex(<<"03">>),
    <<>>,
    "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"
   },
   %% Vector 3: 1 octet (context "foo")
   {
    "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
    "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
    binary:decode_hex(<<"03">>),
    binary:decode_hex(<<"666f6f">>),
    "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00"
   },
   %% Vector 4: 11 octets
   {
    "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328",
    "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400",
    binary:decode_hex(<<"0c3e544074ec63b0265e0c">>),
    <<>>,
    "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00"
   },
   %% Vector 5: 12 octets
   {
    "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b",
    "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580",
    binary:decode_hex(<<"64a65f3cdedcdd66811e2915">>),
    <<>>,
    "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00"
   },
   %% Vector 6: 13 octets
   {
    "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e",
    "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80",
    binary:decode_hex(<<"64a65f3cdedcdd66811e2915e7">>),
    <<>>,
    "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100"
   },
   %% Vector 7: 64 octets
   {
    "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01",
    "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00",
    binary:decode_hex(<<"bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944">>),
    <<>>,
    "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900"
   },
   %% Vector 8: 256 octets
   {
    "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5",
    "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00",
    binary:decode_hex(<<"15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11">>),
    <<>>,
    "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00"
   }
  ].

rfc8032_vectors_test() ->
  lists:foreach(
    fun({SKHex, PKHex, Msg, Ctx, SigHex}) ->
      SK = binary:decode_hex(list_to_binary(SKHex)),
      ExpectedPK = binary:decode_hex(list_to_binary(PKHex)),
      ExpectedSig = binary:decode_hex(list_to_binary(SigHex)),

      #{public := DerivedPK} = ecu_eddsa448:sign_seed_keypair(SK),
      ?assertEqual(ExpectedPK, DerivedPK),

      Sig = ecu_eddsa448:sign_detached(Msg, SK, Ctx),
      ?assertEqual(ExpectedSig, Sig),

      ?assertEqual(true, ecu_eddsa448:sign_verify_detached(Sig, Msg, ExpectedPK, Ctx)),

      SignedMsg = ecu_eddsa448:sign(Msg, SK, Ctx),
      ?assertEqual({ok, Msg}, ecu_eddsa448:sign_open(SignedMsg, ExpectedPK, Ctx))
    end,
    rfc8032_test_vectors()
  ).

crypto_cross_check_test() ->
  lists:foreach(
    fun(_) ->
      #{secret := <<SK:57/binary, _/binary>>, public := PK} = ecu_eddsa448:sign_keypair(),
      Msg = crypto:strong_rand_bytes(64),
      Sig = ecu_eddsa448:sign_detached(Msg, SK),

      %% Verify our signature with OTP crypto (empty context)
      ?assertEqual(true, crypto:verify(eddsa, none, Msg, Sig, [PK, ed448])),

      %% Verify OTP crypto signature with ecu_eddsa448
      CryptoSig = crypto:sign(eddsa, none, Msg, [SK, ed448]),
      ?assertEqual(Sig, CryptoSig),
      ?assertEqual(true, ecu_eddsa448:sign_verify_detached(CryptoSig, Msg, PK))
    end,
    lists:seq(1, 3)
  ).

point_encode_test() ->
  CompressedB = ecu_ed448:compress(?GP),
  DecompressedB = ecu_ed448:decompress(CompressedB),
  ?assertEqual(CompressedB, ecu_ed448:compress(DecompressedB)),
  ?assert(ecu_ed448:on_curve(DecompressedB)).

decompress_identity_test() ->
  %% Identity point y = 1, x = 0
  Ident = <<1:8, 0:56/unit:8>>,
  ?assertEqual({0, 1, 1}, ecu_ed448:decompress(Ident)).

decompress_canonical_test() ->
  %% y >= P is non-canonical
  NonCanonicalY = <<(?P + 1):448/little-unsigned-integer, 0:8>>,
  ?assertError(badarg, ecu_ed448:decompress(NonCanonicalY)),
  %% x = 0 with high bit (sign bit) set is non-canonical
  SignBitX0 = <<1:8, 0:55/unit:8, 128:8>>,
  ?assertError(badarg, ecu_ed448:decompress(SignBitX0)),
  %% Unused bits in final octet (bits 0..6) non-zero
  UnusedBitsSet = <<1:8, 0:55/unit:8, 1:8>>,
  ?assertError(badarg, ecu_ed448:decompress(UnusedBitsSet)).

malleable_s_test() ->
  #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
  Msg = <<"test message for ed448">>,
  Sig = ecu_eddsa448:sign_detached(Msg, Priv),
  <<R:57/binary, S:456/little-unsigned-integer>> = Sig,
  S1 = S + ?N,
  ?assert(S1 < (1 bsl 456)),
  MalleableSig = <<R:57/binary, S1:456/little-unsigned-integer>>,
  ?assertEqual(false, ecu_eddsa448:sign_verify_detached(MalleableSig, Msg, Pub)),
  SignedMsg = <<MalleableSig/binary, Msg/binary>>,
  ?assertEqual({error, failed_verification}, ecu_eddsa448:sign_open(SignedMsg, Pub)).

small_order_pubkey_test() ->
  %% Neutral point {0, 1, 1} has order 1 (which divides 4)
  WeakA = <<1:8, 0:56/unit:8>>,
  Msg = <<"1">>,
  Sig = <<0:912>>,
  ?assertEqual(false, ecu_eddsa448:sign_verify_detached(Sig, Msg, WeakA)),
  ?assertEqual({error, failed_verification}, ecu_eddsa448:sign_open(<<Sig/binary, Msg/binary>>, WeakA)).

invalid_pubkey_no_crash_test() ->
  BadPK = <<2:448/little-unsigned-integer, 0:8>>,
  Msg = <<"test message">>,
  Sig = <<0:912>>,
  ?assertEqual(false, ecu_eddsa448:sign_verify_detached(Sig, Msg, BadPK)),
  ?assertEqual({error, failed_verification}, ecu_eddsa448:sign_open(<<Sig/binary, Msg/binary>>, BadPK)).

mismatched_pubkey_in_sk_test() ->
  #{secret := <<Sec:57/binary, _RealPub:57/binary>>} = ecu_eddsa448:sign_keypair(),
  FakePub = crypto:strong_rand_bytes(57),
  BadSK = <<Sec/binary, FakePub/binary>>,
  Msg = <<"test message">>,
  ?assertError(badarg, ecu_eddsa448:sign_detached(Msg, BadSK)),
  ?assertError(badarg, ecu_eddsa448:sign(Msg, BadSK)).

context_mismatch_test() ->
  #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
  Msg = <<"context test message">>,
  Ctx1 = <<"context 1">>,
  Ctx2 = <<"context 2">>,
  Sig1 = ecu_eddsa448:sign_detached(Msg, Priv, Ctx1),
  ?assertEqual(true, ecu_eddsa448:sign_verify_detached(Sig1, Msg, Pub, Ctx1)),
  ?assertEqual(false, ecu_eddsa448:sign_verify_detached(Sig1, Msg, Pub, Ctx2)),
  ?assertEqual(false, ecu_eddsa448:sign_verify_detached(Sig1, Msg, Pub, <<>>)).

point_arithmetic_test() ->
  Neutral = {0, 1, 1},
  ?assert(ecu_ed448:pt_eq(ecu_ed448:p_add(?GP, Neutral), ?GP)),
  ?assert(ecu_ed448:pt_eq(ecu_ed448:p_add(Neutral, ?GP), ?GP)),
  ?assert(ecu_ed448:pt_eq(ecu_ed448:p_add(?GP, ?GP), ecu_ed448:p_dbl(?GP))),
  ?assert(ecu_ed448:pt_eq(ecu_ed448:p_sub(?GP, ?GP), Neutral)),
  ?assert(ecu_ed448:pt_eq(ecu_ed448:p_add(?GP, ecu_ed448:p_neg(?GP)), Neutral)).

scalar_mul_test() ->
  K = 123456789,
  P1 = ecu_ed448:scalar_mul_base_noclamp(K),
  P2 = ecu_ed448:scalar_mul_noclamp(K, ?GP),
  ?assert(ecu_ed448:pt_eq(P1, P2)),
  ?assert(ecu_ed448:on_curve(P1)).

multi_scalar_mul_test() ->
  ?assertEqual({0, 1, 1}, ecu_ed448:multi_scalar_mul([])),
  P = ecu_ed448:scalar_mul_base_noclamp(42),
  K1 = 12345,
  Expected1 = ecu_ed448:scalar_mul_noclamp(K1, P),
  Actual1 = ecu_ed448:multi_scalar_mul([{K1, P}]),
  ?assert(ecu_ed448:pt_eq(Expected1, Actual1)),

  P2 = ecu_ed448:scalar_mul_base_noclamp(99),
  K2 = 67890,
  Expected2 = ecu_ed448:p_add(Expected1, ecu_ed448:scalar_mul_noclamp(K2, P2)),
  Actual2 = ecu_ed448:multi_scalar_mul([{K1, P}, {K2, P2}]),
  ?assert(ecu_ed448:pt_eq(Expected2, Actual2)).

batch_verify_empty_test() ->
  ?assertEqual(true, ecu_eddsa448:sign_verify_batch([])).

batch_verify_single_test() ->
  #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
  Msg = <<"single batch message for ed448">>,
  Sig = ecu_eddsa448:sign_detached(Msg, Priv),
  ?assertEqual(true, ecu_eddsa448:sign_verify_batch([{Sig, Msg, Pub}])),
  <<_R:57/binary, S:57/binary>> = Sig,
  CorruptedSig = <<(crypto:strong_rand_bytes(57))/binary, S/binary>>,
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch([{CorruptedSig, Msg, Pub}])).

batch_verify_valid_batch_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa448:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 4) ],
  ?assertEqual(true, ecu_eddsa448:sign_verify_batch(Batch)).

batch_verify_valid_batch_with_context_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Ctx = <<"ctx ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa448:sign_detached(Msg, Priv, Ctx),
              {Sig, Msg, Pub, Ctx}
            end || I <- lists:seq(1, 3) ],
  ?assertEqual(true, ecu_eddsa448:sign_verify_batch(Batch)).

batch_verify_tampered_sig_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa448:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 4) ],
  {Sig3, Msg3, Pub3} = lists:nth(3, Batch),
  <<R3:57/binary, S3:456/little-unsigned-integer>> = Sig3,
  CorruptedSig3 = <<R3/binary, ((S3 + 1) rem ?N):456/little>>,
  TamperedBatch = lists:sublist(Batch, 2) ++ [{CorruptedSig3, Msg3, Pub3}] ++ lists:nthtail(3, Batch),
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch(TamperedBatch)).

batch_verify_tampered_msg_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa448:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 4) ],
  {Sig2, Msg2, Pub2} = lists:nth(2, Batch),
  TamperedBatch = lists:sublist(Batch, 1) ++ [{Sig2, <<Msg2/binary, "!">>, Pub2}] ++ lists:nthtail(2, Batch),
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch(TamperedBatch)).

batch_verify_tampered_pk_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa448:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 4) ],
  #{public := OtherPub} = ecu_eddsa448:sign_keypair(),
  {Sig4, Msg4, _Pub4} = lists:nth(4, Batch),
  TamperedBatch = lists:sublist(Batch, 3) ++ [{Sig4, Msg4, OtherPub}] ++ lists:nthtail(4, Batch),
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch(TamperedBatch)).

batch_verify_malleable_s_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa448:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 3) ],
  {Sig2, Msg2, Pub2} = lists:nth(2, Batch),
  <<R2:57/binary, S2:456/little-unsigned-integer>> = Sig2,
  MalleableSig = <<R2/binary, (S2 + ?N):456/little-unsigned-integer>>,
  TamperedBatch = lists:sublist(Batch, 1) ++ [{MalleableSig, Msg2, Pub2}] ++ lists:nthtail(2, Batch),
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch(TamperedBatch)).

batch_verify_malformed_test() ->
  Bad1 = id([not_a_tuple]),
  Bad2 = id(not_a_list),
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch(Bad1)),
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch([{<<0:456>>, <<"msg">>, <<0:456>>}])),
  ?assertEqual(false, ecu_eddsa448:sign_verify_batch(Bad2)).

batch_verify_single_with_context_test() ->
  #{secret := Priv, public := Pub} = ecu_eddsa448:sign_keypair(),
  Msg = <<"single batch message with ctx">>,
  Ctx = <<"custom context">>,
  Sig = ecu_eddsa448:sign_detached(Msg, Priv, Ctx),
  ?assertEqual(true, ecu_eddsa448:sign_verify_batch([{Sig, Msg, Pub}], Ctx)),
  ?assertEqual(true, ecu_eddsa448:sign_verify_batch([{Sig, Msg, Pub, Ctx}], <<"ignored default">>)).

argon04_scalar_window_truncation_ed448_test() ->
  LargeK = (1 bsl 456) + 12345,
  Pt = ecu_ed448:scalar_mul_base(1),
  ResLarge = ecu_ed448:scalar_mul_noclamp(LargeK, Pt),
  ResExpected = ecu_ed448:scalar_mul_noclamp(LargeK rem ?N, Pt),
  ?assert(ecu_ed448:pt_eq(ResLarge, ResExpected)).

id(X) -> X.
