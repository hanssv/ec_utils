%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for ML-KEM (FIPS 203) and hybrid post-quantum key exchange.
%%% Includes NIST ACVP test vectors, OTP crypto differential tests,
%%% implicit rejection verification, and input validation.
%%% @end
%%%-------------------------------------------------------------------
-module(ml_kem_tests).

-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% NIST ACVP Intermediate Vectors (FIPS 203)
%% ===================================================================

nist_ml_kem_512_vector_test() ->
  D = binary:decode_hex(<<"e1e3206875e67d7e81353774fe9025035b9b41a4a9f6ec00b91c600442fd717d">>),
  Z = binary:decode_hex(<<"c6f5785a6f2b42e843228be53eb768d64c6f9d4355ae95f083e51ed57c437310">>),
  M = binary:decode_hex(<<"a741ec2002be6f4fa76037b7f0644f833fa823e630401a39d3240c6e82a430bb">>),
  ExpectedK = binary:decode_hex(
    <<"62a8c220b01793ecd183dea9762c5602211e0aab001cbc892d0a95693ab17cc1">>
  ),
  {PK, SK} = ecu_ml_kem:keypair_from_seed(ml_kem_512, D, Z),
  ?assertEqual(800, byte_size(PK)),
  ?assertEqual(1632, byte_size(SK)),
  {K, C} = ecu_ml_kem:encaps(PK, M),
  ?assertEqual(768, byte_size(C)),
  ?assertEqual(ExpectedK, K),
  DecapsK = ecu_ml_kem:decaps(SK, C),
  ?assertEqual(ExpectedK, DecapsK),
  %% Implicit rejection on corrupted ciphertext:
  <<CFirst:8, CRest/binary>> = C,
  CorruptedC = <<(CFirst bxor 1):8, CRest/binary>>,
  RejectedK = ecu_ml_kem:decaps(SK, CorruptedC),
  ?assertNotEqual(ExpectedK, RejectedK),
  ExpectedRejectedK = ecu_keccak:shake256(<<Z/binary, CorruptedC/binary>>, 256),
  ?assertEqual(ExpectedRejectedK, RejectedK).

nist_ml_kem_768_vector_test() ->
  D = binary:decode_hex(<<"f688563f7c66a5da2d8bdb5a5f3e07bd8dce6f7efcec7f41298d79863459f7cd">>),
  Z = binary:decode_hex(<<"d1d49a515250dbceb9f6e3fcc1c7d5306918964b21ddb22207e03e57f0600da8">>),
  M = binary:decode_hex(<<"3dc27ca0a6594b0e56320457c45a0f76bb8a213ea4a76d442186a0aefadbcdb9">>),
  ExpectedK = binary:decode_hex(
    <<"4b4eba37eff0315dc6009dcffb4dfbbb680f8f2ebde8715fa3d6daf70256a2d9">>
  ),
  {PK, SK} = ecu_ml_kem:keypair_from_seed(ml_kem_768, D, Z),
  ?assertEqual(1184, byte_size(PK)),
  ?assertEqual(2400, byte_size(SK)),
  {K, C} = ecu_ml_kem:encaps(PK, M),
  ?assertEqual(1088, byte_size(C)),
  ?assertEqual(ExpectedK, K),
  DecapsK = ecu_ml_kem:decaps(SK, C),
  ?assertEqual(ExpectedK, DecapsK),
  %% Implicit rejection on corrupted ciphertext:
  <<CFirst:8, CRest/binary>> = C,
  CorruptedC = <<(CFirst bxor 1):8, CRest/binary>>,
  RejectedK = ecu_ml_kem:decaps(SK, CorruptedC),
  ?assertNotEqual(ExpectedK, RejectedK),
  ExpectedRejectedK = ecu_keccak:shake256(<<Z/binary, CorruptedC/binary>>, 256),
  ?assertEqual(ExpectedRejectedK, RejectedK).

nist_ml_kem_1024_vector_test() ->
  D = binary:decode_hex(<<"2a62c39ef4fc499f2d132716f480bb7521a49558ae84ee80d9352e66daf1e3a8">>),
  Z = binary:decode_hex(<<"5f574ef7f013d4336801fed022178c3ed91d0b6d51325315fc1dcabf4770a2ea">>),
  M = binary:decode_hex(<<"e07d685ed308e609c9c7842026e35732f6ffc6e2fee10f0afd348f2b42a8acb4">>),
  ExpectedK = binary:decode_hex(
    <<"6c4f4a231255a8cdfb7424c8dabf3a624cefaffd28964efe220ab6178fa6b324">>
  ),
  {PK, SK} = ecu_ml_kem:keypair_from_seed(ml_kem_1024, D, Z),
  ?assertEqual(1568, byte_size(PK)),
  ?assertEqual(3168, byte_size(SK)),
  {K, C} = ecu_ml_kem:encaps(PK, M),
  ?assertEqual(1568, byte_size(C)),
  ?assertEqual(ExpectedK, K),
  DecapsK = ecu_ml_kem:decaps(SK, C),
  ?assertEqual(ExpectedK, DecapsK),
  %% Implicit rejection on corrupted ciphertext:
  <<CFirst:8, CRest/binary>> = C,
  CorruptedC = <<(CFirst bxor 1):8, CRest/binary>>,
  RejectedK = ecu_ml_kem:decaps(SK, CorruptedC),
  ?assertNotEqual(ExpectedK, RejectedK),
  ExpectedRejectedK = ecu_keccak:shake256(<<Z/binary, CorruptedC/binary>>, 256),
  ?assertEqual(ExpectedRejectedK, RejectedK).

%% ===================================================================
%% OTP 29 Differential Interoperability Tests
%% ===================================================================

otp_differential_512_test() ->
  case is_otp_mlkem_available(mlkem512) of
    true ->
      {PK1, SK1} = ecu_ml_kem:keypair(ml_kem_512),
      {SS_otp, CT_otp} = crypto:encapsulate_key(mlkem512, PK1),
      SS_ecu1 = ecu_ml_kem:decaps(SK1, CT_otp),
      ?assertEqual(SS_otp, SS_ecu1),
      case crypto:generate_key(mlkem512, []) of
        {PK2, SK2} when is_binary(PK2), is_binary(SK2) ->
          {SS_ecu2, CT_ecu2} = ecu_ml_kem:encaps(PK2),
          SS_otp2 = crypto:decapsulate_key(mlkem512, SK2, CT_ecu2),
          ?assertEqual(SS_ecu2, SS_otp2)
      end;
    false ->
      ok
  end.

otp_differential_768_test() ->
  case is_otp_mlkem_available(mlkem768) of
    true ->
      {PK1, SK1} = ecu_ml_kem:keypair(ml_kem_768),
      {SS_otp, CT_otp} = crypto:encapsulate_key(mlkem768, PK1),
      SS_ecu1 = ecu_ml_kem:decaps(SK1, CT_otp),
      ?assertEqual(SS_otp, SS_ecu1),
      case crypto:generate_key(mlkem768, []) of
        {PK2, SK2} when is_binary(PK2), is_binary(SK2) ->
          {SS_ecu2, CT_ecu2} = ecu_ml_kem:encaps(PK2),
          SS_otp2 = crypto:decapsulate_key(mlkem768, SK2, CT_ecu2),
          ?assertEqual(SS_ecu2, SS_otp2)
      end;
    false ->
      ok
  end.

otp_differential_1024_test() ->
  case is_otp_mlkem_available(mlkem1024) of
    true ->
      {PK1, SK1} = ecu_ml_kem:keypair(ml_kem_1024),
      {SS_otp, CT_otp} = crypto:encapsulate_key(mlkem1024, PK1),
      SS_ecu1 = ecu_ml_kem:decaps(SK1, CT_otp),
      ?assertEqual(SS_otp, SS_ecu1),
      case crypto:generate_key(mlkem1024, []) of
        {PK2, SK2} when is_binary(PK2), is_binary(SK2) ->
          {SS_ecu2, CT_ecu2} = ecu_ml_kem:encaps(PK2),
          SS_otp2 = crypto:decapsulate_key(mlkem1024, SK2, CT_ecu2),
          ?assertEqual(SS_ecu2, SS_otp2)
      end;
    false ->
      ok
  end.

is_otp_mlkem_available(Alg) ->
  try
    crypto:generate_key(Alg, []),
    true
  catch
    _:_ -> false
  end.

%% ===================================================================
%% Hybrid X25519 + ML-KEM-768 Tests
%% ===================================================================

hybrid_keypair_and_roundtrip_test() ->
  {HPK, HSK} = ecu_ecdh:hybrid_keypair(x25519_mlkem768),
  ?assertEqual(1216, byte_size(HPK)),
  ?assertEqual(2432, byte_size(HSK)),
  {SS_sender, HCT} = ecu_ecdh:hybrid_encaps(HPK),
  ?assertEqual(32, byte_size(SS_sender)),
  ?assertEqual(1120, byte_size(HCT)),
  SS_recver = ecu_ecdh:hybrid_decaps(HSK, HCT),
  ?assertEqual(SS_sender, SS_recver).

hybrid_tampered_ciphertext_test() ->
  {HPK, HSK} = ecu_ecdh:hybrid_keypair(x25519_mlkem768),
  {SS_sender, HCT} = ecu_ecdh:hybrid_encaps(HPK),
  <<EphPub:32/binary, KEM_CT:1088/binary>> = HCT,
  %% Case 1: Corrupt ECDH ephemeral pubkey
  <<E0:8, ERest/binary>> = EphPub,
  BadEphCT = <<(E0 bxor 1):8, ERest/binary, KEM_CT/binary>>,
  BadSS1 = ecu_ecdh:hybrid_decaps(HSK, BadEphCT),
  ?assertNotEqual(SS_sender, BadSS1),
  %% Case 2: Corrupt KEM ciphertext
  <<K0:8, KRest/binary>> = KEM_CT,
  BadKemCT = <<EphPub/binary, (K0 bxor 1):8, KRest/binary>>,
  BadSS2 = ecu_ecdh:hybrid_decaps(HSK, BadKemCT),
  ?assertNotEqual(SS_sender, BadSS2).

%% ===================================================================
%% Input Validation & Negative Tests
%% ===================================================================

parameter_set_aliases_test() ->
  D = crypto:strong_rand_bytes(32),
  Z = crypto:strong_rand_bytes(32),
  ?assertEqual(
    ecu_ml_kem:keypair_from_seed(ml_kem_512, D, Z),
    ecu_ml_kem:keypair_from_seed(mlkem512, D, Z)
  ),
  ?assertEqual(
    ecu_ml_kem:keypair_from_seed(ml_kem_768, D, Z),
    ecu_ml_kem:keypair_from_seed(mlkem768, D, Z)
  ),
  ?assertEqual(
    ecu_ml_kem:keypair_from_seed(ml_kem_1024, D, Z),
    ecu_ml_kem:keypair_from_seed(mlkem1024, D, Z)
  ),
  ?assertError(badarg, apply(ecu_ml_kem, keypair, [invalid_set])).

bad_seed_lengths_test() ->
  ?assertError(badarg, ecu_ml_kem:keypair_from_seed(ml_kem_768, <<1:8>>, crypto:strong_rand_bytes(32))),
  ?assertError(badarg, ecu_ml_kem:keypair_from_seed(ml_kem_768, crypto:strong_rand_bytes(32), <<1:8>>)).

bad_key_lengths_test() ->
  ?assertError(badarg, ecu_ml_kem:encaps(<<0:801/unit:8>>)),
  ?assertError(badarg, ecu_ml_kem:encaps(crypto:strong_rand_bytes(800), <<1:8>>)),
  ?assertError(badarg, ecu_ml_kem:decaps(<<0:100/unit:8>>, <<0:768/unit:8>>)),
  ?assertError(badarg, ecu_ml_kem:decaps(<<0:1632/unit:8>>, <<0:100/unit:8>>)).

public_key_modulus_validation_test() ->
  %% If any decoded coefficient in public key is >= 3329, encaps must reject it
  {PK, _SK} = ecu_ml_kem:keypair(ml_kem_512),
  %% Corrupt first 12 bits to 4095 (0xFFF >= 3329)
  <<_B0:8, _B1:8, Rest/binary>> = PK,
  CorruptedPK = <<16#FF:8, 16#FF:8, Rest/binary>>,
  ?assertError(invalid_public_key, ecu_ml_kem:encaps(CorruptedPK)).
