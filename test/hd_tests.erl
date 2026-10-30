%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for ecu_hd (BIP-32, BIP-44, SLIP-0010, AEX-10) and ecu_base58.
%%% @end
%%%-------------------------------------------------------------------
-module(hd_tests).

-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% Base58 & Base58Check Tests
%% ===================================================================

base58_basic_test() ->
  ?assertEqual(<<"">>, ecu_base58:encode(<<>>)),
  ?assertEqual({ok, <<>>}, ecu_base58:decode(<<"">>)),
  ?assertEqual(<<"1">>, ecu_base58:encode(<<0>>)),
  ?assertEqual({ok, <<0>>}, ecu_base58:decode(<<"1">>)),
  ?assertEqual(<<"111">>, ecu_base58:encode(<<0, 0, 0>>)),
  ?assertEqual({ok, <<0, 0, 0>>}, ecu_base58:decode(<<"111">>)),
  ?assertEqual(<<"2g">>, ecu_base58:encode(<<97>>)),
  ?assertEqual({ok, <<97>>}, ecu_base58:decode(<<"2g">>)).

base58_check_test() ->
  Payload = <<"hello world">>,
  Encoded = ecu_base58:encode_check(Payload),
  ?assertEqual({ok, Payload}, ecu_base58:decode_check(Encoded)),
  ?assertEqual({ok, Payload}, ecu_base58:decode_check(binary_to_list(Encoded))),

  %% Tampered checksum should fail
  <<Prefix:5/binary, BadChar:8, Suffix/binary>> = Encoded,
  TamperedChar =
    case BadChar of
      $a -> $b;
      _ -> $a
    end,
  Tampered = <<Prefix/binary, TamperedChar:8, Suffix/binary>>,
  ?assertEqual({error, bad_checksum}, ecu_base58:decode_check(Tampered)),

  %% Invalid characters (0, O, I, l) should fail
  ?assertEqual({error, bad_char}, ecu_base58:decode(<<"0">>)),
  ?assertEqual({error, bad_char}, ecu_base58:decode(<<"O">>)),
  ?assertEqual({error, bad_char}, ecu_base58:decode(<<"I">>)),
  ?assertEqual({error, bad_char}, ecu_base58:decode(<<"l">>)).

%% ===================================================================
%% BIP-32 Official Test Vectors
%% ===================================================================

bip32_test_vector_1_test() ->
  %% Test Vector 1 from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  Seed = ecu_misc:hex_to_bin("000102030405060708090a0b0c0d0e0f"),
  {ok, M} = ecu_hd:master_key(secp256k1, Seed),
  ?assertEqual(
    <<"xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8">>,
    ecu_hd:to_base58(public, M)
  ),
  ?assertEqual(
    <<"xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi">>,
    ecu_hd:to_base58(private, M)
  ),

  %% m/0'
  {ok, K0H} = ecu_hd:derive_path("m/0H", M),
  ?assertEqual(
    <<"xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw">>,
    ecu_hd:to_base58(public, K0H)
  ),
  ?assertEqual(
    <<"xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7">>,
    ecu_hd:to_base58(private, K0H)
  ),

  %% m/0'/1
  {ok, K0H1} = ecu_hd:derive_path("m/0'/1", M),
  ?assertEqual(
    <<"xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ">>,
    ecu_hd:to_base58(public, K0H1)
  ),
  ?assertEqual(
    <<"xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs">>,
    ecu_hd:to_base58(private, K0H1)
  ),

  %% m/0'/1/2'
  {ok, K0H12H} = ecu_hd:derive_path("m/0H/1/2H", M),
  ?assertEqual(
    <<"xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5">>,
    ecu_hd:to_base58(public, K0H12H)
  ),
  ?assertEqual(
    <<"xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM">>,
    ecu_hd:to_base58(private, K0H12H)
  ),

  %% m/0'/1/2'/2
  {ok, K0H12H2} = ecu_hd:derive_path("m/0'/1/2'/2", M),
  ?assertEqual(
    <<"xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV">>,
    ecu_hd:to_base58(public, K0H12H2)
  ),
  ?assertEqual(
    <<"xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334">>,
    ecu_hd:to_base58(private, K0H12H2)
  ),

  %% m/0'/1/2'/2/1000000000
  {ok, K0H12H2B} = ecu_hd:derive_path("m/0H/1/2H/2/1000000000", M),
  ?assertEqual(
    <<"xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy">>,
    ecu_hd:to_base58(public, K0H12H2B)
  ),
  ?assertEqual(
    <<"xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76">>,
    ecu_hd:to_base58(private, K0H12H2B)
  ).

bip32_test_vector_2_test() ->
  %% Test Vector 2 from BIP-32
  Seed =
    ecu_misc:hex_to_bin(
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7"
      "b7875726f6c696663605d5a5754514e4b484542"
    ),
  {ok, M} = ecu_hd:master_key(secp256k1, Seed),
  ?assertEqual(
    <<"xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB">>,
    ecu_hd:to_base58(public, M)
  ),
  ?assertEqual(
    <<"xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U">>,
    ecu_hd:to_base58(private, M)
  ),

  %% m/0
  {ok, K0} = ecu_hd:derive_path("m/0", M),
  ?assertEqual(
    <<"xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH">>,
    ecu_hd:to_base58(public, K0)
  ),
  ?assertEqual(
    <<"xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt">>,
    ecu_hd:to_base58(private, K0)
  ),

  %% m/0/2147483647'
  {ok, K0H} = ecu_hd:derive_path("m/0/2147483647H", M),
  ?assertEqual(
    <<"xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a">>,
    ecu_hd:to_base58(public, K0H)
  ),
  ?assertEqual(
    <<"xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9">>,
    ecu_hd:to_base58(private, K0H)
  ),

  %% m/0/2147483647'/1
  {ok, K0H1} = ecu_hd:derive_path("m/0/2147483647H/1", M),
  ?assertEqual(
    <<"xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon">>,
    ecu_hd:to_base58(public, K0H1)
  ),
  ?assertEqual(
    <<"xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef">>,
    ecu_hd:to_base58(private, K0H1)
  ),

  %% m/0/2147483647'/1/2147483646'
  {ok, K0H1H} = ecu_hd:derive_path("m/0/2147483647H/1/2147483646H", M),
  ?assertEqual(
    <<"xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL">>,
    ecu_hd:to_base58(public, K0H1H)
  ),
  ?assertEqual(
    <<"xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc">>,
    ecu_hd:to_base58(private, K0H1H)
  ),

  %% m/0/2147483647'/1/2147483646'/2
  {ok, K0H1H2} = ecu_hd:derive_path("m/0/2147483647H/1/2147483646H/2", M),
  ?assertEqual(
    <<"xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt">>,
    ecu_hd:to_base58(public, K0H1H2)
  ),
  ?assertEqual(
    <<"xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j">>,
    ecu_hd:to_base58(private, K0H1H2)
  ).

bip32_test_vector_3_test() ->
  %% Test Vector 3 from BIP-32
  Seed =
    ecu_misc:hex_to_bin(
      "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab"
      "5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
    ),
  {ok, M} = ecu_hd:master_key(secp256k1, Seed),
  ?assertEqual(
    <<"xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13">>,
    ecu_hd:to_base58(public, M)
  ),
  ?assertEqual(
    <<"xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6">>,
    ecu_hd:to_base58(private, M)
  ),

  %% m/0'
  {ok, K0H} = ecu_hd:derive_path("m/0'", M),
  ?assertEqual(
    <<"xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y">>,
    ecu_hd:to_base58(public, K0H)
  ),
  ?assertEqual(
    <<"xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L">>,
    ecu_hd:to_base58(private, K0H)
  ).

%% ===================================================================
%% SLIP-0010 Official Test Vectors (Ed25519)
%% ===================================================================

slip0010_test() ->
  Seed = ecu_misc:hex_to_bin("000102030405060708090a0b0c0d0e0f"),
  {ok, M} = ecu_hd:master_key(ed25519, Seed),

  ?assertEqual(
    ecu_misc:hex_to_bin("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
    ecu_hd:chain_code(M)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")},
    ecu_hd:private_key(M)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed")},
    ecu_hd:public_key(M)
  ),

  %% m/0'
  {ok, K0H} = ecu_hd:derive_path("m/0H", M),
  ?assertEqual(
    ecu_misc:hex_to_bin("8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
    ecu_hd:chain_code(K0H)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3")},
    ecu_hd:private_key(K0H)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c")},
    ecu_hd:public_key(K0H)
  ),
  ?assertEqual(ecu_misc:hex_to_bin("ddebc675"), ecu_hd:parent_fingerprint(K0H)),

  %% m/0'/1'
  {ok, K0H1H} = ecu_hd:derive_path("m/0H/1H", M),
  ?assertEqual(
    ecu_misc:hex_to_bin("a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14"),
    ecu_hd:chain_code(K0H1H)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2")},
    ecu_hd:private_key(K0H1H)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187")},
    ecu_hd:public_key(K0H1H)
  ),
  ?assertEqual(ecu_misc:hex_to_bin("13dab143"), ecu_hd:parent_fingerprint(K0H1H)),

  %% m/0'/1'/2'/2'/1000000000'
  {ok, KDeep} = ecu_hd:derive_path("m/0H/1H/2H/2H/1000000000H", M),
  ?assertEqual(
    ecu_misc:hex_to_bin("68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"),
    ecu_hd:chain_code(KDeep)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793")},
    ecu_hd:private_key(KDeep)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a")},
    ecu_hd:public_key(KDeep)
  ),
  ?assertEqual(ecu_misc:hex_to_bin("d6322ccd"), ecu_hd:parent_fingerprint(KDeep)).

%% ===================================================================
%% AEX-10 Derivation Tests
%% ===================================================================

aex10_test() ->
  Seed = ecu_misc:hex_to_bin("000102030405060708090a0b0c0d0e0f"),

  %% Account 0, Address 0
  {ok, K0} = ecu_hd:derive_aex10(Seed, 0, 0),
  ?assertEqual(
    ecu_misc:hex_to_bin("55DABD8682B4ED808AD21AF8798B34905EE8E1A0057F15DC151A8487CFAB630F"),
    ecu_hd:chain_code(K0)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("624357924DABE9460677F574853CBE017B5506E53F41EC0179AFCA9519957925")},
    ecu_hd:private_key(K0)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("9A3D5001D37C85E72A953B1C0EB7C5BC8B5FBD4640AA4D488FA029CD526F206B")},
    ecu_hd:public_key(K0)
  ),
  ?assertEqual(ecu_misc:hex_to_bin("0AC70E0D"), ecu_hd:parent_fingerprint(K0)),

  %% Account 0, Address 17
  {ok, K17} = ecu_hd:derive_aex10(Seed, 0, 17),
  ?assertEqual(
    ecu_misc:hex_to_bin("98CAA03190E8F23CE5362ED3F3EAFCB4FB9A08B9E9329DC168BCB3EF563283BF"),
    ecu_hd:chain_code(K17)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("E2ED1D3BC80DB4644D5D855E60791E72C2E98AA69ED4D024C659FF642D8F6B77")},
    ecu_hd:private_key(K17)
  ),
  ?assertEqual(
    {ok, ecu_misc:hex_to_bin("833A6227139952868E49BBBDAAB17852C002B1651CC8A633F623A554A59A00FE")},
    ecu_hd:public_key(K17)
  ),
  ?assertEqual(ecu_misc:hex_to_bin("0AC70E0D"), ecu_hd:parent_fingerprint(K17)).

%% ===================================================================
%% Public Child Derivation Equivalence & Error Cases
%% ===================================================================

public_derivation_equivalence_test() ->
  lists:foreach(
    fun(_) ->
      Seed = crypto:strong_rand_bytes(32),
      {ok, M} = ecu_hd:master_key(secp256k1, Seed),
      MPub = ecu_hd:to_public(M),

      %% Unhardened child derivation
      Ix1 = rand:uniform(1000),
      Ix2 = rand:uniform(1000),

      {ok, PrivChild1} = ecu_hd:ckd_priv(M, Ix1),
      {ok, PrivChild2} = ecu_hd:ckd_priv(PrivChild1, Ix2),

      {ok, PubChild1} = ecu_hd:ckd_pub(MPub, Ix1),
      {ok, PubChild2} = ecu_hd:ckd_pub(PubChild1, Ix2),

      ?assertEqual(ecu_hd:public_key(PrivChild1), ecu_hd:public_key(PubChild1)),
      ?assertEqual(ecu_hd:public_key(PrivChild2), ecu_hd:public_key(PubChild2)),
      ?assertEqual(ecu_hd:chain_code(PrivChild2), ecu_hd:chain_code(PubChild2)),
      ?assertEqual(ecu_hd:parent_fingerprint(PrivChild2), ecu_hd:parent_fingerprint(PubChild2))
    end,
    lists:seq(1, 10)
  ).

invalid_operations_test() ->
  Seed = crypto:strong_rand_bytes(32),
  {ok, MSecp} = ecu_hd:master_key(secp256k1, Seed),
  {ok, MEd} = ecu_hd:master_key(ed25519, Seed),

  %% Unhardened derivation on Ed25519 is rejected
  ?assertEqual(
    {error, unhardened_derivation_not_supported_for_ed25519},
    ecu_hd:ckd_priv(MEd, 0)
  ),
  ?assertEqual(
    {error, public_derivation_not_supported_for_ed25519},
    ecu_hd:ckd_pub(MEd, 0)
  ),

  %% Hardened derivation from a public key is rejected
  MSecpPub = ecu_hd:to_public(MSecp),
  ?assertEqual(
    {error, cannot_derive_hardened_from_public_key},
    ecu_hd:ckd_pub(MSecpPub, 16#80000000)
  ),
  ?assertEqual(
    {error, no_private_key},
    ecu_hd:ckd_priv(MSecpPub, 0)
  ),

  %% Invalid seed sizes
  ?assertEqual({error, invalid_seed_length}, ecu_hd:master_key(secp256k1, binary:copy(<<0>>, 15))),
  ?assertEqual({error, invalid_seed_length}, ecu_hd:master_key(secp256k1, binary:copy(<<0>>, 65))),

  %% Deserialization validation: private key bounds and prefix
  N = 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
  PrivHdr = <<16#0488ADE4:32, 0:8, 0:32, 0:32, 0:256>>,
  ?assertEqual({error, invalid_private_key}, ecu_hd:deserialize(<<PrivHdr/binary, 0:8, 0:256>>)),
  ?assertEqual({error, invalid_private_key}, ecu_hd:deserialize(<<PrivHdr/binary, 0:8, N:256>>)),
  ?assertEqual({error, invalid_private_key}, ecu_hd:deserialize(<<PrivHdr/binary, 0:8, (N + 1):256>>)),
  ?assertEqual({error, invalid_private_key_prefix}, ecu_hd:deserialize(<<PrivHdr/binary, 1:8, 1:256>>)),

  %% Deserialization validation: off-curve public key
  PubHdr = <<16#0488B21E:32, 0:8, 0:32, 0:32, 0:256>>,
  ?assertEqual({error, invalid_public_key}, ecu_hd:deserialize(<<PubHdr/binary, 2:8, 5:256>>)),

  %% Deserialization validation: depth-0 master key metadata
  ?assertEqual(
    {error, invalid_master_key_metadata},
    ecu_hd:deserialize(<<16#0488ADE4:32, 0:8, 1:32, 0:32, 0:256, 0:8, 1:256>>)
  ),
  ?assertEqual(
    {error, invalid_master_key_metadata},
    ecu_hd:deserialize(<<16#0488ADE4:32, 0:8, 0:32, 1:32, 0:256, 0:8, 1:256>>)
  ),

  %% Strict path parsing rejects invalid signs, empty segments, trailing slashes
  ?assertEqual({error, {invalid_path_index, "+5"}}, ecu_hd:derive_path("m/+5", MSecp)),
  ?assertEqual({error, {invalid_path_index, "-0"}}, ecu_hd:derive_path("m/-0", MSecp)),
  ?assertEqual({error, invalid_path}, ecu_hd:derive_path("m/0//1", MSecp)),
  ?assertEqual({error, invalid_path}, ecu_hd:derive_path("m/0/1/", MSecp)),

  %% Base58 length capping rejects inputs exceeding 4096 bytes
  LongInput = binary:copy(<<"1">>, 4097),
  ?assertEqual({error, input_too_long}, ecu_base58:decode(LongInput)),
  ?assertEqual({error, input_too_long}, ecu_base58:decode_check(LongInput)).
