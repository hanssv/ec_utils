-module(ecu_sha2_tests).

-include_lib("eunit/include/eunit.hrl").

sha256_test() ->
  ?assertEqual(crypto:hash(sha256, <<>>), ecu_sha2:sha256(<<>>)),
  ?assertEqual(crypto:hash(sha256, <<"abc">>), ecu_sha2:sha256(<<"abc">>)),
  ?assertEqual(
    crypto:hash(sha256, <<"The quick brown fox jumps over the lazy dog">>),
    ecu_sha2:sha256(<<"The quick brown fox jumps over the lazy dog">>)
  ).

sha224_test() ->
  ?assertEqual(crypto:hash(sha224, <<>>), ecu_sha2:sha224(<<>>)),
  ?assertEqual(crypto:hash(sha224, <<"abc">>), ecu_sha2:sha224(<<"abc">>)).

sha512_test() ->
  ?assertEqual(crypto:hash(sha512, <<>>), ecu_sha2:sha512(<<>>)),
  ?assertEqual(crypto:hash(sha512, <<"abc">>), ecu_sha2:sha512(<<"abc">>)),
  ?assertEqual(
    crypto:hash(sha512, <<"The quick brown fox jumps over the lazy dog">>),
    ecu_sha2:sha512(<<"The quick brown fox jumps over the lazy dog">>)
  ).

sha384_test() ->
  ?assertEqual(crypto:hash(sha384, <<>>), ecu_sha2:sha384(<<>>)),
  ?assertEqual(crypto:hash(sha384, <<"abc">>), ecu_sha2:sha384(<<"abc">>)),
  ?assertEqual(
    crypto:hash(sha384, <<"The quick brown fox jumps over the lazy dog">>),
    ecu_sha2:sha384(<<"The quick brown fox jumps over the lazy dog">>)
  ).

hmac_all_algs_test() ->
  Keys = [
    <<>>,
    <<"short_key">>,
    binary:copy(<<"k">>, 64),
    binary:copy(<<"k">>, 100),
    binary:copy(<<"k">>, 150)
  ],
  Datas = [
    <<>>,
    <<"hello">>,
    <<"The quick brown fox jumps over the lazy dog">>,
    binary:copy(<<"data">>, 250)
  ],
  Algs = [sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512],
  lists:foreach(
    fun(Alg) ->
      lists:foreach(
        fun(Key) ->
          lists:foreach(
            fun(Data) ->
              Expected = crypto:mac(hmac, Alg, Key, Data),
              Actual = ecu_hmac:hmac(Alg, Key, Data),
              ?assertEqual(Expected, Actual)
            end,
            Datas
          )
        end,
        Keys
      )
    end,
    Algs
  ),
  % Test ripemd160 HMAC separately with explicit dynamic call for eqwalizer
  lists:foreach(
    fun(Key) ->
      Expected = erlang:apply(crypto, mac, [hmac, ripemd160, Key, <<"test">>]),
      Actual = ecu_hmac:hmac(ripemd160, Key, <<"test">>),
      ?assertEqual(Expected, Actual)
    end,
    Keys
  ).

pbkdf2_test() ->
  Pass = <<"password">>,
  Salt = <<"salt">>,
  ?assertEqual(
    crypto:pbkdf2_hmac(sha512, Pass, Salt, 1, 64),
    ecu_pbkdf2:pbkdf2_hmac(sha512, Pass, Salt, 1, 64)
  ),
  ?assertEqual(
    crypto:pbkdf2_hmac(sha512, Pass, Salt, 2, 64),
    ecu_pbkdf2:pbkdf2_hmac(sha512, Pass, Salt, 2, 64)
  ),
  ?assertEqual(
    crypto:pbkdf2_hmac(sha512, Pass, Salt, 2048, 64),
    ecu_pbkdf2:pbkdf2_hmac(sha512, Pass, Salt, 2048, 64)
  ).

hkdf_rfc5869_test() ->
  % RFC 5869 Test Case 1 (SHA-256)
  IKM = binary:copy(<<16#0b>>, 22),
  Salt = <<
    16#00,
    16#01,
    16#02,
    16#03,
    16#04,
    16#05,
    16#06,
    16#07,
    16#08,
    16#09,
    16#0a,
    16#0b,
    16#0c
  >>,
  Info = <<
    16#f0,
    16#f1,
    16#f2,
    16#f3,
    16#f4,
    16#f5,
    16#f6,
    16#f7,
    16#f8,
    16#f9
  >>,
  PRKExpected = <<
    16#07,
    16#77,
    16#09,
    16#36,
    16#2c,
    16#2e,
    16#32,
    16#df,
    16#0d,
    16#dc,
    16#3f,
    16#0d,
    16#c4,
    16#7b,
    16#ba,
    16#63,
    16#90,
    16#b6,
    16#c7,
    16#3b,
    16#b5,
    16#0f,
    16#9c,
    16#31,
    16#22,
    16#ec,
    16#84,
    16#4a,
    16#d7,
    16#c2,
    16#b3,
    16#e5
  >>,
  OKMExpected = <<
    16#3c,
    16#b2,
    16#5f,
    16#25,
    16#fa,
    16#ac,
    16#d5,
    16#7a,
    16#90,
    16#43,
    16#4f,
    16#64,
    16#d0,
    16#36,
    16#2f,
    16#2a,
    16#2d,
    16#2d,
    16#0a,
    16#90,
    16#cf,
    16#1a,
    16#5a,
    16#4c,
    16#5d,
    16#b0,
    16#2d,
    16#56,
    16#ec,
    16#c4,
    16#c5,
    16#bf,
    16#34,
    16#00,
    16#72,
    16#08,
    16#d5,
    16#b8,
    16#87,
    16#18,
    16#58,
    16#65
  >>,
  PRK = ecu_hkdf:extract(sha256, Salt, IKM),
  ?assertEqual(crypto:mac(hmac, sha256, Salt, IKM), PRK),
  ?assertEqual(PRKExpected, PRK),
  OKM = ecu_hkdf:expand(sha256, PRK, Info, 42),
  ?assertEqual(OKMExpected, OKM),
  ?assertEqual(OKMExpected, ecu_hkdf:hkdf(sha256, IKM, Salt, Info, 42)).
