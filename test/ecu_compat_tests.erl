-module(ecu_compat_tests).

-include_lib("eunit/include/eunit.hrl").

-ifdef(NO_CRYPTO).

pure_mode_test() ->
  ?assertEqual(pure, ecu_compat:mode()),
  ?assertEqual(false, ecu_compat:is_crypto_available()),
  ?assertError(no_crypto_compiled, ecu_compat:set_mode(otp)),
  ?assertEqual(ok, ecu_compat:set_mode(pure)).

pure_hash_test() ->
  ?assertEqual(
    <<16#ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad:256>>,
    ecu_compat:hash(sha256, <<"abc">>)
  ),
  ?assertEqual(
    <<
      16#ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f:512
    >>,
    ecu_compat:hash(sha512, <<"abc">>)
  ),
  ?assertEqual(
    <<16#8eb208f7e05d987a9b044a8e98c6b087f15a0bfc:160>>,
    ecu_compat:hash(ripemd160, <<"abc">>)
  ).

pure_rand_test() ->
  Bytes = ecu_compat:strong_rand_bytes(32),
  ?assertEqual(32, byte_size(Bytes)),
  Bytes2 = ecu_compat:strong_rand_bytes(32),
  ?assertNotEqual(Bytes, Bytes2).

pure_exor_test() ->
  ?assertEqual(<<0, 0, 0>>, ecu_compat:exor(<<1, 2, 3>>, <<1, 2, 3>>)),
  ?assertEqual(<<255, 255>>, ecu_compat:exor(<<16#aa, 16#55>>, <<16#55, 16#aa>>)).

pure_mod_pow_test() ->
  ?assertEqual(<<1, 189>>, ecu_compat:mod_pow(4, 13, 497)).

-else.

mode_switching_test() ->
  OrigMode = ecu_compat:mode(),
  try
    ecu_compat:set_mode(pure),
    ?assertEqual(pure, ecu_compat:mode()),
    ?assertEqual(false, ecu_compat:is_crypto_available()),
    ecu_compat:set_mode(otp),
    ?assertEqual(otp, ecu_compat:mode()),
    ?assertEqual(true, ecu_compat:is_crypto_available()),
    ecu_compat:set_mode(default),
    ?assertEqual(default, ecu_compat:mode())
  after
    ecu_compat:set_mode(OrigMode)
  end.

differential_hash_test() ->
  OrigMode = ecu_compat:mode(),
  Algs = [
    sha224,
    sha256,
    sha384,
    sha512,
    ripemd160,
    sha3_224,
    sha3_256,
    sha3_384,
    sha3_512,
    keccak256
  ],
  Inputs = [
    <<>>,
    <<"abc">>,
    <<"The quick brown fox jumps over the lazy dog">>,
    binary:copy(<<"test">>, 100)
  ],
  try
    lists:foreach(
      fun(Alg) ->
        lists:foreach(
          fun(In) ->
            ecu_compat:set_mode(pure),
            PureHash = ecu_compat:hash(Alg, In),
            ecu_compat:set_mode(otp),
            OtpHash = ecu_compat:hash(Alg, In),
            ?assertEqual(OtpHash, PureHash)
          end,
          Inputs
        )
      end,
      Algs
    )
  after
    ecu_compat:set_mode(OrigMode)
  end.

differential_xof_test() ->
  OrigMode = ecu_compat:mode(),
  Inputs = [<<>>, <<"hello">>, binary:copy(<<"data">>, 50)],
  BitLens = [8, 32, 256, 512, 114 * 8],
  try
    lists:foreach(
      fun(Alg) ->
        lists:foreach(
          fun(In) ->
            lists:foreach(
              fun(Bits) ->
                ecu_compat:set_mode(pure),
                PureXof = ecu_compat:hash_xof(Alg, In, Bits),
                ecu_compat:set_mode(otp),
                OtpXof = ecu_compat:hash_xof(Alg, In, Bits),
                ?assertEqual(OtpXof, PureXof)
              end,
              BitLens
            )
          end,
          Inputs
        )
      end,
      [shake128, shake256]
    )
  after
    ecu_compat:set_mode(OrigMode)
  end.

differential_exor_test() ->
  OrigMode = ecu_compat:mode(),
  try
    lists:foreach(
      fun(Len) ->
        A = binary:copy(<<"a">>, Len),
        B = binary:copy(<<"b">>, Len),
        ecu_compat:set_mode(pure),
        PureExor = ecu_compat:exor(A, B),
        ecu_compat:set_mode(otp),
        OtpExor = ecu_compat:exor(A, B),
        ?assertEqual(OtpExor, PureExor)
      end,
      [1, 16, 32, 64, 128]
    )
  after
    ecu_compat:set_mode(OrigMode)
  end.

differential_rand_bytes_test() ->
  OrigMode = ecu_compat:mode(),
  try
    ecu_compat:set_mode(pure),
    PureBytes = ecu_compat:strong_rand_bytes(32),
    ?assertEqual(32, byte_size(PureBytes)),
    ecu_compat:set_mode(otp),
    OtpBytes = ecu_compat:strong_rand_bytes(32),
    ?assertEqual(32, byte_size(OtpBytes)),
    ?assertNotEqual(PureBytes, OtpBytes)
  after
    ecu_compat:set_mode(OrigMode)
  end.

differential_pbkdf2_test() ->
  OrigMode = ecu_compat:mode(),
  try
    Pass = <<"password">>,
    Salt = <<"salt">>,
    lists:foreach(
      fun(Iter) ->
        ecu_compat:set_mode(pure),
        PureKey = ecu_compat:pbkdf2_hmac(sha512, Pass, Salt, Iter, 64),
        ecu_compat:set_mode(otp),
        OtpKey = ecu_compat:pbkdf2_hmac(sha512, Pass, Salt, Iter, 64),
        ?assertEqual(OtpKey, PureKey)
      end,
      [1, 2, 10]
    )
  after
    ecu_compat:set_mode(OrigMode)
  end.

differential_mod_pow_test() ->
  OrigMode = ecu_compat:mode(),
  try
    Vectors = [
      {3, 0, 7},
      {4, 13, 497},
      {1234567, 7654321, 1000000007},
      {2, 65537, 1000000009}
    ],
    lists:foreach(
      fun({A, B, P}) ->
        ecu_compat:set_mode(pure),
        PureRes = ecu_compat:mod_pow(A, B, P),
        ecu_compat:set_mode(otp),
        OtpRes = ecu_compat:mod_pow(A, B, P),
        ?assertEqual(OtpRes, PureRes)
      end,
      Vectors
    )
  after
    ecu_compat:set_mode(OrigMode)
  end.

-endif.
