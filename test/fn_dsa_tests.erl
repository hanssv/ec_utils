%%%-------------------------------------------------------------------
%%% @doc
%%% Tests for pure-Erlang FN-DSA (FIPS 206 / Falcon) implementation.
%%% Includes verification against Known Answer Tests (KATs) and
%%% differential cross-checking against the Rust reference NIF.
%%% @end
%%%-------------------------------------------------------------------
-module(fn_dsa_tests).

-include_lib("eunit/include/eunit.hrl").

parameter_set_identification_test() ->
  ?assertEqual(fn_dsa_512, ecu_fn_dsa:parameter_set(fn_dsa_512)),
  ?assertEqual(fn_dsa_512, ecu_fn_dsa:parameter_set(falcon512)),
  ?assertEqual(fn_dsa_1024, ecu_fn_dsa:parameter_set(fn_dsa_1024)),
  ?assertEqual(fn_dsa_1024, ecu_fn_dsa:parameter_set(falcon1024)),
  DummyPK512 = <<9:8, 0:(896 * 8)>>,
  DummyPK1024 = <<10:8, 0:(1792 * 8)>>,
  ?assertEqual(fn_dsa_512, ecu_fn_dsa:parameter_set(DummyPK512)),
  ?assertEqual(fn_dsa_1024, ecu_fn_dsa:parameter_set(DummyPK1024)),
  DummySig512 = <<16#39:8, 0:(40 * 8), 0:64>>,
  DummySig1024 = <<16#3A:8, 0:(40 * 8), 0:64>>,
  ?assertEqual(fn_dsa_512, ecu_fn_dsa:parameter_set(DummySig512)),
  ?assertEqual(fn_dsa_1024, ecu_fn_dsa:parameter_set(DummySig1024)),
  ?assertError(badarg, ecu_fn_dsa:parameter_set(unknown_set)),
  ?assertError(badarg, ecu_fn_dsa:parameter_set(<<1, 2, 3>>)).

kat_vectors_verify_test() ->
  KatFile = filename:join([code:lib_dir(ec_utils), "..", "..", "..", "test", "fn_dsa_kat_vectors.term"]),
  FileToRead =
    case filelib:is_file(KatFile) of
      true -> KatFile;
      false -> "test/fn_dsa_kat_vectors.term"
    end,
  {ok, [Kats]} = file:consult(FileToRead),
  lists:foreach(
    fun(Kat) ->
      #{msg := Msg, falcon512 := F512, falcon1024 := F1024} = Kat,
      #{pk := PK512, sig := Sig512} = F512,
      #{pk := PK1024, sig := Sig1024} = F1024,

      %% 1. Verify 512
      ?assert(ecu_fn_dsa:verify(Msg, Sig512, PK512)),
      ?assert(ecu_fn_dsa:verify(fn_dsa_512, Msg, Sig512, PK512)),
      ?assertNot(ecu_fn_dsa:verify(<<"Tampered message">>, Sig512, PK512)),

      %% 2. Verify 1024
      ?assert(ecu_fn_dsa:verify(Msg, Sig1024, PK1024)),
      ?assert(ecu_fn_dsa:verify(fn_dsa_1024, Msg, Sig1024, PK1024)),
      ?assertNot(ecu_fn_dsa:verify(<<"Tampered message">>, Sig1024, PK1024))
    end,
    Kats
  ).

differential_nif_verify_test() ->
  case ecu_fn_dsa_nif:is_available() of
    true ->
      %% Generate new keypair from NIF and sign with NIF
      {ok, {PK512, SK512}} = ecu_fn_dsa_nif:falcon512_keypair(),
      Msg512 = <<"Live differential test message for Falcon-512">>,
      {ok, Sig512} = ecu_fn_dsa_nif:falcon512_sign(SK512, Msg512),

      %% Verify in pure Erlang
      ?assert(ecu_fn_dsa:verify(Msg512, Sig512, PK512)),
      ?assert(ecu_fn_dsa:verify(fn_dsa_512, Msg512, Sig512, PK512)),
      ?assertNot(ecu_fn_dsa:verify(<<"Wrong message">>, Sig512, PK512)),

      %% Falcon-1024
      {ok, {PK1024, SK1024}} = ecu_fn_dsa_nif:falcon1024_keypair(),
      Msg1024 = <<"Live differential test message for Falcon-1024">>,
      {ok, Sig1024} = ecu_fn_dsa_nif:falcon1024_sign(SK1024, Msg1024),

      ?assert(ecu_fn_dsa:verify(Msg1024, Sig1024, PK1024)),
      ?assert(ecu_fn_dsa:verify(fn_dsa_1024, Msg1024, Sig1024, PK1024)),
      ?assertNot(ecu_fn_dsa:verify(<<"Wrong message">>, Sig1024, PK1024));
    false ->
      ok
  end.

invalid_signatures_test() ->
  KatFile = "test/fn_dsa_kat_vectors.term",
  {ok, [Kats]} = file:consult(KatFile),
  Kat = hd(Kats),
  #{msg := Msg, falcon512 := #{pk := PK512, sig := Sig512}} = Kat,

  %% Wrong header byte
  <<_:8, SigRest/binary>> = Sig512,
  BadHeaderSig = <<16#20:8, SigRest/binary>>,
  ?assertNot(ecu_fn_dsa:verify(Msg, BadHeaderSig, PK512)),

  %% Truncated signature
  TruncatedSig = binary:part(Sig512, 0, byte_size(Sig512) - 10),
  ?assertNot(ecu_fn_dsa:verify(Msg, TruncatedSig, PK512)),

  %% Corrupted signature byte
  <<Pre:200/binary, B:8, Post/binary>> = Sig512,
  CorruptedSig = <<Pre/binary, (B bxor 16#FF):8, Post/binary>>,
  ?assertNot(ecu_fn_dsa:verify(Msg, CorruptedSig, PK512)),

  %% Truncated PK
  TruncatedPK = binary:part(PK512, 0, 500),
  ?assertNot(ecu_fn_dsa:verify(Msg, Sig512, TruncatedPK)),

  %% Overlong context (> 255 bytes)
  OverlongCtx = binary:copy(<<"x">>, 256),
  ?assertNot(ecu_fn_dsa:verify(Msg, Sig512, PK512, OverlongCtx)).

secret_key_codec_and_public_key_derivation_test() ->
  KatFile = "test/fn_dsa_kat_vectors.term",
  {ok, [Kats]} = file:consult(KatFile),
  Kat = hd(Kats),
  #{falcon512 := #{pk := PK512, sk := SK512}, falcon1024 := #{pk := PK1024, sk := SK1024}} = Kat,

  %% 1. Falcon-512 secret key decode & encode roundtrip
  {ok, {fn_dsa_512, F512, G512, FBig512, GBig512}} = ecu_fn_dsa:decode_secret_key(SK512),
  ?assertEqual(SK512, ecu_fn_dsa:encode_secret_key(fn_dsa_512, F512, G512, FBig512)),

  %% Verify public key derivation: h = g * f^(-1) mod q
  FTuple512 = list_to_tuple([(X rem 12289 + 12289) rem 12289 || X <- F512]),
  GTuple512 = list_to_tuple([(X rem 12289 + 12289) rem 12289 || X <- G512]),
  FHat512List = tuple_to_list(ecu_fn_dsa:ntt(FTuple512, 9)),
  GHat512List = tuple_to_list(ecu_fn_dsa:ntt(GTuple512, 9)),
  HHat512 =
    list_to_tuple([
      (GVal * ecu_fn_dsa:mod_inv(FVal, 12289)) rem 12289
     || {GVal, FVal} <- lists:zip(GHat512List, FHat512List)
    ]),
  HPoly512 = tuple_to_list(ecu_fn_dsa:inv_ntt(HHat512, 9)),
  ?assertEqual(PK512, ecu_fn_dsa:encode_public_key(fn_dsa_512, HPoly512)),
  {ok, {fn_dsa_512, DecodedH512}} = ecu_fn_dsa:decode_public_key(PK512),
  ?assertEqual(HPoly512, DecodedH512),

  %% Verify NTRU relation: f * G - g * F = q mod (x^n + 1)
  %% Check modulo q: f * G - g * F = 0 mod q
  GBigTuple512 = list_to_tuple([(X rem 12289 + 12289) rem 12289 || X <- GBig512]),
  FBigTuple512 = list_to_tuple([(X rem 12289 + 12289) rem 12289 || X <- FBig512]),
  GBigHat512List = tuple_to_list(ecu_fn_dsa:ntt(GBigTuple512, 9)),
  FBigHat512List = tuple_to_list(ecu_fn_dsa:ntt(FBigTuple512, 9)),
  DiffHat512 = [
    ((FVal * GBigVal - GVal * FBigVal) rem 12289 + 12289) rem 12289
   || {{FVal, GBigVal}, {GVal, FBigVal}} <-
      lists:zip(lists:zip(FHat512List, GBigHat512List), lists:zip(GHat512List, FBigHat512List))
  ],
  ?assertEqual([0 || _ <- lists:seq(1, 512)], DiffHat512),

  %% 2. Falcon-1024 secret key decode & encode roundtrip
  {ok, {fn_dsa_1024, F1024, G1024, FBig1024, _GBig1024}} = ecu_fn_dsa:decode_secret_key(SK1024),
  ?assertEqual(SK1024, ecu_fn_dsa:encode_secret_key(fn_dsa_1024, F1024, G1024, FBig1024)),

  FTuple1024 = list_to_tuple([(X rem 12289 + 12289) rem 12289 || X <- F1024]),
  GTuple1024 = list_to_tuple([(X rem 12289 + 12289) rem 12289 || X <- G1024]),
  FHat1024List = tuple_to_list(ecu_fn_dsa:ntt(FTuple1024, 10)),
  GHat1024List = tuple_to_list(ecu_fn_dsa:ntt(GTuple1024, 10)),
  HHat1024 =
    list_to_tuple([
      (GVal * ecu_fn_dsa:mod_inv(FVal, 12289)) rem 12289
     || {GVal, FVal} <- lists:zip(GHat1024List, FHat1024List)
    ]),
  HPoly1024 = tuple_to_list(ecu_fn_dsa:inv_ntt(HHat1024, 10)),
  ?assertEqual(PK1024, ecu_fn_dsa:encode_public_key(fn_dsa_1024, HPoly1024)),
  {ok, {fn_dsa_1024, DecodedH1024}} = ecu_fn_dsa:decode_public_key(PK1024),
  ?assertEqual(HPoly1024, DecodedH1024).

pure_erlang_sign_and_verify_test() ->
  KatFile = "test/fn_dsa_kat_vectors.term",
  {ok, [Kats]} = file:consult(KatFile),
  Kat = hd(Kats),
  #{falcon512 := #{pk := PK512, sk := SK512}, falcon1024 := #{pk := PK1024, sk := SK1024}} = Kat,
  Msg = <<"Test pure-Erlang FN-DSA signing!">>,

  %% 1. Sign Falcon-512 with pure Erlang
  {ok, Sig512} = ecu_fn_dsa:sign(Msg, SK512),
  ?assert(byte_size(Sig512) =< 666),
  ?assert(ecu_fn_dsa:verify(Msg, Sig512, PK512)),
  ?assertNot(ecu_fn_dsa:verify(<<"Tampered">>, Sig512, PK512)),
  case ecu_fn_dsa_nif:is_available() of
    true ->
      ?assert(ecu_fn_dsa_nif:falcon512_verify(PK512, Msg, Sig512)),
      ?assertNot(ecu_fn_dsa_nif:falcon512_verify(PK512, <<"Tampered">>, Sig512));
    false ->
      ok
  end,

  %% 2. Sign Falcon-1024 with pure Erlang
  {ok, Sig1024} = ecu_fn_dsa:sign(Msg, SK1024),
  ?assert(byte_size(Sig1024) =< 1280),
  ?assert(ecu_fn_dsa:verify(Msg, Sig1024, PK1024)),
  ?assertNot(ecu_fn_dsa:verify(<<"Tampered">>, Sig1024, PK1024)),
  case ecu_fn_dsa_nif:is_available() of
    true ->
      ?assert(ecu_fn_dsa_nif:falcon1024_verify(PK1024, Msg, Sig1024)),
      ?assertNot(ecu_fn_dsa_nif:falcon1024_verify(PK1024, <<"Tampered">>, Sig1024));
    false ->
      ok
  end.

deterministic_signing_test() ->
  KatFile = "test/fn_dsa_kat_vectors.term",
  {ok, [Kats]} = file:consult(KatFile),
  Kat = hd(Kats),
  #{falcon512 := #{pk := PK512, sk := SK512}} = Kat,
  Msg = <<"Deterministic FN-DSA message">>,

  {ok, Sig1} = ecu_fn_dsa:sign_deterministic(Msg, SK512),
  {ok, Sig2} = ecu_fn_dsa:sign_deterministic(Msg, SK512),
  ?assertEqual(Sig1, Sig2),
  ?assert(ecu_fn_dsa:verify(Msg, Sig1, PK512)),
  case ecu_fn_dsa_nif:is_available() of
    true ->
      ?assert(ecu_fn_dsa_nif:falcon512_verify(PK512, Msg, Sig1));
    false ->
      ok
  end.

comp_encode_decode_roundtrip_test() ->
  %% Test roundtrip of comp_encode and decode_s2 on random valid s2 coefficients
  lists:foreach(
    fun(_) ->
      S2 = [rand:uniform(200) - 100 || _ <- lists:seq(1, 512)],
      {ok, Comp} = ecu_fn_dsa:comp_encode(S2, 625),
      {ok, Decoded} = ecu_fn_dsa:decode_s2(Comp, 512),
      ?assertEqual(S2, Decoded)
    end,
    lists:seq(1, 10)
  ).

differential_keypair_nif_sign_erlang_test() ->
  case ecu_fn_dsa_nif:is_available() of
    true ->
      lists:foreach(
        fun(I) ->
          %% 1. Generate live keypair from Rust NIF
          {ok, {PK512, SK512}} = ecu_fn_dsa_nif:falcon512_keypair(),
          Msg512 = iolist_to_binary(["Differential roundtrip test message 512 #", integer_to_list(I)]),
          %% Sign with pure Erlang
          {ok, Sig512} = ecu_fn_dsa:sign(Msg512, SK512),
          %% Verify with Rust NIF
          ?assert(ecu_fn_dsa_nif:falcon512_verify(PK512, Msg512, Sig512)),
          %% Verify with pure Erlang
          ?assert(ecu_fn_dsa:verify(Msg512, Sig512, PK512)),

          %% 2. Same for Falcon-1024
          {ok, {PK1024, SK1024}} = ecu_fn_dsa_nif:falcon1024_keypair(),
          Msg1024 = iolist_to_binary(["Differential roundtrip test message 1024 #", integer_to_list(I)]),
          {ok, Sig1024} = ecu_fn_dsa:sign(Msg1024, SK1024),
          ?assert(ecu_fn_dsa_nif:falcon1024_verify(PK1024, Msg1024, Sig1024)),
          ?assert(ecu_fn_dsa:verify(Msg1024, Sig1024, PK1024))
        end,
        lists:seq(1, 3)
      );
    false ->
      ok
  end.
