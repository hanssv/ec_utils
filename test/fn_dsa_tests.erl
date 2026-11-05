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
