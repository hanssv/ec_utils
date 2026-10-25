%%% File        : schnorr_tests.erl
%%% Description : Unit tests and official BIP-340 test vector runner
-module(schnorr_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

-include("ecu_secp256k1.hrl").

bip340_test_vectors_test() ->
  Filename = filename:join([code:priv_dir(ec_utils), "..", "test", "bip340_test_vectors.csv"]),
  Path = case filelib:is_file(Filename) of
           true  -> Filename;
           false -> "test/bip340_test_vectors.csv"
         end,
  {ok, CsvBinary} = file:read_file(Path),
  Lines = binary:split(CsvBinary, [<<"\r\n">>, <<"\n">>], [global, trim_all]),
  [_Header | Rows] = Lines,
  lists:foreach(fun(Row) -> run_test_vector(Row) end, Rows),
  ok.

run_test_vector(RowBin) ->
  Tokens = binary:split(RowBin, <<",">>, [global]),
  case Tokens of
    [IndexBin, SecBinHex, PubBinHex, AuxBinHex, MsgBinHex, SigBinHex, ExpectedResultBin | _] ->
      Idx = binary_to_integer(IndexBin),
      PubBin = hex_to_bin(PubBinHex),
      MsgBin = hex_to_bin(MsgBinHex),
      SigBin = hex_to_bin(SigBinHex),
      ExpectedVerify = (string:uppercase(binary_to_list(ExpectedResultBin)) == "TRUE"),

      %% 1. If secret key is provided, test public key derivation and signing
      case SecBinHex of
        <<>> -> ok;
        _  ->
          SecBin = hex_to_bin(SecBinHex),
          AuxBin = hex_to_bin(AuxBinHex),
          #{public := DerivedPub} = ecu_schnorr:sign_keypair_from_secret(SecBin),
          ?assertEqual({Idx, PubBin}, {Idx, DerivedPub}),
          ComputedSig = ecu_schnorr:sign(MsgBin, SecBin, AuxBin),
          ?assertEqual({Idx, SigBin}, {Idx, ComputedSig})
      end,

      %% 2. Test signature verification
      ActualVerify = ecu_schnorr:verify(SigBin, MsgBin, PubBin),
      ?assertEqual({Idx, ExpectedVerify}, {Idx, ActualVerify});
    _ ->
      ok
  end.

hex_to_bin(<<>>) -> <<>>;
hex_to_bin(Bin) when is_binary(Bin) ->
  binary:decode_hex(Bin).

roundtrip_test() ->
  #{public := Pub, secret := Sec} = ecu_schnorr:sign_keypair(),
  Msg = <<"Hello, BIP-340 Schnorr!">>,
  Sig = ecu_schnorr:sign(Msg, Sec),
  ?assertEqual(true, ecu_schnorr:verify(Sig, Msg, Pub)),
  CorruptedSig = <<(crypto:strong_rand_bytes(32))/binary, (binary:part(Sig, 32, 32))/binary>>,
  ?assertEqual(false, ecu_schnorr:verify(CorruptedSig, Msg, Pub)),
  ?assertEqual(false, ecu_schnorr:verify(Sig, <<"Corrupted Msg">>, Pub)).

tagged_hash_test() ->
  %% Verify tagged_hash matches manual formula
  Tag = <<"BIP0340/challenge">>,
  Data = <<"test data">>,
  H = crypto:hash(sha256, Tag),
  Expected = crypto:hash(sha256, <<H/binary, H/binary, Data/binary>>),
  Actual = ecu_schnorr:tagged_hash(Tag, Data),
  ?assertEqual(Expected, Actual).

schnorr_benchmark_test() ->
  Pairs = [ ecu_schnorr:sign_keypair() || _ <- lists:seq(1, 10) ],
  Msg = <<"Benchmark test message for BIP-340 Schnorr signatures">>,
  {SignTime, Sigs} = timer:tc(fun() ->
    [ ecu_schnorr:sign(Msg, maps:get(secret, KP)) || KP <- Pairs ]
  end),
  {VerifyTime, Results} = timer:tc(fun() ->
    [ ecu_schnorr:verify(Sig, Msg, maps:get(public, KP)) || {Sig, KP} <- lists:zip(Sigs, Pairs) ]
  end),
  ?debugFmt("", []),
  ?debugFmt("Average time for BIP-340 sign:   ~.3f ms", [(SignTime / 1000) / length(Pairs)]),
  ?debugFmt("Average time for BIP-340 verify: ~.3f ms", [(VerifyTime / 1000) / length(Pairs)]),
  [ ?assert(R) || R <- Results ].
