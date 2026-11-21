%%%-------------------------------------------------------------------
%%% @doc
%%% Unit tests for BabyJubjub elliptic curve arithmetic and EdDSA.
%%% @end
%%%-------------------------------------------------------------------
-module(babyjubjub_tests).

-include_lib("eunit/include/eunit.hrl").

parameters_test() ->
  Q = ecu_babyjubjub:q(),
  A = ecu_babyjubjub:a(),
  D = ecu_babyjubjub:d(),
  Suborder = ecu_babyjubjub:suborder(),
  Cofactor = ecu_babyjubjub:cofactor(),
  Base8 = ecu_babyjubjub:base8(),
  Gen = ecu_babyjubjub:generator(),
  Id = ecu_babyjubjub:identity(),

  ?assertEqual(16#30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001, Q),
  ?assertEqual(168700, A),
  ?assertEqual(168696, D),
  ?assertEqual(8, Cofactor),
  ?assertEqual({0, 1}, Id),

  ?assert(ecu_babyjubjub:is_on_curve(Base8)),
  ?assert(ecu_babyjubjub:is_on_curve(Gen)),
  ?assert(ecu_babyjubjub:is_on_curve(Id)),
  ?assert(ecu_babyjubjub:is_in_subgroup(Base8)),
  ?assertEqual(Base8, ecu_babyjubjub:mul(Gen, 8)),
  ?assertEqual(Id, ecu_babyjubjub:mul(Base8, Suborder)).

group_laws_test() ->
  P = ecu_babyjubjub:base8(),
  Id = ecu_babyjubjub:identity(),

  ?assertEqual(P, ecu_babyjubjub:add(P, Id)),
  ?assertEqual(P, ecu_babyjubjub:add(Id, P)),
  ?assertEqual(Id, ecu_babyjubjub:add(P, ecu_babyjubjub:neg(P))),

  P2 = ecu_babyjubjub:double(P),
  ?assertEqual(P2, ecu_babyjubjub:add(P, P)),
  ?assertEqual(P2, ecu_babyjubjub:mul(P, 2)),

  P3 = ecu_babyjubjub:add(P2, P),
  ?assertEqual(P3, ecu_babyjubjub:mul(P, 3)),

  ?assertEqual(ecu_babyjubjub:add(P, P2), ecu_babyjubjub:add(P2, P)),
  P5 = ecu_babyjubjub:add(P2, P3),
  ?assertEqual(P5, ecu_babyjubjub:mul(P, 5)).

compress_decompress_test_vector_test() ->
  P = {
    17777552123799933955779906779655732241715742912184938656739573121738514868268,
    2626589144620713026669568689430873010625803728049924121243784502389097019475
  },
  ?assert(ecu_babyjubjub:is_on_curve(P)),
  Comp = ecu_babyjubjub:compress(P),
  ExpectedHex = "53b81ed5bffe9545b54016234682e7b2f699bd42a5e9eae27ff4051bc698ce85",
  ?assertEqual(ExpectedHex, string:to_lower(binary_to_list(binary:encode_hex(Comp)))),
  ?assertEqual({ok, P}, ecu_babyjubjub:decompress(Comp)).

decompress_vectors_test() ->
  Y0 = binary:decode_hex(<<"b5328f8791d48f20bec6e481d91c7ada235f1facf22547901c18656b6c3e042f">>),
  {ok, P0} = ecu_babyjubjub:decompress(Y0),
  ExpectedX0 = binary:decode_unsigned(
    binary:decode_hex(<<"b86cc8d9c97daef0afe1a4753c54fb2d8a530dc74c7eee4e72b3fdf2496d2113">>), little
  ),
  ?assertEqual(ExpectedX0, element(1, P0)),

  Y1 = binary:decode_hex(<<"70552d3ff548e09266ded29b33ce75139672b062b02aa66bb0d9247ffecf1d0b">>),
  {ok, P1} = ecu_babyjubjub:decompress(Y1),
  ExpectedX1 = binary:decode_unsigned(
    binary:decode_hex(<<"30f1635ba7d56f9cb32c3ffbe6dca508a68c7f43936af11a23c785ce98cb3404">>), little
  ),
  ?assertEqual(ExpectedX1, element(1, P1)).

decompress_invalid_test() ->
  ?assertEqual({error, bad_length}, ecu_babyjubjub:decompress(<<0:248>>)),
  Q = ecu_babyjubjub:q(),
  TooBig = <<(Q + 5):256/little>>,
  ?assertEqual({error, y_outside_field}, ecu_babyjubjub:decompress(TooBig)).

blake512_test() ->
  Msg =
    <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1>>,
  Hash = ecu_blake512:hash(Msg),
  ExpectedHex =
    "c992db23d6290c70ffcc02f7abeb00b9d00fa8b43e55d7949c28ba6be7545d3253882a61bd004a236ef1cdba01b27ba0aedfb08eefdbfb7c19657c880b43ddf1",
  ?assertEqual(ExpectedHex, string:to_lower(binary_to_list(binary:encode_hex(Hash)))),

  EmptyHash = ecu_blake512:hash(<<>>),
  ExpectedEmpty =
    "a8cfbbd73726062df0c6864dda65defe58ef0cc52a5625090fa17601e1eecd1b628e94f396ae402a00acc9eab77b4d4c2e852aaaa25a636d80af3fc7913ef5b8",
  ?assertEqual(ExpectedEmpty, string:to_lower(binary_to_list(binary:encode_hex(EmptyHash)))).

eddsa_circomlib_test_vector_test() ->
  SK =
    <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1>>,
  PKComp = ecu_babyjubjub:derive_public_key(SK),
  ExpectedPKHex = "c433f7a696b7aa3a5224efb3993baf0ccd9e92eecee0c29a3f6c8208a9e81d9e",
  ?assertEqual(ExpectedPKHex, string:to_lower(binary_to_list(binary:encode_hex(PKComp)))),

  MsgBin = binary:decode_hex(<<"00010203040506070809">>),
  Sig = ecu_babyjubjub:sign(SK, MsgBin),
  ?assertEqual(64, byte_size(Sig)),

  <<_R8Comp:32/binary, S:256/little>> = Sig,
  ?assertEqual(
    "1672775540645840396591609181675628451599263765380031905495115170613215233181", integer_to_list(S)
  ),

  ?assert(ecu_babyjubjub:verify(PKComp, Sig, MsgBin)),
  ?assertNot(ecu_babyjubjub:verify(PKComp, Sig, binary:decode_hex(<<"00010203040506070808">>))).

eddsa_roundtrip_test() ->
  {SK, PK} = ecu_babyjubjub:keypair(),
  Msg = 12345678901234567890,
  Sig = ecu_babyjubjub:sign(SK, Msg),
  ?assert(ecu_babyjubjub:verify(PK, Sig, Msg)),
  ?assertNot(ecu_babyjubjub:verify(PK, Sig, Msg + 1)),
  <<BadSigHead:63/binary, LastByte:8>> = Sig,
  TamperedSig = <<BadSigHead/binary, (LastByte bxor 1):8>>,
  ?assertNot(ecu_babyjubjub:verify(PK, TamperedSig, Msg)).

nif_differential_test() ->
  case ecu_babyjubjub_nif:is_available() of
    true ->
      SK =
        <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
          27, 28, 29, 30, 31, 32>>,
      ErlPK = ecu_babyjubjub:derive_public_key(SK),
      {ok, NifPK} = ecu_babyjubjub_nif:eddsa_prv2pub(SK),
      ?assertEqual(ErlPK, NifPK),

      Msg = 987654321012345,
      MsgBE = <<Msg:256/big>>,
      ErlSig = ecu_babyjubjub:sign(SK, Msg),
      {ok, NifSig} = ecu_babyjubjub_nif:eddsa_sign(SK, MsgBE),
      ?assertEqual(ErlSig, NifSig),

      ?assert(ecu_babyjubjub:verify(ErlPK, NifSig, Msg)),
      ?assertEqual({ok, true}, ecu_babyjubjub_nif:eddsa_verify(NifPK, ErlSig, MsgBE)),

      %% Point addition differential
      P1 = ecu_babyjubjub:compress(ecu_babyjubjub:base8()),
      P2 = ecu_babyjubjub:compress(ecu_babyjubjub:double(ecu_babyjubjub:base8())),
      ErlP3 = ecu_babyjubjub:compress(
        ecu_babyjubjub:add(ecu_babyjubjub:base8(), ecu_babyjubjub:double(ecu_babyjubjub:base8()))
      ),
      {ok, NifP3} = ecu_babyjubjub_nif:point_add(P1, P2),
      ?assertEqual(ErlP3, NifP3),

      %% Scalar multiplication differential
      Scalar = 123456789,
      ScalarBE = <<Scalar:256/big>>,
      ErlMul = ecu_babyjubjub:compress(ecu_babyjubjub:mul(ecu_babyjubjub:base8(), Scalar)),
      {ok, NifMul} = ecu_babyjubjub_nif:point_mul(P1, ScalarBE),
      ?assertEqual(ErlMul, NifMul);
    false ->
      ok
  end.
