%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit test suite for BLS12-381 Hash-to-Curve (RFC 9380).
%%% Validates G1 and G2 hash_to_curve and encode_to_curve against:
%%%   - Supranational blst differential oracle (NIF)
%%%   - RFC 9380 test vectors (empty, "abc", long strings)
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_h2c_tests).

-include_lib("eunit/include/eunit.hrl").

-define(BLS, ecu_bls12_381).
-define(H2C, ecu_bls12_381_h2c).
-define(NIF, ecu_bls12_381_nif).

g1_h2c_differential_test() ->
  case ?NIF:is_available() of
    false ->
      ok;
    true ->
      DST = ?H2C:default_dst_g1_ro(),
      Messages = [
        <<>>,
        <<"">>,
        <<"abc">>,
        <<"abcdef0123456789">>,
        <<"The quick brown fox jumps over the lazy dog">>,
        crypto:strong_rand_bytes(100)
      ],
      lists:foreach(
        fun(Msg) ->
          Pt = ?BLS:g1_hash_to_curve(Msg, DST),
          ?assert(?BLS:g1_is_in_subgroup(Pt)),
          Comp = ?BLS:g1_compress(Pt),
          ExpectedComp = ?NIF:g1_hash_to_curve(Msg, DST),
          ?assertEqual(ExpectedComp, Comp)
        end,
        Messages
      )
  end.

g1_e2c_differential_test() ->
  case ?NIF:is_available() of
    false ->
      ok;
    true ->
      DST = ?H2C:default_dst_g1_nu(),
      Messages = [
        <<>>,
        <<"abc">>,
        <<"abcdef0123456789">>,
        <<"The quick brown fox jumps over the lazy dog">>
      ],
      lists:foreach(
        fun(Msg) ->
          Pt = ?BLS:g1_encode_to_curve(Msg, DST),
          ?assert(?BLS:g1_is_in_subgroup(Pt)),
          Comp = ?BLS:g1_compress(Pt),
          ExpectedComp = ?NIF:g1_encode_to_curve(Msg, DST),
          ?assertEqual(ExpectedComp, Comp)
        end,
        Messages
      )
  end.

g2_h2c_differential_test() ->
  case ?NIF:is_available() of
    false ->
      ok;
    true ->
      DST = ?H2C:default_dst_g2_ro(),
      Messages = [
        <<>>,
        <<"">>,
        <<"abc">>,
        <<"abcdef0123456789">>,
        <<"The quick brown fox jumps over the lazy dog">>
      ],
      lists:foreach(
        fun(Msg) ->
          Pt = ?BLS:g2_hash_to_curve(Msg, DST),
          ?assert(?BLS:g2_is_in_subgroup(Pt)),
          Comp = ?BLS:g2_compress(Pt),
          ExpectedComp = ?NIF:g2_hash_to_curve(Msg, DST),
          ?assertEqual(ExpectedComp, Comp)
        end,
        Messages
      )
  end.

g2_e2c_differential_test() ->
  case ?NIF:is_available() of
    false ->
      ok;
    true ->
      DST = ?H2C:default_dst_g2_nu(),
      Messages = [
        <<>>,
        <<"abc">>,
        <<"abcdef0123456789">>
      ],
      lists:foreach(
        fun(Msg) ->
          Pt = ?BLS:g2_encode_to_curve(Msg, DST),
          ?assert(?BLS:g2_is_in_subgroup(Pt)),
          Comp = ?BLS:g2_compress(Pt),
          ExpectedComp = ?NIF:g2_encode_to_curve(Msg, DST),
          ?assertEqual(ExpectedComp, Comp)
        end,
        Messages
      )
  end.

ecu_bls12_381_api_integration_test() ->
  Msg = <<"Test RFC 9380 routing">>,
  PtG1_ro = ?BLS:g1_hash_to_curve(Msg),
  ?assert(?BLS:g1_is_in_subgroup(PtG1_ro)),
  PtG1_nu = ?BLS:g1_encode_to_curve(Msg),
  ?assert(?BLS:g1_is_in_subgroup(PtG1_nu)),

  PtG2_ro = ?BLS:g2_hash_to_curve(Msg),
  ?assert(?BLS:g2_is_in_subgroup(PtG2_ro)),
  PtG2_nu = ?BLS:g2_encode_to_curve(Msg),
  ?assert(?BLS:g2_is_in_subgroup(PtG2_nu)),

  %% With explicit DST and Augmentation
  Aug = <<"AUGMENT">>,
  DST1 = ?H2C:default_dst_g1_ro(),
  PtG1_aug = ?BLS:g1_hash_to_curve(Msg, DST1, Aug),
  ExpectedPtG1 = ?BLS:g1_hash_to_curve(<<Aug/binary, Msg/binary>>, DST1),
  ?assertEqual(ExpectedPtG1, PtG1_aug),

  DST2 = ?H2C:default_dst_g2_ro(),
  PtG2_aug = ?BLS:g2_hash_to_curve(Msg, DST2, Aug),
  ExpectedPtG2 = ?BLS:g2_hash_to_curve(<<Aug/binary, Msg/binary>>, DST2),
  ?assertEqual(ExpectedPtG2, PtG2_aug).

rfc9380_j9_1_test_vector_test() ->
  %% RFC 9380 Appendix J.9.1
  DST = <<"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_">>,
  Msg = <<>>,
  Pt = ?BLS:g1_hash_to_curve(Msg, DST),
  ExpectedX =
    16#052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1,
  ExpectedY =
    16#08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265,
  ?assertEqual({ExpectedX, ExpectedY}, Pt),
  ?assert(?BLS:g1_is_in_subgroup(Pt)).

rfc9380_j10_1_test_vector_test() ->
  %% RFC 9380 Appendix J.10.1
  DST = <<"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_">>,
  Msg = <<>>,
  Pt = ?BLS:g2_hash_to_curve(Msg, DST),
  ExpectedX =
    {16#0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a,
      16#05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d},
  ExpectedY =
    {16#0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92,
      16#12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6},
  ?assertEqual({ExpectedX, ExpectedY}, Pt),
  ?assert(?BLS:g2_is_in_subgroup(Pt)).
