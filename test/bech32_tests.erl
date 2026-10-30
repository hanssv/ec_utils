%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests and BIP-173 / BIP-350 test vectors for ecu_bech32,
%%% including differential cross-checks against ecu_rustcrypto_nif.
%%% @end
%%%-------------------------------------------------------------------
-module(bech32_tests).

-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% BIP-173 Valid Strings
%% ===================================================================

bip173_valid_strings_test() ->
  ValidStrings = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl"
  ],
  lists:foreach(
    fun(Str) ->
      {ok, {Hrp, Data, Variant}} = ecu_bech32:decode(Str),
      ?assertEqual(bech32, Variant),
      {ok, Reencoded} = ecu_bech32:encode(Hrp, Data, Variant),
      ?assertEqual(string:lowercase(list_to_binary(Str)), Reencoded),
      case ecu_rustcrypto_nif:is_available() of
        true ->
          {NifHrp, NifData, NifVar} = ecu_rustcrypto_nif:bech32_decode(list_to_binary(Str)),
          ?assertEqual(Hrp, string:lowercase(NifHrp)),
          ?assertEqual(Data, NifData),
          ?assertEqual(bech32, NifVar);
        false ->
          ok
      end
    end,
    ValidStrings
  ).

%% ===================================================================
%% BIP-350 Valid Bech32m Strings
%% ===================================================================

bip350_valid_bech32m_strings_test() ->
  ValidStrings = [
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa"
  ],
  lists:foreach(
    fun(Str) ->
      {ok, {Hrp, Data, Variant}} = ecu_bech32:decode(Str),
      ?assertEqual(bech32m, Variant),
      {ok, Reencoded} = ecu_bech32:encode(Hrp, Data, Variant),
      ?assertEqual(string:lowercase(list_to_binary(Str)), Reencoded),
      case ecu_rustcrypto_nif:is_available() of
        true ->
          {NifHrp, NifData, NifVar} = ecu_rustcrypto_nif:bech32_decode(list_to_binary(Str)),
          ?assertEqual(Hrp, string:lowercase(NifHrp)),
          ?assertEqual(Data, NifData),
          ?assertEqual(bech32m, NifVar);
        false ->
          ok
      end
    end,
    ValidStrings
  ).

%% ===================================================================
%% Invalid Checksum / String Format Tests
%% ===================================================================

bip173_invalid_strings_test() ->
  InvalidStrings = [
    [16#20] ++ "1nwldj5",
    [16#7F] ++ "1axkuhx",
    [16#80] ++ "1eym55h",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt" ++ [16#FF],
    "A1G7SGD8",
    "10a06t8",
    "1qzzfhee",
    "a12UEL5L"
  ],
  lists:foreach(
    fun(Str) ->
      ?assertMatch({error, _}, ecu_bech32:decode(Str))
    end,
    InvalidStrings
  ).

%% ===================================================================
%% BIP-173 & BIP-350 SegWit Address Test Vectors
%% ===================================================================

bip173_bip350_valid_segwit_addresses_test() ->
  ValidAddresses = [
    {"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", <<"bc">>},
    {"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", <<"tb">>},
    {"bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", <<"bc">>},
    {"BC1SW50QGDZ25J", <<"bc">>},
    {"bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", <<"bc">>},
    {"tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", <<"tb">>},
    {"tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", <<"tb">>},
    {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", <<"bc">>}
  ],
  lists:foreach(
    fun({Addr, ExpectedHrp}) ->
      {ok, {Ver, Prog}} = ecu_bech32:decode_segwit_address(ExpectedHrp, Addr),
      {ok, Encoded} = ecu_bech32:encode_segwit_address(ExpectedHrp, Ver, Prog),
      ?assertEqual(string:lowercase(list_to_binary(Addr)), Encoded),
      case ecu_rustcrypto_nif:is_available() of
        true ->
          {NifHrp, NifVer, NifProg} =
            ecu_rustcrypto_nif:bech32_segwit_decode(list_to_binary(Addr)),
          ?assertEqual(ExpectedHrp, string:lowercase(NifHrp)),
          ?assertEqual(Ver, NifVer),
          ?assertEqual(Prog, NifProg),
          NifEnc = ecu_rustcrypto_nif:bech32_segwit_encode(ExpectedHrp, Ver, Prog),
          ?assertEqual(Encoded, NifEnc);
        false ->
          ok
      end
    end,
    ValidAddresses
  ).

bip350_invalid_segwit_addresses_test() ->
  InvalidAddresses = [
    {"tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut", <<"bc">>},
    {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", <<"bc">>},
    {"tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", <<"tb">>},
    {"BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", <<"bc">>},
    {"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", <<"bc">>},
    {"tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47", <<"tb">>},
    {"bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", <<"bc">>},
    {"BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", <<"bc">>},
    {"bc1pw5dgrnzv", <<"bc">>},
    {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", <<"bc">>},
    {"BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", <<"bc">>},
    {"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", <<"tb">>},
    {"bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", <<"bc">>},
    {"tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j", <<"tb">>},
    {"bc1gmk9yu", <<"bc">>}
  ],
  lists:foreach(
    fun({Addr, ExpectedHrp}) ->
      ?assertMatch({error, _}, ecu_bech32:decode_segwit_address(ExpectedHrp, Addr))
    end,
    InvalidAddresses
  ).

%% ===================================================================
%% Bit Conversion Tests
%% ===================================================================

convert_bits_test() ->
  Data = crypto:strong_rand_bytes(32),
  {ok, Bits5} = ecu_bech32:convert_bits(Data, 8, 5, true),
  {ok, Recovered} = ecu_bech32:convert_bits(Bits5, 5, 8, false),
  ?assertEqual(Data, Recovered),

  %% Incomplete padding rejected when Pad = false
  ?assertEqual({error, invalid_padding}, ecu_bech32:convert_bits(<<1, 2, 3>>, 8, 5, false)),
  %% Invalid character outside bit boundary
  ?assertEqual({error, invalid_character}, ecu_bech32:convert_bits([32], 5, 8, true)).
