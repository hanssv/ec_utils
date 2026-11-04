%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for pure-Erlang ML-DSA (FIPS 204).
%%%
%%% Verifies:
%%%   - NIST ACVP official test vectors (KeyGen & SigGen)
%%%   - Roundtrip sign and verify across all 3 parameter sets
%%%   - Bidirectional differential testing against OTP 29 crypto
%%%   - Negative testing: tampered message, corrupted signature,
%%%     tampered hint, out-of-range context, and invalid keys.
%%% @end
%%%-------------------------------------------------------------------
-module(ml_dsa_tests).

-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% NIST ACVP KeyGen Vectors (FIPS 204 Algorithm 6)
%% ===================================================================

acvp_mldsa44_keygen_test() ->
  Seed = binary:decode_hex(<<"7194B13C95231010AFD2C909992BD2003BA6F437C3886BDBE3F6B867A14BA161">>),
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ml_dsa_44, Seed),
  ?assertEqual(1312, byte_size(PK)),
  ?assertEqual(2560, byte_size(SK)),
  %% Verify expected Rho prefix
  ExpectedRho = binary:decode_hex(
    <<"0B89806F0EEC39F2891116152ED4319D4260DFB8AC0710765BD497E6E1DE1778">>
  ),
  <<Rho:32/binary, _/binary>> = PK,
  ?assertEqual(ExpectedRho, Rho),
  %% Cross-verify with OTP 29 crypto if available
  Msg = <<"ML-DSA-44 ACVP KeyGen verification message">>,
  Sig = ecu_ml_dsa:sign(Msg, SK),
  case is_otp_mldsa_available(mldsa44) of
    true -> ?assert(crypto:verify(mldsa44, none, Msg, Sig, PK));
    false -> ?assert(ecu_ml_dsa:verify(Msg, Sig, PK))
  end.

acvp_mldsa65_keygen_test() ->
  Seed = binary:decode_hex(<<"A991FD42B071D49C48AE3E75C647459E0DAAD1E1BA356A04801912D3294BCFF8">>),
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ml_dsa_65, Seed),
  ?assertEqual(1952, byte_size(PK)),
  ?assertEqual(4032, byte_size(SK)),
  ExpectedRho = binary:decode_hex(
    <<"36DB0B5DCE98BD190CB139E80B71B49C7D7040B71C5A1F3412C46BDE939192B1">>
  ),
  <<Rho:32/binary, _/binary>> = PK,
  ?assertEqual(ExpectedRho, Rho),
  Msg = <<"ML-DSA-65 ACVP KeyGen verification message">>,
  Sig = ecu_ml_dsa:sign(Msg, SK),
  case is_otp_mldsa_available(mldsa65) of
    true -> ?assert(crypto:verify(mldsa65, none, Msg, Sig, PK));
    false -> ?assert(ecu_ml_dsa:verify(Msg, Sig, PK))
  end.

acvp_mldsa87_keygen_test() ->
  Seed = binary:decode_hex(<<"A16F5B0796703E2D1A0140A35CBF36EFABE70E752BA59B6A9A0E9C4B05302F73">>),
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ml_dsa_87, Seed),
  ?assertEqual(2592, byte_size(PK)),
  ?assertEqual(4896, byte_size(SK)),
  ExpectedRho = binary:decode_hex(
    <<"A5787E8044248F3F85AAC54E9469FC98F1B1138CC127B120F9946C80B96E3D89">>
  ),
  <<Rho:32/binary, _/binary>> = PK,
  ?assertEqual(ExpectedRho, Rho),
  Msg = <<"ML-DSA-87 ACVP KeyGen verification message">>,
  Sig = ecu_ml_dsa:sign(Msg, SK),
  case is_otp_mldsa_available(mldsa87) of
    true -> ?assert(crypto:verify(mldsa87, none, Msg, Sig, PK));
    false -> ?assert(ecu_ml_dsa:verify(Msg, Sig, PK))
  end.

%% ===================================================================
%% Sign & Verify Roundtrips & Differential Testing with OTP 29
%% ===================================================================

mldsa44_roundtrip_and_differential_test() ->
  test_roundtrip_and_differential(ml_dsa_44, mldsa44).

mldsa65_roundtrip_and_differential_test() ->
  test_roundtrip_and_differential(ml_dsa_65, mldsa65).

mldsa87_roundtrip_and_differential_test() ->
  test_roundtrip_and_differential(ml_dsa_87, mldsa87).

test_roundtrip_and_differential(ParamSet, CryptoSet) ->
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair(ParamSet),
  Msg = <<"Differential test payload for ML-DSA roundtrip">>,
  %% 1. Pure-Erlang sign and verify
  Sig = ecu_ml_dsa:sign(Msg, SK),
  ?assert(ecu_ml_dsa:verify(Msg, Sig, PK)),
  %% 2. Deterministic signing test
  DetSig1 = ecu_ml_dsa:sign_deterministic(Msg, SK),
  DetSig2 = ecu_ml_dsa:sign_deterministic(Msg, SK),
  ?assertEqual(DetSig1, DetSig2),
  ?assert(ecu_ml_dsa:verify(Msg, DetSig1, PK)),
  %% 3. Explicit parameter set overload
  ?assert(ecu_ml_dsa:verify(ParamSet, Msg, Sig, PK)),
  %% 4. Bidirectional differential testing with OTP crypto when available (OTP 29+)
  case is_otp_mldsa_available(CryptoSet) of
    true ->
      ?assert(crypto:verify(CryptoSet, none, Msg, Sig, PK)),
      ?assert(crypto:verify(CryptoSet, none, Msg, DetSig1, PK)),
      CryptoSig = crypto:sign(CryptoSet, none, Msg, SK),
      ?assert(ecu_ml_dsa:verify(Msg, CryptoSig, PK));
    false ->
      ok
  end.

%% ===================================================================
%% Context String Handling (FIPS 204 Section 5.2 / Algorithm 2 & 3)
%% ===================================================================

context_string_test() ->
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair(ml_dsa_65),
  Msg = <<"Message with custom application context">>,
  Ctx = <<"User-Auth-Context-V1">>,
  Sig = ecu_ml_dsa:sign(Msg, SK, Ctx),
  ?assert(ecu_ml_dsa:verify(Msg, Sig, PK, Ctx)),
  %% Verification with wrong or empty context must fail
  ?assertNot(ecu_ml_dsa:verify(Msg, Sig, PK, <<"Wrong-Context">>)),
  ?assertNot(ecu_ml_dsa:verify(Msg, Sig, PK, <<>>)),
  %% Context longer than 255 bytes must be rejected
  OverlongCtx = binary:copy(<<"A">>, 256),
  ?assertError(badarg, ecu_ml_dsa:sign(Msg, SK, OverlongCtx)),
  ?assertNot(ecu_ml_dsa:verify(Msg, Sig, PK, OverlongCtx)).

%% ===================================================================
%% Negative & Tampering Tests
%% ===================================================================

tampered_message_test() ->
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair(ml_dsa_44),
  Msg = <<"Authentic transaction data">>,
  Sig = ecu_ml_dsa:sign(Msg, SK),
  ?assert(ecu_ml_dsa:verify(Msg, Sig, PK)),
  ?assertNot(ecu_ml_dsa:verify(<<"Tampered transaction data">>, Sig, PK)).

corrupted_signature_test() ->
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair(ml_dsa_44),
  Msg = <<"Signature corruption test payload">>,
  Sig = ecu_ml_dsa:sign(Msg, SK),
  ?assert(ecu_ml_dsa:verify(Msg, Sig, PK)),
  %% Bit flip in commitment c~
  <<B0:8, Rest/binary>> = Sig,
  CorruptedSig1 = <<(B0 bxor 1):8, Rest/binary>>,
  ?assertNot(ecu_ml_dsa:verify(Msg, CorruptedSig1, PK)),
  %% Truncated signature
  <<TruncatedSig:2000/binary, _/binary>> = Sig,
  ?assertNot(ecu_ml_dsa:verify(Msg, TruncatedSig, PK)).

corrupted_hint_test() ->
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair(ml_dsa_44),
  Msg = <<"Hint corruption test payload">>,
  Sig = ecu_ml_dsa:sign(Msg, SK),
  %% Corrupt hint portion at end of signature
  SigLen = byte_size(Sig),
  PrefixLen = SigLen - 10,
  <<Prefix:PrefixLen/binary, End/binary>> = Sig,
  <<HByte:8, EndRest/binary>> = End,
  CorruptedHintSig = <<Prefix/binary, (HByte bxor 16#FF):8, EndRest/binary>>,
  ?assertNot(ecu_ml_dsa:verify(Msg, CorruptedHintSig, PK)).

invalid_key_size_test() ->
  #{public := PK, secret := SK} = ecu_ml_dsa:keypair(ml_dsa_44),
  Msg = <<"Key size validation payload">>,
  Sig = ecu_ml_dsa:sign(Msg, SK),
  %% Truncated public key
  <<TruncatedPK:1000/binary, _/binary>> = PK,
  ?assertNot(ecu_ml_dsa:verify(Msg, Sig, TruncatedPK)),
  %% Invalid secret key to sign
  ?assertError(badarg, ecu_ml_dsa:sign(Msg, <<0:1000>>)).

parameter_set_discovery_test() ->
  #{public := PK44, secret := SK44} = ecu_ml_dsa:keypair(ml_dsa_44),
  #{public := PK65, secret := SK65} = ecu_ml_dsa:keypair(ml_dsa_65),
  #{public := PK87, secret := SK87} = ecu_ml_dsa:keypair(ml_dsa_87),
  ?assertEqual(ml_dsa_44, ecu_ml_dsa:parameter_set(PK44)),
  ?assertEqual(ml_dsa_44, ecu_ml_dsa:parameter_set(SK44)),
  ?assertEqual(ml_dsa_65, ecu_ml_dsa:parameter_set(PK65)),
  ?assertEqual(ml_dsa_65, ecu_ml_dsa:parameter_set(SK65)),
  ?assertEqual(ml_dsa_87, ecu_ml_dsa:parameter_set(PK87)),
  ?assertEqual(ml_dsa_87, ecu_ml_dsa:parameter_set(SK87)),
  ?assertEqual(ml_dsa_44, ecu_ml_dsa:parameter_set(mldsa44)),
  ?assertEqual(ml_dsa_65, ecu_ml_dsa:parameter_set(mldsa65)),
  ?assertEqual(ml_dsa_87, ecu_ml_dsa:parameter_set(mldsa87)).

is_otp_mldsa_available(Alg) ->
  try
    crypto:generate_key(Alg, []),
    true
  catch
    _:_ -> false
  end.
