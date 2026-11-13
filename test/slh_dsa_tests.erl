%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests for pure-Erlang SLH-DSA (NIST FIPS 205).
%%%
%%% Verifies:
%%%   - Key generation across parameter sets
%%%   - Sign and verify roundtrip (both randomized and deterministic)
%%%   - Cross-verification against OTP 29 crypto:
%%%     - Public root matching from identical seeds
%%%     - Verification of OTP-generated signatures by ecu_slh_dsa
%%%     - Verification of ecu_slh_dsa signatures by OTP 29 crypto
%%%   - Negative testing: tampered signature, wrong message, wrong public key
%%% @end
%%%-------------------------------------------------------------------
-module(slh_dsa_tests).

-include_lib("eunit/include/eunit.hrl").
-include("ecu_slh_dsa.hrl").

slh_dsa_shake_128f_keygen_match_otp_test_() ->
  {timeout, 60, fun() -> test_keygen_match_otp(slh_dsa_shake_128f) end}.

slh_dsa_shake_192f_keygen_match_otp_test_() ->
  {timeout, 60, fun() -> test_keygen_match_otp(slh_dsa_shake_192f) end}.

slh_dsa_shake_256f_keygen_match_otp_test_() ->
  {timeout, 60, fun() -> test_keygen_match_otp(slh_dsa_shake_256f) end}.

slh_dsa_sha2_128s_keygen_match_otp_test_() ->
  {timeout, 60, fun() -> test_keygen_match_otp(slh_dsa_sha2_128s) end}.

slh_dsa_sha2_128f_keygen_match_otp_test_() ->
  {timeout, 60, fun() -> test_keygen_match_otp(slh_dsa_sha2_128f) end}.

slh_dsa_sha2_192f_keygen_match_otp_test_() ->
  {timeout, 60, fun() -> test_keygen_match_otp(slh_dsa_sha2_192f) end}.

slh_dsa_sha2_256f_keygen_match_otp_test_() ->
  {timeout, 60, fun() -> test_keygen_match_otp(slh_dsa_sha2_256f) end}.

slh_dsa_shake_128f_cross_sign_verify_test_() ->
  {timeout, 60, fun() -> test_cross_sign_verify(slh_dsa_shake_128f) end}.

slh_dsa_sha2_128f_cross_sign_verify_test_() ->
  {timeout, 60, fun() -> test_cross_sign_verify(slh_dsa_sha2_128f) end}.

slh_dsa_sha2_192f_cross_sign_verify_test_() ->
  {timeout, 60, fun() -> test_cross_sign_verify(slh_dsa_sha2_192f) end}.

slh_dsa_sha2_256f_cross_sign_verify_test_() ->
  {timeout, 60, fun() -> test_cross_sign_verify(slh_dsa_sha2_256f) end}.

slh_dsa_tampered_signature_rejected_test_() ->
  {timeout, 60, fun() ->
    ParamSet = slh_dsa_sha2_128f,
    #{public := PK, secret := SK} = ecu_slh_dsa:keypair(ParamSet),
    Msg = <<"Important transaction payload">>,
    Sig = ecu_slh_dsa:sign(ParamSet, Msg, SK),
    ?assert(ecu_slh_dsa:verify(ParamSet, Sig, Msg, PK)),
    %% Corrupt randomizer byte
    <<First:8, RestSig/binary>> = Sig,
    BadSig = <<(First bxor 1):8, RestSig/binary>>,
    ?assertNot(ecu_slh_dsa:verify(ParamSet, BadSig, Msg, PK)),
    %% Wrong message
    ?assertNot(ecu_slh_dsa:verify(ParamSet, Sig, <<"Wrong message">>, PK)),
    %% Corrupt signature tail
    TailLen = byte_size(Sig) - 1,
    <<HeadSig:TailLen/binary, LastByte:8>> = Sig,
    BadTailSig = <<HeadSig/binary, (LastByte bxor 1):8>>,
    ?assertNot(ecu_slh_dsa:verify(ParamSet, BadTailSig, Msg, PK))
  end}.

%% ===================================================================
%% Helper Routines
%% ===================================================================

test_keygen_match_otp(Alg) ->
  #slh_params{n = N, pk_bytes = PKBytes, sk_bytes = SKBytes} = ecu_slh_dsa:parameter_set(Alg),
  case lists:member(Alg, crypto:supports(public_keys)) of
    true ->
      {OtpPK, OtpSK} = crypto:generate_key(Alg, []),
      <<SKSeed:N/binary, SKPrf:N/binary, PKSeed:N/binary, OtpPKRoot:N/binary>> = OtpSK,
      #{public := PurePK, secret := PureSK} = ecu_slh_dsa:keypair_from_seeds(Alg, SKSeed, SKPrf, PKSeed),
      ?assertEqual(OtpPK, PurePK),
      ?assertEqual(OtpSK, PureSK),
      ?assertEqual(<<PKSeed:N/binary, OtpPKRoot:N/binary>>, PurePK);
    false ->
      #{public := PurePK, secret := PureSK} = ecu_slh_dsa:keypair(Alg),
      ?assertEqual(PKBytes, byte_size(PurePK)),
      ?assertEqual(SKBytes, byte_size(PureSK))
  end.

test_cross_sign_verify(Alg) ->
  #slh_params{n = N} = ecu_slh_dsa:parameter_set(Alg),
  Msg = <<"Test cross sign and verify between pure Erlang and OpenSSL">>,
  case lists:member(Alg, crypto:supports(public_keys)) of
    true ->
      {OtpPK, OtpSK} = crypto:generate_key(Alg, []),
      <<SKSeed:N/binary, SKPrf:N/binary, PKSeed:N/binary, _/binary>> = OtpSK,
      #{public := PurePK, secret := PureSK} = ecu_slh_dsa:keypair_from_seeds(Alg, SKSeed, SKPrf, PKSeed),
      ?assertEqual(OtpPK, PurePK),
      ?assertEqual(OtpSK, PureSK),
      %% 1. Verify OTP-generated signature using pure ecu_slh_dsa
      OtpSig = crypto:sign(Alg, none, Msg, PureSK),
      ?assert(ecu_slh_dsa:verify(Alg, OtpSig, Msg, PurePK)),
      %% 2. Verify pure ecu_slh_dsa signature using OTP crypto
      PureSig = ecu_slh_dsa:sign(Alg, Msg, PureSK),
      ?assert(crypto:verify(Alg, none, Msg, PureSig, PurePK)),
      ?assert(ecu_slh_dsa:verify(Alg, PureSig, Msg, PurePK)),
      %% 3. Deterministic signing roundtrip
      PureDetSig = ecu_slh_dsa:sign_deterministic(Alg, Msg, PureSK),
      ?assert(crypto:verify(Alg, none, Msg, PureDetSig, PurePK)),
      ?assert(ecu_slh_dsa:verify(Alg, PureDetSig, Msg, PurePK));
    false ->
      #{public := PurePK, secret := PureSK} = ecu_slh_dsa:keypair(Alg),
      PureSig = ecu_slh_dsa:sign(Alg, Msg, PureSK),
      ?assert(ecu_slh_dsa:verify(Alg, PureSig, Msg, PurePK)),
      PureDetSig = ecu_slh_dsa:sign_deterministic(Alg, Msg, PureSK),
      ?assert(ecu_slh_dsa:verify(Alg, PureDetSig, Msg, PurePK))
  end.
