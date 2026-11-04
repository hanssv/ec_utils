%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang ML-DSA (FIPS 204), cross-checked
%%% with OTP 29 crypto.
%%% @end
%%%-------------------------------------------------------------------
-module(ml_dsa_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_param_set() ->
  oneof([ml_dsa_44, ml_dsa_65, ml_dsa_87]).

gen_seed() ->
  noshrink(binary(32)).

gen_msg() ->
  binary().

gen_context() ->
  ?LET(Len, choose(0, 32), binary(Len)).

%% ===================================================================
%% Properties
%% ===================================================================

%% Roundtrip signing and verification across all three parameter sets
prop_ml_dsa_roundtrip() ->
  ?FORALL(
    {ParamSet, Seed, Msg},
    {gen_param_set(), gen_seed(), gen_msg()},
    begin
      #{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ParamSet, Seed),
      Sig = ecu_ml_dsa:sign(Msg, SK),
      equals(true, ecu_ml_dsa:verify(Msg, Sig, PK))
    end
  ).

%% Differential testing against OTP crypto ML-DSA implementation
prop_differential_otp() ->
  ?FORALL(
    {ParamSet, Seed, Msg},
    {gen_param_set(), gen_seed(), gen_msg()},
    begin
      OtpAlg = to_otp_alg(ParamSet),
      case is_otp_supported(OtpAlg) of
        true ->
          %% 1. ECU keygen -> ECU sign -> OTP verify
          #{public := PK1, secret := SK1} = ecu_ml_dsa:keypair_from_seed(ParamSet, Seed),
          Sig1 = ecu_ml_dsa:sign(Msg, SK1),
          OtpVerify1 = crypto:verify(OtpAlg, none, Msg, Sig1, PK1),

          %% 2. ECU keygen -> OTP sign -> ECU verify
          OtpSig1 = crypto:sign(OtpAlg, none, Msg, SK1),
          EcuVerify1 = ecu_ml_dsa:verify(Msg, OtpSig1, PK1),

          %% 3. OTP keygen -> ECU sign -> OTP verify
          {PK2, SK2} = crypto:generate_key(OtpAlg, []),
          Sig2 = ecu_ml_dsa:sign(Msg, SK2),
          OtpVerify2 = crypto:verify(OtpAlg, none, Msg, Sig2, PK2),

          %% 4. OTP keygen -> OTP sign -> ECU verify
          OtpSig2 = crypto:sign(OtpAlg, none, Msg, SK2),
          EcuVerify2 = ecu_ml_dsa:verify(Msg, OtpSig2, PK2),

          conjunction([
            {ecu_sig_verified_by_otp, equals(true, OtpVerify1)},
            {otp_sig_verified_by_ecu, equals(true, EcuVerify1)},
            {otp_key_ecu_sig_verified_by_otp, equals(true, OtpVerify2)},
            {otp_key_otp_sig_verified_by_ecu, equals(true, EcuVerify2)}
          ]);
        false ->
          true
      end
    end
  ).

%% Deterministic signing produces identical signatures
prop_deterministic_signing() ->
  ?FORALL(
    {ParamSet, Seed, Msg, Ctx},
    {gen_param_set(), gen_seed(), gen_msg(), gen_context()},
    begin
      #{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ParamSet, Seed),
      Sig1 = ecu_ml_dsa:sign_deterministic(Msg, SK, Ctx),
      Sig2 = ecu_ml_dsa:sign_deterministic(Msg, SK, Ctx),
      conjunction([
        {deterministic_signatures_match, equals(Sig1, Sig2)},
        {deterministic_signature_verifies, equals(true, ecu_ml_dsa:verify(Msg, Sig1, PK, Ctx))}
      ])
    end
  ).

%% Tampered message or signature rejection
prop_tampered_rejection() ->
  ?FORALL(
    {ParamSet, Seed, Msg},
    {gen_param_set(), gen_seed(), gen_msg()},
    begin
      #{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ParamSet, Seed),
      Sig = ecu_ml_dsa:sign(Msg, SK),
      %% 1. Alter message
      TamperedMsg = <<Msg/binary, "tampered">>,
      TamperedMsgRejected = not ecu_ml_dsa:verify(TamperedMsg, Sig, PK),
      %% 2. Corrupt commitment c~ in signature (first byte bit flip)
      <<B0:8, RestSig/binary>> = Sig,
      CorruptedSig = <<(B0 bxor 1):8, RestSig/binary>>,
      CorruptedSigRejected = not ecu_ml_dsa:verify(Msg, CorruptedSig, PK),
      conjunction([
        {tampered_msg_rejected, equals(true, TamperedMsgRejected)},
        {corrupted_sig_rejected, equals(true, CorruptedSigRejected)}
      ])
    end
  ).

%% Context separation property: signature with Ctx1 fails with Ctx2
prop_context_separation() ->
  ?FORALL(
    {ParamSet, Seed, Msg, Ctx1, Ctx2},
    {gen_param_set(), gen_seed(), gen_msg(), gen_context(), gen_context()},
    ?IMPLIES(
      Ctx1 =/= Ctx2,
      begin
        #{public := PK, secret := SK} = ecu_ml_dsa:keypair_from_seed(ParamSet, Seed),
        Sig = ecu_ml_dsa:sign(Msg, SK, Ctx1),
        equals(false, ecu_ml_dsa:verify(Msg, Sig, PK, Ctx2))
      end
    )
  ).

%% ===================================================================
%% Helpers
%% ===================================================================

to_otp_alg(ml_dsa_44) -> mldsa44;
to_otp_alg(mldsa44) -> mldsa44;
to_otp_alg(ml_dsa_65) -> mldsa65;
to_otp_alg(mldsa65) -> mldsa65;
to_otp_alg(ml_dsa_87) -> mldsa87;
to_otp_alg(mldsa87) -> mldsa87.

is_otp_supported(Alg) ->
  try
    crypto:supports(public_keys),
    lists:member(Alg, crypto:supports(public_keys))
  catch
    _:_ -> false
  end.
