%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang SLH-DSA (NIST FIPS 205),
%%% cross-checked with OTP 29 crypto.
%%% @end
%%%-------------------------------------------------------------------
-module(slh_dsa_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_slh_dsa.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_fast_param_set() ->
  oneof([
    slh_dsa_sha2_128f,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_256f,
    slh_dsa_shake_128f
  ]).

gen_sha2_param_set() ->
  oneof([
    slh_dsa_sha2_128f,
    slh_dsa_sha2_192f,
    slh_dsa_sha2_256f
  ]).

gen_seeds(ParamSet) ->
  #slh_params{n = N} = ecu_slh_dsa:parameter_set(ParamSet),
  ?LET(
    {SKSeed, SKPrf, PKSeed},
    {binary(N), binary(N), binary(N)},
    {SKSeed, SKPrf, PKSeed}
  ).

gen_msg() ->
  binary().

gen_context() ->
  ?LET(Len, choose(0, 32), binary(Len)).

%% ===================================================================
%% Properties
%% ===================================================================

%% Roundtrip signing and verification across fast parameter sets
prop_slh_dsa_roundtrip() ->
  ?FORALL(
    ParamSet,
    gen_sha2_param_set(),
    ?FORALL(
      {{SKSeed, SKPrf, PKSeed}, Msg, Ctx},
      {gen_seeds(ParamSet), gen_msg(), gen_context()},
      begin
        #{public := PK, secret := SK} =
          ecu_slh_dsa:keypair_from_seeds(ParamSet, SKSeed, SKPrf, PKSeed),
        Sig = ecu_slh_dsa:sign(ParamSet, Msg, SK, Ctx),
        equals(true, ecu_slh_dsa:verify(ParamSet, Sig, Msg, PK, Ctx))
      end
    )
  ).

%% Differential testing against OTP crypto SLH-DSA implementation
prop_differential_otp() ->
  ?FORALL(
    ParamSet,
    gen_sha2_param_set(),
    case is_otp_supported(ParamSet) of
      true ->
        ?FORALL(
          {{SKSeed, SKPrf, PKSeed}, Msg},
          {gen_seeds(ParamSet), gen_msg()},
          begin
            %% 1. Pure keypair generation matches OTP format and verification
            #{public := PK1, secret := SK1} =
              ecu_slh_dsa:keypair_from_seeds(ParamSet, SKSeed, SKPrf, PKSeed),
            Sig1 = ecu_slh_dsa:sign(ParamSet, Msg, SK1),
            OtpVerify1 = crypto:verify(ParamSet, none, Msg, Sig1, PK1),

            %% 2. Pure verification of OTP signature
            OtpSig1 = crypto:sign(ParamSet, none, Msg, SK1),
            EcuVerify1 = ecu_slh_dsa:verify(ParamSet, OtpSig1, Msg, PK1),

            %% 3. OTP keygen -> pure sign -> OTP verify
            {PK2, SK2} = crypto:generate_key(ParamSet, []),
            Sig2 = ecu_slh_dsa:sign(ParamSet, Msg, SK2),
            OtpVerify2 = crypto:verify(ParamSet, none, Msg, Sig2, PK2),

            conjunction([
              {ecu_sig_verified_by_otp, equals(true, OtpVerify1)},
              {otp_sig_verified_by_ecu, equals(true, EcuVerify1)},
              {otp_key_ecu_sig_verified_by_otp, equals(true, OtpVerify2)}
            ])
          end
        );
      false ->
        true
    end
  ).

%% Deterministic signing produces identical signatures
prop_deterministic_signing() ->
  ?FORALL(
    ParamSet,
    gen_sha2_param_set(),
    ?FORALL(
      {{SKSeed, SKPrf, PKSeed}, Msg, Ctx},
      {gen_seeds(ParamSet), gen_msg(), gen_context()},
      begin
        #{public := PK, secret := SK} =
          ecu_slh_dsa:keypair_from_seeds(ParamSet, SKSeed, SKPrf, PKSeed),
        Sig1 = ecu_slh_dsa:sign_deterministic(ParamSet, Msg, SK, Ctx),
        Sig2 = ecu_slh_dsa:sign_deterministic(ParamSet, Msg, SK, Ctx),
        conjunction([
          {deterministic_signatures_match, equals(Sig1, Sig2)},
          {deterministic_signature_verifies,
            equals(true, ecu_slh_dsa:verify(ParamSet, Sig1, Msg, PK, Ctx))}
        ])
      end
    )
  ).

%% Tampered message or signature rejection
prop_tampered_rejection() ->
  ?FORALL(
    ParamSet,
    gen_sha2_param_set(),
    ?FORALL(
      {{SKSeed, SKPrf, PKSeed}, Msg, Ctx},
      {gen_seeds(ParamSet), gen_msg(), gen_context()},
      begin
        #{public := PK, secret := SK} =
          ecu_slh_dsa:keypair_from_seeds(ParamSet, SKSeed, SKPrf, PKSeed),
        Sig = ecu_slh_dsa:sign(ParamSet, Msg, SK, Ctx),
        %% 1. Alter message
        TamperedMsg = <<Msg/binary, "tampered">>,
        TamperedMsgRejected = not ecu_slh_dsa:verify(ParamSet, Sig, TamperedMsg, PK, Ctx),
        %% 2. Corrupt randomizer byte in signature
        <<First:8, RestSig/binary>> = Sig,
        CorruptedSig = <<(First bxor 1):8, RestSig/binary>>,
        CorruptedSigRejected = not ecu_slh_dsa:verify(ParamSet, CorruptedSig, Msg, PK, Ctx),
        conjunction([
          {tampered_msg_rejected, equals(true, TamperedMsgRejected)},
          {corrupted_sig_rejected, equals(true, CorruptedSigRejected)}
        ])
      end
    )
  ).

%% Context separation property: signature with Ctx1 fails with Ctx2
prop_context_separation() ->
  ?FORALL(
    ParamSet,
    gen_sha2_param_set(),
    ?FORALL(
      {{SKSeed, SKPrf, PKSeed}, Msg, Ctx1, Ctx2},
      {gen_seeds(ParamSet), gen_msg(), gen_context(), gen_context()},
      ?IMPLIES(
        Ctx1 =/= Ctx2,
        begin
          #{public := PK, secret := SK} =
            ecu_slh_dsa:keypair_from_seeds(ParamSet, SKSeed, SKPrf, PKSeed),
          Sig = ecu_slh_dsa:sign(ParamSet, Msg, SK, Ctx1),
          equals(false, ecu_slh_dsa:verify(ParamSet, Sig, Msg, PK, Ctx2))
        end
      )
    )
  ).

%% ===================================================================
%% Helpers
%% ===================================================================

is_otp_supported(Alg) ->
  try
    lists:member(Alg, crypto:supports(public_keys))
  catch
    _:_ -> false
  end.
