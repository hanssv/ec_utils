%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for ML-KEM (FIPS 203) and hybrid post-quantum
%%% key exchange, cross-checked with OTP 29 crypto.
%%% @end
%%%-------------------------------------------------------------------
-module(ml_kem_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_param_set() ->
  oneof([ml_kem_512, ml_kem_768, ml_kem_1024]).

gen_seed() ->
  noshrink(binary(32)).

%% ===================================================================
%% Properties
%% ===================================================================

%% Roundtrip encapsulation/decapsulation across all three parameter sets
prop_ml_kem_roundtrip() ->
  ?FORALL(
    {ParamSet, SeedD, SeedZ, SeedM},
    {gen_param_set(), gen_seed(), gen_seed(), gen_seed()},
    begin
      {PK, SK} = ecu_ml_kem:keypair_from_seed(ParamSet, SeedD, SeedZ),
      {SS, CT} = ecu_ml_kem:encaps(PK, SeedM),
      DecapsSS = ecu_ml_kem:decaps(SK, CT),
      equals(SS, DecapsSS)
    end
  ).

%% Differential testing against OTP crypto KEM implementation
prop_differential_otp() ->
  ?FORALL(
    ParamSet,
    gen_param_set(),
    begin
      OtpAlg = to_otp_alg(ParamSet),
      case is_otp_supported(OtpAlg) of
        true ->
          %% ECU keygen -> OTP encaps -> ECU decaps
          {PK1, SK1} = ecu_ml_kem:keypair(ParamSet),
          {SS_otp, CT_otp} = crypto:encapsulate_key(OtpAlg, PK1),
          SS_ecu1 = ecu_ml_kem:decaps(SK1, CT_otp),
          %% OTP keygen -> ECU encaps -> OTP decaps
          {PK2, SK2} = crypto:generate_key(OtpAlg, []),
          {SS_ecu2, CT_ecu2} = ecu_ml_kem:encaps(PK2),
          SS_otp2 = crypto:decapsulate_key(OtpAlg, SK2, CT_ecu2),
          conjunction([
            {ecu_decaps_matches_otp, equals(SS_otp, SS_ecu1)},
            {otp_decaps_matches_ecu, equals(SS_ecu2, SS_otp2)}
          ]);
        false ->
          true
      end
    end
  ).

%% Tampered ciphertext must trigger implicit rejection (pseudorandom output)
prop_implicit_rejection() ->
  ?FORALL(
    {ParamSet, SeedD, SeedZ, SeedM},
    {gen_param_set(), gen_seed(), gen_seed(), gen_seed()},
    begin
      {PK, SK} = ecu_ml_kem:keypair_from_seed(ParamSet, SeedD, SeedZ),
      {TrueSS, CT} = ecu_ml_kem:encaps(PK, SeedM),
      CtLen = byte_size(CT),
      ?FORALL(
        {ByteIdx, BitMask},
        {choose(0, CtLen - 1), oneof([1, 2, 4, 8, 16, 32, 64, 128])},
        begin
          <<Prefix:ByteIdx/binary, TargetByte:8, Suffix/binary>> = CT,
          CorruptedByte = TargetByte bxor BitMask,
          CorruptedCT = <<Prefix/binary, CorruptedByte:8, Suffix/binary>>,
          RejectedSS = ecu_ml_kem:decaps(SK, CorruptedCT),
          ExpectedRejectedSS = ecu_keccak:shake256(<<SeedZ/binary, CorruptedCT/binary>>, 256),
          conjunction([
            {not_equal_to_true_secret, RejectedSS /= TrueSS},
            {matches_implicit_rejection_hash, equals(ExpectedRejectedSS, RejectedSS)}
          ])
        end
      )
    end
  ).

%% Hybrid X25519 + ML-KEM-768 roundtrip
prop_hybrid_roundtrip() ->
  ?FORALL(
    _,
    return(ok),
    begin
      {HPK, HSK} = ecu_ecdh:hybrid_keypair(x25519_mlkem768),
      {SS_sender, HCT} = ecu_ecdh:hybrid_encaps(HPK),
      SS_recver = ecu_ecdh:hybrid_decaps(HSK, HCT),
      equals(SS_sender, SS_recver)
    end
  ).

%% Hybrid tampered ciphertext rejection
prop_hybrid_tampered() ->
  ?FORALL(
    _,
    return(ok),
    begin
      {HPK, HSK} = ecu_ecdh:hybrid_keypair(x25519_mlkem768),
      {TrueSS, HCT} = ecu_ecdh:hybrid_encaps(HPK),
      CtLen = byte_size(HCT),
      ?FORALL(
        {ByteIdx, BitMask},
        {choose(0, CtLen - 1), oneof([1, 2, 4, 8, 16, 32, 64, 128])},
        begin
          <<Prefix:ByteIdx/binary, TargetByte:8, Suffix/binary>> = HCT,
          CorruptedByte = TargetByte bxor BitMask,
          CorruptedHCT = <<Prefix/binary, CorruptedByte:8, Suffix/binary>>,
          TamperedSS = ecu_ecdh:hybrid_decaps(HSK, CorruptedHCT),
          TamperedSS /= TrueSS
        end
      )
    end
  ).

%% ===================================================================
%% Helpers
%% ===================================================================

to_otp_alg(ml_kem_512) -> mlkem512;
to_otp_alg(ml_kem_768) -> mlkem768;
to_otp_alg(ml_kem_1024) -> mlkem1024.

is_otp_supported(Alg) ->
  try
    crypto:generate_key(Alg, []),
    true
  catch
    _:_ -> false
  end.
