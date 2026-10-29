%%% File        : keccak_eqc.erl
%%% Description : QuickCheck properties for pure-Erlang Keccak & SHA-3
-module(keccak_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

gen_message() ->
  ?SIZED(Size, resize(Size * 10, binary())).

%% Verify pure-Erlang NIST SHA-3 against OTP crypto (OpenSSL)
prop_sha3_matches_crypto() ->
  ?FORALL(Msg, gen_message(),
  begin
    Hash224 = ecu_keccak:sha3_224(Msg),
    Hash256 = ecu_keccak:sha3_256(Msg),
    Hash384 = ecu_keccak:sha3_384(Msg),
    Hash512 = ecu_keccak:sha3_512(Msg),

    (Hash224 =:= crypto:hash(sha3_224, Msg)) andalso
    (Hash256 =:= crypto:hash(sha3_256, Msg)) andalso
    (Hash384 =:= crypto:hash(sha3_384, Msg)) andalso
    (Hash512 =:= crypto:hash(sha3_512, Msg))
  end).

%% Verify SHAKE256 XOF against OTP crypto:hash_xof
prop_shake256_matches_crypto() ->
  ?FORALL({Msg, ByteLen}, {gen_message(), choose(1, 128)},
  begin
    EcuShake = ecu_keccak:shake256(Msg, ByteLen * 8),
    CryptoShake = crypto:hash_xof(shake256, Msg, ByteLen * 8),
    EcuShake =:= CryptoShake
  end).

%% Verify Ethereum Keccak-256 against RustCrypto reference NIF
prop_keccak256_matches_reference() ->
  case ecu_rustcrypto_nif:is_available() of
    false ->
      true;
    true ->
      ?FORALL(Msg, gen_message(),
      begin
        EcuHash = ecu_keccak:keccak256(Msg),
        RefHash = ecu_rustcrypto_nif:keccak256(Msg),
        EcuHash =:= RefHash
      end)
  end.

%% Test known test vectors for Ethereum Keccak-256 and NIST SHA-3
prop_known_vectors() ->
  %% Empty string
  EmptyKeccak = ecu_keccak:keccak256(<<>>),
  EmptySha3_256 = ecu_keccak:sha3_256(<<>>),
  EmptyShake256 = ecu_keccak:shake256(<<>>, 512),

  (EmptyKeccak =:= <<16#c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470:256>>) andalso
  (EmptySha3_256 =:= <<16#a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a:256>>) andalso
  (EmptyShake256 =:= crypto:hash_xof(shake256, <<>>, 512)).
