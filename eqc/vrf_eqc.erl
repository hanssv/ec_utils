%%%-------------------------------------------------------------------
%%% @doc QuickCheck property-based tests for RFC 9381 VRF (`ecu_vrf').
%%% @end
%%%-------------------------------------------------------------------
-module(vrf_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_suite() ->
  elements([
    edwards25519_sha512_ell2,
    edwards25519_sha512_tai,
    secp256k1_sha256_tai,
    secp256k1_sha256_sswu
  ]).

gen_alpha() ->
  ?LET(Len, choose(0, 128), binary(Len)).

gen_keypair(edwards25519_sha512_ell2) ->
  gen_keypair_ed25519(edwards25519_sha512_ell2);
gen_keypair(edwards25519_sha512_tai) ->
  gen_keypair_ed25519(edwards25519_sha512_tai);
gen_keypair(secp256k1_sha256_tai) ->
  gen_keypair_secp256k1(secp256k1_sha256_tai);
gen_keypair(secp256k1_sha256_sswu) ->
  gen_keypair_secp256k1(secp256k1_sha256_sswu).

gen_keypair_ed25519(Suite) ->
  ?LET(
    Seed,
    binary(32),
    begin
      PK = ecu_vrf:derive_public_key(Suite, Seed),
      {PK, Seed}
    end
  ).

gen_keypair_secp256k1(Suite) ->
  ?LET(
    Scalar,
    choose(
      1,
      16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140
    ),
    begin
      SK = <<Scalar:256>>,
      PK = ecu_vrf:derive_public_key(Suite, SK),
      {PK, SK}
    end
  ).

%% ===================================================================
%% Properties
%% ===================================================================

%% @doc Verifies that valid proofs always verify and yield identical hashes.
prop_prove_verify_roundtrip() ->
  ?FORALL(
    Suite,
    gen_suite(),
    ?FORALL(
      {{PK, SK}, Alpha},
      {gen_keypair(Suite), gen_alpha()},
      begin
        {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
        case ecu_vrf:verify(Suite, PK, Pi, Alpha) of
          {ok, Beta} ->
            {ok, BetaProof} = ecu_vrf:proof_to_hash(Suite, Pi),
            Beta =:= BetaProof;
          _ ->
            false
        end
      end
    )
  ).

%% @doc Verifies that proving is strictly deterministic.
prop_prove_determinism() ->
  ?FORALL(
    Suite,
    gen_suite(),
    ?FORALL(
      {{_PK, SK}, Alpha},
      {gen_keypair(Suite), gen_alpha()},
      begin
        {ok, Pi1} = ecu_vrf:prove(Suite, SK, Alpha),
        {ok, Pi2} = ecu_vrf:prove(Suite, SK, Alpha),
        Pi1 =:= Pi2
      end
    )
  ).

%% @doc Tampering with message alpha causes verification to fail.
prop_tampered_alpha_fails() ->
  ?FORALL(
    Suite,
    gen_suite(),
    ?FORALL(
      {{{PK, SK}, Alpha}, TamperByte},
      {{gen_keypair(Suite), gen_alpha()}, choose(1, 255)},
      begin
        {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
        TamperedAlpha =
          case byte_size(Alpha) of
            0 ->
              <<TamperByte>>;
            Size ->
              Pos = choose_int(0, Size - 1),
              <<Pre:Pos/binary, B:8, Post/binary>> = Alpha,
              <<Pre/binary, (B bxor TamperByte):8, Post/binary>>
          end,
        ecu_vrf:verify(Suite, PK, Pi, TamperedAlpha) =:= {error, invalid_proof}
      end
    )
  ).

%% @doc Tampering with proof pi causes verification to fail.
prop_tampered_proof_fails() ->
  ?FORALL(
    Suite,
    gen_suite(),
    ?FORALL(
      {{{PK, SK}, Alpha}, TamperByte},
      {{gen_keypair(Suite), gen_alpha()}, choose(1, 255)},
      begin
        {ok, Pi} = ecu_vrf:prove(Suite, SK, Alpha),
        Pos = choose_int(0, byte_size(Pi) - 1),
        <<Pre:Pos/binary, B:8, Post/binary>> = Pi,
        TamperedPi = <<Pre/binary, (B bxor TamperByte):8, Post/binary>>,
        ecu_vrf:verify(Suite, PK, TamperedPi, Alpha) =:= {error, invalid_proof}
      end
    )
  ).

%% @doc Verifying with an alternate public key fails.
prop_wrong_public_key_fails() ->
  ?FORALL(
    Suite,
    gen_suite(),
    ?FORALL(
      {{{_PK1, SK1}, {PK2, _SK2}}, Alpha},
      {{gen_keypair(Suite), gen_keypair(Suite)}, gen_alpha()},
      begin
        {ok, Pi} = ecu_vrf:prove(Suite, SK1, Alpha),
        case ecu_vrf:verify(Suite, PK2, Pi, Alpha) of
          {error, invalid_proof} -> true;
          _ -> false
        end
      end
    )
  ).

%% @doc Differential property: pure Erlang and reference Rust NIF agree on
%% proofs, verification, and output hashes across random inputs.
prop_nif_differential() ->
  case ecu_vrf_nif:is_available() of
    false ->
      true;
    true ->
      ?FORALL(
        Suite,
        elements([
          edwards25519_sha512_ell2,
          edwards25519_sha512_tai,
          secp256k1_sha256_tai
        ]),
        ?FORALL(
          {{PK, SK}, Alpha},
          {gen_keypair(Suite), gen_alpha()},
          begin
            {ok, ErlPi} = ecu_vrf:prove(Suite, SK, Alpha),
            {ok, ErlBeta} = ecu_vrf:verify(Suite, PK, ErlPi, Alpha),
            {ok, NifBetaFromErlPi} = ecu_vrf_nif:verify(Suite, PK, ErlPi, Alpha),
            {ok, NifPi} = ecu_vrf_nif:prove(Suite, SK, Alpha),
            {ok, NifBeta} = ecu_vrf_nif:verify(Suite, PK, NifPi, Alpha),
            {ok, ErlBetaFromNifPi} = ecu_vrf:verify(Suite, PK, NifPi, Alpha),
            {ok, ErlHashFromNifPi} = ecu_vrf:proof_to_hash(Suite, NifPi),
            {ok, NifHashFromErlPi} = ecu_vrf_nif:proof_to_hash(Suite, ErlPi),
            ErlBeta =:= NifBetaFromErlPi andalso
              NifBeta =:= ErlBetaFromNifPi andalso
              ErlBeta =:= NifBeta andalso
              ErlBeta =:= ErlHashFromNifPi andalso
              ErlBeta =:= NifHashFromErlPi
          end
        )
      )
  end.

choose_int(Min, Max) when Min =:= Max -> Min;
choose_int(Min, Max) -> Min + (erlang:phash2({os:timestamp(), Min, Max}, Max - Min + 1)).
