%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang FN-DSA (FIPS 206 / Falcon),
%%% cross-checked with pqcrypto-falcon reference NIF.
%%% @end
%%%-------------------------------------------------------------------
-module(fn_dsa_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_param_set() ->
  %% Focus mainly on fn_dsa_512 for fast property testing, occasionally 1024
  frequency([
    {4, fn_dsa_512},
    {1, fn_dsa_1024}
  ]).

gen_seed() ->
  noshrink(binary(32)).

gen_msg() ->
  binary().

gen_context() ->
  ?LET(Len, choose(0, 32), binary(Len)).

%% ===================================================================
%% Properties
%% ===================================================================

%% Roundtrip signing and verification
prop_fn_dsa_roundtrip() ->
  ?FORALL(
    {ParamSet, Seed, Msg},
    {gen_param_set(), gen_seed(), gen_msg()},
    begin
      #{public := PK, secret := SK} = ecu_fn_dsa:keypair_from_seed(ParamSet, Seed),
      {ok, Sig} = ecu_fn_dsa:sign(Msg, SK),
      equals(true, ecu_fn_dsa:verify(Msg, Sig, PK))
    end
  ).

%% Deterministic signing consistency
prop_deterministic_signing() ->
  ?FORALL(
    {Seed, Msg},
    {gen_seed(), gen_msg()},
    begin
      #{public := PK, secret := SK} = ecu_fn_dsa:keypair_from_seed(fn_dsa_512, Seed),
      {ok, Sig1} = ecu_fn_dsa:sign_deterministic(Msg, SK),
      {ok, Sig2} = ecu_fn_dsa:sign_deterministic(Msg, SK),
      conjunction([
        {deterministic, equals(Sig1, Sig2)},
        {valid, equals(true, ecu_fn_dsa:verify(Msg, Sig1, PK))}
      ])
    end
  ).

%% Differential cross-testing against Rust NIF
prop_differential_nif() ->
  ?FORALL(
    {Seed, Msg},
    {gen_seed(), gen_msg()},
    case ecu_fn_dsa_nif:is_available() of
      true ->
        %% 1. Pure Erlang keygen -> Pure Erlang sign -> Rust NIF verify
        #{public := PK1, secret := SK1} = ecu_fn_dsa:keypair_from_seed(fn_dsa_512, Seed),
        {ok, Sig1} = ecu_fn_dsa:sign(Msg, SK1),
        NifVerify1 = ecu_fn_dsa_nif:falcon512_verify(PK1, Msg, Sig1),

        %% 2. Rust NIF keygen -> Pure Erlang sign -> Rust NIF & Pure Erlang verify
        {ok, {NifPK, NifSK}} = ecu_fn_dsa_nif:falcon512_keypair(),
        {ok, Sig2} = ecu_fn_dsa:sign(Msg, NifSK),
        NifVerify2 = ecu_fn_dsa_nif:falcon512_verify(NifPK, Msg, Sig2),
        EcuVerify2 = ecu_fn_dsa:verify(Msg, Sig2, NifPK),

        conjunction([
          {ecu_sign_nif_verify, equals(true, NifVerify1)},
          {nif_key_ecu_sign_nif_verify, equals(true, NifVerify2)},
          {nif_key_ecu_sign_ecu_verify, equals(true, EcuVerify2)}
        ]);
      false ->
        true
    end
  ).

%% Tampered message / signature rejection
prop_tampered_rejection() ->
  ?FORALL(
    {Seed, Msg},
    {gen_seed(), gen_msg()},
    begin
      #{public := PK, secret := SK} = ecu_fn_dsa:keypair_from_seed(fn_dsa_512, Seed),
      {ok, Sig} = ecu_fn_dsa:sign(Msg, SK),
      TamperedMsg = <<Msg/binary, "x">>,
      equals(false, ecu_fn_dsa:verify(TamperedMsg, Sig, PK))
    end
  ).

%% Context separation verification
prop_context_separation() ->
  ?FORALL(
    {Seed, Msg, Ctx1, Ctx2},
    {gen_seed(), gen_msg(), gen_context(), gen_context()},
    ?IMPLIES(
      Ctx1 =/= Ctx2,
      begin
        #{public := PK, secret := SK} = ecu_fn_dsa:keypair_from_seed(fn_dsa_512, Seed),
        {ok, Sig} = ecu_fn_dsa:sign(fn_dsa_512, Msg, SK, #{context => Ctx1}),
        conjunction([
          {valid_ctx, equals(true, ecu_fn_dsa:verify(Msg, Sig, PK, Ctx1))},
          {wrong_ctx, equals(false, ecu_fn_dsa:verify(Msg, Sig, PK, Ctx2))}
        ])
      end
    )
  ).
