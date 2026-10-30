%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for ecu_hd (BIP-32 / SLIP-0010) and ecu_base58.
%%% @end
%%%-------------------------------------------------------------------
-module(hd_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_seed() ->
  ?LET(Size, choose(16, 64), binary(Size)).

gen_unhardened_index() ->
  choose(0, 16#7FFFFFFF).

gen_hardened_index() ->
  ?LET(N, choose(0, 16#7FFFFFFF), N + 16#80000000).

gen_binary() ->
  ?SIZED(Size, binary(Size)).

%% ===================================================================
%% Properties: Base58 & Base58Check
%% ===================================================================

prop_base58_roundtrip() ->
  ?FORALL(
    Bin,
    gen_binary(),
    begin
      Encoded = ecu_base58:encode(Bin),
      Decoded = ecu_base58:decode(Encoded),
      Decoded == {ok, Bin}
    end
  ).

prop_base58check_roundtrip() ->
  ?FORALL(
    Bin,
    gen_binary(),
    begin
      Encoded = ecu_base58:encode_check(Bin),
      Decoded = ecu_base58:decode_check(Encoded),
      Decoded == {ok, Bin}
    end
  ).

prop_base58check_tamper() ->
  ?FORALL(
    Bin,
    ?SUCHTHAT(B, gen_binary(), byte_size(B) > 0),
    begin
      Encoded = ecu_base58:encode_check(Bin),
      Sz = byte_size(Encoded),
      Pos = rand:uniform(Sz) - 1,
      <<Prefix:Pos/binary, Byte:8, Suffix/binary>> = Encoded,
      NewByte =
        case Byte of
          $1 -> $2;
          _ -> $1
        end,
      Tampered = <<Prefix/binary, NewByte:8, Suffix/binary>>,
      case ecu_base58:decode_check(Tampered) of
        {ok, TamperedPayload} ->
          %% extremely rare collision
          TamperedPayload == Bin;
        {error, _Reason} ->
          true
      end
    end
  ).

%% ===================================================================
%% Properties: BIP-32 Derivation & Serialization
%% ===================================================================

prop_bip32_public_derivation_equivalence() ->
  ?FORALL(
    {Seed, Ix1, Ix2},
    {gen_seed(), gen_unhardened_index(), gen_unhardened_index()},
    begin
      {ok, MasterPriv} = ecu_hd:master_key(secp256k1, Seed),
      MasterPub = ecu_hd:to_public(MasterPriv),

      {ok, PrivChild1} = ecu_hd:ckd_priv(MasterPriv, Ix1),
      {ok, PrivChild2} = ecu_hd:ckd_priv(PrivChild1, Ix2),

      {ok, PubChild1} = ecu_hd:ckd_pub(MasterPub, Ix1),
      {ok, PubChild2} = ecu_hd:ckd_pub(PubChild1, Ix2),

      ecu_hd:public_key(PrivChild1) == ecu_hd:public_key(PubChild1) andalso
        ecu_hd:public_key(PrivChild2) == ecu_hd:public_key(PubChild2) andalso
        ecu_hd:chain_code(PrivChild2) == ecu_hd:chain_code(PubChild2) andalso
        ecu_hd:parent_fingerprint(PrivChild2) == ecu_hd:parent_fingerprint(PubChild2)
    end
  ).

prop_bip32_serialization_roundtrip() ->
  ?FORALL(
    Seed,
    gen_seed(),
    begin
      {ok, MasterPriv} = ecu_hd:master_key(secp256k1, Seed),
      MasterPub = ecu_hd:to_public(MasterPriv),

      B58Priv = ecu_hd:to_base58(private, MasterPriv),
      B58Pub = ecu_hd:to_base58(public, MasterPub),

      {ok, DecPriv} = ecu_hd:from_base58(B58Priv),
      {ok, DecPub} = ecu_hd:from_base58(B58Pub),

      DecPriv == MasterPriv andalso
        DecPub == MasterPub
    end
  ).

prop_path_syntax_equivalence() ->
  ?FORALL(
    {Seed, Ix},
    {gen_seed(), choose(0, 1000)},
    begin
      {ok, M} = ecu_hd:master_key(secp256k1, Seed),
      PathH = "m/0H/" ++ integer_to_list(Ix),
      PathPrime = "m/0'/" ++ integer_to_list(Ix),
      PathLower = "m/0h/" ++ integer_to_list(Ix),

      {ok, KeyH} = ecu_hd:derive_path(PathH, M),
      {ok, KeyPrime} = ecu_hd:derive_path(PathPrime, M),
      {ok, KeyLower} = ecu_hd:derive_path(PathLower, M),

      KeyH == KeyPrime andalso KeyH == KeyLower
    end
  ).

prop_aex10_derivation() ->
  ?FORALL(
    {Seed, Acct, Addr},
    {gen_seed(), choose(0, 100), choose(0, 100)},
    begin
      {ok, K1} = ecu_hd:derive_aex10(Seed, Acct, Addr),
      Path = io_lib:format("m/44H/457H/~wH/0H/~wH", [Acct, Addr]),
      {ok, K2} = ecu_hd:derive_path_from_seed(ed25519, lists:flatten(Path), Seed),
      K1 == K2
    end
  ).
