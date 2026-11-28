%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for ecu_bip39 (BIP-39 Mnemonic Seed Generation).
%%% @end
%%%-------------------------------------------------------------------
-module(bip39_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% ===================================================================
%% Generators
%% ===================================================================

gen_entropy() ->
  ?LET(Bytes, elements([16, 20, 24, 28, 32]), binary(Bytes)).

gen_mnemonic_size() ->
  elements([128, 160, 192, 224, 256, 12, 15, 18, 21, 24]).

gen_passphrase() ->
  ?SIZED(Size, utf8(Size)).

%% ===================================================================
%% Properties
%% ===================================================================

prop_entropy_mnemonic_roundtrip() ->
  ?FORALL(
    Entropy,
    gen_entropy(),
    begin
      {ok, Mnemonic} = ecu_bip39:entropy_to_mnemonic(Entropy),
      Recovered = ecu_bip39:mnemonic_to_entropy(Mnemonic),
      Recovered == {ok, Entropy}
    end
  ).

prop_generate_mnemonic_valid() ->
  ?FORALL(
    SizeOrWords,
    gen_mnemonic_size(),
    begin
      Mnemonic = ecu_bip39:generate_mnemonic(SizeOrWords),
      ecu_bip39:validate_mnemonic(Mnemonic) == ok
    end
  ).

prop_unknown_word_rejected() ->
  ?FORALL(
    Entropy,
    gen_entropy(),
    begin
      {ok, Mnemonic} = ecu_bip39:entropy_to_mnemonic(Entropy),
      Words = string:lexemes(Mnemonic, " "),
      Pos = rand:uniform(length(Words)),
      {Before, [_Old | After]} = lists:split(Pos - 1, Words),
      CorruptedWords = Before ++ [<<"nonexistentbip39word">>] ++ After,
      CorruptedMnemonic = iolist_to_binary(lists:join(<<" ">>, CorruptedWords)),
      ecu_bip39:validate_mnemonic(CorruptedMnemonic) ==
        {error, {unknown_word, <<"nonexistentbip39word">>}}
    end
  ).

prop_invalid_word_count_rejected() ->
  ?FORALL(
    Entropy,
    gen_entropy(),
    begin
      {ok, Mnemonic} = ecu_bip39:entropy_to_mnemonic(Entropy),
      Words = string:lexemes(Mnemonic, " "),
      DroppedWords = tl(Words),
      DroppedMnemonic = iolist_to_binary(lists:join(<<" ">>, DroppedWords)),
      ecu_bip39:validate_mnemonic(DroppedMnemonic) == {error, invalid_word_count}
    end
  ).

prop_seed_deterministic() ->
  ?FORALL(
    {Entropy, Passphrase},
    {gen_entropy(), gen_passphrase()},
    begin
      {ok, Mnemonic} = ecu_bip39:entropy_to_mnemonic(Entropy),
      Seed1 = ecu_bip39:mnemonic_to_seed(Mnemonic, Passphrase),
      Seed2 = ecu_bip39:mnemonic_to_seed(Mnemonic, Passphrase),
      (Seed1 == Seed2) andalso (byte_size(Seed1) == 64)
    end
  ).

prop_mnemonic_to_master_key() ->
  ?FORALL(
    {Entropy, Passphrase},
    {gen_entropy(), gen_passphrase()},
    begin
      {ok, Mnemonic} = ecu_bip39:entropy_to_mnemonic(Entropy),
      case ecu_bip39:mnemonic_to_master_key(secp256k1, Mnemonic, Passphrase) of
        {ok, MasterKey} ->
          Seed = ecu_bip39:mnemonic_to_seed(Mnemonic, Passphrase),
          {ok, ExpectedMasterKey} = ecu_hd:master_key(secp256k1, Seed),
          MasterKey == ExpectedMasterKey;
        {error, _} ->
          false
      end
    end
  ).

prop_invalid_checksum_rejected() ->
  ?FORALL(
    Entropy,
    gen_entropy(),
    begin
      {ok, Mnemonic} = ecu_bip39:entropy_to_mnemonic(Entropy),
      Words = binary:split(Mnemonic, <<" ">>, [global]),
      LastWord = lists:last(Words),
      %% Flip bit 0 of the last word index (which is in the checksum bits)
      Idx = ecu_bip39_words:index(LastWord),
      NewIdx = Idx bxor 1,
      NewWord = ecu_bip39_words:word(NewIdx),
      CorruptedWords = lists:sublist(Words, length(Words) - 1) ++ [NewWord],
      CorruptedMnemonic = iolist_to_binary(lists:join(<<" ">>, CorruptedWords)),
      ecu_bip39:validate_mnemonic(CorruptedMnemonic) =:= {error, invalid_checksum}
    end
  ).

prop_invalid_entropy_size_rejected() ->
  ?FORALL(
    InvalidSize,
    elements([0, 1, 15, 17, 31, 33, 64]),
    begin
      InvalidEntropy = crypto:strong_rand_bytes(InvalidSize),
      case ecu_bip39:entropy_to_mnemonic(InvalidEntropy) of
        {error, invalid_entropy_length} -> true;
        _ -> false
      end
    end
  ).
