%%%-------------------------------------------------------------------
%%% @doc
%%% BIP-39: Mnemonic code for generating deterministic keys.
%%%
%%% Implements pure-Erlang BIP-39 mnemonic phrase generation, validation,
%%% entropy round-trips, and PBKDF2-HMAC-SHA512 seed derivation with UTF-8 NFKD
%%% normalization. Zero external dependencies.
%%%
%%% Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bip39).

-typing([eqwalizer]).

-export([
  generate_mnemonic/1,
  generate_mnemonic/2,
  entropy_to_mnemonic/1,
  entropy_to_mnemonic/2,
  mnemonic_to_entropy/1,
  mnemonic_to_entropy/2,
  validate_mnemonic/1,
  validate_mnemonic/2,
  mnemonic_to_seed/1,
  mnemonic_to_seed/2,
  mnemonic_to_master_key/2,
  mnemonic_to_master_key/3
]).

-export_type([
  mnemonic_size/0,
  word_count/0,
  entropy_bytes/0,
  wordlist_ref/0,
  bip39_error/0
]).

-type mnemonic_size() :: 128 | 160 | 192 | 224 | 256.
-type word_count() :: 12 | 15 | 18 | 21 | 24.
-type entropy_bytes() :: 16 | 20 | 24 | 28 | 32.
-type wordlist_ref() :: english | module() | [binary()] | tuple().
-type bip39_error() ::
  invalid_entropy_length
  | invalid_word_count
  | invalid_checksum
  | {unknown_word, binary()}
  | bad_wordlist.

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Generates a cryptographically secure BIP-39 mnemonic sentence.
%% Size can be specified either in entropy bits (128, 160, 192, 224, 256)
%% or in word count (12, 15, 18, 21, 24).
-spec generate_mnemonic(mnemonic_size() | word_count()) -> binary().
generate_mnemonic(SizeOrWords) ->
  generate_mnemonic(SizeOrWords, english).

%% @doc Generates a cryptographically secure BIP-39 mnemonic using the specified wordlist.
-spec generate_mnemonic(mnemonic_size() | word_count(), wordlist_ref()) -> binary().
generate_mnemonic(SizeOrWords, Wordlist) ->
  EntropyBits = to_entropy_bits(SizeOrWords),
  EntropyBytes = EntropyBits div 8,
  Entropy = ecu_compat:strong_rand_bytes(EntropyBytes),
  case entropy_to_mnemonic(Entropy, Wordlist) of
    {ok, Mnemonic} -> Mnemonic;
    {error, Reason} -> error({generate_mnemonic_failed, Reason})
  end.

%% @doc Converts binary entropy (16, 20, 24, 28, or 32 bytes) to a BIP-39 mnemonic.
-spec entropy_to_mnemonic(binary()) -> {ok, binary()} | {error, bip39_error()}.
entropy_to_mnemonic(Entropy) ->
  entropy_to_mnemonic(Entropy, english).

%% @doc Converts binary entropy to a mnemonic using the specified wordlist.
-spec entropy_to_mnemonic(binary(), wordlist_ref()) -> {ok, binary()} | {error, bip39_error()}.
entropy_to_mnemonic(Entropy, Wordlist) when is_binary(Entropy) ->
  EntropyBytes = byte_size(Entropy),
  case is_valid_entropy_size(EntropyBytes) of
    false ->
      {error, invalid_entropy_length};
    true ->
      CSBits = (EntropyBytes * 8) div 32,
      <<Checksum:CSBits, _/bitstring>> = ecu_compat:hash(sha256, Entropy),
      Combined = <<Entropy/binary, Checksum:CSBits>>,
      Indices = [Ix || <<Ix:11>> <= Combined],
      case map_indices_to_words(Indices, Wordlist) of
        {ok, Words} ->
          {ok, iolist_to_binary(lists:join(<<" ">>, Words))};
        {error, _} = Err ->
          Err
      end
  end;
entropy_to_mnemonic(_NotBinary, _Wordlist) ->
  {error, invalid_entropy_length}.

%% @doc Converts a BIP-39 mnemonic back to the original entropy.
-spec mnemonic_to_entropy(unicode:chardata() | [unicode:chardata()]) ->
  {ok, binary()} | {error, bip39_error()}.
mnemonic_to_entropy(Mnemonic) ->
  mnemonic_to_entropy(Mnemonic, english).

%% @doc Converts a BIP-39 mnemonic to entropy using the specified wordlist.
-spec mnemonic_to_entropy(unicode:chardata() | [unicode:chardata()], wordlist_ref()) ->
  {ok, binary()} | {error, bip39_error()}.
mnemonic_to_entropy(Mnemonic, Wordlist) ->
  Words = tokenize_words(Mnemonic),
  WordCount = length(Words),
  case is_valid_word_count(WordCount) of
    false ->
      {error, invalid_word_count};
    true ->
      case map_words_to_indices(Words, Wordlist) of
        {error, _} = Err ->
          Err;
        {ok, Indices} ->
          Bits = <<<<Ix:11>> || Ix <- Indices>>,
          CSBits = WordCount div 3,
          EntropyBytes = WordCount * 4 div 3,
          <<Entropy:EntropyBytes/binary, Checksum:CSBits>> = Bits,
          <<ExpectedChecksum:CSBits, _/bitstring>> = ecu_compat:hash(sha256, Entropy),
          case Checksum =:= ExpectedChecksum of
            true ->
              {ok, Entropy};
            false ->
              {error, invalid_checksum}
          end
      end
  end.

%% @doc Validates whether a mnemonic sentence is valid (correct word count,
%% dictionary membership, and checksum).
-spec validate_mnemonic(unicode:chardata() | [unicode:chardata()]) ->
  ok | {error, bip39_error()}.
validate_mnemonic(Mnemonic) ->
  validate_mnemonic(Mnemonic, english).

%% @doc Validates a mnemonic against a specified wordlist.
-spec validate_mnemonic(unicode:chardata() | [unicode:chardata()], wordlist_ref()) ->
  ok | {error, bip39_error()}.
validate_mnemonic(Mnemonic, Wordlist) ->
  case mnemonic_to_entropy(Mnemonic, Wordlist) of
    {ok, _Entropy} -> ok;
    {error, Reason} -> {error, Reason}
  end.

%% @doc Derives a 512-bit (64-byte) binary seed from a mnemonic with an empty passphrase.
-spec mnemonic_to_seed(unicode:chardata() | [unicode:chardata()]) -> <<_:512>>.
mnemonic_to_seed(Mnemonic) ->
  mnemonic_to_seed(Mnemonic, <<>>).

%% @doc Derives a 512-bit (64-byte) binary seed from a mnemonic and passphrase.
%% Both the mnemonic sentence and passphrase are normalized using UTF-8 NFKD per BIP-39.
-spec mnemonic_to_seed(unicode:chardata() | [unicode:chardata()], unicode:chardata()) -> <<_:512>>.
mnemonic_to_seed(Mnemonic, Passphrase) ->
  MnemonicBin = normalize_mnemonic_string(Mnemonic),
  NFKDPassphrase = to_nfkd_binary(Passphrase),
  Salt = <<"mnemonic", NFKDPassphrase/binary>>,
  ecu_compat:pbkdf2_hmac(sha512, MnemonicBin, Salt, 2048, 64).

%% @doc Direct bridge to derive an HD master key from a mnemonic with empty passphrase.
-spec mnemonic_to_master_key(ecu_hd:curve(), unicode:chardata() | [unicode:chardata()]) ->
  {ok, ecu_hd:extended_key()} | {error, term()}.
mnemonic_to_master_key(Curve, Mnemonic) ->
  mnemonic_to_master_key(Curve, Mnemonic, <<>>).

%% @doc Direct bridge to derive an HD master key from a mnemonic and passphrase.
%% Validates the mnemonic before creating the master key.
-spec mnemonic_to_master_key(
  ecu_hd:curve(),
  unicode:chardata() | [unicode:chardata()],
  unicode:chardata()
) ->
  {ok, ecu_hd:extended_key()} | {error, term()}.
mnemonic_to_master_key(Curve, Mnemonic, Passphrase) ->
  case validate_mnemonic(Mnemonic) of
    ok ->
      Seed = mnemonic_to_seed(Mnemonic, Passphrase),
      ecu_hd:master_key(Curve, Seed);
    {error, _} = Err ->
      Err
  end.

%% ===================================================================
%% Internal Helpers
%% ===================================================================

-spec to_entropy_bits(mnemonic_size() | word_count()) -> mnemonic_size().
to_entropy_bits(12) -> 128;
to_entropy_bits(15) -> 160;
to_entropy_bits(18) -> 192;
to_entropy_bits(21) -> 224;
to_entropy_bits(24) -> 256;
to_entropy_bits(128) -> 128;
to_entropy_bits(160) -> 160;
to_entropy_bits(192) -> 192;
to_entropy_bits(224) -> 224;
to_entropy_bits(256) -> 256;
to_entropy_bits(Other) -> error({bad_mnemonic_size, Other}).

-spec is_valid_entropy_size(non_neg_integer()) -> boolean().
is_valid_entropy_size(16) -> true;
is_valid_entropy_size(20) -> true;
is_valid_entropy_size(24) -> true;
is_valid_entropy_size(28) -> true;
is_valid_entropy_size(32) -> true;
is_valid_entropy_size(_) -> false.

-spec is_valid_word_count(non_neg_integer()) -> boolean().
is_valid_word_count(12) -> true;
is_valid_word_count(15) -> true;
is_valid_word_count(18) -> true;
is_valid_word_count(21) -> true;
is_valid_word_count(24) -> true;
is_valid_word_count(_) -> false.

-spec tokenize_words(unicode:chardata() | [unicode:chardata()]) -> [binary()].
tokenize_words(Bin) when is_binary(Bin) ->
  NormBin = to_nfkd_binary(Bin),
  string:lexemes(NormBin, [$\s, $\t, $\r, $\n]);
tokenize_words(List) when is_list(List) ->
  case io_lib:printable_unicode_list(List) of
    true ->
      NormBin = to_nfkd_binary(List),
      string:lexemes(NormBin, [$\s, $\t, $\r, $\n]);
    false ->
      [
        case Item of
          C when is_integer(C) -> to_nfkd_binary([C]);
          Other -> to_nfkd_binary(Other)
        end
       || Item <- List
      ]
  end.

-spec to_nfkd_binary(unicode:chardata()) -> binary().
to_nfkd_binary(Data) ->
  case unicode:characters_to_nfkd_binary(Data) of
    Bin when is_binary(Bin) -> Bin;
    _ -> error({bad_unicode, Data})
  end.

-spec normalize_mnemonic_string(unicode:chardata() | [unicode:chardata()]) -> binary().
normalize_mnemonic_string(Mnemonic) ->
  Words = tokenize_words(Mnemonic),
  iolist_to_binary(lists:join(<<" ">>, Words)).

-spec validate_unique_words([term()]) -> boolean().
validate_unique_words(List) ->
  lists:all(fun is_binary/1, List) andalso
    sets:size(sets:from_list(List, [{version, 2}])) =:= 2048.

-spec map_indices_to_words([non_neg_integer()], wordlist_ref()) ->
  {ok, [binary()]} | {error, bip39_error()}.
map_indices_to_words(Indices, english) ->
  Words = [ecu_bip39_words:word(Idx) || Idx <- Indices],
  {ok, [W || W <- Words, is_binary(W)]};
map_indices_to_words(Indices, Mod) when is_atom(Mod) ->
  try
    Words = [Mod:word(Idx) || Idx <- Indices],
    case lists:all(fun is_binary/1, Words) of
      true -> {ok, Words};
      false -> {error, bad_wordlist}
    end
  catch
    _:_ -> {error, bad_wordlist}
  end;
map_indices_to_words(Indices, WordTuple) when is_tuple(WordTuple) ->
  case tuple_size(WordTuple) of
    2048 ->
      List = tuple_to_list(WordTuple),
      case validate_unique_words(List) of
        true ->
          Words = [element(Idx + 1, WordTuple) || Idx <- Indices],
          {ok, [W || W <- Words, is_binary(W)]};
        false ->
          {error, bad_wordlist}
      end;
    _ ->
      {error, bad_wordlist}
  end;
map_indices_to_words(Indices, WordList) when is_list(WordList) ->
  case length(WordList) of
    2048 ->
      case validate_unique_words(WordList) of
        true ->
          Tuple = list_to_tuple(WordList),
          Words = [element(Idx + 1, Tuple) || Idx <- Indices],
          {ok, [W || W <- Words, is_binary(W)]};
        false ->
          {error, bad_wordlist}
      end;
    _ ->
      {error, bad_wordlist}
  end.

-spec map_words_to_indices([binary()], wordlist_ref()) ->
  {ok, [non_neg_integer()]} | {error, bip39_error()}.
map_words_to_indices(Words, english) ->
  lookup_indices(Words, fun ecu_bip39_words:index/1);
map_words_to_indices(Words, Mod) when is_atom(Mod) ->
  try
    lookup_indices(Words, fun Mod:index/1)
  catch
    _:_ -> {error, bad_wordlist}
  end;
map_words_to_indices(Words, WordTuple) when is_tuple(WordTuple) ->
  case tuple_size(WordTuple) of
    2048 ->
      List = tuple_to_list(WordTuple),
      case validate_unique_words(List) of
        true ->
          Map = maps:from_list([{element(I + 1, WordTuple), I} || I <- lists:seq(0, 2047)]),
          lookup_indices(Words, fun(W) -> maps:get(W, Map, undefined) end);
        false ->
          {error, bad_wordlist}
      end;
    _ ->
      {error, bad_wordlist}
  end;
map_words_to_indices(Words, WordList) when is_list(WordList) ->
  case length(WordList) of
    2048 ->
      case validate_unique_words(WordList) of
        true ->
          Map = maps:from_list(lists:zip(WordList, lists:seq(0, 2047))),
          lookup_indices(Words, fun(W) -> maps:get(W, Map, undefined) end);
        false ->
          {error, bad_wordlist}
      end;
    _ ->
      {error, bad_wordlist}
  end.

-spec lookup_indices([binary()], fun((binary()) -> non_neg_integer() | undefined)) ->
  {ok, [non_neg_integer()]} | {error, bip39_error()}.
lookup_indices([], _LookupFun) ->
  {ok, []};
lookup_indices([W | Rest], LookupFun) ->
  case LookupFun(W) of
    Idx when is_integer(Idx), Idx >= 0, Idx =< 2047 ->
      case lookup_indices(Rest, LookupFun) of
        {ok, Tail} -> {ok, [Idx | Tail]};
        {error, _} = Err -> Err
      end;
    undefined ->
      {error, {unknown_word, W}};
    _ ->
      {error, bad_wordlist}
  end.
