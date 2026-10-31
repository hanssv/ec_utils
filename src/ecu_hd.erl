%%%-------------------------------------------------------------------
%%% @doc
%%% Hierarchical Deterministic (HD) Key Derivation (BIP-32 and SLIP-0010).
%%%
%%% Pure Erlang implementation of hierarchical deterministic wallet derivation
%%% for secp256k1 (BIP-32, BIP-44) and Ed25519 (SLIP-0010, AEX-10).
%%% Supports master key generation from seed, private/public child key derivation,
%%% flexible path syntax (e.g. "m/44'/60'/0'/0/0", "m/44H/457H/0H"), and
%%% serialization to standard Base58Check extended keys ("xprv...", "xpub...").
%%%
%%% References:
%%%   BIP-32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
%%%   BIP-44: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
%%%   SLIP-0010: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
%%%   AEX-10: https://github.com/aeternity/AEXs/blob/master/AEXS/aex-10.md
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_hd).

-typing([eqwalizer]).

%% Master key & Path derivation
-export([
  master_key/2,
  derive_path/2,
  derive_path_from_seed/3,
  ckd_priv/2,
  ckd_pub/2
]).

%% Application / Standard derivations
-export([
  derive_bip44/5,
  derive_bip44/6,
  derive_aex10/3,
  derive_aex10/4,
  derive_aex10_from_masterkey/3,
  derive_aex10_from_masterkey/4
]).

%% Key accessors & conversions
-export([
  private_key/1,
  public_key/1,
  chain_code/1,
  fingerprint/1,
  parent_fingerprint/1,
  depth/1,
  child_number/1,
  curve/1,
  is_private/1,
  to_public/1
]).

%% Serialization & Base58Check
-export([
  serialize/1,
  serialize/2,
  deserialize/1,
  to_base58/1,
  to_base58/2,
  from_base58/1
]).

%% Types
-type curve() :: secp256k1 | ed25519.
-type key_type() :: private | public.

-type extended_key() :: #{
  curve := curve(),
  depth := 0..255,
  fprint := <<_:32>>,
  child_num := non_neg_integer(),
  chain_code := <<_:256>>,
  priv_key := <<_:256>> | undefined,
  pub_key := <<_:264>> | <<_:256>> | undefined
}.

-export_type([curve/0, key_type/0, extended_key/0]).

%% Constants
-define(SECP256K1_SEED_KEY, <<"Bitcoin seed">>).
-define(ED25519_SEED_KEY, <<"ed25519 seed">>).

-define(SECP256K1_ORDER, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).
-define(HARDENED_BIT, 16#80000000).

%% BIP-32 Bitcoin Mainnet version bytes

%% xprv
-define(BIP32_MAINNET_PRIV, <<16#0488ADE4:32>>).
%% xpub
-define(BIP32_MAINNET_PUB, <<16#0488B21E:32>>).

%% ===================================================================
%% Master Key & Child Key Derivation
%% ===================================================================

-spec master_key(curve(), binary()) -> {ok, extended_key()} | {error, term()}.
master_key(Curve, Seed) when (Curve =:= secp256k1 orelse Curve =:= ed25519), is_binary(Seed) ->
  if
    byte_size(Seed) < 16 orelse byte_size(Seed) > 64 ->
      {error, invalid_seed_length};
    true ->
      SeedKey = curve_seed_key(Curve),
      <<IL:256, IR:32/binary>> = crypto:mac(hmac, sha512, SeedKey, Seed),
      case Curve of
        secp256k1 ->
          if
            IL =:= 0 orelse IL >= ?SECP256K1_ORDER ->
              {error, invalid_master_key};
            true ->
              PrivKey = <<IL:256>>,
              PubKey = derive_public_bytes(secp256k1, PrivKey),
              {ok, #{
                curve => secp256k1,
                depth => 0,
                fprint => <<0:32>>,
                child_num => 0,
                chain_code => IR,
                priv_key => PrivKey,
                pub_key => PubKey
              }}
          end;
        ed25519 ->
          PrivKey = <<IL:256>>,
          PubKey = derive_public_bytes(ed25519, PrivKey),
          {ok, #{
            curve => ed25519,
            depth => 0,
            fprint => <<0:32>>,
            child_num => 0,
            chain_code => IR,
            priv_key => PrivKey,
            pub_key => PubKey
          }}
      end
  end;
master_key(_Curve, _Seed) ->
  {error, badarg}.

-spec ckd_priv(extended_key(), non_neg_integer()) -> {ok, extended_key()} | {error, term()}.
ckd_priv(#{priv_key := undefined}, _Index) ->
  {error, no_private_key};
ckd_priv(#{depth := Depth}, _Index) when Depth >= 255 ->
  {error, maximum_depth_exceeded};
ckd_priv(#{curve := secp256k1, priv_key := <<PrivInt:256>>, chain_code := CC} = Parent, Index) when
  is_integer(Index), Index >= 0, Index < 16#100000000
->
  Data =
    if
      Index >= ?HARDENED_BIT ->
        <<0:8, PrivInt:256, Index:32/unsigned-big>>;
      true ->
        PubKey = ensure_compressed_secp256k1_pub(Parent),
        <<PubKey:33/binary, Index:32/unsigned-big>>
    end,
  <<IL:256, IR:32/binary>> = crypto:mac(hmac, sha512, CC, Data),
  if
    IL >= ?SECP256K1_ORDER ->
      {error, invalid_child_key};
    true ->
      ChildPriv = (IL + PrivInt) rem ?SECP256K1_ORDER,
      if
        ChildPriv =:= 0 ->
          {error, invalid_child_key};
        true ->
          ChildPrivBin = <<ChildPriv:256>>,
          ChildPub = derive_public_bytes(secp256k1, ChildPrivBin),
          FP = key_fingerprint(Parent),
          {ok, #{
            curve => secp256k1,
            depth => maps:get(depth, Parent) + 1,
            fprint => FP,
            child_num => Index,
            chain_code => IR,
            priv_key => ChildPrivBin,
            pub_key => ChildPub
          }}
      end
  end;
ckd_priv(#{curve := ed25519, priv_key := <<PrivBin:32/binary>>, chain_code := CC} = Parent, Index) when
  is_integer(Index), Index >= 0, Index < 16#100000000
->
  if
    Index < ?HARDENED_BIT ->
      {error, unhardened_derivation_not_supported_for_ed25519};
    true ->
      Data = <<0:8, PrivBin/binary, Index:32/unsigned-big>>,
      <<IL:256, IR:32/binary>> = crypto:mac(hmac, sha512, CC, Data),
      ChildPrivBin = <<IL:256>>,
      ChildPub = derive_public_bytes(ed25519, ChildPrivBin),
      FP = key_fingerprint(Parent),
      {ok, #{
        curve => ed25519,
        depth => maps:get(depth, Parent) + 1,
        fprint => FP,
        child_num => Index,
        chain_code => IR,
        priv_key => ChildPrivBin,
        pub_key => ChildPub
      }}
  end;
ckd_priv(_Key, _Index) ->
  {error, badarg}.

-spec ckd_pub(extended_key(), non_neg_integer()) -> {ok, extended_key()} | {error, term()}.
ckd_pub(#{depth := Depth}, _Index) when Depth >= 255 ->
  {error, maximum_depth_exceeded};
ckd_pub(#{curve := ed25519}, _Index) ->
  {error, public_derivation_not_supported_for_ed25519};
ckd_pub(#{curve := secp256k1}, Index) when is_integer(Index), Index >= ?HARDENED_BIT ->
  {error, cannot_derive_hardened_from_public_key};
ckd_pub(#{curve := secp256k1, chain_code := CC} = Parent, Index) when
  is_integer(Index), Index >= 0, Index < ?HARDENED_BIT
->
  ParentPub = ensure_compressed_secp256k1_pub(Parent),
  Data = <<ParentPub:33/binary, Index:32/unsigned-big>>,
  <<IL:256, IR:32/binary>> = crypto:mac(hmac, sha512, CC, Data),
  if
    IL >= ?SECP256K1_ORDER ->
      {error, invalid_child_key};
    true ->
      PtIL = ecu_secp256k1:scalar_mul_base(IL),
      PtParent = ecu_secp256k1:decompress(ParentPub),
      PtChild = ecu_secp256k1:p_add(PtIL, PtParent),
      case PtChild of
        {0, 0} ->
          {error, point_at_infinity};
        _Other ->
          ChildPub = ecu_secp256k1:compress(PtChild),
          FP = key_fingerprint(Parent),
          {ok, #{
            curve => secp256k1,
            depth => maps:get(depth, Parent) + 1,
            fprint => FP,
            child_num => Index,
            chain_code => IR,
            priv_key => undefined,
            pub_key => ChildPub
          }}
      end
  end;
ckd_pub(_Key, _Index) ->
  {error, badarg}.

%% ===================================================================
%% Path Derivation
%% ===================================================================

-spec derive_path(string() | binary(), extended_key()) -> {ok, extended_key()} | {error, term()}.
derive_path(Path, Key) when is_binary(Path) ->
  derive_path(binary_to_list(Path), Key);
derive_path(Path, Key) when is_list(Path), is_map(Key) ->
  case parse_path(Path) of
    {ok, Mode, Segments} ->
      derive_segments(Mode, Segments, Key);
    {error, Reason} ->
      {error, Reason}
  end.

-spec derive_path_from_seed(curve(), string() | binary(), binary()) ->
  {ok, extended_key()} | {error, term()}.
derive_path_from_seed(Curve, Path, Seed) ->
  case master_key(Curve, Seed) of
    {ok, MasterKey} ->
      derive_path(Path, MasterKey);
    {error, Reason} ->
      {error, Reason}
  end.

-spec derive_segments(private | public, [non_neg_integer()], extended_key()) ->
  {ok, extended_key()} | {error, term()}.
derive_segments(private, _Segments, #{priv_key := undefined}) ->
  {error, cannot_derive_private_from_public_key};
derive_segments(private, Segments, Key) ->
  fold_ckd(fun ckd_priv/2, Key, Segments);
derive_segments(public, Segments, #{priv_key := undefined} = Key) ->
  fold_ckd(fun ckd_pub/2, Key, Segments);
derive_segments(public, Segments, Key) ->
  case fold_ckd(fun ckd_priv/2, Key, Segments) of
    {ok, DerivedPriv} ->
      {ok, to_public(DerivedPriv)};
    {error, Reason} ->
      {error, Reason}
  end.

-spec fold_ckd(
  fun((extended_key(), non_neg_integer()) -> {ok, extended_key()} | {error, term()}),
  extended_key(),
  [non_neg_integer()]
) -> {ok, extended_key()} | {error, term()}.
fold_ckd(_Fun, Key, []) ->
  {ok, Key};
fold_ckd(Fun, Key, [Ix | Rest]) ->
  case Fun(Key, Ix) of
    {ok, NextKey} ->
      fold_ckd(Fun, NextKey, Rest);
    {error, Reason} ->
      {error, Reason}
  end.

-spec parse_path(string()) -> {ok, private | public, [non_neg_integer()]} | {error, term()}.
parse_path("m/" ++ Rest) ->
  parse_path_segments(Rest, private, []);
parse_path("m") ->
  {ok, private, []};
parse_path("M/" ++ Rest) ->
  parse_path_segments(Rest, public, []);
parse_path("M") ->
  {ok, public, []};
parse_path([C | _] = Path) when C =/= $/ ->
  parse_path_segments(Path, private, []);
parse_path(_InvalidPath) ->
  {error, invalid_path}.

-spec parse_path_segments(string(), private | public, [non_neg_integer()]) ->
  {ok, private | public, [non_neg_integer()]} | {error, term()}.
parse_path_segments(PathStr, Mode, Acc) ->
  Tokens = string:split(PathStr, "/", all),
  case lists:any(fun(T) -> T =:= [] end, Tokens) of
    true ->
      {error, invalid_path};
    false ->
      parse_tokens(Tokens, Mode, Acc)
  end.

-spec parse_tokens([string()], private | public, [non_neg_integer()]) ->
  {ok, private | public, [non_neg_integer()]} | {error, term()}.
parse_tokens([], Mode, Acc) ->
  {ok, Mode, lists:reverse(Acc)};
parse_tokens([Tok | Rest], Mode, Acc) ->
  case parse_index_token(Tok) of
    {ok, Index} ->
      parse_tokens(Rest, Mode, [Index | Acc]);
    {error, Reason} ->
      {error, Reason}
  end.

-spec parse_index_token(string()) -> {ok, non_neg_integer()} | {error, term()}.
parse_index_token(Token) ->
  Rev = lists:reverse(Token),
  case Rev of
    [$' | SuffixRest] ->
      parse_numeric_index(lists:reverse(SuffixRest), true);
    [$h | SuffixRest] ->
      parse_numeric_index(lists:reverse(SuffixRest), true);
    [$H | SuffixRest] ->
      parse_numeric_index(lists:reverse(SuffixRest), true);
    _Other ->
      parse_numeric_index(Token, false)
  end.

-spec parse_numeric_index(string(), boolean()) -> {ok, non_neg_integer()} | {error, term()}.
parse_numeric_index([], _Hardened) ->
  {error, {invalid_path_index, ""}};
parse_numeric_index(Str, Hardened) ->
  case lists:all(fun(C) -> C >= $0 andalso C =< $9 end, Str) of
    true ->
      try list_to_integer(Str) of
        N when is_integer(N), N >= 0, N < ?HARDENED_BIT ->
          if
            Hardened ->
              {ok, N + ?HARDENED_BIT};
            true ->
              {ok, N}
          end;
        _OutOfRange ->
          {error, {invalid_path_index, Str}}
      catch
        _:_ ->
          {error, {invalid_path_index, Str}}
      end;
    false ->
      {error, {invalid_path_index, Str}}
  end.

%% ===================================================================
%% Application & Standard Derivations (BIP-44 & AEX-10)
%% ===================================================================

-spec derive_bip44(curve(), binary(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
  {ok, extended_key()} | {error, term()}.
derive_bip44(Curve, Seed, CoinType, Account, AddressIndex) ->
  derive_bip44(Curve, Seed, CoinType, Account, 0, AddressIndex).

-spec derive_bip44(
  curve(),
  binary(),
  non_neg_integer(),
  non_neg_integer(),
  0 | 1,
  non_neg_integer()
) ->
  {ok, extended_key()} | {error, term()}.
derive_bip44(Curve, Seed, CoinType, Account, Change, AddressIndex) when
  is_integer(CoinType),
  is_integer(Account),
  (Change =:= 0 orelse Change =:= 1),
  is_integer(AddressIndex)
->
  Path =
    io_lib:format(
      "m/44'/~w'/~w'/~w/~w",
      [CoinType, Account, Change, AddressIndex]
    ),
  derive_path_from_seed(Curve, lists:flatten(Path), Seed).

-spec derive_aex10(binary(), non_neg_integer(), non_neg_integer()) ->
  {ok, extended_key()} | {error, term()}.
derive_aex10(Seed, AccountIndex, AddressIndex) ->
  derive_aex10(Seed, AccountIndex, 0, AddressIndex).

-spec derive_aex10(binary(), non_neg_integer(), non_neg_integer(), non_neg_integer()) ->
  {ok, extended_key()} | {error, term()}.
derive_aex10(Seed, AccountIndex, Change, AddressIndex) ->
  Path = aex10_path_string(AccountIndex, Change, AddressIndex),
  derive_path_from_seed(ed25519, Path, Seed).

-spec derive_aex10_from_masterkey(extended_key(), non_neg_integer(), non_neg_integer()) ->
  {ok, extended_key()} | {error, term()}.
derive_aex10_from_masterkey(MasterKey, AccountIndex, AddressIndex) ->
  derive_aex10_from_masterkey(MasterKey, AccountIndex, 0, AddressIndex).

-spec derive_aex10_from_masterkey(
  extended_key(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer()
) ->
  {ok, extended_key()} | {error, term()}.
derive_aex10_from_masterkey(MasterKey, AccountIndex, Change, AddressIndex) ->
  Path = aex10_path_string(AccountIndex, Change, AddressIndex),
  derive_path(Path, MasterKey).

-spec aex10_path_string(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> string().
aex10_path_string(AccountIndex, Change, AddressIndex) ->
  lists:flatten(
    io_lib:format(
      "m/44H/457H/~wH/~wH/~wH",
      [AccountIndex, Change, AddressIndex]
    )
  ).

%% ===================================================================
%% Key Accessors & Conversions
%% ===================================================================

-spec private_key(extended_key()) -> {ok, <<_:256>>} | {error, no_private_key}.
private_key(#{priv_key := <<Priv:32/binary>>}) ->
  {ok, Priv};
private_key(#{priv_key := undefined}) ->
  {error, no_private_key}.

-spec public_key(extended_key()) -> {ok, <<_:264>> | <<_:256>>}.
public_key(#{pub_key := <<Pub/binary>>}) ->
  {ok, Pub};
public_key(#{curve := secp256k1, priv_key := <<Priv/binary>>}) ->
  Pub = derive_public_bytes(secp256k1, Priv),
  {ok, Pub};
public_key(#{curve := ed25519, priv_key := <<Priv/binary>>}) ->
  Pub = derive_public_bytes(ed25519, Priv),
  {ok, Pub}.

-spec chain_code(extended_key()) -> <<_:256>>.
chain_code(#{chain_code := <<CC:32/binary>>}) ->
  CC.

-spec fingerprint(extended_key()) -> <<_:32>>.
fingerprint(Key) ->
  key_fingerprint(Key).

-spec parent_fingerprint(extended_key()) -> <<_:32>>.
parent_fingerprint(#{fprint := <<FP:4/binary>>}) ->
  FP.

-spec depth(extended_key()) -> 0..255.
depth(#{depth := Depth}) ->
  Depth.

-spec child_number(extended_key()) -> non_neg_integer().
child_number(#{child_num := ChildNum}) ->
  ChildNum.

-spec curve(extended_key()) -> curve().
curve(#{curve := Curve}) ->
  Curve.

-spec is_private(extended_key()) -> boolean().
is_private(#{priv_key := <<_:32/binary>>}) ->
  true;
is_private(#{priv_key := undefined}) ->
  false.

-spec to_public(extended_key()) -> extended_key().
to_public(#{pub_key := <<_/binary>>} = Key) ->
  Key#{priv_key => undefined};
to_public(#{curve := Curve, priv_key := <<Priv:32/binary>>} = Key) ->
  Pub = derive_public_bytes(Curve, Priv),
  Key#{priv_key => undefined, pub_key => Pub}.

%% ===================================================================
%% Serialization & Base58Check
%% ===================================================================

-spec serialize(extended_key()) -> binary().
serialize(Key) ->
  KeyType =
    case is_private(Key) of
      true -> private;
      false -> public
    end,
  serialize(KeyType, Key).

-spec serialize(key_type(), extended_key()) -> binary().
serialize(private, #{curve := secp256k1, priv_key := <<Priv:32/binary>>} = Key) ->
  Vsn = ?BIP32_MAINNET_PRIV,
  Depth = maps:get(depth, Key),
  FP = maps:get(fprint, Key),
  Child = maps:get(child_num, Key),
  CC = maps:get(chain_code, Key),
  KeyBytes = <<0:8, Priv:32/binary>>,
  <<Vsn:4/binary, Depth:8, FP:4/binary, Child:32/unsigned-big, CC:32/binary, KeyBytes:33/binary>>;
serialize(public, #{curve := secp256k1} = Key) ->
  Vsn = ?BIP32_MAINNET_PUB,
  Depth = maps:get(depth, Key),
  FP = maps:get(fprint, Key),
  Child = maps:get(child_num, Key),
  CC = maps:get(chain_code, Key),
  KeyBytes = ensure_compressed_secp256k1_pub(Key),
  <<Vsn:4/binary, Depth:8, FP:4/binary, Child:32/unsigned-big, CC:32/binary, KeyBytes:33/binary>>.

-spec deserialize(binary()) -> {ok, extended_key()} | {error, term()}.
deserialize(
  <<Vsn:4/binary, Depth:8, FP:4/binary, Child:32/unsigned-big, CC:32/binary, KeyBytes:33/binary>>
) ->
  if
    Depth =:= 0 andalso (FP =/= <<0:32>> orelse Child =/= 0) ->
      {error, invalid_master_key_metadata};
    true ->
      case Vsn of
        ?BIP32_MAINNET_PRIV ->
          case KeyBytes of
            <<0:8, PrivInt:256>> ->
              if
                PrivInt =:= 0 orelse PrivInt >= ?SECP256K1_ORDER ->
                  {error, invalid_private_key};
                true ->
                  Priv = <<PrivInt:256>>,
                  Pub = derive_public_bytes(secp256k1, Priv),
                  {ok, #{
                    curve => secp256k1,
                    depth => Depth,
                    fprint => FP,
                    child_num => Child,
                    chain_code => CC,
                    priv_key => Priv,
                    pub_key => Pub
                  }}
              end;
            _ ->
              {error, invalid_private_key_prefix}
          end;
        ?BIP32_MAINNET_PUB ->
          case KeyBytes of
            <<Header:8, _/binary>> when Header =:= 2; Header =:= 3 ->
              try ecu_secp256k1:decompress(KeyBytes) of
                {0, 0} ->
                  {error, invalid_public_key};
                _Pt ->
                  {ok, #{
                    curve => secp256k1,
                    depth => Depth,
                    fprint => FP,
                    child_num => Child,
                    chain_code => CC,
                    priv_key => undefined,
                    pub_key => KeyBytes
                  }}
              catch
                _:_ ->
                  {error, invalid_public_key}
              end;
            _InvalidHeader ->
              {error, invalid_public_key_header}
          end;
        _UnsupportedVersion ->
          {error, unsupported_bip32_version}
      end
  end;
deserialize(_InvalidBinary) ->
  {error, invalid_extended_key_binary}.

-spec to_base58(extended_key()) -> binary().
to_base58(Key) ->
  ecu_base58:encode_check(serialize(Key)).

-spec to_base58(key_type(), extended_key()) -> binary().
to_base58(KeyType, Key) ->
  ecu_base58:encode_check(serialize(KeyType, Key)).

-spec from_base58(binary() | string()) -> {ok, extended_key()} | {error, term()}.
from_base58(Base58Str) ->
  case ecu_base58:decode_check(Base58Str) of
    {ok, Bin} ->
      deserialize(Bin);
    {error, Reason} ->
      {error, Reason}
  end.

%% ===================================================================
%% Internal Helpers
%% ===================================================================

-spec curve_seed_key(curve()) -> binary().
curve_seed_key(secp256k1) ->
  ?SECP256K1_SEED_KEY;
curve_seed_key(ed25519) ->
  ?ED25519_SEED_KEY.

-spec derive_public_bytes(curve(), <<_:256>>) -> <<_:264>> | <<_:256>>.
derive_public_bytes(secp256k1, <<Priv:32/binary>>) ->
  <<PrivInt:256>> = Priv,
  Pt = ecu_secp256k1:scalar_mul_base(PrivInt),
  ecu_secp256k1:compress(Pt);
derive_public_bytes(ed25519, <<Priv:32/binary>>) ->
  #{public := Pub} = ecu_eddsa:sign_seed_keypair(Priv),
  Pub.

-spec ensure_compressed_secp256k1_pub(extended_key()) -> <<_:264>>.
ensure_compressed_secp256k1_pub(#{pub_key := <<Pub:33/binary>>}) ->
  Pub;
ensure_compressed_secp256k1_pub(#{priv_key := <<Priv:32/binary>>}) ->
  derive_public_bytes(secp256k1, Priv).

-spec key_fingerprint(extended_key()) -> <<_:32>>.
key_fingerprint(#{curve := secp256k1} = Key) ->
  Pub = ensure_compressed_secp256k1_pub(Key),
  <<FP:4/binary, _/binary>> = crypto:hash(ripemd160, crypto:hash(sha256, Pub)),
  FP;
key_fingerprint(#{curve := ed25519, pub_key := <<Pub:32/binary>>}) ->
  %% SLIP-0010 prepends 0x00 to Ed25519 public keys when hashing for fingerprint
  <<FP:4/binary, _/binary>> = crypto:hash(ripemd160, crypto:hash(sha256, <<0:8, Pub/binary>>)),
  FP;
key_fingerprint(#{curve := ed25519, priv_key := <<Priv:32/binary>>}) ->
  Pub = derive_public_bytes(ed25519, Priv),
  <<FP:4/binary, _/binary>> = crypto:hash(ripemd160, crypto:hash(sha256, <<0:8, Pub/binary>>)),
  FP.
