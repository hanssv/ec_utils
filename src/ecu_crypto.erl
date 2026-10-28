%%% File        : ecu_crypto.erl
%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 13 Jan 2022 by Hans Svensson
-module(ecu_crypto).

-typing([eqwalizer]).

-export([private_to_short/2, public_to_short/2,
         ec_recover/2,
         eth_sign/2, eth_recover/2, eth_verify/3,
         eth_msg_sign/2, eth_msg_recover/2, eth_msg_verify/3, eth_msg_hash/1,
         eth_sig_to_rsv/1, eth_sig_from_rsv/1,
         keccak256/1]).

-include("ecu_secp256k1.hrl").

-type coin() :: bitcoin | ethereum.
-type short_address() :: <<_:160>>.
-type eth_signature() :: <<_:520>>.
-type eth_recovered() :: <<_:256>>.
-type pubkey() :: ecu_secp256k1:pt_compressed() | ecu_secp256k1:pt_uncompressed() | ecu_secp256k1:pt_affine().

-export_type([coin/0, short_address/0, eth_signature/0, eth_recovered/0, pubkey/0]).

-spec private_to_short(coin(), ecu_ecdsa:privkey()) -> short_address().
private_to_short(bitcoin, PrivateKey) ->
  public_to_short(bitcoin, ecu_ecdsa:private_to_public(secp256k1, PrivateKey));
private_to_short(ethereum, PrivateKey) ->
  public_to_short(ethereum, ecu_ecdsa:private_to_public(secp256k1, PrivateKey)).

-spec public_to_short(coin(), pubkey()) -> short_address().
public_to_short(bitcoin, PubKey = <<_:33/bytes>>) ->
  crypto:hash(ripemd160, crypto:hash(sha256, PubKey));
public_to_short(bitcoin, PubKey) ->
  crypto:hash(ripemd160, crypto:hash(sha256, ecu_secp256k1:compress(PubKey)));
public_to_short(ethereum, PubKey) ->
  case PubKey of
    <<_:33/bytes>> -> public_to_short(ethereum, ecu_secp256k1:decompress(PubKey));
    <<4:8, X:256, Y:256>> -> public_to_short(ethereum, {X, Y});
    {X, Y} ->
      <<_:12/bytes, ShortPub:20/bytes>> = keccak256(<<X:256, Y:256>>),
      ShortPub
  end.

-spec eth_msg_sign(iodata(), ecu_ecdsa:privkey()) -> eth_signature().
eth_msg_sign(Msg, PrivateKey = <<_:32/bytes>>) ->
  eth_sign(eth_msg_hash(Msg), PrivateKey).

%% Recovery id V: Ethereum standard uses 27 + (Y rem 2). The case where
%% X >= N (recovery id 2 or 3) occurs with probability ~ 2^-128 and is omitted.
%%
%% Signature Layout:
%% Note that `ec_utils' serializes Ethereum signatures as `<<V:8, R:256, S:256>>'
%% (VRS), adhering to Bitcoin compact signature layout and Aeternity conventions.
%% Standard Ethereum web3/RPC tooling and Solidity ecrecover typically expect
%% `<<R:256, S:256, V:8>>' (RSV). Callers interfacing with external Ethereum tools
%% can use `eth_sig_to_rsv/1' and `eth_sig_from_rsv/1' to convert between layouts.
-spec eth_sign(ecu_ecdsa:msg_hash(), ecu_ecdsa:privkey()) -> eth_signature().
eth_sign(Msg, PrivateKey = <<_:32/bytes>>) ->
  {BaseSig, YVal} = ecu_ecdsa:sign_secp256k1(Msg, PrivateKey),
  V = if YVal rem 2 == 0 -> 27;
         true            -> 28
      end,
  <<V:8, BaseSig/bytes>>.

-spec eth_msg_recover(iodata(), eth_signature()) -> short_address().
eth_msg_recover(Msg, Sig = <<_:65/bytes>>) ->
  eth_recover(eth_msg_hash(Msg), Sig).

%% This is the mythical Ethereum ECRECOVERY operation
-spec ec_recover(ecu_ecdsa:msg_hash(), eth_signature()) -> eth_recovered().
ec_recover(MsgHash = <<_:32/bytes>>, Sig = <<_:65/bytes>>) ->
  <<V:8, R:256, S:256>> = Sig,
  case (V == 27 orelse V == 28) andalso
       (R >= 1 andalso R < ?N) andalso
       (S >= 1 andalso S < ?N) of
    true ->
      try eth_recover(MsgHash, Sig) of
        ShortPub -> <<0:96, ShortPub/binary>>
      catch _:_ ->
        <<0:256>>
      end;
    false ->
      <<0:256>>
  end.

-spec eth_recover(ecu_ecdsa:msg_hash(), eth_signature()) -> short_address().
eth_recover(MsgHash = <<_:32/bytes>>, Sig = <<_:65/bytes>>) ->
  <<E:256>> = MsgHash,
  <<V:8, R:256, S:256>> = Sig,
  Z = E rem ?N,
  RInv = ecu_secp256k1:s_inv(R),
  Rd = ecu_secp256k1:decompress(<<(V - 27 + 2):8, R:256>>),
  K1 = (?N - ecu_secp256k1:s_mul(RInv, Z)) rem ?N,
  K2 = ecu_secp256k1:s_mul(RInv, S),
  case ecu_secp256k1:scalar_mul_dual(K1, {?X, ?Y}, K2, Rd) of
    {0, 0} -> error(point_at_infinity);
    {X, Y} ->
      <<_:12/bytes, RPub:20/bytes>> = keccak256(<<X:256, Y:256>>),
      RPub
  end.

-spec eth_msg_verify(iodata(), short_address(), eth_signature()) -> boolean().
eth_msg_verify(Msg, PublicKey, Sig) ->
  eth_verify(eth_msg_hash(Msg), PublicKey, Sig).

-spec eth_verify(ecu_ecdsa:msg_hash(), short_address(), eth_signature()) -> boolean().
eth_verify(Msg, PublickKey, Sig) ->
  PublickKey == eth_recover(Msg, Sig).

%% Conversion between internal VRS layout (<<V:8, R:256, S:256>>) and
%% external Ethereum web3/Solidity RSV layout (<<R:256, S:256, V:8>>).
-spec eth_sig_to_rsv(eth_signature()) -> <<_:520>>.
eth_sig_to_rsv(<<V:8, R:256, S:256>>) ->
  <<R:256, S:256, V:8>>;
eth_sig_to_rsv(_) ->
  error(badarg).

-spec eth_sig_from_rsv(<<_:520>>) -> eth_signature().
eth_sig_from_rsv(<<R:256, S:256, V:8>>) ->
  <<V:8, R:256, S:256>>;
eth_sig_from_rsv(_) ->
  error(badarg).

-spec eth_msg_hash(iodata()) -> ecu_ecdsa:msg_hash().
eth_msg_hash(Msg0) ->
  BinMsg = iolist_to_binary(Msg0),
  Msg = ["\x19Ethereum Signed Message:\n", integer_to_list(byte_size(BinMsg)), BinMsg],
  keccak256(iolist_to_binary(Msg)).

-spec keccak256(iodata()) -> binary().
keccak256(Data) ->
  sha3:hash(256, iolist_to_binary(Data)).
