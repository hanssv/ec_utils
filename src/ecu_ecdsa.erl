%%% File        : ecu_ecdsa.erl
%%% Author      : Hans Svensson
%%% Description : ecdsa functionality
%%% Created     : 13 Jan 2022 by Hans Svensson
-module(ecu_ecdsa).

-typing([eqwalizer]).

-export([sign/3, verify/4,
         sign_secp256k1/2,
         private_to_public/2,
         rfc6979_k/3]).

-include("ecu_secp256k1.hrl").

-type curve() :: secp256k1.
-type privkey() :: <<_:256>>.
-type pubkey() :: ecu_secp256k1:pt_compressed() | ecu_secp256k1:pt_affine().
-type msg_hash() :: <<_:256>>.
-type signature() :: <<_:512>>.

-export_type([curve/0, privkey/0, pubkey/0, msg_hash/0, signature/0]).

-spec private_to_public(curve(), privkey()) -> ecu_secp256k1:pt_compressed().
private_to_public(secp256k1, <<PrivateKey:256>>) when PrivateKey >= 1,
                                                      PrivateKey < ?N ->
  ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(PrivateKey));
private_to_public(secp256k1, _) ->
  error(badarg).

-spec sign(curve(), msg_hash(), privkey()) -> signature().
sign(secp256k1, MsgHash = <<_:32/bytes>>, PrivateKey = <<_:32/bytes>>) ->
  {Sig, _YVal} = sign_secp256k1(MsgHash, PrivateKey),
  Sig.

%% Returns `false' for anything that isn't a valid signature, including
%% malformed input (out of range r/s, public key not on the curve, ...).
-spec verify(curve(), msg_hash(), pubkey(), signature()) -> boolean().
verify(secp256k1, MsgHash = <<_:32/bytes>>, PubKey = <<_:33/bytes>>, Sig = <<_:64/bytes>>) ->
  try ecu_secp256k1:decompress(PubKey) of
    Affine -> verify(secp256k1, MsgHash, Affine, Sig)
  catch
    error:badarg -> false
  end;
verify(secp256k1, <<_:32/bytes>>, {_, _}, <<R:256, S:256>>)
    when R < 1; R >= ?N; S < 1; S >= ?N ->
  false;
verify(secp256k1, MsgHash = <<_:32/bytes>>, PubKey = {_, _}, <<R:256, S:256>>) ->
  case valid_pubkey(PubKey) of
    true  -> verify_(MsgHash, PubKey, R, S);
    false -> false
  end;
verify(_, _, _, _) ->
  false.

-spec verify_(msg_hash(), ecu_secp256k1:pt_affine(), pos_integer(), pos_integer()) -> boolean().
verify_(<<E:256>>, PubKey, R, S) ->
  Z = E rem ?N,
  W = ecu_secp256k1:s_inv(S),
  U1 = ecu_secp256k1:s_mul(Z, W),
  U2 = ecu_secp256k1:s_mul(R, W),
  case ecu_secp256k1:scalar_mul_dual(U1, {?X, ?Y}, U2, PubKey) of
    {0, 0} -> false; %% point at infinity
    {X, _Y} -> R == (X rem ?N)
  end.

-spec rfc6979_k(curve(), msg_hash(), privkey()) -> pos_integer().
rfc6979_k(secp256k1, MsgHash = <<_:32/bytes>>, PrivKey = <<PrivateKey:256>>)
    when PrivateKey >= 1, PrivateKey < ?N ->
  {K, _V, _HMAC_K} = rfc6979_init(MsgHash, PrivKey),
  K;
rfc6979_k(_, _, _) ->
  error(badarg).

-spec sign_secp256k1(msg_hash(), privkey()) -> {signature(), non_neg_integer()}.
sign_secp256k1(MsgHash = <<_:32/bytes>>, PrivKey = <<PrivateKey:256>>)
    when PrivateKey >= 1, PrivateKey < ?N ->
  <<E:256>> = MsgHash,
  Z = E rem ?N,
  sign_secp256k1_loop(Z, PrivateKey, rfc6979_init(MsgHash, PrivKey));
sign_secp256k1(_, _) ->
  error(badarg).

-spec sign_secp256k1_loop(non_neg_integer(), pos_integer(), {pos_integer(), binary(), binary()}) ->
    {signature(), non_neg_integer()}.
sign_secp256k1_loop(Z, PrivateKey, {K, V, HMAC_K}) ->
  {X, Y} = ecu_secp256k1:scalar_mul_base(K),
  R = X rem ?N,
  S = ecu_secp256k1:s_mul(ecu_secp256k1:s_inv(K),
                          ecu_secp256k1:s_add(Z, ecu_secp256k1:s_mul(R, PrivateKey))),
  if R == 0 orelse S == 0 ->
       sign_secp256k1_loop(Z, PrivateKey, rfc6979_step(V, HMAC_K));
     true ->
       {CanonicalS, FinalY} =
         if S > (?N div 2) ->
              {?N - S, ?P - Y};
            true ->
              {S, Y}
         end,
       {<<R:256, CanonicalS:256>>, FinalY}
  end.

%% RFC 6979 Section 3.2 Deterministic Nonce Generation for secp256k1 (SHA-256)
-spec rfc6979_init(msg_hash(), privkey()) -> {pos_integer(), binary(), binary()}.
rfc6979_init(MsgHash, <<PrivateKey:256>>) ->
  <<E:256>> = MsgHash,
  Z = E rem ?N,
  Bits2Octets = <<Z:256>>,
  Int2Octets = <<PrivateKey:256>>,
  V0 = binary:copy(<<1>>, 32),
  K0 = binary:copy(<<0>>, 32),
  K1 = crypto:mac(hmac, sha256, K0, <<V0/binary, 0:8, Int2Octets/binary, Bits2Octets/binary>>),
  V1 = crypto:mac(hmac, sha256, K1, V0),
  K2 = crypto:mac(hmac, sha256, K1, <<V1/binary, 1:8, Int2Octets/binary, Bits2Octets/binary>>),
  V2 = crypto:mac(hmac, sha256, K2, V1),
  rfc6979_loop(V2, K2).

-spec rfc6979_loop(binary(), binary()) -> {pos_integer(), binary(), binary()}.
rfc6979_loop(V, K) ->
  V1 = crypto:mac(hmac, sha256, K, V),
  <<KInt:256>> = V1,
  if KInt >= 1 andalso KInt < ?N ->
       {KInt, V1, K};
     true ->
       rfc6979_step(V1, K)
  end.

-spec rfc6979_step(binary(), binary()) -> {pos_integer(), binary(), binary()}.
rfc6979_step(V, K) ->
  KNext = crypto:mac(hmac, sha256, K, <<V/binary, 0:8>>),
  VNext = crypto:mac(hmac, sha256, KNext, V),
  rfc6979_loop(VNext, KNext).

%% --- internal functions

%% A public key must be a finite point on the curve with reduced coordinates.
%% Note: the point at infinity ({0, 0}) is not on the curve.
-spec valid_pubkey(term()) -> boolean().
valid_pubkey({X, Y}) when is_integer(X), is_integer(Y) ->
  X >= 0 andalso X < ?P
  andalso Y >= 0 andalso Y < ?P
  andalso ecu_secp256k1:on_curve({X, Y});
valid_pubkey(_) ->
  false.
