%%% File        : ecu_ecdsa.erl
%%% Author      : Hans Svensson
%%% Description : ecdsa functionality
%%% Created     : 13 Jan 2022 by Hans Svensson
-module(ecu_ecdsa).

-export([sign/3, verify/4,
         sign_secp256k1/2,
         private_to_public/2]).

private_to_public(secp256k1, <<PrivateKey:256>>) ->
  N = ecu_secp256k1:n(),
  case PrivateKey >= 1 andalso PrivateKey < N of
    true  -> ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(PrivateKey));
    false -> error(badarg)
  end.

sign(secp256k1, MsgHash = <<_:32/bytes>>, PrivateKey = <<_:32/bytes>>) ->
  {Sig, _YVal} = sign_secp256k1(MsgHash, PrivateKey),
  Sig.

%% Returns `false' for anything that isn't a valid signature, including
%% malformed input (out of range r/s, public key not on the curve, ...).
verify(secp256k1, MsgHash = <<_:32/bytes>>, PubKey = <<_:33/bytes>>, Sig = <<_:64/bytes>>) ->
  verify(secp256k1, MsgHash, ecu_secp256k1:decompress(PubKey), Sig);
verify(secp256k1, MsgHash = <<_:32/bytes>>, PubKey = {_, _}, <<R:256, S:256>>) ->
  N = ecu_secp256k1:n(),
  case R < 1 orelse R >= N orelse S < 1 orelse S >= N of
    true  -> false;
    false ->
      case valid_pubkey(PubKey) of
        true  -> verify_(MsgHash, PubKey, R, S);
        false -> false
      end
  end.

verify_(<<E:256>>, PubKey, R, S) ->
  N = ecu_secp256k1:n(),
  Z = E rem N,
  W = ecu_secp256k1:s_inv(S),
  [P1, P2] = ecu_misc:pcomp(
               [fun() -> ecu_secp256k1:scalar_mul_base(ecu_secp256k1:s_mul(Z, W)) end,
                fun() -> ecu_secp256k1:scalar_mul(ecu_secp256k1:s_mul(R, W), PubKey) end]),
  case ecu_secp256k1:p_add(P1, P2) of
    {0, 0} -> false; %% point at infinity
    {X, _Y} -> R == (X rem N)
  end.

sign_secp256k1(MsgHash = <<_:32/bytes>>, PrivateKey = <<D:256>>) ->
  N = ecu_secp256k1:n(),
  case D >= 1 andalso D < N of
    false -> error(badarg);
    true ->
      <<E:256>> = MsgHash,
      Z = E rem N,
      K = pick_k(secp256k1),
      {X, Y} = ecu_secp256k1:scalar_mul_base(K),
      R = X rem N,
      S = ecu_secp256k1:s_mul(ecu_secp256k1:s_inv(K),
                              ecu_secp256k1:s_add(Z, ecu_secp256k1:s_mul(R, D))),
      if R == 0 orelse S == 0 ->
           sign(secp256k1, MsgHash, PrivateKey);
         true ->
           {<<R:256, S:256>>, Y}
      end
  end.

%% --- internal functions

%% A public key must be a finite point on the curve with reduced coordinates.
%% Note: the point at infinity ({0, 0}) is not on the curve.
valid_pubkey({X, Y}) ->
  is_integer(X) andalso is_integer(Y)
  andalso X >= 0 andalso X < ecu_secp256k1:p()
  andalso Y >= 0 andalso Y < ecu_secp256k1:p()
  andalso ecu_secp256k1:on_curve({X, Y}).

pick_k(secp256k1) ->
  <<K:256>> = crypto:strong_rand_bytes(32),
  case K == 0 orelse K >= ecu_secp256k1:n() of
    true  -> pick_k(secp256k1);
    false -> K
  end.
