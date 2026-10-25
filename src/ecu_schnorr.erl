%%% File        : ecu_schnorr.erl
%%% Author      : Hans Svensson
%%% Description : BIP-340 Schnorr signatures for secp256k1 (Bitcoin Taproot)
-module(ecu_schnorr).

-typing([eqwalizer]).

-include("ecu_secp256k1.hrl").

-type public_key() :: <<_:256>>.
-type secret_key() :: <<_:256>>.
-type keypair() :: #{ public := public_key(), secret := secret_key() }.
-type signature() :: <<_:512>>.

-export_type([public_key/0, secret_key/0, keypair/0, signature/0]).

-export([sign_keypair/0,
         sign_keypair_from_secret/1,
         sign/2,
         sign/3,
         verify/3,
         lift_x/1,
         tagged_hash/2]).

-define(TAG_CHALLENGE_PREFIX, <<123,181,45,122,159,239,88,50,62,177,191,122,64,
                                125,179,130,210,243,242,216,27,177,34,79,73,
                                254,81,143,109,72,211,124,123,181,45,122,159,
                                239,88,50,62,177,191,122,64,125,179,130,210,
                                243,242,216,27,177,34,79,73,254,81,143,109,72,
                                211,124>>).

-define(TAG_AUX_PREFIX, <<241,239,78,94,192,99,202,218,109,148,202,250,157,152,
                          126,160,105,38,88,57,236,193,31,151,45,119,165,46,
                          216,193,204,144,241,239,78,94,192,99,202,218,109,148,
                          202,250,157,152,126,160,105,38,88,57,236,193,31,151,
                          45,119,165,46,216,193,204,144>>).

-define(TAG_NONCE_PREFIX, <<7,73,119,52,167,155,203,53,91,155,140,125,3,79,18,
                            28,244,52,215,62,247,45,218,25,135,0,97,251,82,191,
                            235,47,7,73,119,52,167,155,203,53,91,155,140,125,3,
                            79,18,28,244,52,215,62,247,45,218,25,135,0,97,251,
                            82,191,235,47>>).

%% @doc tagged_hash/2 computes the BIP-340 tagged hash SHA256(SHA256(tag) || SHA256(tag) || data).
-spec tagged_hash(binary() | string(), iodata()) -> <<_:256>>.
tagged_hash(<<"BIP0340/challenge">>, Data) ->
  crypto:hash(sha256, <<?TAG_CHALLENGE_PREFIX/binary, (iolist_to_binary(Data))/binary>>);
tagged_hash(<<"BIP0340/aux">>, Data) ->
  crypto:hash(sha256, <<?TAG_AUX_PREFIX/binary, (iolist_to_binary(Data))/binary>>);
tagged_hash(<<"BIP0340/nonce">>, Data) ->
  crypto:hash(sha256, <<?TAG_NONCE_PREFIX/binary, (iolist_to_binary(Data))/binary>>);
tagged_hash(Tag, Data) ->
  TagBin = iolist_to_binary(Tag),
  TagHash = crypto:hash(sha256, TagBin),
  crypto:hash(sha256, <<TagHash/binary, TagHash/binary, (iolist_to_binary(Data))/binary>>).

%% @doc lift_x/1 lifts a 256-bit X coordinate to a secp256k1 curve point with EVEN Y coordinate.
%% Fails if X >= P or if X is not an X coordinate on secp256k1 (y^2 != x^3 + 7).
-spec lift_x(public_key() | non_neg_integer()) ->
    {ok, {non_neg_integer(), non_neg_integer()}} | error.
lift_x(<<X:256>>) ->
  lift_x(X);
lift_x(X) when is_integer(X), X >= 0, X < ?P ->
  X3 = (X * X rem ?P) * X rem ?P,
  C = (X3 + 7) rem ?P,
  Y = ecu_misc:exp_mod(C, (?P + 1) div 4, ?P),
  case (Y * Y) rem ?P == C of
    false -> error;
    true ->
      EvenY = if Y rem 2 == 0 -> Y; true -> ?P - Y end,
      {ok, {X, EvenY}}
  end;
lift_x(_) ->
  error.

%% @doc sign_keypair/0 generates a random BIP-340 keypair.
-spec sign_keypair() -> keypair().
sign_keypair() ->
  Secret = crypto:strong_rand_bytes(32),
  <<D:256>> = Secret,
  case D > 0 andalso D < ?N of
    true  -> sign_keypair_from_secret(Secret);
    false -> sign_keypair()
  end.

%% @doc sign_keypair_from_secret/1 derives the 32-byte x-only public key from a 32-byte secret key.
%% If d * G has an odd Y coordinate, the secret key is negated modulo N.
-spec sign_keypair_from_secret(secret_key() | <<_:256>>) -> keypair().
sign_keypair_from_secret(<<D0:256>>) when D0 > 0, D0 < ?N ->
  {Px, Py} = ecu_secp256k1:scalar_mul_base(D0),
  Sec = if Py rem 2 == 0 -> <<D0:256>>; true -> <<(?N - D0):256>> end,
  #{public => <<Px:256>>, secret => Sec};
sign_keypair_from_secret(_) ->
  error(badarg).

%% @doc sign/2 signs a message with a 32-byte secret key using fresh random auxiliary bytes.
-spec sign(iodata(), secret_key()) -> signature().
sign(Msg, SecretKey) ->
  AuxRand = crypto:strong_rand_bytes(32),
  sign(Msg, SecretKey, AuxRand).

%% @doc sign/3 signs a message with a 32-byte secret key and 32-byte auxiliary randomness.
-spec sign(iodata(), secret_key(), <<_:256>>) -> signature().
sign(Msg, <<D0:256>>, <<AuxRand:32/binary>>) when D0 > 0, D0 < ?N ->
  {Px, Py} = ecu_secp256k1:scalar_mul_base(D0),
  D = if Py rem 2 == 0 -> D0; true -> ?N - D0 end,
  PxBin = <<Px:256>>,
  AuxHash = crypto:hash(sha256, <<?TAG_AUX_PREFIX/binary, AuxRand/binary>>),
  T = crypto:exor(<<D:256>>, AuxHash),
  MsgBin = iolist_to_binary(Msg),
  RandNonce = crypto:hash(sha256, <<?TAG_NONCE_PREFIX/binary, T/binary, PxBin/binary, MsgBin/binary>>),
  <<K0:256>> = RandNonce,
  K1 = K0 rem ?N,
  case K1 of
    0 -> error(badarg);
    _ ->
      {Rx, Ry} = ecu_secp256k1:scalar_mul_base(K1),
      K = if Ry rem 2 == 0 -> K1; true -> ?N - K1 end,
      RxBin = <<Rx:256>>,
      ChallengeHash = crypto:hash(sha256, <<?TAG_CHALLENGE_PREFIX/binary, RxBin/binary, PxBin/binary, MsgBin/binary>>),
      <<E0:256>> = ChallengeHash,
      E = E0 rem ?N,
      S = (K + E * D) rem ?N,
      <<Rx:256, S:256>>
  end;
sign(_, _, _) ->
  error(badarg).

%% @doc verify/3 verifies a BIP-340 Schnorr signature (r, s) against msg and 32-byte x-only pubkey.
-spec verify(signature() | binary(), iodata(), public_key() | binary()) -> boolean().
verify(<<Rx:256, S:256>>, Msg, <<Px:256>>) ->
  case Px < ?P andalso Rx < ?P andalso S < ?N of
    false -> false;
    true ->
      case lift_x(Px) of
        error -> false;
        {ok, {Px, Py}} ->
          MsgBin = iolist_to_binary(Msg),
          RxBin = <<Rx:256>>,
          PxBin = <<Px:256>>,
          ChallengeHash = crypto:hash(sha256, <<?TAG_CHALLENGE_PREFIX/binary, RxBin/binary, PxBin/binary, MsgBin/binary>>),
          <<E0:256>> = ChallengeHash,
          E = E0 rem ?N,
          NegE = (?N - E) rem ?N,
          R = ecu_secp256k1:scalar_mul_dual(S, {?X, ?Y}, NegE, {Px, Py}),
          case R of
            {0, 0} -> false;
            {RxActual, RyActual} ->
              RyActual rem 2 == 0 andalso RxActual == Rx
          end
      end
  end;
verify(_, _, _) ->
  false.
