%%% File        : ecu_eddsa.erl
%%% Author      : Hans Svensson
%%% Description : eddsa functionality - when possible compatible with enacl.
%%% Created     : 19 Jan 2022 by Hans Svensson
-module(ecu_eddsa).

-include("ecu_ed25519.hrl").

-export([sign_keypair/0,
         sign_seed_keypair/1,
         sign/2,
         sign_open/2,
         sign_detached/2,
         sign_verify_detached/3]).


%% @doc sign_keypair/0 creates a keypair for signing
%%
%% The keypair is returned as a map with keys 'public' and 'secret'.
%% @end
-spec sign_keypair() -> #{ public => binary(), secret => binary() }.
sign_keypair() ->
  Secret = crypto:strong_rand_bytes(32),
  sign_seed_keypair(Secret).

%% @doc sign_seed_keypair/1 computes the signing keypair from a seed.
%%
%% The keypair is returned as a map with keys 'public' and 'secret'.
%% @end
-spec sign_seed_keypair(Secret :: <<_:256>>) -> #{ public => binary(), secret => binary() }.
sign_seed_keypair(<<Secret:32/binary>>) ->
  <<Seed:32/binary, _/binary>> = crypto:hash(sha512, Secret),
  Pub = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base(Seed)),
  #{public => Pub, secret => <<Secret:32/binary, Pub:32/binary>>}.

%% @doc sign/2 signs a message with private/secret key.
%%
%% Given a message `Msg' and a secret key `SK' the function will sign the
%% message and return a signed message `SM'.
%% @end
-spec sign(Msg :: iodata(), SK :: <<_:256>> | <<_:512>>) -> SM :: binary().
sign(Msg, SK) when bit_size(SK) == 256; bit_size(SK) == 512 ->
  BinMsg = iolist_to_binary(Msg),
  Sig = sign_detached(Msg, SK),
  <<Sig/binary, BinMsg/binary>>.

%% @doc sign_open/2 opens a signed message.
%%
%% Given a signed message `SMsg' and a public key `PK', verify that the
%% message has the right signature. Returns either `{ok, Msg}' or
%% `{error, failed_verification}' depending on the correctness of the
%% signature.
%% @end
-spec sign_open(SMsg :: binary(), PK :: <<_:256>>) ->
    {ok, Msg :: binary()} | {error, failed_verification}.
sign_open(<<Sig:64/binary, BinMsg/binary>>, <<PK:32/binary>>) ->
  case sign_verify_detached(Sig, BinMsg, PK) of
    true  -> {ok, BinMsg};
    false -> {error, failed_verification}
  end;
sign_open(_, _) ->
  {error, failed_verification}.

%% @doc sign_detached/2 computes the signature of a message with private/secret
%% key.
%%
%% Given a message `Msg' and a secret key `SK' the function will compute the
%% digital signature `Sig'.
%% @end
-spec sign_detached(Msg :: iodata(), SK :: <<_:256>> | <<_:512>>) -> Sig :: binary().
sign_detached(Msg, SK) when bit_size(SK) == 256; bit_size(SK) == 512 ->
  BinMsg = iolist_to_binary(Msg),
  <<Secret:32/binary, _/binary>> = SK,

  %% Grab the Seed, also referred to as 'a' (clamped) and the Prefix
  <<Seed0:32/bytes, Prefix:32/bytes>> = crypto:hash(sha512, Secret),
  Seed = clamp(Seed0),

  DerivedPub = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base(Seed0)),
  Pub = case SK of
          <<_:32/binary, Pub0:32/binary>> ->
            case Pub0 == DerivedPub of
              true  -> DerivedPub;
              false -> error(badarg)
            end;
          _ ->
            DerivedPub
        end,

  %% Compute r = H(prefix || msg)
  Rs0 = crypto:hash(sha512, <<Prefix/bytes, BinMsg/bytes>>),
  Rs = ecu_ed25519:scalar_reduce(Rs0),

  %% Compute R = s⋅G (and since we want the computation to be invertible use
  %% the 'noclamp' version).
  R = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Rs)),

  %% Compute k = H(R' || Pub || msg)
  Ks0 = crypto:hash(sha512, <<R/bytes, Pub/bytes, BinMsg/bytes>>),
  Ks = ecu_ed25519:scalar_reduce(Ks0),

  %% Compute s = (r + k * a) mod L
  Ss = ecu_ed25519:s_add(Rs, ecu_ed25519:s_mul(Ks, Seed)),

  %% Form the signature {R, s}
  <<R/bytes, Ss/bytes>>.


%% @doc sign_verify_detached/3 verifies the given signature against the given
%% message for the given public key.
%%
%% Given a signature `Sig', a message `Msg', and a public key `PK', the
%% function computes true iff the `Sig' is valid for `Msg' and `PK'; and,
%% false otherwise.
%% @end
-spec sign_verify_detached(Sig :: <<_:512>>, Msg :: iodata(), PK :: <<_:256>>) -> boolean().
sign_verify_detached(<<Sig:64/bytes>>, Msg, <<PK:32/bytes>>) ->
  <<R:32/binary, Ss:32/binary>> = Sig,
  <<S:256/little-unsigned-integer>> = Ss,
  case S < ?N of
    false -> false;
    true ->
      try
        A = ecu_ed25519:decompress(PK),
        case ecu_ed25519:is_small_order(A) of
          true -> false;
          false ->
            BinMsg = iolist_to_binary(Msg),
            Ks0 = crypto:hash(sha512, <<R/binary, PK/binary, BinMsg/binary>>),
            <<K:256/little-unsigned-integer>> = ecu_ed25519:scalar_reduce(Ks0),
            NegK = (?N - K) rem ?N,
            R_prime = ecu_ed25519:scalar_mul_dual_base(S, NegK, A),
            case ecu_ed25519:is_small_order(R_prime) of
              true  -> false;
              false -> ecu_ed25519:compress(R_prime) == R
            end
        end
      catch
        error:badarg -> false
      end
  end;
sign_verify_detached(_, _, _) ->
  false.

%% Clamp a 32-byte little-endian integer - i.e clear the lowest three bits
%% of the first byte and clear the highest and set the second highest of
%% the last byte (i.e. making it divisible by 8 and
clamp(<<B0:8, B1_30:30/binary, B31:8>>) ->
  <<(B0 band 16#f8):8, B1_30/binary, ((B31 band 16#7f) bor 16#40):8>>.
