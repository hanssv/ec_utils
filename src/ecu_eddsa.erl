%%% File        : ecu_eddsa.erl
%%% Author      : Hans Svensson
%%% Description : eddsa functionality - when possible compatible with enacl.
%%% Created     : 19 Jan 2022 by Hans Svensson
-module(ecu_eddsa).

-typing([eqwalizer]).

-include("ecu_ed25519.hrl").

-type public_key() :: <<_:256>>.
-type secret_key() :: <<_:256>> | <<_:512>>.
-type keypair() :: #{ public := public_key(), secret := <<_:512>> }.
-type signature() :: <<_:512>>.

-export_type([public_key/0, secret_key/0, keypair/0, signature/0]).

-export([sign_keypair/0,
         sign_seed_keypair/1,
         sign/2,
         sign_open/2,
         sign_detached/2,
         sign_verify_detached/3,
         sign_verify_batch/1]).

%% @doc sign_keypair/0 creates a keypair for signing
%%
%% The keypair is returned as a map with keys 'public' and 'secret'.
%% @end
-spec sign_keypair() -> keypair().
sign_keypair() ->
  Secret = crypto:strong_rand_bytes(32),
  sign_seed_keypair(Secret).

%% @doc sign_seed_keypair/1 computes the signing keypair from a seed.
%%
%% The keypair is returned as a map with keys 'public' and 'secret'.
%% @end
-spec sign_seed_keypair(Secret :: <<_:256>>) -> keypair().
sign_seed_keypair(<<Secret:32/binary>>) ->
  <<Seed:32/binary, _/binary>> = crypto:hash(sha512, Secret),
  Pub = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base(Seed)),
  #{public => Pub, secret => <<Secret:32/binary, Pub:32/binary>>}.

%% @doc sign/2 signs a message with private/secret key.
%%
%% Given a message `Msg' and a secret key `SK' the function will sign the
%% message and return a signed message `SM'.
%% @end
-spec sign(Msg :: iodata(), SK :: secret_key()) -> SM :: binary().
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
-spec sign_open(SMsg :: binary(), PK :: public_key()) ->
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
-spec sign_detached(Msg :: iodata(), SK :: secret_key()) -> Sig :: signature().
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
-spec sign_verify_detached(Sig :: signature() | binary(), Msg :: iodata(), PK :: public_key() | binary()) -> boolean().
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

%% @doc sign_verify_batch/1 verifies a batch of detached signatures.
%%
%% Given a list of `{Sig, Msg, PK}' tuples, this function verifies all signatures
%% in a single batch using RFC 8032 Section 5.1.7 batch verification.
%% Returns true iff ALL signatures in the batch are valid; false otherwise.
%% @end
-spec sign_verify_batch(
    [{signature() | binary(), iodata(), public_key() | binary()}]
) -> boolean().
sign_verify_batch([]) ->
  true;
sign_verify_batch([{Sig, Msg, PK}]) ->
  sign_verify_detached(Sig, Msg, PK);
sign_verify_batch(Items) when is_list(Items) ->
  try
    verify_batch_impl(Items)
  catch
    error:_ -> false
  end;
sign_verify_batch(_) ->
  false.

-spec verify_batch_impl([{signature() | binary(), iodata(), public_key() | binary()}]) -> boolean().
verify_batch_impl(Items) ->
  {Points, S_Batch} = parse_batch(Items, [], 0),
  P_others = ecu_ed25519:multi_scalar_mul(Points),
  P_base = ecu_ed25519:scalar_mul_base_noclamp(S_Batch),
  P_total = ecu_ed25519:p_sub(P_others, P_base),
  ecu_ed25519:is_small_order(P_total).

-spec parse_batch([{signature() | binary(), iodata(), public_key() | binary()}],
                  [{non_neg_integer(), ecu_ed25519:pt_hom_ext()}],
                  non_neg_integer()) ->
    {[{non_neg_integer(), ecu_ed25519:pt_hom_ext()}], non_neg_integer()}.
parse_batch([], PointsAcc, SAcc) ->
  {PointsAcc, SAcc};
parse_batch([{<<R_bin:32/binary, Ss:32/binary>>, Msg, <<PK:32/binary>>} | Rest], PointsAcc, SAcc) ->
  <<S:256/little-unsigned-integer>> = Ss,
  case S < ?N of
    false -> error(badarg);
    true ->
      A = ecu_ed25519:decompress(PK),
      case ecu_ed25519:is_small_order(A) of
        true  -> error(badarg);
        false ->
          R = ecu_ed25519:decompress(R_bin),
          case ecu_ed25519:is_small_order(R) of
            true  -> error(badarg);
            false ->
              BinMsg = iolist_to_binary(Msg),
              Ks0 = crypto:hash(sha512, <<R_bin/binary, PK/binary, BinMsg/binary>>),
              <<K:256/little-unsigned-integer>> = ecu_ed25519:scalar_reduce(Ks0),
              <<Z0:128/little-unsigned-integer>> = crypto:strong_rand_bytes(16),
              Z = case Z0 of 0 -> 1; _ -> Z0 end,
              C = (Z * K) rem ?N,
              NewSAcc = (SAcc + Z * S) rem ?N,
              NewPoints = [{Z, R}, {C, A} | PointsAcc],
              parse_batch(Rest, NewPoints, NewSAcc)
          end
      end
  end;
parse_batch([_ | _], _PointsAcc, _SAcc) ->
  error(badarg).

%% Clamp a 32-byte little-endian integer - i.e clear the lowest three bits
%% of the first byte and clear the highest and set the second highest of
%% the last byte (i.e. making it divisible by 8 and
-spec clamp(<<_:256>>) -> <<_:256>>.
clamp(<<B0:8, B1_30:30/binary, B31:8>>) ->
  <<(B0 band 16#f8):8, B1_30/binary, ((B31 band 16#7f) bor 16#40):8>>.
