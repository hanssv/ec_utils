%%% File        : ecu_eddsa448.erl
%%% Description : Pure Erlang EdDSA over Curve448 (Ed448, RFC 8032)
-module(ecu_eddsa448).

-typing([eqwalizer]).

-include("ecu_ed448.hrl").

-type public_key() :: <<_:456>>.
-type secret_key() :: <<_:456>> | <<_:912>>.
-type keypair() :: #{ public := public_key(), secret := <<_:912>> }.
-type signature() :: <<_:912>>.

-export_type([public_key/0, secret_key/0, keypair/0, signature/0]).

-export([sign_keypair/0,
         sign_seed_keypair/1,
         sign/2, sign/3,
         sign_open/2, sign_open/3,
         sign_detached/2, sign_detached/3,
         sign_verify_detached/3, sign_verify_detached/4,
         sign_verify_batch/1, sign_verify_batch/2]).

%% @doc sign_keypair/0 creates a keypair for signing
%%
%% The keypair is returned as a map with keys 'public' and 'secret'.
%% @end
-spec sign_keypair() -> keypair().
sign_keypair() ->
  Secret = crypto:strong_rand_bytes(57),
  sign_seed_keypair(Secret).

%% @doc sign_seed_keypair/1 computes the signing keypair from a seed.
%%
%% The keypair is returned as a map with keys 'public' and 'secret'.
%% @end
-spec sign_seed_keypair(Secret :: <<_:456>>) -> keypair().
sign_seed_keypair(<<Secret:57/binary>>) ->
  <<Seed:57/binary, _/binary>> = crypto:hash_xof(shake256, Secret, 114 * 8),
  Pub = ecu_ed448:compress(ecu_ed448:scalar_mul_base(Seed)),
  #{public => Pub, secret => <<Secret:57/binary, Pub:57/binary>>}.

%% @doc sign/2 signs a message with private/secret key using empty context.
%% @end
-spec sign(Msg :: iodata(), SK :: secret_key()) -> SM :: binary().
sign(Msg, SK) ->
  sign(Msg, SK, <<>>).

%% @doc sign/3 signs a message with private/secret key and context.
%% @end
-spec sign(Msg :: iodata(), SK :: secret_key(), Context :: binary()) -> SM :: binary().
sign(Msg, SK, Context) when (bit_size(SK) == 456 orelse bit_size(SK) == 912),
                            byte_size(Context) =< 255 ->
  BinMsg = iolist_to_binary(Msg),
  Sig = sign_detached(Msg, SK, Context),
  <<Sig/binary, BinMsg/binary>>.

%% @doc sign_open/2 opens a signed message using empty context.
%% @end
-spec sign_open(SMsg :: binary(), PK :: public_key()) ->
    {ok, Msg :: binary()} | {error, failed_verification}.
sign_open(SMsg, PK) ->
  sign_open(SMsg, PK, <<>>).

%% @doc sign_open/3 opens a signed message using specified context.
%% @end
-spec sign_open(SMsg :: binary(), PK :: public_key(), Context :: binary()) ->
    {ok, Msg :: binary()} | {error, failed_verification}.
sign_open(<<Sig:114/binary, BinMsg/binary>>, <<PK:57/binary>>, Context)
  when byte_size(Context) =< 255 ->
  case sign_verify_detached(Sig, BinMsg, PK, Context) of
    true  -> {ok, BinMsg};
    false -> {error, failed_verification}
  end;
sign_open(_, _, _) ->
  {error, failed_verification}.

%% @doc sign_detached/2 computes the detached signature of a message with private/secret
%% key using empty context.
%% @end
-spec sign_detached(Msg :: iodata(), SK :: secret_key()) -> Sig :: signature().
sign_detached(Msg, SK) ->
  sign_detached(Msg, SK, <<>>).

%% @doc sign_detached/3 computes the detached signature of a message with private/secret
%% key and context string.
%% @end
-spec sign_detached(Msg :: iodata(), SK :: secret_key(), Context :: binary()) -> Sig :: signature().
sign_detached(Msg, SK, Context) when (bit_size(SK) == 456 orelse bit_size(SK) == 912),
                                     byte_size(Context) =< 255 ->
  BinMsg = iolist_to_binary(Msg),
  <<Secret:57/binary, _/binary>> = SK,

  <<Seed0:57/bytes, Prefix:57/bytes>> = crypto:hash_xof(shake256, Secret, 114 * 8),
  Seed = clamp(Seed0),

  DerivedPub = ecu_ed448:compress(ecu_ed448:scalar_mul_base(Seed0)),
  Pub = case SK of
          <<_:57/binary, Pub0:57/binary>> ->
            case Pub0 == DerivedPub of
              true  -> DerivedPub;
              false -> error(badarg)
            end;
          _ ->
            DerivedPub
        end,

  Dom = dom4(0, Context),

  %% Compute r = SHAKE256(dom4(0, Context) || prefix || msg, 114) mod L
  Rs0 = crypto:hash_xof(shake256, <<Dom/binary, Prefix/binary, BinMsg/binary>>, 114 * 8),
  Rs = ecu_ed448:scalar_reduce(Rs0),

  %% Compute R = [r]B
  R = ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(Rs)),

  %% Compute k = SHAKE256(dom4(0, Context) || R || Pub || msg, 114) mod L
  Ks0 = crypto:hash_xof(shake256, <<Dom/binary, R/binary, Pub/binary, BinMsg/binary>>, 114 * 8),
  Ks = ecu_ed448:scalar_reduce(Ks0),

  %% Compute s = (r + k * a) mod L
  Ss = ecu_ed448:s_add(Rs, ecu_ed448:s_mul(Ks, Seed)),

  %% Form the signature {R, s}
  <<R/binary, Ss/binary>>.

%% @doc sign_verify_detached/3 verifies signature against message and public key
%% using empty context.
%% @end
-spec sign_verify_detached(Sig :: signature() | binary(), Msg :: iodata(), PK :: public_key() | binary()) -> boolean().
sign_verify_detached(Sig, Msg, PK) ->
  sign_verify_detached(Sig, Msg, PK, <<>>).

%% @doc sign_verify_detached/4 verifies signature against message, public key, and context.
%% @end
-spec sign_verify_detached(Sig :: signature() | binary(), Msg :: iodata(), PK :: public_key() | binary(), Context :: binary()) -> boolean().
sign_verify_detached(<<Sig:114/bytes>>, Msg, <<PK:57/bytes>>, Context) when byte_size(Context) =< 255 ->
  <<R:57/binary, Ss:57/binary>> = Sig,
  <<S:456/little-unsigned-integer>> = Ss,
  case S < ?N of
    false -> false;
    true ->
      try
        A = ecu_ed448:decompress(PK),
        case ecu_ed448:is_small_order(A) of
          true -> false;
          false ->
            BinMsg = iolist_to_binary(Msg),
            Dom = dom4(0, Context),
            Ks0 = crypto:hash_xof(shake256, <<Dom/binary, R/binary, PK/binary, BinMsg/binary>>, 114 * 8),
            <<K:456/little-unsigned-integer>> = ecu_ed448:scalar_reduce(Ks0),
            NegK = (?N - K) rem ?N,
            R_prime = ecu_ed448:scalar_mul_dual_base(S, NegK, A),
            case ecu_ed448:is_small_order(R_prime) of
              true  -> false;
              false -> ecu_ed448:compress(R_prime) == R
            end
        end
      catch
        error:badarg -> false
      end
  end;
sign_verify_detached(_, _, _, _) ->
  false.

%% @doc sign_verify_batch/1 verifies a batch of detached signatures.
%%
%% Given a list of `{Sig, Msg, PK}' or `{Sig, Msg, PK, Context}' tuples,
%% this function verifies all signatures in a single batch using RFC 8032 batch verification.
%% Returns true iff ALL signatures in the batch are valid; false otherwise.
%% @end
-spec sign_verify_batch(
    [{signature() | binary(), iodata(), public_key() | binary()} |
     {signature() | binary(), iodata(), public_key() | binary(), binary()}]
) -> boolean().
sign_verify_batch([]) ->
  true;
sign_verify_batch([{Sig, Msg, PK}]) ->
  sign_verify_detached(Sig, Msg, PK, <<>>);
sign_verify_batch([{Sig, Msg, PK, Context}]) ->
  sign_verify_detached(Sig, Msg, PK, Context);
sign_verify_batch(Items) when is_list(Items) ->
  sign_verify_batch(Items, <<>>);
sign_verify_batch(_) ->
  false.

%% @doc sign_verify_batch/2 verifies a batch of detached signatures with default context.
%% @end
-spec sign_verify_batch(
    [{signature() | binary(), iodata(), public_key() | binary()} |
     {signature() | binary(), iodata(), public_key() | binary(), binary()}],
    binary()
) -> boolean().
sign_verify_batch([], _DefaultCtx) ->
  true;
sign_verify_batch(Items, DefaultCtx) when is_list(Items), byte_size(DefaultCtx) =< 255 ->
  try
    verify_batch_impl(Items, DefaultCtx)
  catch
    error:_ -> false
  end;
sign_verify_batch(_, _) ->
  false.

-spec verify_batch_impl(
    [{signature() | binary(), iodata(), public_key() | binary()} |
     {signature() | binary(), iodata(), public_key() | binary(), binary()}],
    binary()
) -> boolean().
verify_batch_impl(Items, DefaultCtx) ->
  {Points, S_Batch} = parse_batch(Items, DefaultCtx, [], 0),
  P_others = ecu_ed448:multi_scalar_mul(Points),
  P_base = ecu_ed448:scalar_mul_base_noclamp(S_Batch),
  P_total = ecu_ed448:p_sub(P_others, P_base),
  ecu_ed448:is_small_order(P_total).

-spec parse_batch([{signature() | binary(), iodata(), public_key() | binary()} |
                   {signature() | binary(), iodata(), public_key() | binary(), binary()}],
                  binary(),
                  [{non_neg_integer(), ecu_ed448:pt_projective()}],
                  non_neg_integer()) ->
    {[{non_neg_integer(), ecu_ed448:pt_projective()}], non_neg_integer()}.
parse_batch([], _DefaultCtx, PointsAcc, SAcc) ->
  {PointsAcc, SAcc};
parse_batch([Item | Rest], DefaultCtx, PointsAcc, SAcc) ->
  {Sig, Msg, PK, Context} =
    case Item of
      {ItemSig, ItemMsg, ItemPK}                                        -> {ItemSig, ItemMsg, ItemPK, DefaultCtx};
      {ItemSig, ItemMsg, ItemPK, ItemCtx} when byte_size(ItemCtx) =< 255 -> {ItemSig, ItemMsg, ItemPK, ItemCtx};
      _                                                                 -> error(badarg)
    end,
  case {Sig, PK} of
    {<<R_bin:57/binary, Ss:57/binary>>, <<_:57/binary>>} ->
      <<S:456/little-unsigned-integer>> = Ss,
      case S < ?N of
        false -> error(badarg);
        true ->
          A = ecu_ed448:decompress(PK),
          case ecu_ed448:is_small_order(A) of
            true  -> error(badarg);
            false ->
              R = ecu_ed448:decompress(R_bin),
              case ecu_ed448:is_small_order(R) of
                true  -> error(badarg);
                false ->
                  BinMsg = iolist_to_binary(Msg),
                  Dom = dom4(0, Context),
                  Ks0 = crypto:hash_xof(shake256, <<Dom/binary, R_bin/binary, PK/binary, BinMsg/binary>>, 114 * 8),
                  <<K:456/little-unsigned-integer>> = ecu_ed448:scalar_reduce(Ks0),
                  <<Z0:128/little-unsigned-integer>> = crypto:strong_rand_bytes(16),
                  Z = case Z0 of 0 -> 1; _ -> Z0 end,
                  C = (Z * K) rem ?N,
                  NewSAcc = (SAcc + Z * S) rem ?N,
                  NewPoints = [{Z, R}, {C, A} | PointsAcc],
                  parse_batch(Rest, DefaultCtx, NewPoints, NewSAcc)
              end
          end
      end;
    _ ->
      error(badarg)
  end.

%% Clamp a 57-byte little-endian integer - clear lowest 2 bits of byte 0,
%% set highest bit of byte 55, clear all 8 bits of byte 56.
-spec clamp(<<_:456>>) -> <<_:456>>.
clamp(<<B0:8, Mid:54/binary, B55:8, _B56:8>>) ->
  <<(B0 band 16#fc):8, Mid/binary, (B55 bor 16#80):8, 0:8>>.

-spec dom4(byte(), binary()) -> binary().
dom4(F, C) when is_integer(F), is_binary(C), byte_size(C) =< 255 ->
  <<"SigEd448", F:8, (byte_size(C)):8, C/binary>>.
