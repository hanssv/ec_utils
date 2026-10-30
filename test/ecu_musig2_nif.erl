%%% File        : ecu_musig2_nif.erl
%%% Description : Optional reference NIF wrapping the official Rust `musig2` crate (BIP-327)
-module(ecu_musig2_nif).

-export([is_available/0,
         is_loaded/0,
         key_agg/1,
         nonce_gen/1,
         nonce_gen/2,
         nonce_agg/1,
         sign/5,
         verify/6,
         aggregate/4]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_musig2_nif).

init() ->
  PrivDir = case code:priv_dir(?APPNAME) of
              {error, bad_name} ->
                case code:which(?MODULE) of
                  Filename when is_list(Filename) ->
                    filename:join([filename:dirname(Filename), "..", "priv"]);
                  _ ->
                    "priv"
                end;
              Dir ->
                Dir
            end,
  SoPath = filename:join(PrivDir, ?LIBNAME),
  case filelib:is_file(SoPath ++ ".so") orelse filelib:is_file(SoPath ++ ".dylib") of
    true ->
      case erlang:load_nif(SoPath, 0) of
        ok -> ok;
        _Err -> ok
      end;
    false ->
      ok
  end.

%% @doc Returns true if the optional BIP-327 MuSig2 reference NIF is compiled and loaded.
-spec is_available() -> boolean().
is_available() ->
  try
    is_loaded()
  catch
    _:_ -> false
  end.

is_loaded() ->
  erlang:nif_error(not_loaded).

%% @doc Aggregate public keys (32-byte x-only or 33-byte compressed) into an aggregated public key and context.
-spec key_agg([binary()]) -> {ok, {binary(), binary()}} | {error, term()}.
key_agg(Pubkeys) ->
  try key_agg_nif(Pubkeys) of
    {AggPk, Ctx} -> {ok, {AggPk, Ctx}}
  catch
    error:badarg -> {error, badarg};
    error:undef -> {error, nif_not_loaded}
  end.

%% @doc Generate a secret nonce and public nonce from a 32-byte secret key and optional message.
-spec nonce_gen(binary()) -> {ok, {binary(), binary()}} | {error, term()}.
nonce_gen(SecKey) ->
  nonce_gen(SecKey, <<>>).

-spec nonce_gen(binary(), binary()) -> {ok, {binary(), binary()}} | {error, term()}.
nonce_gen(SecKey, Msg) ->
  try nonce_gen_nif(SecKey, Msg) of
    {SecNonce, PubNonce} -> {ok, {SecNonce, PubNonce}}
  catch
    error:badarg -> {error, badarg};
    error:undef -> {error, nif_not_loaded}
  end.

%% @doc Aggregate a list of public nonces into an aggregate nonce.
-spec nonce_agg([binary()]) -> {ok, binary()} | {error, term()}.
nonce_agg(PubNonces) ->
  try nonce_agg_nif(PubNonces) of
    AggNonce -> {ok, AggNonce}
  catch
    error:badarg -> {error, badarg};
    error:undef -> {error, nif_not_loaded}
  end.

%% @doc Generate a partial signature.
-spec sign(Ctx :: binary(),
           SecKey :: binary(),
           SecNonce :: binary(),
           AggNonce :: binary(),
           Msg :: binary()) -> {ok, binary()} | {error, term()}.
sign(Ctx, SecKey, SecNonce, AggNonce, Msg) ->
  try sign_nif(Ctx, SecKey, SecNonce, AggNonce, Msg) of
    PartialSig -> {ok, PartialSig}
  catch
    error:badarg -> {error, badarg};
    error:undef -> {error, nif_not_loaded}
  end.

%% @doc Verify a partial signature.
-spec verify(Ctx :: binary(),
             PartialSig :: binary(),
             PubNonce :: binary(),
             SignerPk :: binary(),
             AggNonce :: binary(),
             Msg :: binary()) -> boolean().
verify(Ctx, PartialSig, PubNonce, SignerPk, AggNonce, Msg) ->
  try
    verify_nif(Ctx, PartialSig, PubNonce, SignerPk, AggNonce, Msg)
  catch
    _:_ -> false
  end.

%% @doc Aggregate partial signatures into a final 64-byte BIP-340 Schnorr signature.
-spec aggregate(Ctx :: binary(),
                AggNonce :: binary(),
                Msg :: binary(),
                PartialSigs :: [binary()]) -> {ok, binary()} | {error, term()}.
aggregate(Ctx, AggNonce, Msg, PartialSigs) ->
  try aggregate_nif(Ctx, AggNonce, Msg, PartialSigs) of
    Sig -> {ok, Sig}
  catch
    error:badarg -> {error, badarg};
    error:undef -> {error, nif_not_loaded}
  end.

%% --- NIF stubs ---

key_agg_nif(_Pubkeys) ->
  erlang:nif_error(not_loaded).

nonce_gen_nif(_SecKey, _Msg) ->
  erlang:nif_error(not_loaded).

nonce_agg_nif(_PubNonces) ->
  erlang:nif_error(not_loaded).

sign_nif(_Ctx, _SecKey, _SecNonce, _AggNonce, _Msg) ->
  erlang:nif_error(not_loaded).

verify_nif(_Ctx, _PartialSig, _PubNonce, _SignerPk, _AggNonce, _Msg) ->
  erlang:nif_error(not_loaded).

aggregate_nif(_Ctx, _AggNonce, _Msg, _PartialSigs) ->
  erlang:nif_error(not_loaded).
