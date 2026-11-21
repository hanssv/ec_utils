%%%-------------------------------------------------------------------
%%% @doc
%%% Optional reference NIF wrapping Rust `babyjubjub-rs` for
%%% BabyJubjub elliptic curve arithmetic and Circom-compatible EdDSA.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_babyjubjub_nif).

-export([
  is_available/0,
  point_add/2,
  point_mul/2,
  decompress_point/1,
  eddsa_prv2pub/1,
  eddsa_sign/2,
  eddsa_verify/3
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_babyjubjub_nif).

init() ->
  PrivDir =
    case code:priv_dir(?APPNAME) of
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

%% @doc Returns true if the optional BabyJubjub reference NIF is compiled and loaded.
-spec is_available() -> boolean().
is_available() ->
  try
    is_available_nif()
  catch
    _:_ -> false
  end.

is_available_nif() ->
  erlang:nif_error(not_loaded).

%% @doc Add two compressed points on BabyJubjub.
-spec point_add(binary(), binary()) -> {ok, binary()} | {error, term()}.
point_add(P1, P2) ->
  try point_add_nif(P1, P2) of
    {ok, P3} when is_binary(P3) -> {ok, P3};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

point_add_nif(_P1, _P2) ->
  erlang:nif_error(not_loaded).

%% @doc Scalar multiplication on BabyJubjub with 32-byte BE scalar.
-spec point_mul(binary(), binary()) -> {ok, binary()} | {error, term()}.
point_mul(P, ScalarBE) ->
  try point_mul_nif(P, ScalarBE) of
    {ok, Res} when is_binary(Res) -> {ok, Res};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

point_mul_nif(_P, _ScalarBE) ->
  erlang:nif_error(not_loaded).

%% @doc Decompress a 32-byte point into {X_be, Y_be}.
-spec decompress_point(binary()) -> {ok, {binary(), binary()}} | {error, term()}.
decompress_point(P) ->
  try decompress_point_nif(P) of
    {ok, {X, Y}} when is_binary(X), is_binary(Y) -> {ok, {X, Y}};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

decompress_point_nif(_P) ->
  erlang:nif_error(not_loaded).

%% @doc Derive compressed public key from 32-byte secret key seed.
-spec eddsa_prv2pub(binary()) -> {ok, binary()} | {error, term()}.
eddsa_prv2pub(SK) ->
  try eddsa_prv2pub_nif(SK) of
    {ok, PK} when is_binary(PK) -> {ok, PK};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

eddsa_prv2pub_nif(_SK) ->
  erlang:nif_error(not_loaded).

%% @doc Sign a message (field element as 32-byte BE) using Circom-compatible Poseidon EdDSA.
-spec eddsa_sign(binary(), binary()) -> {ok, binary()} | {error, term()}.
eddsa_sign(SK, MsgBE) ->
  try eddsa_sign_nif(SK, MsgBE) of
    {ok, Sig} when is_binary(Sig) -> {ok, Sig};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

eddsa_sign_nif(_SK, _MsgBE) ->
  erlang:nif_error(not_loaded).

%% @doc Verify a 64-byte signature against compressed PK and message.
-spec eddsa_verify(binary(), binary(), binary()) -> {ok, boolean()} | {error, term()}.
eddsa_verify(PK, Sig, MsgBE) ->
  try eddsa_verify_nif(PK, Sig, MsgBE) of
    {ok, Valid} when is_boolean(Valid) -> {ok, Valid};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

eddsa_verify_nif(_PK, _Sig, _MsgBE) ->
  erlang:nif_error(not_loaded).
