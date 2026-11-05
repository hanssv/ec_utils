%%%-------------------------------------------------------------------
%%% @doc
%%% Optional reference NIF wrapping pqcrypto-falcon (NIST Falcon / FIPS 206).
%%% Used exclusively for differential testing and cross-verification.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_fn_dsa_nif).

-export([
  is_available/0,
  is_loaded/0,
  falcon512_keypair/0,
  falcon512_sign/2,
  falcon512_verify/3,
  falcon1024_keypair/0,
  falcon1024_sign/2,
  falcon1024_verify/3
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_fn_dsa_nif).

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

is_loaded() ->
  erlang:system_info(nif_version) =/= undefined andalso
    is_available_nif().

is_available() ->
  is_available_nif().

is_available_nif() ->
  false.

falcon512_keypair() ->
  erlang:nif_error(not_loaded).

falcon512_sign(_SK, _Msg) ->
  erlang:nif_error(not_loaded).

falcon512_verify(_PK, _Msg, _Sig) ->
  erlang:nif_error(not_loaded).

falcon1024_keypair() ->
  erlang:nif_error(not_loaded).

falcon1024_sign(_SK, _Msg) ->
  erlang:nif_error(not_loaded).

falcon1024_verify(_PK, _Msg, _Sig) ->
  erlang:nif_error(not_loaded).
