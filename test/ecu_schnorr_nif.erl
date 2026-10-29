%%% File        : ecu_schnorr_nif.erl
%%% Description : Optional reference NIF wrapping Rust k256 for BIP-340 Schnorr
-module(ecu_schnorr_nif).

-export([is_available/0, sign/3, verify/3, public_key/1]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_schnorr_nif).

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

%% @doc Returns true if the optional k256 reference NIF is compiled and loaded.
-spec is_available() -> boolean().
is_available() ->
  try
    is_binary(public_key(<<1:256>>))
  catch
    _:_ -> false
  end.

sign(_Priv, _Msg, _Aux) ->
  erlang:nif_error(not_loaded).

verify(_Sig, _Msg, _Pub) ->
  erlang:nif_error(not_loaded).

public_key(_Priv) ->
  erlang:nif_error(not_loaded).
