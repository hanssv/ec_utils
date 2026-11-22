%%%-------------------------------------------------------------------
%%% @doc
%%% Optional reference NIF wrapping Rust `r1cs-file` and `wtns-file`
%%% for Circom R1CS and WTNS parsing, roundtripping, and constraint checking.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_circom_nif).

-export([
  is_available/0,
  r1cs_info/1,
  wtns_info/1,
  r1cs_roundtrip/1,
  wtns_roundtrip/1,
  check_constraints/2
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_circom_nif).

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

%% @doc Returns true if the optional Circom reference NIF is compiled and loaded.
-spec is_available() -> boolean().
is_available() ->
  try
    is_available_nif()
  catch
    _:_ -> false
  end.

is_available_nif() ->
  erlang:nif_error(not_loaded).

-spec r1cs_info(binary()) -> {ok, map()} | {error, binary() | string()}.
r1cs_info(_Bin) ->
  erlang:nif_error(not_loaded).

-spec wtns_info(binary()) -> {ok, map()} | {error, binary() | string()}.
wtns_info(_Bin) ->
  erlang:nif_error(not_loaded).

-spec r1cs_roundtrip(binary()) -> {ok, binary()} | {error, binary() | string()}.
r1cs_roundtrip(_Bin) ->
  erlang:nif_error(not_loaded).

-spec wtns_roundtrip(binary()) -> {ok, binary()} | {error, binary() | string()}.
wtns_roundtrip(_Bin) ->
  erlang:nif_error(not_loaded).

-spec check_constraints(binary(), binary()) -> {ok, boolean()} | {error, binary() | string()}.
check_constraints(_R1csBin, _WtnsBin) ->
  erlang:nif_error(not_loaded).
