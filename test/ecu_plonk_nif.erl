%%%-------------------------------------------------------------------
%%% @doc
%%% Reference NIF wrapping Arkworks PLONK verifier for differential testing.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_plonk_nif).

-export([
  is_available/0,
  is_loaded/0,
  verify_bn254/29
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_plonk_nif).

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
        ok ->
          ok;
        {error, {reload, _}} ->
          ok;
        {error, Reason} ->
          error_logger:warning_msg("Failed to load NIF ~s: ~p~n", [SoPath, Reason]),
          ok
      end;
    false ->
      ok
  end.

-spec is_available() -> boolean().
is_available() ->
  false.

-spec is_loaded() -> boolean().
is_loaded() ->
  case erlang:system_info(nif_version) of
    undefined -> false;
    _ -> is_available()
  end.

-spec verify_bn254(
  non_neg_integer(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  [binary()],
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary(),
  binary()
) -> boolean().
verify_bn254(
  _Power,
  _K1,
  _K2,
  _W,
  _Qm,
  _Ql,
  _Qr,
  _Qo,
  _Qc,
  _S1,
  _S2,
  _S3,
  _X2,
  _PubInputs,
  _A,
  _B,
  _C,
  _Z,
  _T1,
  _T2,
  _T3,
  _EvalA,
  _EvalB,
  _EvalC,
  _EvalS1,
  _EvalS2,
  _EvalZw,
  _Wxi,
  _Wxiw
) ->
  erlang:nif_error(nif_not_loaded).
