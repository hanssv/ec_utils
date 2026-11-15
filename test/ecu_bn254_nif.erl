%%%-------------------------------------------------------------------
%%% @doc
%%% Optional reference NIF wrapping Arkworks ark-bn254.
%%% Used exclusively for differential testing and cross-verification.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bn254_nif).

-export([
  is_available/0,
  is_loaded/0,
  g1_generator/0,
  g1_mult/2,
  g1_add/2,
  g2_generator/0,
  g2_mult/2,
  g2_add/2,
  pairing/2,
  pairing_check/1,
  groth16_verify/9
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_bn254_nif).

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
  erlang:system_info(nif_version) =/= undefined andalso is_available().

-spec g1_generator() -> binary().
g1_generator() ->
  erlang:nif_error(nif_not_loaded).

-spec g1_mult(binary(), binary()) -> {ok, binary()} | {error, binary()}.
g1_mult(_Point, _Scalar) ->
  erlang:nif_error(nif_not_loaded).

-spec g1_add(binary(), binary()) -> {ok, binary()} | {error, binary()}.
g1_add(_P1, _P2) ->
  erlang:nif_error(nif_not_loaded).

-spec g2_generator() -> binary().
g2_generator() ->
  erlang:nif_error(nif_not_loaded).

-spec g2_mult(binary(), binary()) -> {ok, binary()} | {error, binary()}.
g2_mult(_Point, _Scalar) ->
  erlang:nif_error(nif_not_loaded).

-spec g2_add(binary(), binary()) -> {ok, binary()} | {error, binary()}.
g2_add(_P1, _P2) ->
  erlang:nif_error(nif_not_loaded).

-spec pairing(binary(), binary()) -> {ok, boolean()} | {error, binary()}.
pairing(_P1, _P2) ->
  erlang:nif_error(nif_not_loaded).

-spec pairing_check([{binary(), binary()}]) -> boolean().
pairing_check(_Pairs) ->
  erlang:nif_error(nif_not_loaded).

-spec groth16_verify(
  binary(), binary(), binary(), binary(), [binary()], [binary()], binary(), binary(), binary()
) -> boolean().
groth16_verify(_Alpha, _Beta, _Gamma, _Delta, _IC, _Inputs, _A, _B, _C) ->
  erlang:nif_error(nif_not_loaded).
