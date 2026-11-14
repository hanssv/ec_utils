%%%-------------------------------------------------------------------
%%% @doc
%%% Reference NIF wrapping Rust Poseidon implementations:
%%% - BN254 via light-poseidon (Circomlib compatible)
%%% - BLS12-381 via Hades permutation (Aeternity / FATE compatible)
%%% Used exclusively for differential testing, cross-verification, and benchmarks.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_poseidon_nif).

-export([
  is_available/0,
  is_loaded/0,
  hash/2,
  hash3/3
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_poseidon_nif).

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
  is_available().

is_available() ->
  false.

-spec hash(bls12_381 | bn254, [binary()]) -> {ok, binary()} | {error, term()}.
hash(_Curve, _Inputs) ->
  erlang:nif_error(not_loaded).

-spec hash3(bls12_381 | bn254, binary(), binary()) -> {ok, binary()} | {error, term()}.
hash3(_Curve, _A, _B) ->
  erlang:nif_error(not_loaded).
