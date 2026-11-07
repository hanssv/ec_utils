%%%-------------------------------------------------------------------
%%% @doc
%%% Optional reference NIF wrapping Supranational blst (BLS12-381).
%%% Used exclusively for differential testing and cross-verification.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bls12_381_nif).

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
  min_pk_keygen/1,
  min_pk_sign/3,
  min_pk_verify/4,
  min_pk_aggregate/1,
  min_pk_fast_aggregate_verify/4,
  min_sig_keygen/1,
  min_sig_sign/3,
  min_sig_verify/4
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_bls12_381_nif).

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

g1_generator() ->
  erlang:nif_error(not_loaded).

g1_mult(_P, _Scalar) ->
  erlang:nif_error(not_loaded).

g1_add(_P1, _P2) ->
  erlang:nif_error(not_loaded).

g2_generator() ->
  erlang:nif_error(not_loaded).

g2_mult(_P, _Scalar) ->
  erlang:nif_error(not_loaded).

g2_add(_P1, _P2) ->
  erlang:nif_error(not_loaded).

pairing(_P1, _P2) ->
  erlang:nif_error(not_loaded).

pairing_check(_Pairs) ->
  erlang:nif_error(not_loaded).

min_pk_keygen(_IKM) ->
  erlang:nif_error(not_loaded).

min_pk_sign(_SK, _Msg, _DST) ->
  erlang:nif_error(not_loaded).

min_pk_verify(_PK, _Msg, _Sig, _DST) ->
  erlang:nif_error(not_loaded).

min_pk_aggregate(_Sigs) ->
  erlang:nif_error(not_loaded).

min_pk_fast_aggregate_verify(_PKs, _Msg, _Sig, _DST) ->
  erlang:nif_error(not_loaded).

min_sig_keygen(_IKM) ->
  erlang:nif_error(not_loaded).

min_sig_sign(_SK, _Msg, _DST) ->
  erlang:nif_error(not_loaded).

min_sig_verify(_PK, _Msg, _Sig, _DST) ->
  erlang:nif_error(not_loaded).
