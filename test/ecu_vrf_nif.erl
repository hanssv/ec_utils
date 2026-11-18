%%%-------------------------------------------------------------------
%%% @doc
%%% Optional reference NIF wrapping Rust RFC 9381 VRF implementations
%%% (`vrf-rfc9381` and `vrf_fun`).
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_vrf_nif).

-export([
  is_available/0,
  prove/3,
  verify/4,
  proof_to_hash/2
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_vrf_nif).

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

%% @doc Returns true if the optional VRF reference NIF is compiled and loaded.
-spec is_available() -> boolean().
is_available() ->
  try
    is_available_nif()
  catch
    _:_ -> false
  end.

is_available_nif() ->
  erlang:nif_error(not_loaded).

%% @doc Prove VRF using reference Rust NIF.
-spec prove(atom() | binary() | string(), binary(), binary()) ->
  {ok, binary()} | {error, term()}.
prove(Suite, SK, Alpha) ->
  try prove_nif(to_binary(Suite), SK, Alpha) of
    {ok, Pi} when is_binary(Pi) -> {ok, Pi};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

prove_nif(_Suite, _SK, _Alpha) ->
  erlang:nif_error(not_loaded).

%% @doc Verify VRF proof using reference Rust NIF, returning output hash Beta.
-spec verify(atom() | binary() | string(), binary(), binary(), binary()) ->
  {ok, binary()} | {error, term()}.
verify(Suite, PK, Pi, Alpha) ->
  try verify_nif(to_binary(Suite), PK, Pi, Alpha) of
    {ok, Beta} when is_binary(Beta) -> {ok, Beta};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

verify_nif(_Suite, _PK, _Pi, _Alpha) ->
  erlang:nif_error(not_loaded).

%% @doc Extract hash Beta from proof Pi using reference Rust NIF.
-spec proof_to_hash(atom() | binary() | string(), binary()) ->
  {ok, binary()} | {error, term()}.
proof_to_hash(Suite, Pi) ->
  try proof_to_hash_nif(to_binary(Suite), Pi) of
    {ok, Beta} when is_binary(Beta) -> {ok, Beta};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

proof_to_hash_nif(_Suite, _Pi) ->
  erlang:nif_error(not_loaded).

to_binary(A) when is_atom(A) -> atom_to_binary(A, utf8);
to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L) -> list_to_binary(L).
