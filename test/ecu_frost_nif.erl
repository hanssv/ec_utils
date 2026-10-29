%%% File        : ecu_frost_nif.erl
%%% Description : Optional reference NIF wrapping Zcash frost-core crates (RFC 9591)
-module(ecu_frost_nif).

-export([is_available/0,
         is_loaded/0,
         verify/4,
         bench_round/3,
         sign_sample/4]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_frost_nif).

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

%% @doc Returns true if the optional FROST reference NIF is compiled and loaded.
-spec is_available() -> boolean().
is_available() ->
  try
    is_loaded()
  catch
    _:_ -> false
  end.

is_loaded() ->
  erlang:nif_error(not_loaded).

%% @doc Verify a threshold or aggregated signature using the official RFC 9591 implementation.
-spec verify(Suite :: atom() | binary() | string(),
             Sig :: binary(),
             Msg :: binary(),
             Pub :: binary()) -> boolean().
verify(Suite, Sig, Msg, Pub) ->
  verify_nif(to_binary(Suite), Sig, Msg, Pub).

verify_nif(_Suite, _Sig, _Msg, _Pub) ->
  erlang:nif_error(not_loaded).

%% @doc Run benchmark iterations of commit, part sign, aggregate, and verify in Rust.
-spec bench_round(Suite :: atom() | binary() | string(),
                  T :: pos_integer(),
                  N :: pos_integer()) ->
  {float(), float(), float(), float()}.
bench_round(Suite, T, N) ->
  bench_round_nif(to_binary(Suite), T, N).

bench_round_nif(_Suite, _T, _N) ->
  erlang:nif_error(not_loaded).

%% @doc Generate a sample threshold signature using Rust dealer and signers.
-spec sign_sample(Suite :: atom() | binary() | string(),
                  T :: pos_integer(),
                  N :: pos_integer(),
                  Msg :: binary()) ->
  {Sig :: binary(), PubKey :: binary()}.
sign_sample(Suite, T, N, Msg) ->
  sign_sample_nif(to_binary(Suite), T, N, Msg).

sign_sample_nif(_Suite, _T, _N, _Msg) ->
  erlang:nif_error(not_loaded).

to_binary(A) when is_atom(A) -> atom_to_binary(A, utf8);
to_binary(B) when is_binary(B) -> B;
to_binary(L) when is_list(L) -> list_to_binary(L).
