%%%-------------------------------------------------------------------
%%% @doc
%%% Optional reference NIF wrapping Rust `jubjub` (zkcrypto) for
%%% Jubjub elliptic curve arithmetic on BLS12-381.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_jubjub_nif).

-export([
  is_available/0,
  generator/0,
  point_add/2,
  point_double/1,
  point_mul/2,
  decompress_point/1,
  compress_point/2,
  is_on_curve/1,
  is_in_subgroup/1,
  montgomery_ladder/2
]).
-export([init/0]).

-on_load(init/0).

-define(APPNAME, ec_utils).
-define(LIBNAME, ecu_jubjub_nif).

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

%% @doc Returns true if the optional Jubjub reference NIF is compiled and loaded.
-spec is_available() -> boolean().
is_available() ->
  try
    is_available_nif()
  catch
    _:_ -> false
  end.

is_available_nif() ->
  erlang:nif_error(not_loaded).

%% @doc Return the 32-byte compressed subgroup generator.
-spec generator() -> {ok, binary()} | {error, term()}.
generator() ->
  try generator_nif() of
    Res when is_binary(Res) -> {ok, Res};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

generator_nif() ->
  erlang:nif_error(not_loaded).

%% @doc Add two compressed points on Jubjub.
-spec point_add(binary(), binary()) -> {ok, binary()} | {error, term()}.
point_add(P1, P2) ->
  try point_add_nif(P1, P2) of
    {ok, Res} when is_binary(Res) -> {ok, Res};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

point_add_nif(_P1, _P2) ->
  erlang:nif_error(not_loaded).

%% @doc Double a compressed point on Jubjub.
-spec point_double(binary()) -> {ok, binary()} | {error, term()}.
point_double(P) ->
  try point_double_nif(P) of
    {ok, Res} when is_binary(Res) -> {ok, Res};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

point_double_nif(_P) ->
  erlang:nif_error(not_loaded).

%% @doc Scalar multiplication on Jubjub with 32-byte LE scalar.
-spec point_mul(binary(), binary()) -> {ok, binary()} | {error, term()}.
point_mul(P, ScalarLE) ->
  try point_mul_nif(P, ScalarLE) of
    {ok, Res} when is_binary(Res) -> {ok, Res};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

point_mul_nif(_P, _ScalarLE) ->
  erlang:nif_error(not_loaded).

%% @doc Decompress a 32-byte point into {U_le, V_le}.
-spec decompress_point(binary()) -> {ok, {binary(), binary()}} | {error, term()}.
decompress_point(P) ->
  try decompress_point_nif(P) of
    {ok, {U, V}} when is_binary(U), is_binary(V) -> {ok, {U, V}};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

decompress_point_nif(_P) ->
  erlang:nif_error(not_loaded).

%% @doc Compress {U_le, V_le} into 32-byte compressed point.
-spec compress_point(binary(), binary()) -> {ok, binary()} | {error, term()}.
compress_point(U, V) ->
  try compress_point_nif(U, V) of
    {ok, Res} when is_binary(Res) -> {ok, Res};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

compress_point_nif(_U, _V) ->
  erlang:nif_error(not_loaded).

%% @doc Check if compressed point is on curve.
-spec is_on_curve(binary()) -> boolean().
is_on_curve(P) ->
  try
    is_on_curve_nif(P)
  catch
    _:_ -> false
  end.

is_on_curve_nif(_P) ->
  erlang:nif_error(not_loaded).

%% @doc Check if compressed point is in prime-order subgroup.
-spec is_in_subgroup(binary()) -> boolean().
is_in_subgroup(P) ->
  try
    is_in_subgroup_nif(P)
  catch
    _:_ -> false
  end.

is_in_subgroup_nif(_P) ->
  erlang:nif_error(not_loaded).

%% @doc Evaluate scalar multiplication on Jubjub Montgomery curve using the u-only ladder.
-spec montgomery_ladder(<<_:256>>, <<_:256>>) -> {ok, <<_:256>>} | {error, term()}.
montgomery_ladder(ScalarLE, UCoordLE) ->
  try montgomery_ladder_nif(ScalarLE, UCoordLE) of
    {ok, Res} when is_binary(Res) -> {ok, Res};
    {error, Reason} -> {error, Reason}
  catch
    error:Reason -> {error, Reason}
  end.

montgomery_ladder_nif(_ScalarLE, _UCoordLE) ->
  erlang:nif_error(not_loaded).
