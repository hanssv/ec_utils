%%%-------------------------------------------------------------------
%%% @doc
%%% CLI runner and main entry point for the ec_utils benchmarking suite.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bench).

-export([
  main/1
]).

-define(DEFAULT_DURATION_MS, 250).
-define(DEFAULT_THRESHOLD_PCT, 15.0).

-spec main([string()]) -> no_return().
main(Args) ->
  case parse_args(Args, #{}) of
    {ok, help} ->
      print_help(),
      halt(0);
    {ok, Opts} ->
      run(Opts);
    {error, Reason} ->
      io:format(standard_error, "Error: ~s~n~n", [Reason]),
      print_help(),
      halt(1)
  end.

run(Opts) ->
  Filter = maps:get(filter, Opts, all),
  DurationMs = maps:get(duration_ms, Opts, ?DEFAULT_DURATION_MS),
  ThresholdPct = maps:get(threshold_pct, Opts, ?DEFAULT_THRESHOLD_PCT),
  SavePath = maps:get(save_path, Opts, undefined),
  ComparePath = maps:get(compare_path, Opts, undefined),
  Markdown = maps:get(markdown, Opts, false),
  JsonOut = maps:get(json, Opts, false),
  FailOnRegression = maps:get(fail_on_regression, Opts, false),

  Benchmarks = ecu_bench_suites:get_benchmarks(Filter),
  case Benchmarks of
    [] ->
      io:format("No benchmarks matched filter: ~p~n", [Filter]),
      halt(1);
    _ ->
      ok
  end,

  case JsonOut orelse Markdown of
    true ->
      ok;
    false ->
      io:format(
        "==> Running ~p benchmark(s) [duration: ~p ms/bench, filter: ~p]...~n~n",
        [length(Benchmarks), DurationMs, Filter]
      )
  end,

  MinIterations = maps:get(min_iterations, Opts, auto),
  BenchOpts = #{duration_ms => DurationMs, min_iterations => MinIterations},
  Results = ecu_bench_runner:run_all(Benchmarks, BenchOpts),

  %% Print results (when not comparing with markdown)
  case {JsonOut, Markdown, ComparePath} of
    {true, _, _} ->
      ok;
    {false, true, undefined} ->
      io:format("~s~n", [ecu_bench_runner:format_markdown(Results)]);
    {false, false, _} ->
      io:format("~s~n", [ecu_bench_runner:format_table(Results)]);
    _ ->
      ok
  end,

  %% Handle JSON output / saving
  Metadata = collect_metadata(),
  case SavePath of
    undefined ->
      ok;
    FilePath ->
      JsonBin = ecu_bench_runner:to_json(Results, Metadata),
      case file:write_file(FilePath, JsonBin) of
        ok ->
          case JsonOut orelse Markdown of
            true -> ok;
            false -> io:format("==> Saved benchmark baseline to: ~s~n~n", [FilePath])
          end;
        {error, WriteErr} ->
          io:format(standard_error, "Failed to write baseline file: ~p~n", [WriteErr])
      end
  end,

  case JsonOut of
    true ->
      io:format("~s~n", [ecu_bench_runner:to_json(Results, Metadata)]);
    false ->
      ok
  end,

  %% Handle Comparison
  case ComparePath of
    undefined ->
      halt(0);
    BaselineFile ->
      case file:read_file(BaselineFile) of
        {ok, BaselineBin} ->
          case ecu_bench_runner:from_json(BaselineBin) of
            {ok, BaselineResults, _BaseMeta} ->
              Comparison =
                ecu_bench_runner:compare(Results, BaselineResults, ThresholdPct),
              case Markdown of
                true ->
                  io:format("~s~n", [ecu_bench_runner:format_comparison_markdown(Comparison)]);
                false ->
                  io:format("~n==> Regression Comparison against ~s:~n~n", [BaselineFile]),
                  io:format("~s~n", [ecu_bench_runner:format_comparison_table(Comparison)])
              end,
              case {maps:get(has_regression, Comparison), FailOnRegression} of
                {true, true} ->
                  io:format(standard_error, "ERROR: Performance regression detected!~n", []),
                  halt(1);
                _ ->
                  halt(0)
              end;
            {error, ParseErr} ->
              io:format(standard_error, "Failed to parse baseline JSON: ~p~n", [ParseErr]),
              halt(1)
          end;
        {error, ReadErr} ->
          io:format(standard_error, "Failed to read baseline file: ~p~n", [ReadErr]),
          halt(1)
      end
  end.

collect_metadata() ->
  GitCommit = get_git_commit(),
  OtpRelease = list_to_binary(erlang:system_info(otp_release)),
  SystemArch = list_to_binary(erlang:system_info(system_architecture)),
  {{Year, Month, Day}, {Hour, Min, Sec}} = calendar:universal_time(),
  Timestamp =
    iolist_to_binary(
      io_lib:format(
        "~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0BZ",
        [Year, Month, Day, Hour, Min, Sec]
      )
    ),
  #{
    <<"timestamp">> => Timestamp,
    <<"otp_release">> => OtpRelease,
    <<"system_architecture">> => SystemArch,
    <<"git_commit">> => GitCommit
  }.

get_git_commit() ->
  case os:cmd("git rev-parse --short HEAD 2>/dev/null") of
    "" -> <<"unknown">>;
    CommitStr -> list_to_binary(string:trim(CommitStr))
  end.

parse_args([], Acc) ->
  {ok, Acc};
parse_args(["-h" | _], _Acc) ->
  {ok, help};
parse_args(["--help" | _], _Acc) ->
  {ok, help};
parse_args(["-f", Filter | Rest], Acc) ->
  parse_args(Rest, Acc#{filter => Filter});
parse_args(["--filter", Filter | Rest], Acc) ->
  parse_args(Rest, Acc#{filter => Filter});
parse_args(["-d", DurationStr | Rest], Acc) ->
  try list_to_integer(DurationStr) of
    D when D > 0 -> parse_args(Rest, Acc#{duration_ms => D});
    _ -> {error, "Duration must be positive"}
  catch
    _:_ -> {error, "Invalid duration integer: " ++ DurationStr}
  end;
parse_args(["--duration", DurationStr | Rest], Acc) ->
  parse_args(["-d", DurationStr | Rest], Acc);
parse_args(["--min-iterations", MinStr | Rest], Acc) ->
  try list_to_integer(MinStr) of
    M when M > 0 -> parse_args(Rest, Acc#{min_iterations => M});
    _ -> {error, "Min iterations must be positive"}
  catch
    _:_ -> {error, "Invalid min-iterations integer: " ++ MinStr}
  end;
parse_args(["-s", Path | Rest], Acc) ->
  parse_args(Rest, Acc#{save_path => Path});
parse_args(["--save", Path | Rest], Acc) ->
  parse_args(Rest, Acc#{save_path => Path});
parse_args(["-c", Path | Rest], Acc) ->
  parse_args(Rest, Acc#{compare_path => Path});
parse_args(["--compare", Path | Rest], Acc) ->
  parse_args(Rest, Acc#{compare_path => Path});
parse_args(["-t", ThreshStr | Rest], Acc) ->
  try list_to_float(ThreshStr) of
    T when T >= 0.0 -> parse_args(Rest, Acc#{threshold_pct => T})
  catch
    _:_ ->
      try list_to_integer(ThreshStr) of
        I when I >= 0 -> parse_args(Rest, Acc#{threshold_pct => float(I)})
      catch
        _:_ -> {error, "Invalid threshold percentage: " ++ ThreshStr}
      end
  end;
parse_args(["--threshold", ThreshStr | Rest], Acc) ->
  parse_args(["-t", ThreshStr | Rest], Acc);
parse_args(["-m" | Rest], Acc) ->
  parse_args(Rest, Acc#{markdown => true});
parse_args(["--markdown" | Rest], Acc) ->
  parse_args(Rest, Acc#{markdown => true});
parse_args(["--json" | Rest], Acc) ->
  parse_args(Rest, Acc#{json => true});
parse_args(["--fail-on-regression" | Rest], Acc) ->
  parse_args(Rest, Acc#{fail_on_regression => true});
parse_args([Unknown | Rest], Acc) ->
  case maps:find(filter, Acc) of
    error ->
      %% Allow positional filter argument e.g. ./bin/bench ed25519
      parse_args(Rest, Acc#{filter => Unknown});
    {ok, _} ->
      {error, "Unknown argument: " ++ Unknown}
  end.

print_help() ->
  io:format(
    "Usage: ./bin/bench [OPTIONS] [FILTER]~n~n"
    "Options:~n"
    "  -f, --filter <PATTERN>     Filter benchmarks by group or name substring (default: all)~n"
    "  -d, --duration <MS>        Target benchmark duration in milliseconds (default: 250)~n"
    "  -s, --save <FILE>          Save benchmark results as JSON baseline to FILE~n"
    "  -c, --compare <FILE>       Compare results against baseline JSON in FILE~n"
    "  -t, --threshold <PCT>      Regression percentage threshold (default: 15.0%)~n"
    "  -m, --markdown             Output results as GitHub-flavored Markdown table~n"
    "      --json                 Output raw JSON results to stdout~n"
    "      --fail-on-regression   Exit code 1 if regressions exceed threshold~n"
    "  -h, --help                 Display this help message~n~n"
    "Available benchmark groups:~n"
    "  all, ed25519, secp256k1, ed448, ecdh, ml_kem, ml_dsa,~n"
    "  frost, musig2, h2c, keccak, hd~n"
  ).
