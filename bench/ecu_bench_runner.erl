%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang benchmark execution engine, statistical analyzer,
%%% and regression comparison tool.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bench_runner).

-export([
  run_all/2,
  run_bench/2,
  format_table/1,
  format_markdown/1,
  to_json/2,
  from_json/1,
  compare/3,
  format_comparison_table/1,
  format_comparison_markdown/1
]).

-export_type([
  bench_def/0,
  bench_result/0,
  comparison_item/0,
  comparison_summary/0
]).

-type bench_def() :: #{
  id := atom() | binary(),
  name := binary(),
  group := atom() | binary(),
  run := fun(() -> any()) | {fun((any()) -> any()), any()}
}.

-type bench_result() :: #{
  id := binary(),
  name := binary(),
  group := binary(),
  iterations := pos_integer(),
  total_time_us := pos_integer(),
  ops_per_sec := float(),
  mean_us := float(),
  median_us := float(),
  p95_us := float(),
  p99_us := float(),
  min_us := non_neg_integer(),
  max_us := non_neg_integer()
}.

-type current_item() ::
  bench_result()
  | #{
    id := binary(),
    name := binary(),
    group := binary(),
    mean_us := float(),
    ops_per_sec := float()
  }.

-type comparison_item() :: #{
  id := binary(),
  name := binary(),
  group := binary(),
  baseline_mean_us := float(),
  current_mean_us := float(),
  baseline_ops_per_sec := float(),
  current_ops_per_sec := float(),
  delta_pct := float(),
  status := faster | similar | slower | regression
}.

-type comparison_summary() :: #{
  items := [comparison_item()],
  has_regression := boolean(),
  threshold_pct := float()
}.

%% ===================================================================
%% Benchmark Execution
%% ===================================================================

-spec run_all([bench_def()], map()) -> [bench_result()].
run_all(BenchDefs, Opts) ->
  lists:map(fun(Def) -> run_bench(Def, Opts) end, BenchDefs).

-spec run_bench(bench_def(), map()) -> bench_result().
run_bench(#{id := Id, name := Name, group := Group, run := RunSpec}, Opts) ->
  DurationMs = maps:get(duration_ms, Opts, 250),
  TargetDurationUs = DurationMs * 1000,
  {Fun, State} =
    case RunSpec of
      {F, S} when is_function(F, 1) -> {F, S};
      F when is_function(F, 0) -> {fun(_) -> F() end, ok}
    end,

  %% Step 1: Calibration & Warmup
  CalibT0 = erlang:monotonic_time(microsecond),
  Fun(State),
  CalibT1 = erlang:monotonic_time(microsecond),
  SingleOpUs = max(1, CalibT1 - CalibT0),

  BatchSize =
    if
      SingleOpUs < 2 -> 500;
      SingleOpUs < 10 -> 100;
      SingleOpUs < 50 -> 20;
      SingleOpUs < 200 -> 5;
      true -> 1
    end,

  %% Minimum iterations floor to guarantee statistical stability for slow ops
  MinOps =
    case maps:get(min_iterations, Opts, auto) of
      auto ->
        if
          SingleOpUs > 20000 -> 15;
          SingleOpUs > 5000 -> 25;
          SingleOpUs > 1000 -> 50;
          true -> 100
        end;
      CustomMin when is_integer(CustomMin), CustomMin > 0 ->
        CustomMin
    end,

  %% Quick warmup (at least 3 batches or 10ms worth)
  WarmupBatches = max(3, min(20, 10000 div max(1, SingleOpUs * BatchSize))),
  run_batches(WarmupBatches, BatchSize, Fun, State),

  %% Step 2: Timed execution collecting batch timings
  StartTime = erlang:monotonic_time(microsecond),
  {TotalOps, BatchTimings} =
    collect_samples(StartTime, TargetDurationUs, BatchSize, Fun, State, 0, [], MinOps),
  EndTime = erlang:monotonic_time(microsecond),
  TotalTimeUs = max(1, EndTime - StartTime),

  %% Step 3: Statistical reduction
  OpTimings = [TimeUs / BatchSize || TimeUs <- BatchTimings],
  Sorted = lists:sort(OpTimings),
  N = length(Sorted),
  MinUs = round(hd(Sorted)),
  MaxUs = round(lists:last(Sorted)),
  MedianUs = percentile(50.0, Sorted, N),
  P95Us = percentile(95.0, Sorted, N),
  P99Us = percentile(99.0, Sorted, N),
  MeanUs = TotalTimeUs / TotalOps,
  OpsPerSec = (TotalOps * 1000000.0) / TotalTimeUs,

  #{
    id => to_binary(Id),
    name => to_binary(Name),
    group => to_binary(Group),
    iterations => TotalOps,
    total_time_us => TotalTimeUs,
    ops_per_sec => OpsPerSec,
    mean_us => MeanUs,
    median_us => MedianUs,
    p95_us => P95Us,
    p99_us => P99Us,
    min_us => MinUs,
    max_us => MaxUs
  }.

collect_samples(StartTime, TargetUs, BatchSize, Fun, State, AccOps, AccTimes, MinOps) ->
  T0 = erlang:monotonic_time(microsecond),
  run_batch(BatchSize, Fun, State),
  T1 = erlang:monotonic_time(microsecond),
  ElapsedBatch = max(1, T1 - T0),
  NewAccOps = AccOps + BatchSize,
  NewAccTimes = [ElapsedBatch | AccTimes],
  TotalElapsed = T1 - StartTime,
  if
    TotalElapsed >= TargetUs andalso NewAccOps >= MinOps ->
      {NewAccOps, lists:reverse(NewAccTimes)};
    true ->
      collect_samples(
        StartTime,
        TargetUs,
        BatchSize,
        Fun,
        State,
        NewAccOps,
        NewAccTimes,
        MinOps
      )
  end.

run_batches(0, _BatchSize, _Fun, _State) ->
  ok;
run_batches(N, BatchSize, Fun, State) ->
  run_batch(BatchSize, Fun, State),
  run_batches(N - 1, BatchSize, Fun, State).

run_batch(0, _Fun, _State) ->
  ok;
run_batch(N, Fun, State) ->
  Fun(State),
  run_batch(N - 1, Fun, State).

percentile(Pct, Sorted, N) ->
  Idx = max(1, min(N, round((Pct / 100.0) * N))),
  lists:nth(Idx, Sorted).

to_binary(B) when is_binary(B) -> B;
to_binary(A) when is_atom(A) -> atom_to_binary(A, utf8);
to_binary(L) when is_list(L) -> list_to_binary(L).

%% ===================================================================
%% Formatting & Tables
%% ===================================================================

-spec format_table([bench_result()]) -> iolist().
format_table(Results) ->
  Header =
    io_lib:format(
      "~-32s ~-12s ~14s ~12s ~12s ~12s~n",
      ["Benchmark", "Group", "Ops/sec", "Mean (us)", "Median (us)", "p95 (us)"]
    ),
  Sep = lists:duplicate(100, $-) ++ "\n",
  Rows = [
    io_lib:format(
      "~-32s ~-12s ~14.1f ~12.2f ~12.2f ~12.2f~n",
      [
        maps:get(name, R),
        maps:get(group, R),
        maps:get(ops_per_sec, R),
        maps:get(mean_us, R),
        maps:get(median_us, R),
        maps:get(p95_us, R)
      ]
    )
   || R <- Results
  ],
  [Header, Sep, Rows].

-spec format_markdown([bench_result()]) -> iolist().
format_markdown(Results) ->
  Header = "| Benchmark | Group | Ops/sec | Mean (µs) | Median (µs) | p95 (µs) |\n",
  Sep = "|:---|:---|---:|---:|---:|---:|\n",
  Rows = [
    io_lib:format(
      "| ~s | ~s | ~s | ~s | ~s | ~s |\n",
      [
        maps:get(name, R),
        maps:get(group, R),
        format_num(maps:get(ops_per_sec, R), 1),
        format_num(maps:get(mean_us, R), 2),
        format_num(maps:get(median_us, R), 2),
        format_num(maps:get(p95_us, R), 2)
      ]
    )
   || R <- Results
  ],
  [Header, Sep, Rows].

format_num(V, Decimals) ->
  io_lib:format("~.*f", [Decimals, V]).

%% ===================================================================
%% JSON Serialization
%% ===================================================================

-spec to_json([bench_result()], map()) -> binary().
to_json(Results, Metadata) ->
  Payload = #{
    <<"metadata">> => Metadata,
    <<"results">> => Results
  },
  iolist_to_binary(json:encode(Payload)).

-spec from_json(binary()) -> {ok, [map()], map()} | {error, any()}.
from_json(Bin) when is_binary(Bin) ->
  try
    Decoded = json:decode(Bin),
    Metadata = maps:get(<<"metadata">>, Decoded, #{}),
    Results = maps:get(<<"results">>, Decoded, []),
    {ok, Results, Metadata}
  catch
    C:E ->
      {error, {C, E}}
  end.

%% ===================================================================
%% Comparison & Regression Detection
%% ===================================================================

-spec compare([current_item()], [map()], float()) -> comparison_summary().
compare(CurrentResults, BaselineResults, ThresholdPct) ->
  BaselineMap = maps:from_list([
    {maps:get(<<"id">>, B, maps:get(id, B, <<"">>)), B}
   || B <- BaselineResults
  ]),

  Items = lists:filtermap(
    fun(Cur) ->
      CurId = maps:get(id, Cur),
      case maps:find(CurId, BaselineMap) of
        {ok, Base} ->
          BaseMean = to_float(maps:get(<<"mean_us">>, Base, maps:get(mean_us, Base, 0.0))),
          CurMean = to_float(maps:get(mean_us, Cur, 0.0)),
          BaseOps = to_float(
            maps:get(<<"ops_per_sec">>, Base, maps:get(ops_per_sec, Base, 0.0))
          ),
          CurOps = to_float(maps:get(ops_per_sec, Cur, 0.0)),

          DeltaPct =
            case BaseMean > 0.0 of
              true -> ((CurMean - BaseMean) / BaseMean) * 100.0;
              false -> 0.0
            end,

          Status =
            if
              DeltaPct < -5.0 -> faster;
              DeltaPct > ThresholdPct -> regression;
              DeltaPct > 5.0 -> slower;
              true -> similar
            end,

          {true, #{
            id => CurId,
            name => maps:get(name, Cur),
            group => maps:get(group, Cur),
            baseline_mean_us => BaseMean,
            current_mean_us => CurMean,
            baseline_ops_per_sec => BaseOps,
            current_ops_per_sec => CurOps,
            delta_pct => DeltaPct,
            status => Status
          }};
        error ->
          false
      end
    end,
    CurrentResults
  ),

  HasRegression = lists:any(fun(#{status := S}) -> S =:= regression end, Items),
  #{
    items => Items,
    has_regression => HasRegression,
    threshold_pct => ThresholdPct
  }.

to_float(V) when is_float(V) -> V;
to_float(V) when is_integer(V) -> float(V).

-spec format_comparison_table(comparison_summary()) -> iolist().
format_comparison_table(#{items := Items, threshold_pct := Threshold}) ->
  Header =
    io_lib:format(
      "~-32s ~12s ~12s ~12s ~14s~n",
      ["Benchmark", "Baseline(us)", "Current(us)", "Delta (%)", "Status"]
    ),
  Sep = lists:duplicate(86, $-) ++ "\n",
  Rows = [
    begin
      StatusStr =
        case Status of
          faster -> "[FASTER]";
          similar -> "[SAME]";
          slower -> "[SLOWER]";
          regression -> "[REGRESSION!]"
        end,
      DeltaStr =
        case Delta >= 0.0 of
          true -> io_lib:format("+~.1f%", [Delta]);
          false -> io_lib:format("~.1f%", [Delta])
        end,
      io_lib:format(
        "~-32s ~12.2f ~12.2f ~12s ~14s~n",
        [Name, BaseMean, CurMean, DeltaStr, StatusStr]
      )
    end
   || #{
      name := Name,
      baseline_mean_us := BaseMean,
      current_mean_us := CurMean,
      delta_pct := Delta,
      status := Status
    } <- Items
  ],
  SummaryNote =
    case lists:any(fun(#{status := S}) -> S =:= regression end, Items) of
      true ->
        io_lib:format("~nALERT: Regressions detected exceeding threshold (~.1f%)!~n", [Threshold]);
      false ->
        io_lib:format("~nAll benchmarks within acceptable threshold (~.1f%).~n", [Threshold])
    end,
  [Header, Sep, Rows, SummaryNote].

-spec format_comparison_markdown(comparison_summary()) -> iolist().
format_comparison_markdown(#{items := Items, threshold_pct := Threshold}) ->
  Header = "| Benchmark | Group | Baseline (µs) | PR (µs) | Delta | Status |\n",
  Sep = "|:---|:---|---:|---:|---:|:---|\n",
  Rows = [
    begin
      StatusBadge =
        case Status of
          faster -> "**Faster**";
          similar -> "Same";
          slower -> "Slower";
          regression -> "**REGRESSION**"
        end,
      DeltaStr =
        case Delta >= 0.0 of
          true -> io_lib:format("+~.1f%", [Delta]);
          false -> io_lib:format("~.1f%", [Delta])
        end,
      io_lib:format(
        "| ~s | ~s | ~s | ~s | ~s | ~s |\n",
        [
          Name,
          Group,
          format_num(BaseMean, 2),
          format_num(CurMean, 2),
          DeltaStr,
          StatusBadge
        ]
      )
    end
   || #{
      name := Name,
      group := Group,
      baseline_mean_us := BaseMean,
      current_mean_us := CurMean,
      delta_pct := Delta,
      status := Status
    } <- Items
  ],
  SummaryNote =
    case lists:any(fun(#{status := S}) -> S =:= regression end, Items) of
      true ->
        io_lib:format(
          "~n> [!WARNING]~n> Performance regression detected exceeding threshold (~.1f%)!~n",
          [Threshold]
        );
      false ->
        io_lib:format(
          "~n> [!NOTE]~n> All benchmarks within acceptable threshold (~.1f%).~n",
          [Threshold]
        )
    end,
  [Header, Sep, Rows, SummaryNote].
