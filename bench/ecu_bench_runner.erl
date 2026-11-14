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
  combine_results/1,
  mann_whitney_u/2,
  format_table/1,
  format_markdown/1,
  to_json/2,
  from_json/1,
  compare/3,
  format_comparison_table/1,
  format_comparison_markdown/1,
  hodges_lehmann/1
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
  hl_us => float(),
  p95_us := float(),
  p99_us := float(),
  min_us := non_neg_integer(),
  max_us := non_neg_integer(),
  samples => [float()]
}.

-type current_item() ::
  bench_result()
  | #{
    id := binary(),
    name := binary(),
    group := binary(),
    mean_us => float(),
    hl_us => float(),
    median_us => float(),
    ops_per_sec := float(),
    samples => [float()]
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
  p_value => float() | undefined,
  status := faster | similar | regression | unstable
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
  prewarm_benchmarks(BenchDefs),
  lists:filtermap(
    fun(Def) ->
      case run_bench_in_process(Def, Opts) of
        skip -> false;
        Result -> {true, Result}
      end
    end,
    BenchDefs
  ).

run_bench_in_process(Def, Opts) ->
  Parent = self(),
  Ref = make_ref(),
  {_Pid, MonRef} =
    spawn_monitor(fun() ->
      Result = run_bench(Def, Opts),
      Parent ! {Ref, Result}
    end),
  receive
    {Ref, Result} ->
      demonitor(MonRef, [flush]),
      Result;
    {'DOWN', MonRef, process, _, {undef, _}} ->
      skip;
    {'DOWN', MonRef, process, _, Reason} ->
      exit(Reason)
  end.

-spec prewarm_benchmarks([bench_def()]) -> ok.
prewarm_benchmarks(BenchDefs) ->
  %% Run a single pass over all benchmarks in an isolated process to load every
  %% module into the BEAM code server, trigger JIT compilation of all native code
  %% paths, and warm OS/CPU caches without polluting the runner heap.
  Parent = self(),
  Ref = make_ref(),
  {_Pid, MonRef} =
    spawn_monitor(fun() ->
      lists:foreach(
        fun(#{run := RunSpec}) ->
          case RunSpec of
            {F, S} when is_function(F, 1) ->
              try
                F(S)
              catch
                _:_ -> ok
              end;
            F when is_function(F, 0) ->
              try
                F()
              catch
                _:_ -> ok
              end
          end
        end,
        BenchDefs
      ),
      Parent ! {Ref, ok}
    end),
  receive
    {Ref, ok} ->
      demonitor(MonRef, [flush]),
      ok;
    {'DOWN', MonRef, process, _, Reason} ->
      exit(Reason)
  end.

-spec run_bench(bench_def(), map()) -> bench_result().
run_bench(#{id := Id, name := Name, group := Group, run := RunSpec}, Opts) ->
  {Fun, State} =
    case RunSpec of
      {F, S} when is_function(F, 1) -> {F, S};
      F when is_function(F, 0) -> {fun(_) -> F() end, ok}
    end,

  %% Step 1: Mandatory first execution (code loading, JIT trace compilation, initial allocator warm)
  %% We time this single execution to determine operation scale with zero throwaway runs.
  T_warm0 = erlang:monotonic_time(microsecond),
  Fun(State),
  T_warm1 = erlang:monotonic_time(microsecond),
  FirstOpUs = max(1, T_warm1 - T_warm0),

  %% Determine scale and batch size:
  {SingleOpUs, BatchSize} =
    if
      FirstOpUs >= 100000 ->
        %% Slowest (> 100 ms, e.g. SLH-DSA sign): 1 iteration already executes millions
        %% of opcodes and cycles GC. 0 additional warmup needed.
        {FirstOpUs, 1};
      FirstOpUs >= 20000 ->
        %% Heavy ops (20 - 100 ms, e.g. ML-DSA-87 sign): 2 additional warmups (~40-80 ms)
        run_batches(2, 1, Fun, State),
        {FirstOpUs, 1};
      FirstOpUs >= 200 ->
        %% Medium ops (0.2 - 20 ms, e.g. ML-DSA 44/65, FROST, secp256k1):
        %% Warmup budget ~40 ms to ensure BEAM allocator carriers are fully saturated.
        run_batches(max(5, min(20, 40000 div FirstOpUs)), 1, Fun, State),
        {FirstOpUs, 1};
      true ->
        %% Sub-millisecond ops (< 200 us): batch to >= 500 us to eliminate timer quantization
        BS =
          if
            FirstOpUs < 2 -> 500;
            FirstOpUs < 10 -> 100;
            FirstOpUs < 50 -> 20;
            true -> 5
          end,
        %% Run warm batches to saturate carrier allocators (capped at 25 ms total)
        WarmBatches = max(20, min(50, 25000 div max(1, FirstOpUs * BS))),
        T_batch0 = erlang:monotonic_time(microsecond),
        run_batches(WarmBatches, BS, Fun, State),
        T_batch1 = erlang:monotonic_time(microsecond),
        AvgBatchUs = max(1, (T_batch1 - T_batch0) div WarmBatches),
        {max(1, AvgBatchUs div BS), BS}
    end,

  %% Dynamically determine target duration and minimum iteration floor:
  {TargetDurationUs, MinOps} =
    case maps:get(duration_ms, Opts, auto) of
      auto ->
        if
          %% > 100 ms (e.g. SLH-DSA sign ~340 ms): 2 iterations per round (~680 ms)
          SingleOpUs >= 100000 -> {SingleOpUs * 2, 2};
          %% 20-100 ms (e.g. ML-DSA 87 sign ~70 ms): 6 iterations per round (~420 ms)
          SingleOpUs >= 20000 -> {max(200000, SingleOpUs * 6), 6};
          %% 5-20 ms (e.g. ML-DSA 44/65, BLS): 15 iterations per round (~150-250 ms)
          SingleOpUs >= 5000 -> {max(200000, SingleOpUs * 15), 15};
          %% 0.2-5 ms (e.g. FROST, secp256k1, Ed25519, ML-KEM): 200 ms sample window
          SingleOpUs >= 200 -> {200000, 50};
          %% < 200 us: 200 ms sample window with batching
          true -> {200000, 50 * BatchSize}
        end;
      FixedMs when is_integer(FixedMs), FixedMs > 0 ->
        {FixedMs * 1000, maps:get(min_iterations, Opts, 1)}
    end,

  %% Step 2: Timed execution collecting batch timings
  %% Pre-size heap to prevent allocator carrier reallocations and GC cycles during timing loop
  OldMinHeap = erlang:process_flag(min_heap_size, 100000),
  erlang:garbage_collect(),
  StartTime = erlang:monotonic_time(microsecond),
  {TotalOps, BatchTimings} =
    collect_samples(StartTime, TargetDurationUs, BatchSize, Fun, State, 0, [], MinOps),
  EndTime = erlang:monotonic_time(microsecond),
  erlang:process_flag(min_heap_size, OldMinHeap),
  TotalTimeUs = max(1, EndTime - StartTime),

  %% Step 3: Statistical reduction
  OpTimings = [TimeUs / BatchSize || TimeUs <- BatchTimings],
  Sorted = lists:sort(OpTimings),
  N = length(Sorted),
  MinUs = round(hd(Sorted)),
  MaxUs = round(lists:last(Sorted)),
  MedianUs = median(Sorted, N),
  HLUs = hodges_lehmann(Sorted, N),
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
    hl_us => HLUs,
    p95_us => P95Us,
    p99_us => P99Us,
    min_us => MinUs,
    max_us => MaxUs,
    samples => OpTimings
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

median([]) ->
  0.0;
median(Sorted) ->
  median(Sorted, length(Sorted)).

median(Sorted, N) when N rem 2 =:= 0, N > 0 ->
  Mid1 = lists:nth(N div 2, Sorted),
  Mid2 = lists:nth((N div 2) + 1, Sorted),
  (Mid1 + Mid2) / 2.0;
median(Sorted, N) when N > 0 ->
  lists:nth((N div 2) + 1, Sorted);
median([], _) ->
  0.0.

-spec hodges_lehmann([float()]) -> float().
hodges_lehmann([]) ->
  0.0;
hodges_lehmann([X]) ->
  X;
hodges_lehmann(Sorted) ->
  hodges_lehmann(Sorted, length(Sorted)).

-spec hodges_lehmann([float()], non_neg_integer()) -> float().
hodges_lehmann([], _N) ->
  0.0;
hodges_lehmann([X], _N) ->
  X;
hodges_lehmann(Sorted, N) ->
  Samples =
    if
      N > 150 -> subsample(Sorted, N, 100);
      true -> Sorted
    end,
  Pairwise = pairwise_means(Samples),
  SortedPairs = lists:sort(Pairwise),
  median(SortedPairs).

subsample(Sorted, N, TargetN) when N =< TargetN ->
  Sorted;
subsample(Sorted, N, TargetN) ->
  Step = (N - 1) / (TargetN - 1),
  Arr = list_to_tuple(Sorted),
  [element(round(1 + I * Step), Arr) || I <- lists:seq(0, TargetN - 1)].

pairwise_means([]) ->
  [];
pairwise_means([X | Rest]) ->
  [(X + Y) / 2.0 || Y <- [X | Rest]] ++ pairwise_means(Rest).

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

-spec combine_results([[map()]]) -> [map()].
combine_results([]) ->
  [];
combine_results([Single]) ->
  Single;
combine_results([First | _] = AllRuns) ->
  IdOrder = [maps:get(id, R, maps:get(<<"id">>, R, <<"">>)) || R <- First],
  Grouped = lists:foldl(
    fun(Run, AccMap) ->
      lists:foldl(
        fun(Item, InnerAcc) ->
          Id = maps:get(id, Item, maps:get(<<"id">>, Item, <<"">>)),
          maps:update_with(Id, fun(Items) -> [Item | Items] end, [Item], InnerAcc)
        end,
        AccMap,
        Run
      )
    end,
    #{},
    AllRuns
  ),
  lists:filtermap(
    fun(Id) ->
      case maps:find(Id, Grouped) of
        {ok, Items} ->
          {true, merge_bench_items(lists:reverse(Items))};
        error ->
          false
      end
    end,
    IdOrder
  ).

merge_bench_items([First | _] = Items) ->
  Id = maps:get(id, First, maps:get(<<"id">>, First, <<"">>)),
  Name = maps:get(name, First, maps:get(<<"name">>, First, <<"">>)),
  Group = maps:get(group, First, maps:get(<<"group">>, First, <<"">>)),
  TotalOps = lists:sum([
    to_integer(maps:get(iterations, It, maps:get(<<"iterations">>, It, 1)))
   || It <- Items
  ]),
  TotalTimeUs = lists:sum([
    to_integer(maps:get(total_time_us, It, maps:get(<<"total_time_us">>, It, 1)))
   || It <- Items
  ]),
  CombinedSamples = lists:append([
    get_samples(It)
   || It <- Items
  ]),
  MeanUs = TotalTimeUs / max(1, TotalOps),
  OpsPerSec = (TotalOps * 1000000.0) / max(1, TotalTimeUs),
  RoundMeds = lists:sort([
    to_float(maps:get(median_us, It, maps:get(<<"median_us">>, It, MeanUs)))
   || It <- Items
  ]),
  MedianUs = median(RoundMeds),
  RoundHLs = lists:sort([get_estimator(It) || It <- Items]),
  HLUs = median(RoundHLs),
  case CombinedSamples of
    [] ->
      #{
        id => Id,
        name => Name,
        group => Group,
        iterations => TotalOps,
        total_time_us => TotalTimeUs,
        ops_per_sec => OpsPerSec,
        mean_us => MeanUs,
        median_us => MedianUs,
        hl_us => HLUs,
        p95_us => MedianUs,
        p99_us => MedianUs,
        min_us => round(MedianUs),
        max_us => round(MedianUs),
        samples => []
      };
    _ ->
      Sorted = lists:sort(CombinedSamples),
      N = length(Sorted),
      #{
        id => Id,
        name => Name,
        group => Group,
        iterations => TotalOps,
        total_time_us => TotalTimeUs,
        ops_per_sec => OpsPerSec,
        mean_us => MeanUs,
        median_us => MedianUs,
        hl_us => HLUs,
        p95_us => percentile(95.0, Sorted, N),
        p99_us => percentile(99.0, Sorted, N),
        min_us => round(hd(Sorted)),
        max_us => round(lists:last(Sorted)),
        samples => Sorted
      }
  end.

to_integer(V) when is_integer(V) -> V;
to_integer(V) when is_float(V) -> round(V).

-spec mann_whitney_u([float()], [float()]) -> float().
mann_whitney_u(A, B) when length(A) < 5 orelse length(B) < 5 ->
  1.0;
mann_whitney_u(A, B) ->
  N1 = length(A),
  N2 = length(B),
  N = N1 + N2,
  Tagged = [{X, a} || X <- A] ++ [{Y, b} || Y <- B],
  Sorted = lists:sort(fun({V1, _}, {V2, _}) -> V1 =< V2 end, Tagged),
  {Ranked, TieSum} = assign_ranks(Sorted, 1, [], 0),
  R1 = lists:sum([R || {a, R} <- Ranked]),
  U1 = N1 * N2 + (N1 * (N1 + 1)) / 2.0 - R1,
  U2 = N1 * N2 - U1,
  U = min(U1, U2),
  Mu = (N1 * N2) / 2.0,
  Denominator = N * (N - 1),
  TieCorrection =
    case Denominator > 0 of
      true -> TieSum / Denominator;
      false -> 0.0
    end,
  Variance = (N1 * N2 / 12.0) * ((N + 1) - TieCorrection),
  case Variance > 0.0 of
    true ->
      Sigma = math:sqrt(Variance),
      Diff = abs(U - Mu),
      Z = max(0.0, Diff - 0.5) / Sigma,
      math:erfc(Z / math:sqrt(2.0));
    false ->
      1.0
  end.

assign_ranks([], _CurRank, Acc, TieSum) ->
  {lists:reverse(Acc), TieSum};
assign_ranks([{Val, _} | _] = List, CurRank, Acc, TieSum) ->
  {Ties, Rest} = lists:splitwith(fun({V, _}) -> V == Val end, List),
  Cnt = length(Ties),
  Avg = CurRank + (Cnt - 1) / 2.0,
  NewAcc = [{Tag, Avg} || {_, Tag} <- Ties] ++ Acc,
  NewTieSum = TieSum + (Cnt * Cnt * Cnt - Cnt),
  assign_ranks(Rest, CurRank + Cnt, NewAcc, NewTieSum).

get_samples(Map) ->
  case maps:find(<<"samples">>, Map) of
    {ok, S} when is_list(S) -> [to_float(X) || X <- S];
    _ ->
      case maps:find(samples, Map) of
        {ok, S} when is_list(S) -> [to_float(X) || X <- S];
        _ -> []
      end
  end.

-spec compare([[current_item()]] | [current_item()], [[map()]] | [map()], float()) ->
  comparison_summary().
compare([], _, ThresholdPct) ->
  #{items => [], has_regression => false, threshold_pct => ThresholdPct};
compare([FirstCur | _] = Current, [FirstBase | _] = Baseline, ThresholdPct) when
  is_list(FirstCur), is_list(FirstBase)
->
  compare_paired_runs(Current, Baseline, ThresholdPct);
compare([FirstCur | _] = Current, Baseline, ThresholdPct) when is_list(FirstCur) ->
  compare_paired_runs(Current, [Baseline], ThresholdPct);
compare(Current, [FirstBase | _] = Baseline, ThresholdPct) when is_list(FirstBase) ->
  compare_paired_runs([Current], Baseline, ThresholdPct);
compare(Current, Baseline, ThresholdPct) ->
  compare_paired_runs([Current], [Baseline], ThresholdPct).

-spec compare_paired_runs([[current_item()]], [[map()]], float()) -> comparison_summary().
compare_paired_runs(CurRuns, BaseRuns, ThresholdPct) ->
  NumPairs = min(length(CurRuns), length(BaseRuns)),
  CurPairs = lists:sublist(CurRuns, NumPairs),
  BasePairs = lists:sublist(BaseRuns, NumPairs),
  IndexedBase = [
    maps:from_list([
      {to_binary(maps:get(id, B, maps:get(<<"id">>, B, <<"">>))), B}
     || B <- R
    ])
   || R <- BasePairs
  ],
  IndexedCur = [
    maps:from_list([
      {to_binary(maps:get(id, C, maps:get(<<"id">>, C, <<"">>))), C}
     || C <- R
    ])
   || R <- CurPairs
  ],
  [FirstRun | _] = CurPairs,
  Items = lists:filtermap(
    fun(Item0) ->
      Id = to_binary(maps:get(id, Item0, maps:get(<<"id">>, Item0, <<"">>))),
      Name = to_binary(maps:get(name, Item0, maps:get(<<"name">>, Item0, Id))),
      Group = to_binary(maps:get(group, Item0, maps:get(<<"group">>, Item0, <<"">>))),
      Pairs = [
        {maps:find(Id, lists:nth(K, IndexedBase)), maps:find(Id, lists:nth(K, IndexedCur))}
       || K <- lists:seq(1, NumPairs)
      ],
      ValidPairs = [{B, C} || {{ok, B}, {ok, C}} <- Pairs],
      case ValidPairs of
        [] ->
          false;
        _ ->
          Deltas = [
            begin
              B_est = get_estimator(B),
              C_est = get_estimator(C),
              case B_est > 0.0 of
                true -> ((C_est - B_est) / B_est) * 100.0;
                false -> 0.0
              end
            end
           || {B, C} <- ValidPairs
          ],
          SortedDeltas = lists:sort(Deltas),
          DeltaPct = median(SortedDeltas),
          BaseEsts = lists:sort([get_estimator(B) || {B, _} <- ValidPairs]),
          BaseEst = median(BaseEsts),
          CurEsts = lists:sort([get_estimator(C) || {_, C} <- ValidPairs]),
          CurEst = median(CurEsts),
          BaseOpsList = lists:sort([
            to_float(maps:get(ops_per_sec, B, maps:get(<<"ops_per_sec">>, B, 0.0)))
           || {B, _} <- ValidPairs
          ]),
          BaseOps = median(BaseOpsList),
          CurOpsList = lists:sort([
            to_float(maps:get(ops_per_sec, C, maps:get(<<"ops_per_sec">>, C, 0.0)))
           || {_, C} <- ValidPairs
          ]),
          CurOps = median(CurOpsList),
          BaseSamples = lists:append([get_samples(B) || {B, _} <- ValidPairs]),
          CurSamples = lists:append([get_samples(C) || {_, C} <- ValidPairs]),
          PVal =
            case length(BaseSamples) >= 5 andalso length(CurSamples) >= 5 of
              true -> mann_whitney_u(BaseSamples, CurSamples);
              false -> undefined
            end,
          IsSignificant =
            case PVal of
              undefined -> true;
              P -> P < 0.001
            end,
          Status =
            if
              IsSignificant andalso DeltaPct < -ThresholdPct -> faster;
              IsSignificant andalso DeltaPct > ThresholdPct -> regression;
              abs(DeltaPct) > ThresholdPct -> unstable;
              true -> similar
            end,
          {true, #{
            id => Id,
            name => Name,
            group => Group,
            baseline_mean_us => BaseEst,
            current_mean_us => CurEst,
            baseline_ops_per_sec => BaseOps,
            current_ops_per_sec => CurOps,
            delta_pct => DeltaPct,
            p_value => PVal,
            status => Status
          }}
      end
    end,
    FirstRun
  ),
  HasRegression = lists:any(fun(#{status := S}) -> S =:= regression end, Items),
  #{
    items => Items,
    has_regression => HasRegression,
    threshold_pct => ThresholdPct
  }.

to_float(V) when is_float(V) -> V;
to_float(V) when is_integer(V) -> float(V).

get_estimator(Map) ->
  case maps:find(<<"hl_us">>, Map) of
    {ok, HL} ->
      to_float(HL);
    error ->
      case maps:find(hl_us, Map) of
        {ok, HL} ->
          to_float(HL);
        error ->
          case maps:find(<<"median_us">>, Map) of
            {ok, Med} ->
              to_float(Med);
            error ->
              case maps:find(median_us, Map) of
                {ok, Med} ->
                  to_float(Med);
                error ->
                  to_float(maps:get(<<"mean_us">>, Map, maps:get(mean_us, Map, 0.0)))
              end
          end
      end
  end.

-spec format_comparison_table(comparison_summary()) -> iolist().
format_comparison_table(#{items := Items, threshold_pct := Threshold}) ->
  Header =
    io_lib:format(
      "~-32s ~12s ~12s ~12s ~10s ~14s~n",
      ["Benchmark", "Baseline(us)", "Current(us)", "Delta (%)", "p-val", "Status"]
    ),
  Sep = lists:duplicate(98, $-) ++ "\n",
  Rows = [
    begin
      StatusStr =
        case Status of
          faster -> "[FASTER]";
          similar -> "[SAME]";
          regression -> "[REGRESSION!]";
          unstable -> "[UNSTABLE]"
        end,
      DeltaStr =
        case Delta >= 0.0 of
          true -> io_lib:format("+~.1f%", [Delta]);
          false -> io_lib:format("~.1f%", [Delta])
        end,
      PValStr =
        case PVal of
          undefined -> "-";
          P when P < 0.001 -> "<0.001";
          P -> io_lib:format("~.3f", [P])
        end,
      io_lib:format(
        "~-32s ~12.2f ~12.2f ~12s ~10s ~14s~n",
        [Name, BaseMean, CurMean, DeltaStr, PValStr, StatusStr]
      )
    end
   || #{
      name := Name,
      baseline_mean_us := BaseMean,
      current_mean_us := CurMean,
      delta_pct := Delta,
      p_value := PVal,
      status := Status
    } <- Items
  ],
  HasRegression = lists:any(fun(#{status := S}) -> S =:= regression end, Items),
  HasUnstable = lists:any(fun(#{status := S}) -> S =:= unstable end, Items),
  SummaryNote =
    if
      HasRegression ->
        io_lib:format("~nALERT: Regressions detected exceeding threshold (~.1f%)!~n", [Threshold]);
      HasUnstable ->
        io_lib:format(
          "~nALERT: Unstable benchmarks detected exceeding threshold (~.1f%)!~n",
          [Threshold]
        );
      true ->
        io_lib:format("~nAll benchmarks within acceptable threshold (~.1f%).~n", [Threshold])
    end,
  [Header, Sep, Rows, SummaryNote].

-spec format_comparison_markdown(comparison_summary()) -> iolist().
format_comparison_markdown(#{items := Items, threshold_pct := Threshold}) ->
  Header = "| Benchmark | Group | Baseline (µs) | PR (µs) | Delta | p-value | Status |\n",
  Sep = "|:---|:---|---:|---:|---:|---:|:---|\n",
  Rows = [
    begin
      StatusBadge =
        case Status of
          faster -> "**Faster**";
          similar -> "Same";
          regression -> "**REGRESSION**";
          unstable -> "**UNSTABLE**"
        end,
      DeltaStr =
        case Delta >= 0.0 of
          true -> io_lib:format("+~.1f%", [Delta]);
          false -> io_lib:format("~.1f%", [Delta])
        end,
      PValStr =
        case PVal of
          undefined -> "-";
          P when P < 0.001 -> "< 0.001";
          P -> io_lib:format("~.3f", [P])
        end,
      io_lib:format(
        "| ~s | ~s | ~s | ~s | ~s | ~s | ~s |\n",
        [
          Name,
          Group,
          format_num(BaseMean, 2),
          format_num(CurMean, 2),
          DeltaStr,
          PValStr,
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
      p_value := PVal,
      status := Status
    } <- Items
  ],
  Note =
    "\n*Statistical significance evaluated via two-tailed Mann-Whitney U test (threshold p < 0.001).*\n",
  HasRegression = lists:any(fun(#{status := S}) -> S =:= regression end, Items),
  HasUnstable = lists:any(fun(#{status := S}) -> S =:= unstable end, Items),
  SummaryNote =
    if
      HasRegression ->
        io_lib:format(
          "~n> [!WARNING]~n> Performance regression detected exceeding threshold (~.1f%)!~n",
          [Threshold]
        );
      HasUnstable ->
        io_lib:format(
          "~n> [!WARNING]~n> Unstable benchmarks detected exceeding threshold (~.1f%)!~n",
          [Threshold]
        );
      true ->
        io_lib:format(
          "~n> [!NOTE]~n> All benchmarks within acceptable threshold (~.1f%).~n",
          [Threshold]
        )
    end,
  [Header, Sep, Rows, Note, SummaryNote].
