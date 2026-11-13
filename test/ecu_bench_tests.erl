%%%-------------------------------------------------------------------
%%% @doc
%%% Unit tests for ecu_bench_runner and ecu_bench_suites.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bench_tests).

-include_lib("eunit/include/eunit.hrl").

bench_runner_execution_test() ->
  BenchDef = #{
    id => test_bench,
    name => <<"Test Benchmark">>,
    group => test_group,
    run => fun() -> lists:seq(1, 100) end
  },
  Opts = #{duration_ms => 30},
  Result = ecu_bench_runner:run_bench(BenchDef, Opts),
  ?assertEqual(<<"test_bench">>, maps:get(id, Result)),
  ?assertEqual(<<"Test Benchmark">>, maps:get(name, Result)),
  ?assertEqual(<<"test_group">>, maps:get(group, Result)),
  ?assert(maps:get(iterations, Result) >= 5),
  ?assert(maps:get(mean_us, Result) > 0.0),
  ?assert(maps:get(ops_per_sec, Result) > 0.0),
  ?assert(maps:get(median_us, Result) > 0.0),
  ?assert(maps:get(hl_us, Result) > 0.0),
  ?assert(maps:get(p95_us, Result) >= maps:get(median_us, Result)).

hodges_lehmann_test() ->
  ?assertEqual(0.0, ecu_bench_runner:hodges_lehmann([])),
  ?assertEqual(42.0, ecu_bench_runner:hodges_lehmann([42.0])),
  ?assertEqual(20.0, ecu_bench_runner:hodges_lehmann([10.0, 20.0, 30.0])),
  %% Outlier test: single massive spike does not corrupt Hodges-Lehmann estimate
  Clean = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0],
  WithSpike = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 5000.0],
  ?assertEqual(10.0, ecu_bench_runner:hodges_lehmann(Clean)),
  ?assertEqual(10.0, ecu_bench_runner:hodges_lehmann(WithSpike)).

bench_formatting_test() ->
  Result = #{
    id => <<"bench_1">>,
    name => <<"Sample Bench">>,
    group => <<"sample">>,
    iterations => 100,
    total_time_us => 10000,
    ops_per_sec => 10000.0,
    mean_us => 100.0,
    median_us => 98.0,
    p95_us => 110.0,
    p99_us => 115.0,
    min_us => 90,
    max_us => 120
  },
  TableBin = iolist_to_binary(ecu_bench_runner:format_table([Result])),
  ?assert(binary:match(TableBin, <<"Sample Bench">>) =/= nomatch),
  ?assert(binary:match(TableBin, <<"Ops/sec">>) =/= nomatch),

  MdBin = iolist_to_binary(ecu_bench_runner:format_markdown([Result])),
  ?assert(binary:match(MdBin, <<"| Sample Bench |">>) =/= nomatch),
  ?assert(binary:match(MdBin, <<"| 10000.0 |">>) =/= nomatch).

bench_json_roundtrip_test() ->
  Result = #{
    id => <<"bench_1">>,
    name => <<"Sample Bench">>,
    group => <<"sample">>,
    iterations => 100,
    total_time_us => 10000,
    ops_per_sec => 10000.0,
    mean_us => 100.0,
    median_us => 98.0,
    p95_us => 110.0,
    p99_us => 115.0,
    min_us => 90,
    max_us => 120
  },
  Meta = #{<<"commit">> => <<"abcdef">>},
  JsonBin = ecu_bench_runner:to_json([Result], Meta),
  ?assert(is_binary(JsonBin)),
  {ok, DecodedResults, DecodedMeta} = ecu_bench_runner:from_json(JsonBin),
  ?assertEqual(1, length(DecodedResults)),
  ?assertEqual(Meta, DecodedMeta),
  Decoded = hd(DecodedResults),
  ?assertEqual(<<"bench_1">>, maps:get(<<"id">>, Decoded)).

bench_compare_regression_test() ->
  Baseline = [
    #{
      <<"id">> => <<"b1">>,
      <<"name">> => <<"Bench 1">>,
      <<"group">> => <<"g1">>,
      <<"mean_us">> => 100.0,
      <<"ops_per_sec">> => 10000.0
    },
    #{
      <<"id">> => <<"b2">>,
      <<"name">> => <<"Bench 2">>,
      <<"group">> => <<"g1">>,
      <<"mean_us">> => 100.0,
      <<"ops_per_sec">> => 10000.0
    },
    #{
      <<"id">> => <<"b3">>,
      <<"name">> => <<"Bench 3">>,
      <<"group">> => <<"g1">>,
      <<"mean_us">> => 100.0,
      <<"ops_per_sec">> => 10000.0
    }
  ],
  Current = [
    #{
      id => <<"b1">>,
      name => <<"Bench 1">>,
      group => <<"g1">>,
      mean_us => 80.0,
      ops_per_sec => 12500.0
    },
    #{
      id => <<"b2">>,
      name => <<"Bench 2">>,
      group => <<"g1">>,
      mean_us => 160.0,
      ops_per_sec => 6250.0
    },
    #{
      id => <<"b3">>,
      name => <<"Bench 3">>,
      group => <<"g1">>,
      mean_us => 120.0,
      ops_per_sec => 8333.0
    }
  ],
  Comparison = ecu_bench_runner:compare(Current, Baseline, 10.0),
  ?assertEqual(true, maps:get(has_regression, Comparison)),
  Items = maps:get(items, Comparison),
  ?assertEqual(3, length(Items)),
  [Item1, Item2, Item3] = Items,
  ?assertEqual(faster, maps:get(status, Item1)),
  ?assertEqual(regression, maps:get(status, Item2)),
  ?assertEqual(regression, maps:get(status, Item3)),
  TableBin = iolist_to_binary(ecu_bench_runner:format_comparison_table(Comparison)),
  ?assert(binary:match(TableBin, <<"[FASTER]">>) =/= nomatch),
  ?assert(binary:match(TableBin, <<"[REGRESSION!]">>) =/= nomatch),

  MdBin = iolist_to_binary(ecu_bench_runner:format_comparison_markdown(Comparison)),
  ?assert(binary:match(MdBin, <<"| Bench 1 |">>) =/= nomatch),
  ?assert(binary:match(MdBin, <<"**REGRESSION**">>) =/= nomatch).

mann_whitney_u_test() ->
  %% Insufficient sample size returns 1.0 (no significance)
  ?assertEqual(1.0, ecu_bench_runner:mann_whitney_u([1.0, 2.0], [3.0, 4.0])),

  %% Identical distributions should have p >= 0.05
  A = [10.0, 11.0, 12.0, 10.5, 11.5, 10.2, 11.8, 10.9, 11.1, 12.2],
  B = [10.2, 11.1, 11.9, 10.6, 11.4, 10.1, 11.7, 10.8, 11.2, 12.0],
  PIdentical = ecu_bench_runner:mann_whitney_u(A, B),
  ?assert(PIdentical > 0.05),

  %% Completely separated distributions should have p < 0.001
  C = [20.0, 21.0, 22.0, 20.5, 21.5, 20.2, 21.8, 20.9, 21.1, 22.2],
  PDistinct = ecu_bench_runner:mann_whitney_u(A, C),
  ?assert(PDistinct < 0.001).

bench_combine_results_test() ->
  Round1 = [
    #{
      id => <<"bench_1">>,
      name => <<"Bench 1">>,
      group => <<"g1">>,
      iterations => 10,
      total_time_us => 1000,
      ops_per_sec => 10000.0,
      mean_us => 100.0,
      median_us => 98.0,
      hl_us => 98.0,
      p95_us => 105.0,
      p99_us => 108.0,
      min_us => 90,
      max_us => 110,
      samples => [95.0, 100.0, 105.0]
    }
  ],
  Round2 = [
    #{
      id => <<"bench_1">>,
      name => <<"Bench 1">>,
      group => <<"g1">>,
      iterations => 10,
      total_time_us => 1100,
      ops_per_sec => 9090.0,
      mean_us => 110.0,
      median_us => 108.0,
      hl_us => 108.0,
      p95_us => 115.0,
      p99_us => 118.0,
      min_us => 100,
      max_us => 120,
      samples => [100.0, 110.0, 120.0]
    }
  ],
  Combined = ecu_bench_runner:combine_results([Round1, Round2]),
  ?assertEqual(1, length(Combined)),
  Item = hd(Combined),
  ?assertEqual(20, maps:get(iterations, Item)),
  ?assertEqual(2100, maps:get(total_time_us, Item)),
  ?assertEqual(6, length(maps:get(samples, Item))).

bench_compare_paired_runs_test() ->
  MakeRound = fun(Id, Mean, Samples) ->
    [
      #{
        id => Id,
        name => <<"Test">>,
        group => <<"g">>,
        iterations => 10,
        total_time_us => round(Mean * 10),
        ops_per_sec => 1000.0,
        mean_us => Mean,
        median_us => Mean,
        hl_us => Mean,
        p95_us => Mean,
        p99_us => Mean,
        min_us => round(Mean),
        max_us => round(Mean),
        samples => Samples
      }
    ]
  end,
  %% Base rounds: 100, 100, 100, 100
  B1 = MakeRound(<<"b1">>, 100.0, [100.0, 100.0]),
  B2 = MakeRound(<<"b1">>, 100.0, [100.0, 100.0]),
  B3 = MakeRound(<<"b1">>, 100.0, [100.0, 100.0]),
  B4 = MakeRound(<<"b1">>, 100.0, [100.0, 100.0]),
  %% PR rounds: +4%, -2%, +3%, +1%
  P1 = MakeRound(<<"b1">>, 104.0, [104.0, 104.0]),
  P2 = MakeRound(<<"b1">>, 98.0, [98.0, 98.0]),
  P3 = MakeRound(<<"b1">>, 103.0, [103.0, 103.0]),
  P4 = MakeRound(<<"b1">>, 101.0, [101.0, 101.0]),
  %% Paired comparison computes median of paired deltas: [-2%, +1%, +3%, +4%] -> median is +2.0%
  Comp = ecu_bench_runner:compare([P1, P2, P3, P4], [B1, B2, B3, B4], 5.0),
  [Item] = maps:get(items, Comp),
  ?assertEqual(2.0, maps:get(delta_pct, Item)),
  ?assertEqual(similar, maps:get(status, Item)),
  ?assertEqual(false, maps:get(has_regression, Comp)).

bench_compare_noise_filtering_test() ->
  %% If samples have large overlapping variance (p >= 0.001),
  %% high delta is classified as unstable (not a proven regression),
  %% so has_regression remains false!
  BaseSamples = [100.0, 150.0, 200.0, 250.0, 300.0, 120.0, 180.0, 220.0, 260.0, 140.0],
  %% Current has higher median (+20%) but wide overlapping spread
  CurSamples = [120.0, 170.0, 220.0, 270.0, 320.0, 140.0, 200.0, 240.0, 280.0, 160.0],
  Baseline = [
    #{
      <<"id">> => <<"noisy_bench">>,
      <<"name">> => <<"Noisy Bench">>,
      <<"group">> => <<"g1">>,
      <<"hl_us">> => 195.0,
      <<"ops_per_sec">> => 5000.0,
      <<"samples">> => BaseSamples
    }
  ],
  Current = [
    #{
      id => <<"noisy_bench">>,
      name => <<"Noisy Bench">>,
      group => <<"g1">>,
      mean_us => 234.0,
      hl_us => 234.0,
      ops_per_sec => 4200.0,
      samples => CurSamples
    }
  ],
  Comp = ecu_bench_runner:compare(Current, Baseline, 15.0),
  [CompItem] = maps:get(items, Comp),
  %% Because p >= 0.001, it is flagged as unstable, NOT a proven regression!
  ?assertEqual(unstable, maps:get(status, CompItem)),
  ?assertEqual(false, maps:get(has_regression, Comp)),

  %% True regression: tight non-overlapping samples (p < 0.01) and delta > 50us
  TightBase = [100.0, 101.0, 102.0, 100.5, 101.5, 100.2, 101.8, 100.9, 101.1, 102.2],
  TightCur = [200.0, 201.0, 202.0, 200.5, 201.5, 200.2, 201.8, 200.9, 201.1, 202.2],
  Baseline2 = [
    #{
      <<"id">> => <<"real_reg">>,
      <<"name">> => <<"Real Reg">>,
      <<"group">> => <<"g1">>,
      <<"mean_us">> => 101.0,
      <<"hl_us">> => 101.0,
      <<"ops_per_sec">> => 9900.0,
      <<"samples">> => TightBase
    }
  ],
  Current2 = [
    #{
      id => <<"real_reg">>,
      name => <<"Real Reg">>,
      group => <<"g1">>,
      mean_us => 201.0,
      hl_us => 201.0,
      ops_per_sec => 4975.0,
      samples => TightCur
    }
  ],
  Comp2 = ecu_bench_runner:compare(Current2, Baseline2, 15.0),
  [CompItem2] = maps:get(items, Comp2),
  ?assertEqual(regression, maps:get(status, CompItem2)),
  ?assertEqual(true, maps:get(has_regression, Comp2)).

bench_suites_registry_test() ->
  Suites = ecu_bench_suites:list_suites(),
  ?assert(lists:member(all, Suites)),
  ?assert(lists:member(ed25519, Suites)),
  ?assert(lists:member(ml_kem, Suites)),
  ?assert(lists:member(ml_dsa, Suites)),

  Ed25519Benches = ecu_bench_suites:get_benchmarks(ed25519),
  ?assert(length(Ed25519Benches) > 0),

  AllBenches = ecu_bench_suites:get_benchmarks(all),
  ?assert(length(AllBenches) >= length(Ed25519Benches)).
