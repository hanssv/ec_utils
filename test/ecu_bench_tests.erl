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
  ?assert(maps:get(p95_us, Result) >= maps:get(median_us, Result)).

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
      mean_us => 125.0,
      ops_per_sec => 8000.0
    }
  ],
  Comparison = ecu_bench_runner:compare(Current, Baseline, 10.0),
  ?assertEqual(true, maps:get(has_regression, Comparison)),
  Items = maps:get(items, Comparison),
  ?assertEqual(2, length(Items)),
  [Item1, Item2] = Items,
  ?assertEqual(faster, maps:get(status, Item1)),
  ?assertEqual(regression, maps:get(status, Item2)),
  TableBin = iolist_to_binary(ecu_bench_runner:format_comparison_table(Comparison)),
  ?assert(binary:match(TableBin, <<"[FASTER]">>) =/= nomatch),
  ?assert(binary:match(TableBin, <<"[REGRESSION!]">>) =/= nomatch).

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
