%%%-------------------------------------------------------------------
%%% @doc
%%% Tests for FN-DSA Fast Fourier Transform (FFT) and Fast Fourier
%%% Sampling (FFS) engine.
%%% @end
%%%-------------------------------------------------------------------
-module(fn_dsa_fft_tests).

-include_lib("eunit/include/eunit.hrl").

complex_arithmetic_test() ->
  A = {3.0, 4.0},
  B = {1.0, -2.0},
  ?assertEqual({4.0, 2.0}, ecu_fn_dsa_fft:c_add(A, B)),
  ?assertEqual({2.0, 6.0}, ecu_fn_dsa_fft:c_sub(A, B)),
  ?assertEqual({11.0, -2.0}, ecu_fn_dsa_fft:c_mul(A, B)),
  ?assertEqual({3.0, -4.0}, ecu_fn_dsa_fft:c_conj(A)),
  %% Division: (A / B) * B == A
  Div = ecu_fn_dsa_fft:c_div(A, B),
  MulBack = ecu_fn_dsa_fft:c_mul(Div, B),
  {R, I} = MulBack,
  ?assert(abs(R - 3.0) < 1.0e-12),
  ?assert(abs(I - 4.0) < 1.0e-12).

fft_roundtrip_512_test() ->
  P = list_to_tuple([float(rand:uniform(100) - 50) || _ <- lists:seq(1, 512)]),
  Transformed = ecu_fn_dsa_fft:fft(P, 9),
  Back = ecu_fn_dsa_fft:inv_fft(Transformed, 9),
  Diffs = [abs(X - Y) || {X, Y} <- lists:zip(tuple_to_list(P), tuple_to_list(Back))],
  MaxDiff = lists:max(Diffs),
  ?assert(MaxDiff < 1.0e-12).

fft_roundtrip_1024_test() ->
  P = list_to_tuple([float(rand:uniform(100) - 50) || _ <- lists:seq(1, 1024)]),
  Transformed = ecu_fn_dsa_fft:fft(P, 10),
  Back = ecu_fn_dsa_fft:inv_fft(Transformed, 10),
  Diffs = [abs(X - Y) || {X, Y} <- lists:zip(tuple_to_list(P), tuple_to_list(Back))],
  MaxDiff = lists:max(Diffs),
  ?assert(MaxDiff < 1.0e-12).

split_merge_fft_test() ->
  F512 = list_to_tuple([{rand:uniform(), rand:uniform()} || _ <- lists:seq(1, 256)]),
  {F0, F1} = ecu_fn_dsa_fft:poly_split_fft(F512, 9),
  F_Merged = ecu_fn_dsa_fft:poly_merge_fft(F0, F1, 9),
  MaxDiff512 = lists:max([
    max(abs(R1 - R2), abs(I1 - I2))
   || {{R1, I1}, {R2, I2}} <- lists:zip(tuple_to_list(F512), tuple_to_list(F_Merged))
  ]),
  ?assert(MaxDiff512 < 1.0e-14),

  %% 1024
  F1024 = list_to_tuple([{rand:uniform(), rand:uniform()} || _ <- lists:seq(1, 512)]),
  {G0, G1} = ecu_fn_dsa_fft:poly_split_fft(F1024, 10),
  G_Merged = ecu_fn_dsa_fft:poly_merge_fft(G0, G1, 10),
  MaxDiff1024 = lists:max([
    max(abs(R1 - R2), abs(I1 - I2))
   || {{R1, I1}, {R2, I2}} <- lists:zip(tuple_to_list(F1024), tuple_to_list(G_Merged))
  ]),
  ?assert(MaxDiff1024 < 1.0e-14).

poly_mul_fft_vs_direct_test() ->
  N = 512,
  AList = [float(rand:uniform(10) - 5) || _ <- lists:seq(1, N)],
  BList = [float(rand:uniform(10) - 5) || _ <- lists:seq(1, N)],
  A = list_to_tuple(AList),
  B = list_to_tuple(BList),
  AHat = ecu_fn_dsa_fft:fft(A, 9),
  BHat = ecu_fn_dsa_fft:fft(B, 9),
  ProdHat = ecu_fn_dsa_fft:poly_mul_fft(AHat, BHat),
  ProdFFT = ecu_fn_dsa_fft:inv_fft(ProdHat, 9),
  DirectProd = [
    lists:foldl(
      fun(J, Acc) ->
        Aj = lists:nth(J + 1, AList),
        K = (I - J + N) rem N,
        Bk = lists:nth(K + 1, BList),
        Sign =
          if
            J > I -> -1.0;
            true -> 1.0
          end,
        Acc + Sign * Aj * Bk
      end,
      0.0,
      lists:seq(0, N - 1)
    )
   || I <- lists:seq(0, N - 1)
  ],
  Diffs = [abs(X - Y) || {X, Y} <- lists:zip(tuple_to_list(ProdFFT), DirectProd)],
  MaxDiff = lists:max(Diffs),
  ?assert(MaxDiff < 1.0e-11).

gaussian0_sampler_test() ->
  Stream0 = ecu_fn_dsa_fft:prng_init(crypto:strong_rand_bytes(32)),
  {Samples, _} = lists:foldl(
    fun(_, {Acc, CurStream}) ->
      {Z, NextStream} = ecu_fn_dsa_fft:gaussian0_sampler(CurStream),
      {[Z | Acc], NextStream}
    end,
    {[], Stream0},
    lists:seq(1, 1000)
  ),
  Mean = lists:sum(Samples) / length(Samples),
  %% Expected mean is approx 1.1478
  ?assert(Mean > 0.9 andalso Mean < 1.4),
  ?assert(lists:min(Samples) >= 0),
  ?assert(lists:max(Samples) =< 18).
