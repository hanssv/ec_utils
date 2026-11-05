%%%-------------------------------------------------------------------
%%% @doc
%%% Fast Fourier Transform (FFT) and Fast Fourier Sampling (FFS) engine
%%% for FN-DSA (FIPS 206 / Falcon).
%%%
%%% Implements complex arithmetic in `C[x] / (x^d + 1)` using 64-bit IEEE floats,
%%% LDL tree Gram-Schmidt orthogonalization, and discrete Gaussian sampling
%%% over the Falcon tree.
%%%
%%% References:
%%% - FIPS 206 (Draft): Fast-Fourier Lattice-based Digital Signature Standard
%%% - Falcon Specification, Section 3.7 & 3.8: https://falcon-sign.info/falcon.pdf
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_fn_dsa_fft).

-typing([eqwalizer]).

-export([
  c_add/2,
  c_sub/2,
  c_mul/2,
  c_div/2,
  c_conj/1,
  fft/2,
  inv_fft/2,
  poly_add_fft/1,
  poly_add_fft/2,
  poly_sub_fft/2,
  poly_mul_fft/2,
  poly_adj_fft/1,
  poly_muladj_fft/2,
  poly_mulselfadj_fft/1,
  poly_div_fft/2,
  poly_mul_const_fft/2,
  poly_neg_fft/1,
  poly_split_fft/2,
  poly_merge_fft/3,
  poly_ldl_fft/2,
  gaussian0_sampler/1,
  sample_z/4,
  ff_sampling_dyntree/8,
  prng_init/1,
  prng_take_bits/2
]).

-opaque prng_state() :: {binary(), non_neg_integer(), bitstring()}.

-export_type([
  c_num/0,
  c_poly/0,
  real_poly/0,
  prng_state/0
]).

-type c_num() :: {float(), float()}.
-type c_poly() :: tuple().
-type real_poly() :: tuple().

%% ===================================================================
%% Complex Arithmetic
%% ===================================================================

-compile({inline, [c_add/2, c_sub/2, c_mul/2, c_conj/1]}).

-spec c_add(c_num(), c_num()) -> c_num().
c_add({AR, AI}, {BR, BI}) ->
  {AR + BR, AI + BI}.

-spec c_sub(c_num(), c_num()) -> c_num().
c_sub({AR, AI}, {BR, BI}) ->
  {AR - BR, AI - BI}.

-spec c_mul(c_num(), c_num()) -> c_num().
c_mul({AR, AI}, {BR, BI}) ->
  {AR * BR - AI * BI, AR * BI + AI * BR}.

-spec c_conj(c_num()) -> c_num().
c_conj({AR, AI}) ->
  {AR, -AI}.

-spec c_div(c_num(), c_num()) -> c_num().
c_div({AR, AI}, {BR, BI}) ->
  Norm = BR * BR + BI * BI,
  InvNorm = 1.0 / Norm,
  {(AR * BR + AI * BI) * InvNorm, (AI * BR - AR * BI) * InvNorm}.

%% ===================================================================
%% Fast Fourier Transform (FFT) in R[x] / (x^n + 1)
%% ===================================================================

-spec fft(real_poly(), pos_integer()) -> c_poly().
fft(RealPoly, LogN) ->
  N = 1 bsl LogN,
  HN = N bsr 1,
  Init =
    list_to_tuple([
      {float(get_real(J + 1, RealPoly)), float(get_real(J + HN + 1, RealPoly))}
     || J <- lists:seq(0, HN - 1)
    ]),
  fft_loop_u(1, 2, HN, LogN, Init).

-spec fft_loop_u(pos_integer(), pos_integer(), pos_integer(), pos_integer(), c_poly()) -> c_poly().
fft_loop_u(U, M, T, LogN, A) when U < LogN ->
  HT = T bsr 1,
  HM = M bsr 1,
  ANext = fft_loop_i1(0, 0, HM, HT, T, M, A),
  fft_loop_u(U + 1, M bsl 1, HT, LogN, ANext);
fft_loop_u(_U, _M, _T, _LogN, A) ->
  A.

-spec fft_loop_i1(
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  c_poly()
) -> c_poly().
fft_loop_i1(I1, J1, HM, HT, T, M, A) when I1 < HM ->
  S = gm_root(M + I1),
  J2 = J1 + HT,
  ANext = fft_loop_j(J1, J2, HT, S, A),
  fft_loop_i1(I1 + 1, J1 + T, HM, HT, T, M, ANext);
fft_loop_i1(_I1, _J1, _HM, _HT, _T, _M, A) ->
  A.

-spec fft_loop_j(non_neg_integer(), non_neg_integer(), pos_integer(), c_num(), c_poly()) -> c_poly().
fft_loop_j(J, J2, HT, S, A) when J < J2 ->
  X = get_c(J + 1, A),
  Y = c_mul(get_c(J + HT + 1, A), S),
  A1 = setelement(J + 1, A, c_add(X, Y)),
  A2 = setelement(J + HT + 1, A1, c_sub(X, Y)),
  fft_loop_j(J + 1, J2, HT, S, A2);
fft_loop_j(_J, _J2, _HT, _S, A) ->
  A.

%% ===================================================================
%% Inverse Fast Fourier Transform (iFFT)
%% ===================================================================

-spec inv_fft(c_poly(), pos_integer()) -> real_poly().
inv_fft(CPoly, LogN) ->
  N = 1 bsl LogN,
  HN = N bsr 1,
  A_Done = ifft_loop_u(LogN, N, 1, HN, CPoly),
  InvHN = 1.0 / float(HN),
  Reals = [element(1, get_c(J + 1, A_Done)) * InvHN || J <- lists:seq(0, HN - 1)],
  Imags = [element(2, get_c(J + 1, A_Done)) * InvHN || J <- lists:seq(0, HN - 1)],
  list_to_tuple(Reals ++ Imags).

-spec ifft_loop_u(pos_integer(), pos_integer(), pos_integer(), pos_integer(), c_poly()) -> c_poly().
ifft_loop_u(U, M, T, HN, A) when U > 1 ->
  HM = M bsr 1,
  DT = T bsl 1,
  ANext = ifft_loop_i1(0, HM, T, DT, HN, A),
  ifft_loop_u(U - 1, HM, DT, HN, ANext);
ifft_loop_u(_U, _M, _T, _HN, A) ->
  A.

-spec ifft_loop_i1(
  non_neg_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  c_poly()
) -> c_poly().
ifft_loop_i1(J1, HM, T, DT, HN, A) when J1 < HN ->
  I1 = J1 div DT,
  S = c_conj(gm_root(HM + I1)),
  J2 = J1 + T,
  ANext = ifft_loop_j(J1, J2, T, S, A),
  ifft_loop_i1(J1 + DT, HM, T, DT, HN, ANext);
ifft_loop_i1(_J1, _HM, _T, _DT, _HN, A) ->
  A.

-spec ifft_loop_j(non_neg_integer(), non_neg_integer(), pos_integer(), c_num(), c_poly()) -> c_poly().
ifft_loop_j(J, J2, T, S, A) when J < J2 ->
  X = get_c(J + 1, A),
  Y = get_c(J + T + 1, A),
  A1 = setelement(J + 1, A, c_add(X, Y)),
  Diff = c_sub(X, Y),
  A2 = setelement(J + T + 1, A1, c_mul(Diff, S)),
  ifft_loop_j(J + 1, J2, T, S, A2);
ifft_loop_j(_J, _J2, _T, _S, A) ->
  A.

%% ===================================================================
%% FFT Polynomial Operations
%% ===================================================================

-spec poly_add_fft(c_poly(), c_poly()) -> c_poly().
poly_add_fft(A, B) ->
  Len = tuple_size(A),
  list_to_tuple([c_add(get_c(I, A), get_c(I, B)) || I <- lists:seq(1, Len)]).

-spec poly_add_fft([c_poly()]) -> c_poly().
poly_add_fft([H | T]) ->
  lists:foldl(fun(Elem, Acc) -> poly_add_fft(Acc, Elem) end, H, T).

-spec poly_sub_fft(c_poly(), c_poly()) -> c_poly().
poly_sub_fft(A, B) ->
  Len = tuple_size(A),
  list_to_tuple([c_sub(get_c(I, A), get_c(I, B)) || I <- lists:seq(1, Len)]).

-spec poly_mul_fft(c_poly(), c_poly()) -> c_poly().
poly_mul_fft(A, B) ->
  Len = tuple_size(A),
  list_to_tuple([c_mul(get_c(I, A), get_c(I, B)) || I <- lists:seq(1, Len)]).

-spec poly_adj_fft(c_poly()) -> c_poly().
poly_adj_fft(A) ->
  Len = tuple_size(A),
  list_to_tuple([c_conj(get_c(I, A)) || I <- lists:seq(1, Len)]).

-spec poly_muladj_fft(c_poly(), c_poly()) -> c_poly().
poly_muladj_fft(A, B) ->
  Len = tuple_size(A),
  list_to_tuple([c_mul(get_c(I, A), c_conj(get_c(I, B))) || I <- lists:seq(1, Len)]).

-spec poly_mulselfadj_fft(c_poly()) -> c_poly().
poly_mulselfadj_fft(A) ->
  Len = tuple_size(A),
  list_to_tuple([
    begin
      {R, I} = get_c(Idx, A),
      {R * R + I * I, 0.0}
    end
   || Idx <- lists:seq(1, Len)
  ]).

-spec poly_div_fft(c_poly(), c_poly()) -> c_poly().
poly_div_fft(A, B) ->
  Len = tuple_size(A),
  list_to_tuple([c_div(get_c(I, A), get_c(I, B)) || I <- lists:seq(1, Len)]).

-spec poly_mul_const_fft(c_poly(), float()) -> c_poly().
poly_mul_const_fft(A, C) ->
  Len = tuple_size(A),
  list_to_tuple([
    begin
      {R, I} = get_c(Idx, A),
      {R * C, I * C}
    end
   || Idx <- lists:seq(1, Len)
  ]).

-spec poly_neg_fft(c_poly()) -> c_poly().
poly_neg_fft(A) ->
  Len = tuple_size(A),
  list_to_tuple([
    begin
      {R, I} = get_c(Idx, A),
      {-R, -I}
    end
   || Idx <- lists:seq(1, Len)
  ]).

%% ===================================================================
%% Split & Merge in FFT Domain
%% ===================================================================

-spec poly_split_fft(c_poly(), pos_integer()) -> {c_poly(), c_poly()}.
poly_split_fft(F, LogN) ->
  HN = 1 bsl (LogN - 1),
  QN = HN bsr 1,
  if
    LogN =:= 1 ->
      {R, I} = get_c(1, F),
      {{{R, 0.0}}, {{I, 0.0}}};
    true ->
      F0 = [
        begin
          A = get_c(2 * U + 1, F),
          B = get_c(2 * U + 2, F),
          {element(1, c_add(A, B)) * 0.5, element(2, c_add(A, B)) * 0.5}
        end
       || U <- lists:seq(0, QN - 1)
      ],
      F1 = [
        begin
          A = get_c(2 * U + 1, F),
          B = get_c(2 * U + 2, F),
          W = gm_root(U + HN),
          Diff = c_sub(A, B),
          Mul = c_mul(Diff, c_conj(W)),
          {element(1, Mul) * 0.5, element(2, Mul) * 0.5}
        end
       || U <- lists:seq(0, QN - 1)
      ],
      {list_to_tuple(F0), list_to_tuple(F1)}
  end.

-spec poly_merge_fft(c_poly(), c_poly(), pos_integer()) -> c_poly().
poly_merge_fft(F0, F1, LogN) ->
  HN = 1 bsl (LogN - 1),
  QN = HN bsr 1,
  if
    LogN =:= 1 ->
      {R, _} = get_c(1, F0),
      {I, _} = get_c(1, F1),
      {{R, I}};
    true ->
      Pairs = [
        begin
          A = get_c(U + 1, F0),
          W = gm_root(U + HN),
          B = c_mul(get_c(U + 1, F1), W),
          {c_add(A, B), c_sub(A, B)}
        end
       || U <- lists:seq(0, QN - 1)
      ],
      list_to_tuple(lists:flatmap(fun({P1, P2}) -> [P1, P2] end, Pairs))
  end.

%% ===================================================================
%% LDL Decomposition & Tree Construction
%% ===================================================================

%% @doc Decomposes Gram matrix G into LDL components {D00, L10, D11}.
-spec poly_ldl_fft(c_poly(), c_poly()) -> {c_poly(), c_poly(), c_poly()}.
poly_ldl_fft(G00, G01) ->
  %% L10 = G01 / G00
  L10 = poly_div_fft(G01, G00),
  %% D11 = G11 - L10 * adj(G01)
  L10_AdjG01 = poly_muladj_fft(L10, G01),
  D11 = poly_sub_fft(G00, L10_AdjG01),
  {G00, L10, D11}.

%% ===================================================================
%% Discrete Gaussian Sampling
%% ===================================================================

-define(SIGMA_0, 1.8205).
-define(INV_2_SQR_SIGMA0, 0.15086504887537272).

-spec gaussian0_sampler(prng_state()) -> {non_neg_integer(), prng_state()}.
gaussian0_sampler(Rng) ->
  {V, NextRng} = prng_take_bits(Rng, 72),
  Z = count_thresholds(V, gaussian_thresholds()),
  {Z, NextRng}.

-spec sample_z(prng_state(), float(), float(), float()) -> {integer(), prng_state()}.
sample_z(Rng, Mu, InvSigma, SigmaMin) ->
  S = math:floor(Mu),
  R = Mu - S,
  Dss = 0.5 * InvSigma * InvSigma,
  Ccs = InvSigma * SigmaMin,
  sample_z_loop(Rng, S, R, Dss, Ccs).

-spec sample_z_loop(prng_state(), float(), float(), float(), float()) -> {integer(), prng_state()}.
sample_z_loop(Rng0, S, R, Dss, Ccs) ->
  {Z0, Rng1} = gaussian0_sampler(Rng0),
  {BitB, Rng2} = prng_take_bits(Rng1, 1),
  Z =
    if
      BitB =:= 1 -> 1 + Z0;
      true -> -Z0
    end,
  DiffR = float(Z) - R,
  X1 = DiffR * DiffR * Dss,
  X2 = float(Z0 * Z0) * ?INV_2_SQR_SIGMA0,
  X = X1 - X2,
  {Accept, Rng3} = ber_exp(Rng2, X, Ccs),
  case Accept of
    true ->
      {trunc(S) + Z, Rng3};
    false ->
      sample_z_loop(Rng3, S, R, Dss, Ccs)
  end.

-spec ber_exp(prng_state(), float(), float()) -> {boolean(), prng_state()}.
ber_exp(Rng, X, Ccs) ->
  P = Ccs * math:exp(-X),
  if
    P >= 1.0 ->
      {true, Rng};
    P =< 0.0 ->
      {false, Rng};
    true ->
      {Rand64, NextRng} = prng_take_bits(Rng, 64),
      U = float(Rand64) / 18446744073709551616.0,
      {U < P, NextRng}
  end.

%% ===================================================================
%% Fast Fourier Sampling (Dynamic Tree)
%% ===================================================================

-spec ff_sampling_dyntree(
  prng_state(),
  c_poly(),
  c_poly(),
  c_poly(),
  c_poly(),
  c_poly(),
  pos_integer(),
  pos_integer()
) -> {{c_poly(), c_poly()}, prng_state()}.
ff_sampling_dyntree(Rng0, T0, T1, G00, _G01, _G11, OrigLogN, LogN) when LogN =:= 0 ->
  {G00_R, _} = get_c(1, G00),
  InvSigma = inv_sigma(OrigLogN),
  Leaf = math:sqrt(max(0.0, G00_R)) * InvSigma,
  SigmaMin = sigma_min(OrigLogN),
  {T0_R, _} = get_c(1, T0),
  {T1_R, _} = get_c(1, T1),
  {Z0, Rng1} = sample_z(Rng0, T0_R, Leaf, SigmaMin),
  {Z1, Rng2} = sample_z(Rng1, T1_R, Leaf, SigmaMin),
  PolyZ0 = {{float(Z0), 0.0}},
  PolyZ1 = {{float(Z1), 0.0}},
  {{PolyZ0, PolyZ1}, Rng2};
ff_sampling_dyntree(Rng0, T0, T1, G00, G01, G11, OrigLogN, LogN) ->
  %% 1. LDL decomposition: L10 = G01 / G00, D11 = G11 - L10 * adj(G01)
  L10 = poly_div_fft(G01, G00),
  L10_AdjG01 = poly_muladj_fft(L10, G01),
  D11 = poly_sub_fft(G11, L10_AdjG01),
  L10_Adj = poly_adj_fft(L10),
  %% 2. Split D00 (which is G00) and D11
  {D00_0, D00_1} = poly_split_fft(G00, LogN),
  {D11_0, D11_1} = poly_split_fft(D11, LogN),
  %% 3. Sample right child (on T1) using Gram matrix of D11: (D11_0, D11_1, D11_0)
  {T1_0, T1_1} = poly_split_fft(T1, LogN),
  {{Z1_0, Z1_1}, Rng1} =
    ff_sampling_dyntree(Rng0, T1_0, T1_1, D11_0, D11_1, D11_0, OrigLogN, LogN - 1),
  Z1 = poly_merge_fft(Z1_0, Z1_1, LogN),
  %% 4. Adjust T0: Tb0 = T0 + (T1 - Z1) * L10_Adj
  T1_Sub_Z1 = poly_sub_fft(T1, Z1),
  Adjustment = poly_mul_fft(T1_Sub_Z1, L10_Adj),
  Tb0 = poly_add_fft(T0, Adjustment),
  %% 5. Sample left child (on adjusted Tb0) using Gram matrix of D00: (D00_0, D00_1, D00_0)
  {Tb0_0, Tb0_1} = poly_split_fft(Tb0, LogN),
  {{Z0_0, Z0_1}, Rng2} =
    ff_sampling_dyntree(Rng1, Tb0_0, Tb0_1, D00_0, D00_1, D00_0, OrigLogN, LogN - 1),
  Z0 = poly_merge_fft(Z0_0, Z0_1, LogN),
  {{Z0, Z1}, Rng2}.

%% ===================================================================
%% Internal Helpers & Tables
%% ===================================================================

-compile({inline, [get_c/2, get_real/2]}).

-spec get_c(pos_integer(), tuple()) -> c_num().
get_c(Idx, Tuple) ->
  case element(Idx, Tuple) of
    {R, I} when is_float(R), is_float(I) -> {R, I}
  end.

-spec get_real(pos_integer(), tuple()) -> float().
get_real(Idx, Tuple) ->
  case element(Idx, Tuple) of
    V when is_float(V) -> V;
    V when is_integer(V) -> float(V)
  end.

-spec gm_root(non_neg_integer()) -> c_num().
gm_root(Idx) ->
  get_c(Idx + 1, gm_table()).

-spec gm_table() -> tuple().
gm_table() ->
  case persistent_term:get({?MODULE, gm_tab}, undefined) of
    undefined ->
      Pi = math:pi(),
      Table =
        list_to_tuple([
          begin
            Angle = Pi * float(bit_rev10(K)) / 1024.0,
            {math:cos(Angle), math:sin(Angle)}
          end
         || K <- lists:seq(0, 1023)
        ]),
      persistent_term:put({?MODULE, gm_tab}, Table),
      Table;
    Table ->
      Table
  end.

-spec bit_rev10(non_neg_integer()) -> non_neg_integer().
bit_rev10(X) ->
  <<B0:1, B1:1, B2:1, B3:1, B4:1, B5:1, B6:1, B7:1, B8:1, B9:1>> = <<X:10>>,
  <<Y:10>> = <<B9:1, B8:1, B7:1, B6:1, B5:1, B4:1, B3:1, B2:1, B1:1, B0:1>>,
  Y.

-spec inv_sigma(pos_integer()) -> float().
inv_sigma(9) -> 0.006033669668157724;
inv_sigma(10) -> 0.005938645309533116.

-spec sigma_min(pos_integer()) -> float().
sigma_min(9) -> 1.2778336969128337;
sigma_min(10) -> 1.298280334344292.

-spec gaussian_thresholds() -> [non_neg_integer()].
gaussian_thresholds() ->
  [
    (10745844 bsl 48) bor (3068844 bsl 24) bor 3741698,
    (5559083 bsl 48) bor (1580863 bsl 24) bor 8248194,
    (2260429 bsl 48) bor (13669192 bsl 24) bor 2736639,
    (708981 bsl 48) bor (4421575 bsl 24) bor 10046180,
    (169348 bsl 48) bor (7122675 bsl 24) bor 4136815,
    (30538 bsl 48) bor (13063405 bsl 24) bor 7650655,
    (4132 bsl 48) bor (14505003 bsl 24) bor 7826148,
    (417 bsl 48) bor (16768101 bsl 24) bor 11363290,
    (31 bsl 48) bor (8444042 bsl 24) bor 8086568,
    (1 bsl 48) bor (12844466 bsl 24) bor 265321,
    (0 bsl 48) bor (1232676 bsl 24) bor 13644283,
    (0 bsl 48) bor (38047 bsl 24) bor 9111839,
    (0 bsl 48) bor (870 bsl 24) bor 6138264,
    (0 bsl 48) bor (14 bsl 24) bor 12545723,
    (0 bsl 48) bor (0 bsl 24) bor 3104126,
    (0 bsl 48) bor (0 bsl 24) bor 28824,
    (0 bsl 48) bor (0 bsl 24) bor 198,
    (0 bsl 48) bor (0 bsl 24) bor 1
  ].

-spec count_thresholds(non_neg_integer(), [non_neg_integer()]) -> non_neg_integer().
count_thresholds(V, Thresholds) ->
  lists:foldl(
    fun(T, Acc) ->
      if
        V < T -> Acc + 1;
        true -> Acc
      end
    end,
    0,
    Thresholds
  ).

-spec prng_init(binary()) -> prng_state().
prng_init(Seed) when is_binary(Seed) ->
  {Seed, 0, <<>>}.

-spec prng_take_bits(prng_state(), pos_integer()) -> {non_neg_integer(), prng_state()}.
prng_take_bits({Seed, Counter, Buf}, Bits) when bit_size(Buf) >= Bits ->
  <<Val:Bits, RestBuf/bitstring>> = Buf,
  {Val, {Seed, Counter, RestBuf}};
prng_take_bits({Seed, Counter, Buf}, Bits) ->
  NewBytes =
    try
      crypto:hash_xof(shake256, <<Seed/binary, Counter:32/big>>, 256 * 8)
    catch
      _:_ ->
        ecu_keccak:shake256(<<Seed/binary, Counter:32/big>>, 256 * 8)
    end,
  NextBuf = <<Buf/bitstring, NewBytes/binary>>,
  prng_take_bits({Seed, Counter + 1, NextBuf}, Bits).
