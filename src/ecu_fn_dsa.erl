%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang FN-DSA (Fast-Fourier Lattice-based Digital Signature Standard,
%%% FIPS 206 / Falcon).
%%%
%%% Implements lattice-based signatures over the polynomial quotient ring
%%% `Z_q[x] / (x^n + 1)` with modulus `q = 12289` and degree `n in {512, 1024}`.
%%%
%%% Conforms to NIST FIPS 206 and the Falcon specification:
%%% https://falcon-sign.info/falcon.pdf
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_fn_dsa).

-typing([eqwalizer]).

-export([
  keypair/1,
  keypair_from_seed/2,
  parameter_set/1,
  sign/2,
  sign/3,
  sign/4,
  sign_deterministic/2,
  sign_deterministic/3,
  verify/3,
  verify/4,
  decode_secret_key/1,
  encode_secret_key/4,
  decode_public_key/1,
  encode_public_key/2,
  comp_encode/2,
  decode_s2/2,
  mod_inv/2,
  ntt/2,
  inv_ntt/2
]).

-export_type([
  keypair/0,
  parameter_set/0,
  public_key/0,
  secret_key/0,
  decoded_secret_key/0,
  signature/0
]).

-define(FN_DSA_Q, 12289).
-define(ROOT_G, 7).
-define(INV_ROOT_G, 8778).

-define(BOUND_512, 34034726).
-define(BOUND_1024, 70265242).

-type keypair() :: #{public := public_key(), secret := secret_key()}.
-type parameter_set() :: fn_dsa_512 | fn_dsa_1024.
-type public_key() :: binary().
-type secret_key() :: binary().
-type decoded_secret_key() ::
  {parameter_set(), [integer()], [integer()], [integer()], [integer()]}.
-type signature() :: binary().

%% ===================================================================
%% Parameter Sets & Inspection
%% ===================================================================

%% @doc Identifies the canonical parameter set from an atom, key, or signature binary.
-spec parameter_set(parameter_set() | public_key() | secret_key() | signature() | atom()) ->
  parameter_set().
parameter_set(fn_dsa_512) ->
  fn_dsa_512;
parameter_set(falcon512) ->
  fn_dsa_512;
parameter_set(fn_dsa_1024) ->
  fn_dsa_1024;
parameter_set(falcon1024) ->
  fn_dsa_1024;
parameter_set(<<9:8, Rest/binary>>) when byte_size(Rest) =:= 896 ->
  fn_dsa_512;
parameter_set(<<10:8, Rest/binary>>) when byte_size(Rest) =:= 1792 ->
  fn_dsa_1024;
parameter_set(<<16#59:8, Rest/binary>>) when byte_size(Rest) =:= 1280 ->
  fn_dsa_512;
parameter_set(<<16#5A:8, Rest/binary>>) when byte_size(Rest) =:= 2304 ->
  fn_dsa_1024;
parameter_set(<<16#39:8, _:40/binary, _/binary>>) ->
  fn_dsa_512;
parameter_set(<<16#3A:8, _:40/binary, _/binary>>) ->
  fn_dsa_1024;
parameter_set(Bin) when is_binary(Bin) ->
  case byte_size(Bin) of
    897 -> fn_dsa_512;
    1793 -> fn_dsa_1024;
    1281 -> fn_dsa_512;
    2305 -> fn_dsa_1024;
    _ -> error(badarg)
  end;
parameter_set(_) ->
  error(badarg).

%% ===================================================================
%% Key Generation
%% ===================================================================

%% @doc Generates a fresh FN-DSA keypair from system entropy.
-spec keypair(parameter_set() | atom()) -> keypair().
keypair(Set) ->
  Seed = ecu_compat:strong_rand_bytes(32),
  keypair_from_seed(Set, Seed).

%% @doc Generates an FN-DSA keypair deterministically from a seed binary.
-spec keypair_from_seed(parameter_set() | atom(), binary()) -> keypair().
keypair_from_seed(Set0, Seed) when is_binary(Seed), byte_size(Seed) >= 32 ->
  Set = canonical_set(Set0),
  {N, LogN, _PKHead, _SigHead, _MaxSigLen, _Bound, FGBits, FBits, _SKHead, _SKLen} =
    params(Set),
  SigmaFG = 1.17 * math:sqrt(?FN_DSA_Q / (2 * N)),
  InvSigma = 1.0 / SigmaFG,
  SigmaMin =
    case Set of
      fn_dsa_512 -> 1.2778336969128337;
      fn_dsa_1024 -> 1.298280334344292
    end,
  SeedStream = shake256(Seed, 64 * 8),
  Rng0 = ecu_fn_dsa_fft:prng_init(SeedStream),
  keypair_loop(Set, N, LogN, FGBits, FBits, InvSigma, SigmaMin, Rng0);
keypair_from_seed(_, _) ->
  error(badarg).

-spec keypair_loop(
  parameter_set(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  float(),
  float(),
  ecu_fn_dsa_fft:prng_state()
) -> keypair().
keypair_loop(Set, N, LogN, FGBits, FBits, InvSigma, SigmaMin, Rng0) ->
  {F, Rng1} = sample_fg(Rng0, N, InvSigma, SigmaMin),
  {G, Rng2} = sample_fg(Rng1, N, InvSigma, SigmaMin),
  MinFG = -(1 bsl (FGBits - 1)) + 1,
  MaxFG = (1 bsl (FGBits - 1)) - 1,
  ValidFG =
    lists:all(fun(X) -> X >= MinFG andalso X =< MaxFG end, F) andalso
      lists:all(fun(X) -> X >= MinFG andalso X =< MaxFG end, G),
  case ValidFG of
    false ->
      keypair_loop(Set, N, LogN, FGBits, FBits, InvSigma, SigmaMin, Rng2);
    true ->
      F_mod = list_to_tuple([((X rem ?FN_DSA_Q) + ?FN_DSA_Q) rem ?FN_DSA_Q || X <- F]),
      F_ntt = ntt(F_mod, LogN),
      case lists:any(fun(X) -> X =:= 0 end, tuple_to_list(F_ntt)) of
        true ->
          keypair_loop(Set, N, LogN, FGBits, FBits, InvSigma, SigmaMin, Rng2);
        false ->
          case
            (try
              ntru_solve(F, G)
            catch
              _:_ -> not_coprime
            end)
          of
            not_coprime ->
              keypair_loop(Set, N, LogN, FGBits, FBits, InvSigma, SigmaMin, Rng2);
            {SolF, SolG} ->
              MinF = -(1 bsl (FBits - 1)) + 1,
              MaxF = (1 bsl (FBits - 1)) - 1,
              ValidSolF = lists:all(fun(X) -> X >= MinF andalso X =< MaxF end, SolF),
              ValidSolG = lists:all(fun(X) -> X >= -127 andalso X =< 127 end, SolG),
              case ValidSolF andalso ValidSolG of
                false ->
                  keypair_loop(Set, N, LogN, FGBits, FBits, InvSigma, SigmaMin, Rng2);
                true ->
                  G_mod = list_to_tuple([((X rem ?FN_DSA_Q) + ?FN_DSA_Q) rem ?FN_DSA_Q || X <- G]),
                  G_ntt = ntt(G_mod, LogN),
                  H_ntt = list_to_tuple([
                    (G_i * mod_inv(F_i, ?FN_DSA_Q)) rem ?FN_DSA_Q
                   || {G_i, F_i} <- lists:zip(tuple_to_list(G_ntt), tuple_to_list(F_ntt))
                  ]),
                  H = tuple_to_list(inv_ntt(H_ntt, LogN)),
                  PK = encode_public_key(Set, H),
                  SK = encode_secret_key(Set, F, G, SolF),
                  #{public => PK, secret => SK}
              end
          end
      end
  end.

-spec sample_fg(ecu_fn_dsa_fft:prng_state(), pos_integer(), float(), float()) ->
  {[integer()], ecu_fn_dsa_fft:prng_state()}.
sample_fg(Rng, N, InvSigma, SigmaMin) ->
  sample_fg_loop(Rng, N, InvSigma, SigmaMin, []).

-spec sample_fg_loop(
  ecu_fn_dsa_fft:prng_state(),
  non_neg_integer(),
  float(),
  float(),
  [integer()]
) -> {[integer()], ecu_fn_dsa_fft:prng_state()}.
sample_fg_loop(Rng, 0, _InvSigma, _SigmaMin, Acc) ->
  {lists:reverse(Acc), Rng};
sample_fg_loop(Rng0, Count, InvSigma, SigmaMin, Acc) ->
  {Z, Rng1} = ecu_fn_dsa_fft:sample_z(Rng0, 0.0, InvSigma, SigmaMin),
  sample_fg_loop(Rng1, Count - 1, InvSigma, SigmaMin, [Z | Acc]).

-spec ntru_solve([integer()], [integer()]) -> {[integer()], [integer()]}.
ntru_solve(F, G) ->
  N = length(F),
  if
    N =:= 1 ->
      F0 = hd(F),
      G0 = hd(G),
      {D, U, V} = xgcd(F0, G0),
      case D of
        1 ->
          {[-?FN_DSA_Q * V], [?FN_DSA_Q * U]};
        _ ->
          throw({error, not_coprime})
      end;
    true ->
      Fp = field_norm(F),
      Gp = field_norm(G),
      {Fp_sol, Gp_sol} = ntru_solve(Fp, Gp),
      LiftFp = lift(Fp_sol),
      LiftGp = lift(Gp_sol),
      F_init = negacyclic_mul(LiftFp, galois_conj(G)),
      G_init = negacyclic_mul(LiftGp, galois_conj(F)),
      reduce(F, G, F_init, G_init)
  end.

-spec reduce([integer()], [integer()], [integer()], [integer()]) -> {[integer()], [integer()]}.
reduce(F_poly, G_poly, F, G) ->
  N = length(F_poly),
  LogN = trunc(math:log2(N)),
  Size_fg = lists:max([53, max_bitsize(F_poly), max_bitsize(G_poly)]),
  Shift_fg = max(0, Size_fg - 53),
  F_adj = [float(X bsr Shift_fg) || X <- F_poly],
  G_adj = [float(X bsr Shift_fg) || X <- G_poly],
  Fa_fft = ecu_fn_dsa_fft:fft(list_to_tuple(F_adj), LogN),
  Ga_fft = ecu_fn_dsa_fft:fft(list_to_tuple(G_adj), LogN),
  Den_fft = ecu_fn_dsa_fft:poly_add_fft(
    ecu_fn_dsa_fft:poly_mulselfadj_fft(Fa_fft),
    ecu_fn_dsa_fft:poly_mulselfadj_fft(Ga_fft)
  ),
  reduce_loop(F_poly, G_poly, F, G, Fa_fft, Ga_fft, Den_fft, Size_fg, LogN).

-spec reduce_loop(
  [integer()],
  [integer()],
  [integer()],
  [integer()],
  tuple(),
  tuple(),
  tuple(),
  non_neg_integer(),
  non_neg_integer()
) -> {[integer()], [integer()]}.
reduce_loop(F_poly, G_poly, F, G, Fa_fft, Ga_fft, Den_fft, Size_fg, LogN) ->
  Size_FG = lists:max([53, max_bitsize(F), max_bitsize(G)]),
  if
    Size_FG < Size_fg ->
      {F, G};
    true ->
      Shift_FG = max(0, Size_FG - 53),
      F_adj = [float(X bsr Shift_FG) || X <- F],
      G_adj = [float(X bsr Shift_FG) || X <- G],
      FA_fft = ecu_fn_dsa_fft:fft(list_to_tuple(F_adj), LogN),
      GA_fft = ecu_fn_dsa_fft:fft(list_to_tuple(G_adj), LogN),
      Num_fft = ecu_fn_dsa_fft:poly_add_fft(
        ecu_fn_dsa_fft:poly_muladj_fft(FA_fft, Fa_fft),
        ecu_fn_dsa_fft:poly_muladj_fft(GA_fft, Ga_fft)
      ),
      K_fft = ecu_fn_dsa_fft:poly_div_fft(Num_fft, Den_fft),
      K_real = tuple_to_list(ecu_fn_dsa_fft:inv_fft(K_fft, LogN)),
      K = [
        case X of
          Flt when is_float(Flt) -> round(Flt);
          Int when is_integer(Int) -> Int
        end
       || X <- K_real
      ],
      AllZero = lists:all(fun(X) -> X =:= 0 end, K),
      case AllZero of
        true ->
          {F, G};
        false ->
          Shift = Size_FG - Size_fg,
          Fk = negacyclic_mul(F_poly, K),
          Gk = negacyclic_mul(G_poly, K),
          NewF = [F_i - (Fk_i bsl Shift) || {F_i, Fk_i} <- lists:zip(F, Fk)],
          NewG = [G_i - (Gk_i bsl Shift) || {G_i, Gk_i} <- lists:zip(G, Gk)],
          reduce_loop(F_poly, G_poly, NewF, NewG, Fa_fft, Ga_fft, Den_fft, Size_fg, LogN)
      end
  end.

-spec field_norm([integer()]) -> [integer()].
field_norm(A) ->
  N2 = length(A) div 2,
  Arr = list_to_tuple(A),
  Ae = [
    case element(2 * I + 1, Arr) of
      V when is_integer(V) -> V
    end
   || I <- lists:seq(0, N2 - 1)
  ],
  Ao = [
    case element(2 * I + 2, Arr) of
      V when is_integer(V) -> V
    end
   || I <- lists:seq(0, N2 - 1)
  ],
  Ae2 = negacyclic_mul(Ae, Ae),
  Ao2 = negacyclic_mul(Ao, Ao),
  Res0 = hd(Ae2) + lists:last(Ao2),
  ResRest = [
    lists:nth(I + 2, Ae2) - lists:nth(I + 1, Ao2)
   || I <- lists:seq(0, N2 - 2)
  ],
  [Res0 | ResRest].

-spec lift([integer()]) -> [integer()].
lift(A) ->
  lists:flatten([[X, 0] || X <- A]).

-spec galois_conj([integer()]) -> [integer()].
galois_conj(A) ->
  [
    case I rem 2 of
      0 -> X;
      1 -> -X
    end
   || {X, I} <- lists:zip(A, lists:seq(0, length(A) - 1))
  ].

-spec xgcd(integer(), integer()) -> {integer(), integer(), integer()}.
xgcd(A, 0) when A >= 0 -> {A, 1, 0};
xgcd(A, 0) ->
  {-A, -1, 0};
xgcd(A, B) ->
  {D, U1, V1} = xgcd(B, A rem B),
  {D, V1, U1 - (A div B) * V1}.

-spec negacyclic_mul([integer()], [integer()]) -> [integer()].
negacyclic_mul(A, B) ->
  N = length(A),
  ArrA = list_to_tuple(A),
  ArrB = list_to_tuple(B),
  [conv_coeff(I, N, ArrA, ArrB) || I <- lists:seq(0, N - 1)].

-spec conv_coeff(non_neg_integer(), pos_integer(), tuple(), tuple()) -> integer().
conv_coeff(I, N, ArrA, ArrB) ->
  Sum1 = conv_sum_loop(0, I, I, ArrA, ArrB, 0),
  Sum2 = conv_sum_loop(I + 1, N - 1, I + N, ArrA, ArrB, 0),
  Sum1 - Sum2.

-spec conv_sum_loop(
  non_neg_integer(),
  integer(),
  non_neg_integer(),
  tuple(),
  tuple(),
  integer()
) -> integer().
conv_sum_loop(J, End, _Target, _ArrA, _ArrB, Acc) when J > End ->
  Acc;
conv_sum_loop(J, End, Target, ArrA, ArrB, Acc) ->
  AJ =
    case element(J + 1, ArrA) of
      V1 when is_integer(V1) -> V1
    end,
  BI =
    case element(Target - J + 1, ArrB) of
      V2 when is_integer(V2) -> V2
    end,
  conv_sum_loop(J + 1, End, Target, ArrA, ArrB, Acc + AJ * BI).

-spec max_bitsize([integer()]) -> non_neg_integer().
max_bitsize(L) ->
  lists:max([bit_length(X) || X <- L]).

-spec bit_length(integer()) -> non_neg_integer().
bit_length(0) ->
  0;
bit_length(X) when X < 0 -> bit_length(-X);
bit_length(X) ->
  Bin = binary:encode_unsigned(X),
  case Bin of
    <<HighByte, _/binary>> ->
      (byte_size(Bin) - 1) * 8 + high_bit(HighByte)
  end.

-spec high_bit(non_neg_integer()) -> non_neg_integer().
high_bit(B) when B >= 128 -> 8;
high_bit(B) when B >= 64 -> 7;
high_bit(B) when B >= 32 -> 6;
high_bit(B) when B >= 16 -> 5;
high_bit(B) when B >= 8 -> 4;
high_bit(B) when B >= 4 -> 3;
high_bit(B) when B >= 2 -> 2;
high_bit(B) when B >= 1 -> 1;
high_bit(0) -> 0.

%% ===================================================================
%% Signature Verification
%% ===================================================================

%% @doc Verifies an FN-DSA signature against a message and public key.
-spec verify(binary(), signature(), public_key()) -> boolean().
verify(Msg, Signature, PublicKey) when
  is_binary(Msg), is_binary(Signature), is_binary(PublicKey)
->
  verify(Msg, Signature, PublicKey, <<>>);
verify(_, _, _) ->
  false.

%% @doc Verifies an FN-DSA signature with an explicit parameter set or context binary.
-spec verify(
  parameter_set() | atom() | binary(),
  binary() | signature(),
  signature() | public_key(),
  public_key() | binary()
) -> boolean().
verify(Set, Msg, Signature, PublicKey) when
  is_atom(Set), is_binary(Msg), is_binary(Signature), is_binary(PublicKey)
->
  try canonical_set(Set) of
    CanonSet -> verify_with_set(CanonSet, Msg, Signature, PublicKey, <<>>)
  catch
    _:_ -> false
  end;
verify(Msg, Signature, PublicKey, Context) when
  is_binary(Msg), is_binary(Signature), is_binary(PublicKey), is_binary(Context)
->
  try parameter_set(PublicKey) of
    Set -> verify_with_set(Set, Msg, Signature, PublicKey, Context)
  catch
    _:_ -> false
  end;
verify(_, _, _, _) ->
  false.

-spec verify_with_set(parameter_set(), binary(), signature(), public_key(), binary()) ->
  boolean().
verify_with_set(Set, Msg, Signature, PublicKey, Context) ->
  {N, LogN, ExpectedPKHead, ExpectedSigHead, MaxSigLen, Bound, _FGBits, _FBits, _SKHead, _SKLen} =
    params(Set),
  case byte_size(Signature) =< MaxSigLen andalso byte_size(Context) =< 255 of
    false ->
      false;
    true ->
      case Signature of
        <<ExpectedSigHead:8, Salt:40/binary, CompS2/binary>> ->
          case PublicKey of
            <<ExpectedPKHead:8, RestPK/binary>> when byte_size(RestPK) =:= ((N * 14) div 8) ->
              case decode_modq(RestPK, N) of
                {ok, H} ->
                  case decode_s2(CompS2, N) of
                    {ok, S2} ->
                      ChallengeInput =
                        case Context of
                          <<>> ->
                            <<Salt:40/binary, Msg/binary>>;
                          _ ->
                            <<0:8, (byte_size(Context)):8, Context/binary, Salt:40/binary, Msg/binary>>
                        end,
                      C0 = hash_to_point(ChallengeInput, N),
                      verify_norm(H, S2, C0, N, LogN, Bound);
                    error ->
                      false
                  end;
                error ->
                  false
              end;
            _ ->
              false
          end;
        _ ->
          false
      end
  end.

-spec verify_norm([integer()], [integer()], [integer()], pos_integer(), pos_integer(), pos_integer()) ->
  boolean().
verify_norm(H, S2, C0, N, LogN, Bound) ->
  HTuple = list_to_tuple(H),
  S2Tuple = list_to_tuple([(S rem ?FN_DSA_Q + ?FN_DSA_Q) rem ?FN_DSA_Q || S <- S2]),
  H_Hat = ntt(HTuple, LogN),
  S2_Hat = ntt(S2Tuple, LogN),
  Prod_Hat =
    list_to_tuple([
      (poly_get(I, H_Hat) * poly_get(I, S2_Hat)) rem ?FN_DSA_Q
     || I <- lists:seq(1, N)
    ]),
  Prod = inv_ntt(Prod_Hat, LogN),
  S1 = [
    begin
      Diff = ((C - poly_get(I, Prod)) rem ?FN_DSA_Q + ?FN_DSA_Q) rem ?FN_DSA_Q,
      if
        Diff > (?FN_DSA_Q bsr 1) -> Diff - ?FN_DSA_Q;
        true -> Diff
      end
    end
   || {I, C} <- lists:zip(lists:seq(1, N), C0)
  ],
  NormSq = lists:sum([S * S || S <- S1]) + lists:sum([S * S || S <- S2]),
  NormSq =< Bound.

%% ===================================================================
%% Signature Generation
%% ===================================================================

%% @doc Signs a message with a secret key.
-spec sign(binary(), secret_key()) -> {ok, signature()} | {error, term()}.
sign(Msg, SecretKey) when is_binary(Msg), is_binary(SecretKey) ->
  sign(Msg, SecretKey, #{});
sign(_, _) ->
  {error, badarg}.

%% @doc Signs a message with a secret key and context binary or options map.
-spec sign(binary(), secret_key(), binary() | map()) -> {ok, signature()} | {error, term()}.
sign(Msg, SecretKey, Context) when is_binary(Msg), is_binary(SecretKey), is_binary(Context) ->
  sign(Msg, SecretKey, #{context => Context});
sign(Msg, SecretKey, Opts) when is_binary(Msg), is_binary(SecretKey), is_map(Opts) ->
  try parameter_set(SecretKey) of
    Set ->
      sign(Set, Msg, SecretKey, Opts)
  catch
    _:_ -> {error, invalid_key}
  end;
sign(_, _, _) ->
  {error, badarg}.

%% @doc Signs a message with an explicit parameter set and context or options map.
-spec sign(parameter_set() | atom(), binary(), secret_key(), binary() | map()) ->
  {ok, signature()} | {error, term()}.
sign(Set0, Msg, SecretKey, Context) when is_binary(Context) ->
  sign(Set0, Msg, SecretKey, #{context => Context});
sign(Set0, Msg, SecretKey, Opts) when is_binary(Msg), is_binary(SecretKey), is_map(Opts) ->
  try canonical_set(Set0) of
    Set ->
      Context = maps:get(context, Opts, <<>>),
      case is_binary(Context) andalso byte_size(Context) =< 255 of
        true ->
          do_sign(Set, Msg, SecretKey, Context, Opts);
        false ->
          {error, context_too_long}
      end
  catch
    _:_ -> {error, badarg}
  end;
sign(_, _, _, _) ->
  {error, badarg}.

%% @doc Signs a message deterministically without system randomness.
-spec sign_deterministic(binary(), secret_key()) -> {ok, signature()} | {error, term()}.
sign_deterministic(Msg, SecretKey) when is_binary(Msg), is_binary(SecretKey) ->
  sign_deterministic(Msg, SecretKey, <<>>);
sign_deterministic(_, _) ->
  {error, badarg}.

%% @doc Signs a message deterministically with an optional context string.
-spec sign_deterministic(binary(), secret_key(), binary()) -> {ok, signature()} | {error, term()}.
sign_deterministic(Msg, SecretKey, Context) when
  is_binary(Msg), is_binary(SecretKey), is_binary(Context)
->
  sign(Msg, SecretKey, #{context => Context, deterministic => true});
sign_deterministic(_, _, _) ->
  {error, badarg}.

-spec do_sign(parameter_set(), binary(), secret_key(), binary(), map()) ->
  {ok, signature()} | {error, term()}.
do_sign(Set, Msg, SecretKey, Context, Opts) ->
  case decode_secret_key(SecretKey) of
    {ok, {Set, F, GSmall, FBig, GBig}} ->
      {N, LogN, _PKHead, SigHead, MaxSigLen, Bound, _FGBits, _FBits, _SKHead, _SKLen} =
        params(Set),
      Deterministic = maps:get(deterministic, Opts, false),
      Salt =
        case maps:get(salt, Opts, undefined) of
          CustomSalt when is_binary(CustomSalt), byte_size(CustomSalt) =:= 40 ->
            CustomSalt;
          _ when Deterministic ->
            derive_deterministic_salt(SecretKey, Msg, Context);
          _ ->
            ecu_compat:strong_rand_bytes(40)
        end,
      ChallengeInput =
        case Context of
          <<>> ->
            <<Salt:40/binary, Msg/binary>>;
          _ ->
            <<0:8, (byte_size(Context)):8, Context/binary, Salt:40/binary, Msg/binary>>
        end,
      C0 = hash_to_point(ChallengeInput, N),
      F_Real = list_to_tuple([float(X) || X <- F]),
      G_Real = list_to_tuple([float(X) || X <- GSmall]),
      FBig_Real = list_to_tuple([float(X) || X <- FBig]),
      GBig_Real = list_to_tuple([float(X) || X <- GBig]),
      B01 = ecu_fn_dsa_fft:poly_neg_fft(ecu_fn_dsa_fft:fft(F_Real, LogN)),
      B00 = ecu_fn_dsa_fft:fft(G_Real, LogN),
      B11 = ecu_fn_dsa_fft:poly_neg_fft(ecu_fn_dsa_fft:fft(FBig_Real, LogN)),
      B10 = ecu_fn_dsa_fft:fft(GBig_Real, LogN),
      G00 = ecu_fn_dsa_fft:poly_add_fft(
        ecu_fn_dsa_fft:poly_mulselfadj_fft(B00),
        ecu_fn_dsa_fft:poly_mulselfadj_fft(B01)
      ),
      G01 = ecu_fn_dsa_fft:poly_add_fft(
        ecu_fn_dsa_fft:poly_muladj_fft(B00, B10),
        ecu_fn_dsa_fft:poly_muladj_fft(B01, B11)
      ),
      G11 = ecu_fn_dsa_fft:poly_add_fft(
        ecu_fn_dsa_fft:poly_mulselfadj_fft(B10),
        ecu_fn_dsa_fft:poly_mulselfadj_fft(B11)
      ),
      C0_Real = list_to_tuple([float(X) || X <- C0]),
      HM_FFT = ecu_fn_dsa_fft:fft(C0_Real, LogN),
      InvQ = 1.0 / 12289.0,
      T0 = ecu_fn_dsa_fft:poly_mul_const_fft(ecu_fn_dsa_fft:poly_mul_fft(HM_FFT, B11), InvQ),
      T1 = ecu_fn_dsa_fft:poly_mul_const_fft(ecu_fn_dsa_fft:poly_mul_fft(HM_FFT, B01), -InvQ),
      Seed0 =
        case maps:get(seed, Opts, undefined) of
          CustomSeed when is_binary(CustomSeed), byte_size(CustomSeed) =:= 48 ->
            CustomSeed;
          _ when Deterministic ->
            derive_deterministic_seed(SecretKey, Msg, Salt);
          _ ->
            ecu_compat:strong_rand_bytes(48)
        end,
      sign_sampler_loop(
        Seed0,
        0,
        T0,
        T1,
        G00,
        G01,
        G11,
        B00,
        B01,
        B10,
        B11,
        C0,
        N,
        LogN,
        Bound,
        Salt,
        SigHead,
        MaxSigLen - 41
      );
    error ->
      {error, invalid_key}
  end.

-spec sign_sampler_loop(
  binary(),
  non_neg_integer(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  ecu_fn_dsa_fft:c_poly(),
  [non_neg_integer()],
  pos_integer(),
  pos_integer(),
  pos_integer(),
  binary(),
  byte(),
  pos_integer()
) -> {ok, signature()} | {error, term()}.
sign_sampler_loop(
  _Seed,
  50,
  _T0,
  _T1,
  _G00,
  _G01,
  _G11,
  _B00,
  _B01,
  _B10,
  _B11,
  _C0,
  _N,
  _LogN,
  _Bound,
  _Salt,
  _SigHead,
  _MaxCompLen
) ->
  {error, max_rejections_exceeded};
sign_sampler_loop(
  Seed,
  Iter,
  T0,
  T1,
  G00,
  G01,
  G11,
  B00,
  B01,
  B10,
  B11,
  C0,
  N,
  LogN,
  Bound,
  Salt,
  SigHead,
  MaxCompLen
) ->
  Rng0 = ecu_fn_dsa_fft:prng_init(<<Seed/binary, Iter:32/big>>),
  {{Z0, Z1}, _Rng1} =
    ecu_fn_dsa_fft:ff_sampling_dyntree(Rng0, T0, T1, G00, G01, G11, LogN, LogN),
  TX = ecu_fn_dsa_fft:poly_add_fft(
    ecu_fn_dsa_fft:poly_mul_fft(Z0, B00),
    ecu_fn_dsa_fft:poly_mul_fft(Z1, B10)
  ),
  TY = ecu_fn_dsa_fft:poly_add_fft(
    ecu_fn_dsa_fft:poly_mul_fft(Z0, B01),
    ecu_fn_dsa_fft:poly_mul_fft(Z1, B11)
  ),
  Pt0 = ecu_fn_dsa_fft:inv_fft(TX, LogN),
  Pt1 = ecu_fn_dsa_fft:inv_fft(TY, LogN),
  S1 = [C - round(real_poly_get(I, Pt0)) || {I, C} <- lists:zip(lists:seq(1, N), C0)],
  S2 = [-round(real_poly_get(I, Pt1)) || I <- lists:seq(1, N)],
  NormSq = lists:sum([S * S || S <- S1]) + lists:sum([S * S || S <- S2]),
  case NormSq =< Bound of
    true ->
      case comp_encode(S2, MaxCompLen) of
        {ok, CompS2} ->
          Sig = <<SigHead:8, Salt:40/binary, CompS2/binary>>,
          {ok, Sig};
        error ->
          sign_sampler_loop(
            Seed,
            Iter + 1,
            T0,
            T1,
            G00,
            G01,
            G11,
            B00,
            B01,
            B10,
            B11,
            C0,
            N,
            LogN,
            Bound,
            Salt,
            SigHead,
            MaxCompLen
          )
      end;
    false ->
      sign_sampler_loop(
        Seed,
        Iter + 1,
        T0,
        T1,
        G00,
        G01,
        G11,
        B00,
        B01,
        B10,
        B11,
        C0,
        N,
        LogN,
        Bound,
        Salt,
        SigHead,
        MaxCompLen
      )
  end.

-spec derive_deterministic_salt(secret_key(), binary(), binary()) -> binary().
derive_deterministic_salt(SK, Msg, Context) ->
  Input = <<SK/binary, (byte_size(Context)):16/big, Context/binary, Msg/binary, "fn-dsa-salt">>,
  ecu_compat:hash_xof(shake256, Input, 40 * 8).

-spec derive_deterministic_seed(secret_key(), binary(), binary()) -> binary().
derive_deterministic_seed(SK, Msg, Salt) ->
  Input = <<SK/binary, Salt:40/binary, Msg/binary, "fn-dsa-seed">>,
  ecu_compat:hash_xof(shake256, Input, 48 * 8).

%% ===================================================================
%% Key & Signature Codecs
%% ===================================================================

%% @doc Encodes signed polynomial s2 into unary-extended bitstream.
-spec comp_encode([integer()], pos_integer()) -> {ok, binary()} | error.
comp_encode(S2, MaxLen) when is_list(S2), is_integer(MaxLen), MaxLen > 0 ->
  case comp_encode_loop(S2, <<>>) of
    error ->
      error;
    Comp when byte_size(Comp) =< MaxLen ->
      {ok, Comp};
    _ ->
      error
  end;
comp_encode(_, _) ->
  error.

-spec comp_encode_loop([integer()], bitstring()) -> binary() | error.
comp_encode_loop([], Acc) ->
  PadLen = (8 - (bit_size(Acc) rem 8)) rem 8,
  <<Acc/bitstring, 0:PadLen>>;
comp_encode_loop([X | Rest], Acc) when X >= -2047, X =< 2047 ->
  Sign =
    if
      X < 0 -> 1;
      true -> 0
    end,
  AbsX = abs(X),
  Low7 = AbsX band 127,
  High = AbsX bsr 7,
  comp_encode_loop(Rest, <<Acc/bitstring, Sign:1, Low7:7, 0:High, 1:1>>);
comp_encode_loop(_, _) ->
  error.

%% @doc Decodes binary secret key into its parameter set and polynomials {f, g, F, G}.
-spec decode_secret_key(secret_key()) -> {ok, decoded_secret_key()} | error.
decode_secret_key(SK) when is_binary(SK) ->
  try parameter_set(SK) of
    Set ->
      {N, LogN, _PKHead, _SigHead, _MaxSigLen, _Bound, FGBits, FBits, ExpectedSKHead, ExpectedSKLen} =
        params(Set),
      case SK of
        <<ExpectedSKHead:8, Payload/binary>> when byte_size(SK) =:= ExpectedSKLen ->
          case trim_i8_decode(Payload, N, FGBits) of
            {ok, F, Rest1} ->
              case trim_i8_decode(Rest1, N, FGBits) of
                {ok, GSmall, Rest2} ->
                  case trim_i8_decode(Rest2, N, FBits) of
                    {ok, FBig, <<>>} ->
                      case complete_private(F, GSmall, FBig, N, LogN) of
                        {ok, GBig} ->
                          {ok, {Set, F, GSmall, FBig, GBig}};
                        error ->
                          error
                      end;
                    _ ->
                      error
                  end;
                _ ->
                  error
              end;
            _ ->
              error
          end;
        _ ->
          error
      end
  catch
    _:_ -> error
  end;
decode_secret_key(_) ->
  error.

%% @doc Encodes secret polynomials into binary secret key.
-spec encode_secret_key(parameter_set() | atom(), [integer()], [integer()], [integer()]) ->
  secret_key().
encode_secret_key(Set0, F, GSmall, FBig) when is_list(F), is_list(GSmall), is_list(FBig) ->
  Set = canonical_set(Set0),
  {N, _LogN, _PKHead, _SigHead, _MaxSigLen, _Bound, FGBits, FBits, ExpectedSKHead, _ExpectedSKLen} =
    params(Set),
  case length(F) =:= N andalso length(GSmall) =:= N andalso length(FBig) =:= N of
    true ->
      FBin = trim_i8_encode(F, FGBits),
      GBin = trim_i8_encode(GSmall, FGBits),
      FBigBin = trim_i8_encode(FBig, FBits),
      <<ExpectedSKHead:8, FBin/binary, GBin/binary, FBigBin/binary>>;
    false ->
      error(badarg)
  end.

%% @doc Decodes binary public key into parameter set and polynomial h.
-spec decode_public_key(public_key()) -> {ok, {parameter_set(), [non_neg_integer()]}} | error.
decode_public_key(PK) when is_binary(PK) ->
  try parameter_set(PK) of
    Set ->
      {N, _LogN, ExpectedPKHead, _SigHead, _MaxSigLen, _Bound, _FGBits, _FBits, _SKHead, _SKLen} =
        params(Set),
      ExpectedByteLen = (N * 14) div 8,
      case PK of
        <<ExpectedPKHead:8, PackedModQ:ExpectedByteLen/binary>> ->
          case decode_modq(PackedModQ, N) of
            {ok, H} -> {ok, {Set, H}};
            error -> error
          end;
        _ ->
          error
      end
  catch
    _:_ -> error
  end;
decode_public_key(_) ->
  error.

%% @doc Encodes public key polynomial h into binary public key.
-spec encode_public_key(parameter_set() | atom(), [non_neg_integer()]) -> public_key().
encode_public_key(Set0, H) when is_list(H) ->
  Set = canonical_set(Set0),
  {N, _LogN, ExpectedPKHead, _SigHead, _MaxSigLen, _Bound, _FGBits, _FBits, _SKHead, _SKLen} =
    params(Set),
  case length(H) =:= N andalso lists:all(fun(W) -> W >= 0 andalso W < ?FN_DSA_Q end, H) of
    true ->
      Packed = <<<<W:14>> || W <- H>>,
      <<ExpectedPKHead:8, Packed/binary>>;
    false ->
      error(badarg)
  end.

-spec complete_private([integer()], [integer()], [integer()], pos_integer(), pos_integer()) ->
  {ok, [integer()]} | error.
complete_private(F, GSmall, FBig, N, LogN) ->
  FTuple = list_to_tuple([(X rem ?FN_DSA_Q + ?FN_DSA_Q) rem ?FN_DSA_Q || X <- F]),
  GTuple = list_to_tuple([(X rem ?FN_DSA_Q + ?FN_DSA_Q) rem ?FN_DSA_Q || X <- GSmall]),
  FBigTuple = list_to_tuple([(X rem ?FN_DSA_Q + ?FN_DSA_Q) rem ?FN_DSA_Q || X <- FBig]),
  F_Hat = ntt(FTuple, LogN),
  G_Hat = ntt(GTuple, LogN),
  FBig_Hat = ntt(FBigTuple, LogN),
  try
    GBig_Hat = list_to_tuple([
      begin
        FVal = poly_get(I, F_Hat),
        case FVal of
          0 ->
            throw(not_invertible);
          _ ->
            InvF = mod_inv(FVal, ?FN_DSA_Q),
            (poly_get(I, G_Hat) * poly_get(I, FBig_Hat) rem ?FN_DSA_Q * InvF) rem ?FN_DSA_Q
        end
      end
     || I <- lists:seq(1, N)
    ]),
    GBig_Poly = inv_ntt(GBig_Hat, LogN),
    GBig = [
      begin
        W = poly_get(I, GBig_Poly),
        Val =
          if
            W > (?FN_DSA_Q bsr 1) -> W - ?FN_DSA_Q;
            true -> W
          end,
        if
          Val < -127 orelse Val > 127 -> throw(out_of_range);
          true -> Val
        end
      end
     || I <- lists:seq(1, N)
    ],
    {ok, GBig}
  catch
    throw:_ -> error
  end.

%% @doc Computes modular inverse using extended Euclidean algorithm.
-spec mod_inv(integer(), pos_integer()) -> non_neg_integer().
mod_inv(A, M) ->
  {G, X, _} = egcd((A rem M + M) rem M, M),
  case G of
    1 -> (X rem M + M) rem M;
    _ -> error({no_inverse, A, M})
  end.

-spec egcd(integer(), integer()) -> {integer(), integer(), integer()}.
egcd(0, B) ->
  {B, 0, 1};
egcd(A, B) ->
  {G, X1, Y1} = egcd(B rem A, A),
  {G, Y1 - (B div A) * X1, X1}.

-spec trim_i8_decode(binary(), pos_integer(), pos_integer()) ->
  {ok, [integer()], binary()} | error.
trim_i8_decode(Bin, N, Bits) ->
  ByteLen = (N * Bits) div 8,
  case Bin of
    <<Payload:ByteLen/binary, Rest/binary>> ->
      try trim_i8_decode_loop(Payload, N, Bits, 1 bsl (Bits - 1), 1 bsl Bits, []) of
        Coeffs -> {ok, Coeffs, Rest}
      catch
        throw:invalid -> error
      end;
    _ ->
      error
  end.

-spec trim_i8_decode_loop(
  bitstring(), non_neg_integer(), pos_integer(), pos_integer(), pos_integer(), [integer()]
) -> [integer()].
trim_i8_decode_loop(_Rest, 0, _Bits, _Forbidden, _Mod, Acc) ->
  lists:reverse(Acc);
trim_i8_decode_loop(Bin, Count, Bits, Forbidden, Mod, Acc) when Count > 0 ->
  case Bin of
    <<Raw:Bits, Rest/bitstring>> ->
      if
        Raw =:= Forbidden ->
          throw(invalid);
        Raw >= Forbidden ->
          trim_i8_decode_loop(Rest, Count - 1, Bits, Forbidden, Mod, [Raw - Mod | Acc]);
        true ->
          trim_i8_decode_loop(Rest, Count - 1, Bits, Forbidden, Mod, [Raw | Acc])
      end;
    _ ->
      throw(invalid)
  end;
trim_i8_decode_loop(_, _, _, _, _, _) ->
  throw(invalid).

-spec trim_i8_encode([integer()], pos_integer()) -> binary().
trim_i8_encode(Coeffs, Bits) ->
  Forbidden = 1 bsl (Bits - 1),
  Mod = 1 bsl Bits,
  trim_i8_encode_loop(Coeffs, Bits, Forbidden, Mod, <<>>).

-spec trim_i8_encode_loop([integer()], pos_integer(), pos_integer(), pos_integer(), bitstring()) ->
  binary().
trim_i8_encode_loop([], _Bits, _Forbidden, _Mod, Acc) ->
  Acc;
trim_i8_encode_loop([X | Rest], Bits, Forbidden, Mod, Acc) ->
  if
    X =< -Forbidden orelse X >= Forbidden ->
      error(badarg);
    X < 0 ->
      Raw = X + Mod,
      trim_i8_encode_loop(Rest, Bits, Forbidden, Mod, <<Acc/bitstring, Raw:Bits>>);
    true ->
      trim_i8_encode_loop(Rest, Bits, Forbidden, Mod, <<Acc/bitstring, X:Bits>>)
  end.

%% ===================================================================
%% Internal Helpers: Parameters & Decoding
%% ===================================================================

-spec canonical_set(atom()) -> parameter_set().
canonical_set(fn_dsa_512) -> fn_dsa_512;
canonical_set(falcon512) -> fn_dsa_512;
canonical_set(fn_dsa_1024) -> fn_dsa_1024;
canonical_set(falcon1024) -> fn_dsa_1024;
canonical_set(_) -> error(badarg).

-spec params(parameter_set()) ->
  {
    pos_integer(),
    pos_integer(),
    byte(),
    byte(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    byte(),
    pos_integer()
  }.
params(fn_dsa_512) ->
  {512, 9, 16#09, 16#39, 666, ?BOUND_512, 6, 8, 16#59, 1281};
params(fn_dsa_1024) ->
  {1024, 10, 16#0A, 16#3A, 1280, ?BOUND_1024, 5, 8, 16#5A, 2305}.

-spec decode_modq(binary(), pos_integer()) -> {ok, [non_neg_integer()]} | error.
decode_modq(Bin, N) ->
  Coeffs = [W || <<W:14>> <= Bin],
  case length(Coeffs) =:= N andalso lists:all(fun(W) -> W < ?FN_DSA_Q end, Coeffs) of
    true -> {ok, Coeffs};
    false -> error
  end.

-spec decode_s2(binary(), pos_integer()) -> {ok, [integer()]} | error.
decode_s2(Bin, N) ->
  try decode_s2_loop(Bin, 0, N, []) of
    Coeffs -> {ok, Coeffs}
  catch
    _:_ -> error
  end.

-spec decode_s2_loop(bitstring(), non_neg_integer(), pos_integer(), [integer()]) -> [integer()].
decode_s2_loop(<<Sign:1, Low7:7, RestBits/bitstring>>, Count, N, Acc) when Count < N ->
  {Val, RemBits} = decode_unary(RestBits, Low7),
  case Val of
    0 when Sign =:= 1 ->
      error(negative_zero);
    _ ->
      SignedVal =
        if
          Sign =:= 1 -> -Val;
          true -> Val
        end,
      decode_s2_loop(RemBits, Count + 1, N, [SignedVal | Acc])
  end;
decode_s2_loop(RemainingBits, Count, N, Acc) when Count =:= N ->
  RemSize = bit_size(RemainingBits),
  if
    RemSize > 7 ->
      error(overlong_trailing_bits);
    RemSize > 0 ->
      <<ZeroBits:RemSize>> = RemainingBits,
      if
        ZeroBits =/= 0 -> error(nonzero_padding);
        true -> lists:reverse(Acc)
      end;
    true ->
      lists:reverse(Acc)
  end;
decode_s2_loop(_, _, _, _) ->
  error(insufficient_bits).

-spec decode_unary(bitstring(), non_neg_integer()) -> {non_neg_integer(), bitstring()}.
decode_unary(<<0:1, Rest/bitstring>>, M) ->
  if
    M + 128 > 2047 -> error(out_of_bounds);
    true -> decode_unary(Rest, M + 128)
  end;
decode_unary(<<1:1, Rest/bitstring>>, M) ->
  {M, Rest};
decode_unary(<<>>, _M) ->
  error(unexpected_eof).

%% ===================================================================
%% Hash to Point (Challenge Polynomial Generation)
%% ===================================================================

-spec hash_to_point(binary(), pos_integer()) -> [non_neg_integer()].
hash_to_point(Data, N) ->
  hash_to_point_stream(Data, N, N * 2 + 128).

-spec hash_to_point_stream(binary(), pos_integer(), pos_integer()) -> [non_neg_integer()].
hash_to_point_stream(Data, N, ByteLen) ->
  Bytes = shake256(Data, ByteLen * 8),
  case rej_hash_to_point(Bytes, [], 0, N) of
    {ok, Coeffs} ->
      Coeffs;
    need_more ->
      hash_to_point_stream(Data, N, ByteLen + 256)
  end.

-spec rej_hash_to_point(binary(), [non_neg_integer()], non_neg_integer(), pos_integer()) ->
  {ok, [non_neg_integer()]} | need_more.
rej_hash_to_point(<<W:16, Rest/binary>>, Acc, Count, N) when Count < N ->
  if
    W < 61445 ->
      rej_hash_to_point(Rest, [W rem ?FN_DSA_Q | Acc], Count + 1, N);
    true ->
      rej_hash_to_point(Rest, Acc, Count, N)
  end;
rej_hash_to_point(_, Acc, Count, N) when Count =:= N ->
  {ok, lists:reverse(Acc)};
rej_hash_to_point(_, _Acc, _Count, _N) ->
  need_more.

-spec shake256(binary(), pos_integer()) -> binary().
shake256(Data, BitLen) ->
  ecu_compat:hash_xof(shake256, Data, BitLen).

%% ===================================================================
%% Number Theoretic Transform (NTT) in Z_q[x] / (x^n + 1)
%% ===================================================================

-spec ntt(tuple(), pos_integer()) -> tuple().
ntt(Arr, LogN) ->
  N = 1 bsl LogN,
  ntt_m_loop(1, N, Arr, LogN).

-spec ntt_m_loop(pos_integer(), pos_integer(), tuple(), pos_integer()) -> tuple().
ntt_m_loop(M, T, A, LogN) when M < (1 bsl LogN) ->
  HT = T bsr 1,
  ANext = ntt_i_loop(0, 0, M, HT, T, A),
  ntt_m_loop(M bsl 1, HT, ANext, LogN);
ntt_m_loop(_M, _T, A, _LogN) ->
  A.

-spec ntt_i_loop(
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  tuple()
) -> tuple().
ntt_i_loop(I, J1, M, HT, T, A) when I < M ->
  S = zeta(M + I),
  J2 = J1 + HT,
  ANext = ntt_j_loop(J1, J2, HT, S, A),
  ntt_i_loop(I + 1, J1 + T, M, HT, T, ANext);
ntt_i_loop(_I, _J1, _M, _HT, _T, A) ->
  A.

-spec poly_get(pos_integer(), tuple()) -> integer().
poly_get(Idx, Tuple) ->
  case element(Idx, Tuple) of
    V when is_integer(V) -> V
  end.

-spec real_poly_get(pos_integer(), tuple()) -> float().
real_poly_get(Idx, Tuple) ->
  case element(Idx, Tuple) of
    V when is_float(V) -> V
  end.

-spec ntt_j_loop(non_neg_integer(), non_neg_integer(), pos_integer(), integer(), tuple()) -> tuple().
ntt_j_loop(J, J2, HT, S, A) when J < J2 ->
  U = poly_get(J + 1, A),
  V = (poly_get(J + HT + 1, A) * S) rem ?FN_DSA_Q,
  A1 = setelement(J + 1, A, (U + V) rem ?FN_DSA_Q),
  A2 = setelement(J + HT + 1, A1, (U - V + ?FN_DSA_Q) rem ?FN_DSA_Q),
  ntt_j_loop(J + 1, J2, HT, S, A2);
ntt_j_loop(_J, _J2, _HT, _S, A) ->
  A.

-spec inv_ntt(tuple(), pos_integer()) -> tuple().
inv_ntt(Arr, LogN) ->
  N = 1 bsl LogN,
  A_Inv = inv_ntt_m_loop(N, 1, Arr),
  NInv =
    case LogN of
      9 -> 12265;
      10 -> 12277
    end,
  list_to_tuple([(poly_get(I, A_Inv) * NInv) rem ?FN_DSA_Q || I <- lists:seq(1, N)]).

-spec inv_ntt_m_loop(pos_integer(), pos_integer(), tuple()) -> tuple().
inv_ntt_m_loop(M, T, A) when M > 1 ->
  HM = M bsr 1,
  DT = T bsl 1,
  ANext = inv_ntt_i_loop(0, 0, HM, T, DT, A),
  inv_ntt_m_loop(HM, DT, ANext);
inv_ntt_m_loop(_M, _T, A) ->
  A.

-spec inv_ntt_i_loop(
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  tuple()
) -> tuple().
inv_ntt_i_loop(I, J1, HM, T, DT, A) when I < HM ->
  S = inv_zeta(HM + I),
  J2 = J1 + T,
  ANext = inv_ntt_j_loop(J1, J2, T, S, A),
  inv_ntt_i_loop(I + 1, J1 + DT, HM, T, DT, ANext);
inv_ntt_i_loop(_I, _J1, _HM, _T, _DT, A) ->
  A.

-spec inv_ntt_j_loop(non_neg_integer(), non_neg_integer(), pos_integer(), integer(), tuple()) -> tuple().
inv_ntt_j_loop(J, J2, T, S, A) when J < J2 ->
  U = poly_get(J + 1, A),
  V = poly_get(J + T + 1, A),
  A1 = setelement(J + 1, A, (U + V) rem ?FN_DSA_Q),
  W = (U - V + ?FN_DSA_Q) rem ?FN_DSA_Q,
  A2 = setelement(J + T + 1, A1, (W * S) rem ?FN_DSA_Q),
  inv_ntt_j_loop(J + 1, J2, T, S, A2);
inv_ntt_j_loop(_J, _J2, _T, _S, A) ->
  A.

%% ===================================================================
%% Roots of Unity Tables (Bit-Reversed over 10 bits)
%% ===================================================================

-compile({inline, [zeta/1, inv_zeta/1, poly_get/2, real_poly_get/2]}).

-spec zeta(non_neg_integer()) -> integer().
zeta(Idx) ->
  poly_get(Idx + 1, zetas_table()).

-spec inv_zeta(non_neg_integer()) -> integer().
inv_zeta(Idx) ->
  poly_get(Idx + 1, inv_zetas_table()).

-spec zetas_table() -> tuple().
zetas_table() ->
  case persistent_term:get({?MODULE, zetas}, undefined) of
    undefined ->
      Table =
        list_to_tuple([
          mod_exp(?ROOT_G, bit_rev10(I), ?FN_DSA_Q)
         || I <- lists:seq(0, 1023)
        ]),
      persistent_term:put({?MODULE, zetas}, Table),
      Table;
    Table ->
      Table
  end.

-spec inv_zetas_table() -> tuple().
inv_zetas_table() ->
  case persistent_term:get({?MODULE, inv_zetas}, undefined) of
    undefined ->
      Table =
        list_to_tuple([
          mod_exp(?INV_ROOT_G, bit_rev10(I), ?FN_DSA_Q)
         || I <- lists:seq(0, 1023)
        ]),
      persistent_term:put({?MODULE, inv_zetas}, Table),
      Table;
    Table ->
      Table
  end.

-spec bit_rev10(non_neg_integer()) -> non_neg_integer().
bit_rev10(X) ->
  <<B0:1, B1:1, B2:1, B3:1, B4:1, B5:1, B6:1, B7:1, B8:1, B9:1>> = <<X:10>>,
  <<Y:10>> = <<B9:1, B8:1, B7:1, B6:1, B5:1, B4:1, B3:1, B2:1, B1:1, B0:1>>,
  Y.

-spec mod_exp(integer(), non_neg_integer(), pos_integer()) -> integer().
mod_exp(_Base, 0, _Mod) ->
  1;
mod_exp(Base, Exp, Mod) when Exp rem 2 =:= 0 ->
  Half = mod_exp(Base, Exp div 2, Mod),
  (Half * Half) rem Mod;
mod_exp(Base, Exp, Mod) ->
  (Base * mod_exp(Base, Exp - 1, Mod)) rem Mod.
