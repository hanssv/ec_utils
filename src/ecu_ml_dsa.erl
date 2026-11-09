%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang implementation of ML-DSA (FIPS 204).
%%%
%%% Module-Lattice-Based Digital Signature Standard (ML-DSA), formerly known
%%% as CRYSTALS-Dilithium, standardized in NIST FIPS 204 (August 2024).
%%%
%%% Supported parameter sets:
%%%   - `ml_dsa_44' (or `mldsa44'): NIST Security Category 2
%%%   - `ml_dsa_65' (or `mldsa65'): NIST Security Category 3
%%%   - `ml_dsa_87' (or `mldsa87'): NIST Security Category 5
%%%
%%% Provides key generation (`keypair/1', `keypair_from_seed/2'), randomized
%%% signing (`sign/2,3'), deterministic signing (`sign_deterministic/2,3'),
%%% and verification (`verify/3,4') with zero external C/NIF dependencies.
%%%
%%% Reference:
%%%   NIST FIPS 204: Module-Lattice-Based Digital Signature Standard (August 2024)
%%%   https://doi.org/10.6028/NIST.FIPS.204
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_ml_dsa).

-typing([eqwalizer]).

-include("ecu_ml_dsa.hrl").

-export([
  keypair/1,
  keypair_from_seed/2,
  sign/2,
  sign/3,
  sign_deterministic/2,
  sign_deterministic/3,
  verify/3,
  verify/4,
  parameter_set/1
]).

-ifdef(TEST).
-export([
  ntt/1,
  inv_ntt/1,
  sample_in_ball/2,
  rej_ntt_poly/3,
  rej_bounded_poly/3,
  power2round/1,
  decompose/2,
  make_hint/3,
  use_hint/3,
  pk_encode/2,
  pk_decode/2,
  sk_encode/7,
  sk_decode/2,
  sig_encode/6,
  sig_decode/2
]).
-endif.

-type parameter_set() ::
  ml_dsa_44 | ml_dsa_65 | ml_dsa_87 | mldsa44 | mldsa65 | mldsa87.

-type public_key() :: binary().
-type secret_key() :: binary().
-type signature() :: binary().
-type keypair() :: #{public := public_key(), secret := secret_key()}.
-type sign_options() :: #{
  context => binary(),
  rnd => binary()
}.

-type poly_tuple() :: tuple().

-export_type([
  parameter_set/0,
  public_key/0,
  secret_key/0,
  signature/0,
  keypair/0,
  sign_options/0
]).

%% ===================================================================
%% Public API
%% ===================================================================

%% @doc Generates a fresh ML-DSA public and secret keypair from system entropy.
-spec keypair(parameter_set()) -> keypair().
keypair(Set) ->
  Seed = ecu_compat:strong_rand_bytes(32),
  keypair_from_seed(Set, Seed).

%% @doc Generates an ML-DSA keypair deterministically from a 32-byte seed.
%% Follows FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal).
-spec keypair_from_seed(parameter_set(), binary()) -> keypair().
keypair_from_seed(Set, Seed) when is_binary(Seed), byte_size(Seed) =:= 32 ->
  {K, L, Eta, _Tau, _Beta, _Gam1, _Gam2, _Omega, _Lam4} = params(Set),
  SE = shake256(<<Seed/binary, K:8, L:8>>, 128 * 8),
  <<Rho:32/binary, RhoPrime:64/binary, KeyK:32/binary>> = SE,
  MatrixA_hat = expand_a(Rho, K, L),
  {S1, S2} = expand_s(RhoPrime, K, L, Eta),
  S1_hat = [ntt(normalize_poly(S)) || S <- S1],
  T_hat = [
    lists:foldl(
      fun({A_elem, S_elem}, AccP) -> add_poly(AccP, mul_ntt(A_elem, S_elem)) end,
      zero_poly(),
      lists:zip(Row, S1_hat)
    )
   || Row <- MatrixA_hat
  ],
  T = [
    add_poly(inv_ntt(lists:nth(I, T_hat)), normalize_poly(lists:nth(I, S2)))
   || I <- lists:seq(1, K)
  ],
  RoundResults = [power2round(lists:nth(I, T)) || I <- lists:seq(1, K)],
  T1 = [R1 || {R1, _} <- RoundResults],
  T0 = [R0 || {_, R0} <- RoundResults],
  PK = pk_encode(Rho, T1),
  TR = shake256(PK, 64 * 8),
  SK = sk_encode(Rho, KeyK, TR, S1, S2, T0, Eta),
  #{public => PK, secret => SK};
keypair_from_seed(_, _) ->
  error(badarg).

%% @doc Signs a message using randomized signing (FIPS 204 Algorithm 2).
%% Infers parameter set from secret key size with default empty context.
-spec sign(binary(), secret_key()) -> signature().
sign(Msg, SecretKey) when is_binary(Msg), is_binary(SecretKey) ->
  sign(Msg, SecretKey, #{}).

%% @doc Signs a message with explicit parameter set or options / context.
-spec sign(
  parameter_set() | binary(), binary() | secret_key(), secret_key() | binary() | sign_options()
) ->
  signature().
sign(Set, Msg, SecretKey) when is_atom(Set), is_binary(Msg), is_binary(SecretKey) ->
  sign_internal(canonical_set(Set), Msg, SecretKey, #{});
sign(Msg, SecretKey, Context) when is_binary(Msg), is_binary(SecretKey), is_binary(Context) ->
  sign(Msg, SecretKey, #{context => Context});
sign(Msg, SecretKey, Opts) when is_binary(Msg), is_binary(SecretKey), is_map(Opts) ->
  Set = parameter_set_from_sk(SecretKey),
  sign_internal(Set, Msg, SecretKey, Opts);
sign(_, _, _) ->
  error(badarg).

%% @doc Signs a message deterministically (FIPS 204 Algorithm 2 with rnd = 0^32).
-spec sign_deterministic(binary(), secret_key()) -> signature().
sign_deterministic(Msg, SecretKey) when is_binary(Msg), is_binary(SecretKey) ->
  sign_deterministic(Msg, SecretKey, <<>>).

%% @doc Signs a message deterministically with specified context binary.
-spec sign_deterministic(binary(), secret_key(), binary()) -> signature().
sign_deterministic(Msg, SecretKey, Context) when
  is_binary(Msg), is_binary(SecretKey), is_binary(Context)
->
  Set = parameter_set_from_sk(SecretKey),
  sign_internal(Set, Msg, SecretKey, #{context => Context, rnd => <<0:256>>});
sign_deterministic(_, _, _) ->
  error(badarg).

%% @doc Verifies an ML-DSA signature over a message with empty context (FIPS 204 Algorithm 3).
-spec verify(binary(), signature(), public_key()) -> boolean().
verify(Msg, Signature, PublicKey) when
  is_binary(Msg), is_binary(Signature), is_binary(PublicKey)
->
  verify(Msg, Signature, PublicKey, <<>>);
verify(_, _, _) ->
  false.

%% @doc Verifies an ML-DSA signature with explicit parameter set or context binary.
-spec verify(
  parameter_set() | binary(), binary() | signature(), signature() | public_key(), public_key() | binary()
) ->
  boolean().
verify(Set, Msg, Signature, PublicKey) when
  is_atom(Set), is_binary(Msg), is_binary(Signature), is_binary(PublicKey)
->
  verify_with_set(canonical_set(Set), Msg, Signature, PublicKey, <<>>);
verify(Msg, Signature, PublicKey, Context) when
  is_binary(Msg), is_binary(Signature), is_binary(PublicKey), is_binary(Context)
->
  try parameter_set_from_pk(PublicKey) of
    Set ->
      verify_with_set(Set, Msg, Signature, PublicKey, Context)
  catch
    _:_ ->
      false
  end;
verify(_, _, _, _) ->
  false.

%% @doc Determines the canonical parameter set from an atom, key, or signature binary.
-spec parameter_set(parameter_set() | public_key() | secret_key() | signature()) -> parameter_set().
parameter_set(Set) when is_atom(Set) ->
  canonical_set(Set);
parameter_set(KeyOrSig) when is_binary(KeyOrSig) ->
  case byte_size(KeyOrSig) of
    1312 -> ml_dsa_44;
    1952 -> ml_dsa_65;
    2592 -> ml_dsa_87;
    2560 -> ml_dsa_44;
    4032 -> ml_dsa_65;
    4896 -> ml_dsa_87;
    2420 -> ml_dsa_44;
    3309 -> ml_dsa_65;
    4627 -> ml_dsa_87;
    _ -> error(badarg)
  end;
parameter_set(_) ->
  error(badarg).

%% ===================================================================
%% Core Signing & Verification Routines
%% ===================================================================

-spec sign_internal(parameter_set(), binary(), secret_key(), sign_options()) -> signature().
sign_internal(Set, Msg, SecretKey, Opts) ->
  Context = maps:get(context, Opts, <<>>),
  if
    byte_size(Context) > 255 ->
      error(badarg);
    true ->
      ok
  end,
  Rnd =
    case maps:find(rnd, Opts) of
      {ok, RndBytes} when is_binary(RndBytes), byte_size(RndBytes) =:= 32 ->
        RndBytes;
      _ ->
        ecu_compat:strong_rand_bytes(32)
    end,
  {K, L, _Eta, Tau, Beta, Gam1, Gam2, Omega, Lam4} = params(Set),
  {Rho, KeyK, TR, S1, S2, T0} = sk_decode(SecretKey, Set),
  MatrixA_hat = expand_a(Rho, K, L),
  S1_hat = [ntt(normalize_poly(S)) || S <- S1],
  S2_hat = [ntt(normalize_poly(S)) || S <- S2],
  T0_hat = [ntt(normalize_poly(S)) || S <- T0],
  %% Format M' = 0 || |ctx| || ctx || M (FIPS 204 Algorithm 2)
  CtxLen = byte_size(Context),
  MPrime = <<0:8, CtxLen:8, Context/binary, Msg/binary>>,
  Mu = shake256(<<TR:64/binary, MPrime/binary>>, 64 * 8),
  RhoPrimePrime = shake256(<<KeyK:32/binary, Rnd:32/binary, Mu:64/binary>>, 64 * 8),
  sign_loop(
    0,
    RhoPrimePrime,
    MatrixA_hat,
    S1_hat,
    S2_hat,
    T0_hat,
    Mu,
    K,
    L,
    Tau,
    Beta,
    Gam1,
    Gam2,
    Omega,
    Lam4
  ).

-spec sign_loop(
  non_neg_integer(),
  binary(),
  [[poly_tuple()]],
  [poly_tuple()],
  [poly_tuple()],
  [poly_tuple()],
  binary(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer()
) -> signature().
sign_loop(
  Kappa,
  RhoPrimePrime,
  MatrixA_hat,
  S1_hat,
  S2_hat,
  T0_hat,
  Mu,
  K,
  L,
  Tau,
  Beta,
  Gam1,
  Gam2,
  Omega,
  Lam4
) ->
  Y = expand_mask(RhoPrimePrime, Kappa, Gam1, L),
  Y_hat = [ntt(normalize_poly(Yi)) || Yi <- Y],
  W_hat = [
    lists:foldl(
      fun({A_elem, Y_elem}, AccP) -> add_poly(AccP, mul_ntt(A_elem, Y_elem)) end,
      zero_poly(),
      lists:zip(Row, Y_hat)
    )
   || Row <- MatrixA_hat
  ],
  W = [inv_ntt(Wi_hat) || Wi_hat <- W_hat],
  W1 = [high_bits(lists:nth(I, W), Gam2) || I <- lists:seq(1, K)],
  W1_encoded = w1_encode(W1, Gam2),
  CTilde = shake256(<<Mu:64/binary, W1_encoded/binary>>, Lam4 * 8),
  C = sample_in_ball(CTilde, Tau),
  C_hat = ntt(normalize_poly(C)),
  CS1 = [inv_ntt(mul_ntt(C_hat, lists:nth(I, S1_hat))) || I <- lists:seq(1, L)],
  CS2 = [inv_ntt(mul_ntt(C_hat, lists:nth(I, S2_hat))) || I <- lists:seq(1, K)],
  Z = [add_poly(normalize_poly(lists:nth(I, Y)), lists:nth(I, CS1)) || I <- lists:seq(1, L)],
  R0 = [low_bits(sub_poly(lists:nth(I, W), lists:nth(I, CS2)), Gam2) || I <- lists:seq(1, K)],
  Z_norm = inf_norm_vector(Z),
  R0_norm = inf_norm_vector(R0),
  if
    Z_norm >= Gam1 - Beta orelse R0_norm >= Gam2 - Beta ->
      sign_loop(
        Kappa + L,
        RhoPrimePrime,
        MatrixA_hat,
        S1_hat,
        S2_hat,
        T0_hat,
        Mu,
        K,
        L,
        Tau,
        Beta,
        Gam1,
        Gam2,
        Omega,
        Lam4
      );
    true ->
      CT0 = [inv_ntt(mul_ntt(C_hat, lists:nth(I, T0_hat))) || I <- lists:seq(1, K)],
      CT0_neg = [neg_poly(lists:nth(I, CT0)) || I <- lists:seq(1, K)],
      H_R = [
        add_poly(sub_poly(lists:nth(I, W), lists:nth(I, CS2)), lists:nth(I, CT0))
       || I <- lists:seq(1, K)
      ],
      H = [make_hint(lists:nth(I, CT0_neg), lists:nth(I, H_R), Gam2) || I <- lists:seq(1, K)],
      H_weight = weight_hint(H),
      CT0_norm = inf_norm_vector(CT0),
      if
        CT0_norm >= Gam2 orelse H_weight > Omega ->
          sign_loop(
            Kappa + L,
            RhoPrimePrime,
            MatrixA_hat,
            S1_hat,
            S2_hat,
            T0_hat,
            Mu,
            K,
            L,
            Tau,
            Beta,
            Gam1,
            Gam2,
            Omega,
            Lam4
          );
        true ->
          %% Normalize z coefficients to modpm range
          Z_modpm = [
            list_to_tuple([modpm(poly_get(Idx, Zi), ?ML_DSA_Q) || Idx <- lists:seq(1, 256)])
           || Zi <- Z
          ],
          sig_encode(CTilde, Z_modpm, H, Gam1, Omega, K)
      end
  end.

-spec verify_with_set(parameter_set(), binary(), signature(), public_key(), binary()) -> boolean().
verify_with_set(Set, Msg, Signature, PublicKey, Context) ->
  if
    byte_size(Context) > 255 ->
      false;
    true ->
      {K, L, _Eta, Tau, Beta, Gam1, Gam2, _Omega, Lam4} = params(Set),
      ExpectedSigSize = signature_size(Set),
      ExpectedPKSize = public_key_size(Set),
      if
        byte_size(Signature) =/= ExpectedSigSize orelse byte_size(PublicKey) =/= ExpectedPKSize ->
          false;
        true ->
          case sig_decode(Signature, Set) of
            {ok, {CTilde, Z, H}} ->
              Z_norm = inf_norm_vector(Z),
              if
                Z_norm >= Gam1 - Beta ->
                  false;
                true ->
                  {Rho, T1} = pk_decode(PublicKey, K),
                  MatrixA_hat = expand_a(Rho, K, L),
                  TR = shake256(PublicKey, 64 * 8),
                  CtxLen = byte_size(Context),
                  MPrime = <<0:8, CtxLen:8, Context/binary, Msg/binary>>,
                  Mu = shake256(<<TR:64/binary, MPrime/binary>>, 64 * 8),
                  C = sample_in_ball(CTilde, Tau),
                  C_hat = ntt(normalize_poly(C)),
                  Z_hat = [ntt(normalize_poly(Zi)) || Zi <- Z],
                  WPrime_hat = [
                    lists:foldl(
                      fun({A_elem, Z_elem}, AccP) ->
                        add_poly(AccP, mul_ntt(A_elem, Z_elem))
                      end,
                      zero_poly(),
                      lists:zip(Row, Z_hat)
                    )
                   || Row <- MatrixA_hat
                  ],
                  T1_Shifted = [
                    list_to_tuple([
                      (poly_get(Idx, T1i) bsl 13) rem ?ML_DSA_Q
                     || Idx <- lists:seq(1, 256)
                    ])
                   || T1i <- T1
                  ],
                  T1_hat = [ntt(T1s) || T1s <- T1_Shifted],
                  CT1_hat = [mul_ntt(C_hat, lists:nth(I, T1_hat)) || I <- lists:seq(1, K)],
                  WPrime_approx = [
                    inv_ntt(sub_poly(lists:nth(I, WPrime_hat), lists:nth(I, CT1_hat)))
                   || I <- lists:seq(1, K)
                  ],
                  W1Prime = [
                    use_hint(lists:nth(I, H), lists:nth(I, WPrime_approx), Gam2)
                   || I <- lists:seq(1, K)
                  ],
                  W1Prime_encoded = w1_encode(W1Prime, Gam2),
                  CTildePrime = shake256(<<Mu:64/binary, W1Prime_encoded/binary>>, Lam4 * 8),
                  CTilde =:= CTildePrime
              end;
            error ->
              false
          end
      end
  end.

%% ===================================================================
%% NTT & Polynomial Arithmetic
%% ===================================================================

-spec poly_get(pos_integer(), tuple()) -> integer().
poly_get(Idx, Tuple) ->
  case element(Idx, Tuple) of
    V when is_integer(V) -> V
  end.

-spec ntt(poly_tuple()) -> poly_tuple().
ntt(W0) ->
  PolyLoop = fun
    PRec(Len, M, W) when Len >= 1 ->
      BlockLoop = fun
        BRec(Start, M1, W1) when Start < 256 ->
          M2 = M1 + 1,
          Z = poly_get(M2 + 1, ?ML_DSA_ZETAS),
          W2 = butterfly_loop(Start, Start + Len - 1, Len, Z, W1),
          BRec(Start + 2 * Len, M2, W2);
        BRec(_, M1, W1) ->
          {M1, W1}
      end,
      {MNext, WNext} = BlockLoop(0, M, W),
      PRec(Len div 2, MNext, WNext);
    PRec(_, _, W) ->
      W
  end,
  PolyLoop(128, 0, W0).

-spec butterfly_loop(
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  non_neg_integer(),
  poly_tuple()
) -> poly_tuple().
butterfly_loop(J, End, Len, Z, W) when J =< End ->
  Wj = poly_get(J + 1, W),
  WjLen = poly_get(J + Len + 1, W),
  T = (Z * WjLen) rem ?ML_DSA_Q,
  W1 = setelement(J + Len + 1, W, (Wj - T + ?ML_DSA_Q) rem ?ML_DSA_Q),
  W2 = setelement(J + 1, W1, (Wj + T) rem ?ML_DSA_Q),
  butterfly_loop(J + 1, End, Len, Z, W2);
butterfly_loop(_J, _End, _Len, _Z, W) ->
  W.

-spec inv_ntt(poly_tuple()) -> poly_tuple().
inv_ntt(W0) ->
  PolyLoop = fun
    PRec(Len, M, W) when Len < 256 ->
      BlockLoop = fun
        BRec(Start, M1, W1) when Start < 256 ->
          M2 = M1 - 1,
          Z = (?ML_DSA_Q - poly_get(M2 + 1, ?ML_DSA_ZETAS)) rem ?ML_DSA_Q,
          W2 = inv_butterfly_loop(Start, Start + Len - 1, Len, Z, W1),
          BRec(Start + 2 * Len, M2, W2);
        BRec(_, M1, W1) ->
          {M1, W1}
      end,
      {MNext, WNext} = BlockLoop(0, M, W),
      PRec(2 * Len, MNext, WNext);
    PRec(_, _, W) ->
      W
  end,
  WStage = PolyLoop(1, 256, W0),
  list_to_tuple([
    (?ML_DSA_INV_256 * poly_get(I, WStage)) rem ?ML_DSA_Q
   || I <- lists:seq(1, 256)
  ]).

-spec inv_butterfly_loop(
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  non_neg_integer(),
  poly_tuple()
) -> poly_tuple().
inv_butterfly_loop(J, End, Len, Z, W) when J =< End ->
  Wj = poly_get(J + 1, W),
  WjLen = poly_get(J + Len + 1, W),
  T = Wj,
  W1 = setelement(J + 1, W, (T + WjLen) rem ?ML_DSA_Q),
  Diff = (T - WjLen + ?ML_DSA_Q) rem ?ML_DSA_Q,
  W2 = setelement(J + Len + 1, W1, (Z * Diff) rem ?ML_DSA_Q),
  inv_butterfly_loop(J + 1, End, Len, Z, W2);
inv_butterfly_loop(_J, _End, _Len, _Z, W) ->
  W.

-spec add_poly(poly_tuple(), poly_tuple()) -> poly_tuple().
add_poly(PA, PB) ->
  list_to_tuple([
    (poly_get(I, PA) + poly_get(I, PB)) rem ?ML_DSA_Q
   || I <- lists:seq(1, 256)
  ]).

-spec sub_poly(poly_tuple(), poly_tuple()) -> poly_tuple().
sub_poly(PA, PB) ->
  list_to_tuple([
    (poly_get(I, PA) - poly_get(I, PB) + ?ML_DSA_Q) rem ?ML_DSA_Q
   || I <- lists:seq(1, 256)
  ]).

-spec mul_ntt(poly_tuple(), poly_tuple()) -> poly_tuple().
mul_ntt(PA, PB) ->
  list_to_tuple([
    (poly_get(I, PA) * poly_get(I, PB)) rem ?ML_DSA_Q
   || I <- lists:seq(1, 256)
  ]).

-spec neg_poly(poly_tuple()) -> poly_tuple().
neg_poly(P) ->
  list_to_tuple([
    (?ML_DSA_Q - poly_get(I, P)) rem ?ML_DSA_Q
   || I <- lists:seq(1, 256)
  ]).

-spec zero_poly() -> poly_tuple().
zero_poly() ->
  list_to_tuple([0 || _ <- lists:seq(1, 256)]).

-spec normalize_poly(poly_tuple()) -> poly_tuple().
normalize_poly(Poly) ->
  list_to_tuple([
    ((poly_get(Idx, Poly) rem ?ML_DSA_Q) + ?ML_DSA_Q) rem ?ML_DSA_Q
   || Idx <- lists:seq(1, 256)
  ]).

%% ===================================================================
%% Decomposition, Rounding & Hints (FIPS 204 Algorithms 35-40)
%% ===================================================================

-spec modpm(integer(), pos_integer()) -> integer().
modpm(M, Alpha) ->
  Half = Alpha div 2,
  Diff = (Half - M) rem Alpha,
  DiffMod =
    if
      Diff < 0 -> Diff + Alpha;
      true -> Diff
    end,
  -DiffMod + Half.

-spec power2round(poly_tuple()) -> {poly_tuple(), poly_tuple()}.
power2round(R) ->
  R0List = [modpm(poly_get(I, R) rem ?ML_DSA_Q, 8192) || I <- lists:seq(1, 256)],
  R1List = [
    ((poly_get(I, R) rem ?ML_DSA_Q) - lists:nth(I, R0List)) bsr 13
   || I <- lists:seq(1, 256)
  ],
  {list_to_tuple(R1List), list_to_tuple(R0List)}.

-spec decompose(poly_tuple(), pos_integer()) -> {poly_tuple(), poly_tuple()}.
decompose(R, Gam2) ->
  TwiceGam2 = 2 * Gam2,
  Decomposed = [
    decompose_coeff(poly_get(I, R), Gam2, TwiceGam2)
   || I <- lists:seq(1, 256)
  ],
  R1List = [R1 || {R1, _} <- Decomposed],
  R0List = [R0 || {_, R0} <- Decomposed],
  {list_to_tuple(R1List), list_to_tuple(R0List)}.

-spec decompose_coeff(integer(), pos_integer(), pos_integer()) ->
  {non_neg_integer(), integer()}.
decompose_coeff(X, _Gam2, TwiceGam2) ->
  RPrime = (X rem ?ML_DSA_Q + ?ML_DSA_Q) rem ?ML_DSA_Q,
  R0 = modpm(RPrime, TwiceGam2),
  if
    RPrime - R0 =:= ?ML_DSA_Q - 1 ->
      {0, R0 - 1};
    true ->
      {(RPrime - R0) div TwiceGam2, R0}
  end.

-spec high_bits(poly_tuple(), pos_integer()) -> poly_tuple().
high_bits(R, Gam2) ->
  {R1, _} = decompose(R, Gam2),
  R1.

-spec low_bits(poly_tuple(), pos_integer()) -> poly_tuple().
low_bits(R, Gam2) ->
  {_, R0} = decompose(R, Gam2),
  R0.

-spec make_hint(poly_tuple(), poly_tuple(), pos_integer()) -> poly_tuple().
make_hint(Z, R, Gam2) ->
  R1 = high_bits(R, Gam2),
  V1 = high_bits(add_poly(R, Z), Gam2),
  list_to_tuple([
    case poly_get(I, R1) =/= poly_get(I, V1) of
      true -> 1;
      false -> 0
    end
   || I <- lists:seq(1, 256)
  ]).

-spec use_hint(poly_tuple(), poly_tuple(), pos_integer()) -> poly_tuple().
use_hint(H, R, Gam2) ->
  TwiceGam2 = 2 * Gam2,
  M = (?ML_DSA_Q - 1) div TwiceGam2,
  list_to_tuple([
    use_hint_coeff(poly_get(I, H), poly_get(I, R), Gam2, TwiceGam2, M)
   || I <- lists:seq(1, 256)
  ]).

-spec use_hint_coeff(integer(), integer(), pos_integer(), pos_integer(), pos_integer()) ->
  non_neg_integer().
use_hint_coeff(HBit, Coeff, Gam2, TwiceGam2, M) ->
  {R1, R0} = decompose_coeff(Coeff, Gam2, TwiceGam2),
  if
    HBit =:= 1 andalso R0 > 0 ->
      (R1 + 1) rem M;
    HBit =:= 1 andalso R0 =< 0 ->
      (R1 - 1 + M) rem M;
    true ->
      R1
  end.

-spec inf_norm_vector([poly_tuple()]) -> non_neg_integer().
inf_norm_vector(Vec) ->
  lists:foldl(
    fun(Poly, MaxAcc) ->
      lists:foldl(
        fun(I, InnerMax) ->
          Norm = abs(modpm(poly_get(I, Poly), ?ML_DSA_Q)),
          if
            Norm > InnerMax -> Norm;
            true -> InnerMax
          end
        end,
        MaxAcc,
        lists:seq(1, 256)
      )
    end,
    0,
    Vec
  ).

-spec weight_hint([poly_tuple()]) -> non_neg_integer().
weight_hint(H) ->
  lists:foldl(
    fun(Row, Acc) ->
      lists:foldl(
        fun(I, RowAcc) ->
          RowAcc + poly_get(I, Row)
        end,
        Acc,
        lists:seq(1, 256)
      )
    end,
    0,
    H
  ).

%% ===================================================================
%% Sampling & Expansion Functions (FIPS 204 Algorithms 29-34)
%% ===================================================================

-spec expand_a(binary(), pos_integer(), pos_integer()) -> [[poly_tuple()]].
expand_a(Rho, K, L) ->
  [
    [rej_ntt_poly(Rho, S, R) || S <- lists:seq(0, L - 1)]
   || R <- lists:seq(0, K - 1)
  ].

-spec rej_ntt_poly(binary(), non_neg_integer(), non_neg_integer()) -> poly_tuple().
rej_ntt_poly(Rho, S, R) ->
  rej_ntt_poly_stream(Rho, S, R, 840, []).

-spec rej_ntt_poly_stream(
  binary(),
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  [non_neg_integer()]
) -> poly_tuple().
rej_ntt_poly_stream(Rho, S, R, ByteLen, Acc) ->
  Bytes = shake128(<<Rho/binary, S:8, R:8>>, ByteLen * 8),
  case rej_ntt_extract(Bytes, Acc, length(Acc)) of
    {ok, Coeffs} ->
      list_to_tuple(Coeffs);
    {need_more, PartialAcc} ->
      rej_ntt_poly_stream(Rho, S, R, ByteLen + 168, PartialAcc)
  end.

-spec rej_ntt_extract(binary(), [non_neg_integer()], non_neg_integer()) ->
  {ok, [non_neg_integer()]} | {need_more, [non_neg_integer()]}.
rej_ntt_extract(<<B0:8, B1:8, B2:8, Rest/binary>>, Acc, Count) when Count < 256 ->
  B2Prime = B2 band 16#7F,
  Z = B0 bor (B1 bsl 8) bor (B2Prime bsl 16),
  if
    Z < ?ML_DSA_Q ->
      rej_ntt_extract(Rest, [Z | Acc], Count + 1);
    true ->
      rej_ntt_extract(Rest, Acc, Count)
  end;
rej_ntt_extract(_, Acc, 256) ->
  {ok, lists:reverse(Acc)};
rej_ntt_extract(_, Acc, _) ->
  {need_more, Acc}.

-spec expand_s(binary(), pos_integer(), pos_integer(), pos_integer()) ->
  {[poly_tuple()], [poly_tuple()]}.
expand_s(RhoPrime, K, L, Eta) ->
  S1 = [rej_bounded_poly(RhoPrime, R, Eta) || R <- lists:seq(0, L - 1)],
  S2 = [rej_bounded_poly(RhoPrime, R + L, Eta) || R <- lists:seq(0, K - 1)],
  {S1, S2}.

-spec rej_bounded_poly(binary(), non_neg_integer(), pos_integer()) -> poly_tuple().
rej_bounded_poly(RhoPrime, R, Eta) ->
  InitialLen =
    if
      Eta =:= 2 -> 136;
      true -> 272
    end,
  rej_bounded_poly_stream(RhoPrime, R, Eta, InitialLen, []).

-spec rej_bounded_poly_stream(
  binary(),
  non_neg_integer(),
  pos_integer(),
  pos_integer(),
  [integer()]
) -> poly_tuple().
rej_bounded_poly_stream(RhoPrime, R, Eta, ByteLen, Acc) ->
  Bytes = shake256(<<RhoPrime/binary, R:16/little>>, ByteLen * 8),
  case rej_bounded_extract(Bytes, Acc, length(Acc), Eta) of
    {ok, Coeffs} ->
      list_to_tuple(Coeffs);
    {need_more, PartialAcc} ->
      rej_bounded_poly_stream(RhoPrime, R, Eta, ByteLen + 136, PartialAcc)
  end.

-spec rej_bounded_extract(binary(), [integer()], non_neg_integer(), pos_integer()) ->
  {ok, [integer()]} | {need_more, [integer()]}.
rej_bounded_extract(<<Byte:8, Rest/binary>>, Acc, Count, Eta) when Count < 256 ->
  Z0 = Byte band 16#0F,
  Z1 = Byte bsr 4,
  Acc1 =
    if
      Eta =:= 2, Z0 < 15 -> [2 - (Z0 rem 5) | Acc];
      Eta =:= 4, Z0 < 9 -> [4 - Z0 | Acc];
      true -> Acc
    end,
  Count1 = length(Acc1),
  if
    Count1 =:= 256 ->
      {ok, lists:reverse(Acc1)};
    true ->
      Acc2 =
        if
          Eta =:= 2, Z1 < 15 -> [2 - (Z1 rem 5) | Acc1];
          Eta =:= 4, Z1 < 9 -> [4 - Z1 | Acc1];
          true -> Acc1
        end,
      Count2 = length(Acc2),
      if
        Count2 =:= 256 ->
          {ok, lists:reverse(Acc2)};
        true ->
          rej_bounded_extract(Rest, Acc2, Count2, Eta)
      end
  end;
rej_bounded_extract(_, Acc, 256, _Eta) ->
  {ok, lists:reverse(Acc)};
rej_bounded_extract(_, Acc, _, _Eta) ->
  {need_more, Acc}.

-spec expand_mask(binary(), non_neg_integer(), pos_integer(), pos_integer()) -> [poly_tuple()].
expand_mask(RhoPrimePrime, Kappa, Gam1, L) ->
  [
    expand_mask_poly(RhoPrimePrime, Kappa + R, Gam1)
   || R <- lists:seq(0, L - 1)
  ].

-spec expand_mask_poly(binary(), non_neg_integer(), pos_integer()) -> poly_tuple().
expand_mask_poly(RhoPrimePrime, Index, Gam1) ->
  if
    Gam1 =:= 131072 ->
      Bytes = shake256(<<RhoPrimePrime/binary, Index:16/little>>, 576 * 8),
      list_to_tuple(unpack_18(Bytes, Gam1));
    Gam1 =:= 524288 ->
      Bytes = shake256(<<RhoPrimePrime/binary, Index:16/little>>, 640 * 8),
      list_to_tuple(unpack_20(Bytes, Gam1))
  end.

-spec sample_in_ball(binary(), pos_integer()) -> poly_tuple().
sample_in_ball(CTilde, Tau) ->
  sample_in_ball_stream(CTilde, Tau, 136).

-spec sample_in_ball_stream(binary(), pos_integer(), pos_integer()) -> poly_tuple().
sample_in_ball_stream(CTilde, Tau, ByteLen) ->
  Bytes = shake256(CTilde, ByteLen * 8),
  <<Signs:8/binary, RandBytes/binary>> = Bytes,
  SignTuple = list_to_tuple(binary_to_list(Signs)),
  case sample_in_ball_loop(256 - Tau, Tau, SignTuple, RandBytes, zero_poly()) of
    {ok, Poly} ->
      Poly;
    need_more ->
      sample_in_ball_stream(CTilde, Tau, ByteLen + 136)
  end.

-spec sample_in_ball_loop(
  non_neg_integer(),
  pos_integer(),
  tuple(),
  binary(),
  poly_tuple()
) -> {ok, poly_tuple()} | need_more.
sample_in_ball_loop(I, Tau, SignTuple, RandBytes, Poly) when I < 256 ->
  case RandBytes of
    <<J:8, Rest/binary>> when J =< I ->
      ValJ = poly_get(J + 1, Poly),
      SignByte = poly_get(((I + Tau - 256) div 8) + 1, SignTuple),
      SignBit = (SignByte bsr ((I + Tau - 256) rem 8)) band 1,
      NewValJ =
        if
          SignBit =:= 1 -> ?ML_DSA_Q - 1;
          true -> 1
        end,
      Poly1 = setelement(I + 1, Poly, ValJ),
      Poly2 = setelement(J + 1, Poly1, NewValJ),
      sample_in_ball_loop(I + 1, Tau, SignTuple, Rest, Poly2);
    <<_:8, Rest/binary>> ->
      sample_in_ball_loop(I, Tau, SignTuple, Rest, Poly);
    <<>> ->
      need_more
  end;
sample_in_ball_loop(256, _Tau, _SignTuple, _RandBytes, Poly) ->
  {ok, Poly}.

%% ===================================================================
%% Bit Packing & Encoding Routines (FIPS 204 Algorithms 16-28)
%% ===================================================================

-spec pk_encode(binary(), [poly_tuple()]) -> binary().
pk_encode(Rho, T1) ->
  iolist_to_binary([Rho | [pack_10(tuple_to_list(T1i)) || T1i <- T1]]).

-spec pk_decode(binary(), pos_integer()) -> {binary(), [poly_tuple()]}.
pk_decode(PK, K) ->
  <<Rho:32/binary, Rest/binary>> = PK,
  T1 = [
    list_to_tuple(unpack_10(binary:part(Rest, I * 320, 320)))
   || I <- lists:seq(0, K - 1)
  ],
  {Rho, T1}.

-spec sk_encode(
  binary(),
  binary(),
  binary(),
  [poly_tuple()],
  [poly_tuple()],
  [poly_tuple()],
  pos_integer()
) -> binary().
sk_encode(Rho, KeyK, TR, S1, S2, T0, Eta) ->
  PackS =
    if
      Eta =:= 2 -> fun(P) -> pack_3(tuple_to_list(P), 2) end;
      Eta =:= 4 -> fun(P) -> pack_4(tuple_to_list(P), 4) end
    end,
  iolist_to_binary([
    Rho,
    KeyK,
    TR,
    [PackS(S) || S <- S1],
    [PackS(S) || S <- S2],
    [pack_13(tuple_to_list(T), 4096) || T <- T0]
  ]).

-spec sk_decode(secret_key(), parameter_set()) ->
  {binary(), binary(), binary(), [poly_tuple()], [poly_tuple()], [poly_tuple()]}.
sk_decode(SK, Set) ->
  {K, L, Eta, _Tau, _Beta, _Gam1, _Gam2, _Omega, _Lam4} = params(Set),
  <<Rho:32/binary, KeyK:32/binary, TR:64/binary, Rest/binary>> = SK,
  SLen =
    if
      Eta =:= 2 -> 96;
      Eta =:= 4 -> 128
    end,
  UnpackS =
    if
      Eta =:= 2 -> fun(Bin) -> list_to_tuple(unpack_3(Bin, 2)) end;
      Eta =:= 4 -> fun(Bin) -> list_to_tuple(unpack_4(Bin, 4)) end
    end,
  S1BytesLen = L * SLen,
  <<S1Bytes:S1BytesLen/binary, Rest1/binary>> = Rest,
  S1 = [UnpackS(binary:part(S1Bytes, I * SLen, SLen)) || I <- lists:seq(0, L - 1)],
  S2BytesLen = K * SLen,
  <<S2Bytes:S2BytesLen/binary, T0Bytes/binary>> = Rest1,
  S2 = [UnpackS(binary:part(S2Bytes, I * SLen, SLen)) || I <- lists:seq(0, K - 1)],
  T0 = [
    list_to_tuple(unpack_13(binary:part(T0Bytes, I * 416, 416), 4096))
   || I <- lists:seq(0, K - 1)
  ],
  {Rho, KeyK, TR, S1, S2, T0}.

-spec sig_encode(binary(), [poly_tuple()], [poly_tuple()], pos_integer(), pos_integer(), pos_integer()) ->
  binary().
sig_encode(CTilde, Z, H, Gam1, Omega, K) ->
  PackZ =
    if
      Gam1 =:= 131072 -> fun(P) -> pack_18(tuple_to_list(P), Gam1) end;
      Gam1 =:= 524288 -> fun(P) -> pack_20(tuple_to_list(P), Gam1) end
    end,
  ZBin = iolist_to_binary([PackZ(Zi) || Zi <- Z]),
  HBin = hint_bit_pack(H, Omega, K),
  <<CTilde/binary, ZBin/binary, HBin/binary>>.

-spec sig_decode(signature(), parameter_set()) ->
  {ok, {binary(), [poly_tuple()], [poly_tuple()]}} | error.
sig_decode(Sig, Set) ->
  {K, L, _Eta, _Tau, _Beta, Gam1, _Gam2, Omega, Lam4} = params(Set),
  ZPolyLen =
    if
      Gam1 =:= 131072 -> 576;
      Gam1 =:= 524288 -> 640
    end,
  ZBytesLen = L * ZPolyLen,
  HBytesLen = Omega + K,
  ExpectedTotal = Lam4 + ZBytesLen + HBytesLen,
  if
    byte_size(Sig) =/= ExpectedTotal ->
      error;
    true ->
      <<CTilde:Lam4/binary, ZBytes:ZBytesLen/binary, HBytes:HBytesLen/binary>> = Sig,
      UnpackZ =
        if
          Gam1 =:= 131072 -> fun(B) -> list_to_tuple(unpack_18(B, Gam1)) end;
          Gam1 =:= 524288 -> fun(B) -> list_to_tuple(unpack_20(B, Gam1)) end
        end,
      Z = [UnpackZ(binary:part(ZBytes, I * ZPolyLen, ZPolyLen)) || I <- lists:seq(0, L - 1)],
      case hint_bit_unpack(HBytes, Omega, K) of
        {ok, H} ->
          {ok, {CTilde, Z, H}};
        error ->
          error
      end
  end.

-spec w1_encode([poly_tuple()], pos_integer()) -> binary().
w1_encode(W1, Gam2) ->
  if
    Gam2 =:= 95232 ->
      iolist_to_binary([pack_6(tuple_to_list(Wi)) || Wi <- W1]);
    Gam2 =:= 261888 ->
      iolist_to_binary([pack_4_simple(tuple_to_list(Wi)) || Wi <- W1])
  end.

%% -------------------------------------------------------------------
%% Hint Packing & Unpacking (FIPS 204 Algorithms 20-21)
%% -------------------------------------------------------------------

-spec hint_bit_pack([poly_tuple()], pos_integer(), pos_integer()) -> binary().
hint_bit_pack(H, Omega, _K) ->
  {Indices, RowCounts} = hint_pack_rows(H, 0, [], []),
  IndicesBin = iolist_to_binary(Indices),
  PaddingLen = Omega - byte_size(IndicesBin),
  Padding = <<0:(PaddingLen * 8)>>,
  RowCountsBin = iolist_to_binary(RowCounts),
  <<IndicesBin/binary, Padding/binary, RowCountsBin/binary>>.

-spec hint_pack_rows([poly_tuple()], non_neg_integer(), list(), list()) ->
  {list(), list()}.
hint_pack_rows([Row | Rows], Idx, IdxAcc, CountAcc) ->
  {NewIdx, RowIndices} = hint_pack_row(Row, 1, Idx, []),
  hint_pack_rows(Rows, NewIdx, [IdxAcc | RowIndices], [CountAcc, NewIdx]);
hint_pack_rows([], _Idx, IdxAcc, CountAcc) ->
  {IdxAcc, CountAcc}.

-spec hint_pack_row(poly_tuple(), pos_integer(), non_neg_integer(), list()) ->
  {non_neg_integer(), list()}.
hint_pack_row(Row, J, Idx, Acc) when J =< 256 ->
  case poly_get(J, Row) of
    0 -> hint_pack_row(Row, J + 1, Idx, Acc);
    1 -> hint_pack_row(Row, J + 1, Idx + 1, [Acc, J - 1])
  end;
hint_pack_row(_Row, _J, Idx, Acc) ->
  {Idx, Acc}.

-spec hint_bit_unpack(binary(), pos_integer(), pos_integer()) ->
  {ok, [poly_tuple()]} | error.
hint_bit_unpack(Bin, Omega, K) ->
  <<IndicesPart:Omega/binary, RowCountsPart:K/binary>> = Bin,
  RowCounts = binary_to_list(RowCountsPart),
  hint_unpack_validate(RowCounts, IndicesPart, 0, Omega, []).

-spec hint_unpack_validate([byte()], binary(), non_neg_integer(), pos_integer(), [poly_tuple()]) ->
  {ok, [poly_tuple()]} | error.
hint_unpack_validate([Count | RestCounts], IndicesPart, PrevIdx, Omega, AccRows) ->
  if
    Count < PrevIdx orelse Count > Omega ->
      error;
    true ->
      RowLen = Count - PrevIdx,
      <<_:PrevIdx/binary, RowSlice:RowLen/binary, _/binary>> = IndicesPart,
      RowIndices = binary_to_list(RowSlice),
      case is_strictly_increasing(RowIndices) of
        false ->
          error;
        true ->
          RowTuple = lists:foldl(
            fun(Idx0, AccTuple) -> setelement(Idx0 + 1, AccTuple, 1) end,
            zero_poly(),
            RowIndices
          ),
          hint_unpack_validate(RestCounts, IndicesPart, Count, Omega, [RowTuple | AccRows])
      end
  end;
hint_unpack_validate([], IndicesPart, FinalIdx, Omega, AccRows) ->
  PadLen = Omega - FinalIdx,
  <<_:FinalIdx/binary, Pad:PadLen/binary>> = IndicesPart,
  case lists:all(fun(B) -> B =:= 0 end, binary_to_list(Pad)) of
    true -> {ok, lists:reverse(AccRows)};
    false -> error
  end.

-spec is_strictly_increasing([byte()]) -> boolean().
is_strictly_increasing([A, B | Rest]) when A < B ->
  is_strictly_increasing([B | Rest]);
is_strictly_increasing([_]) ->
  true;
is_strictly_increasing([]) ->
  true;
is_strictly_increasing(_) ->
  false.

%% -------------------------------------------------------------------
%% Chunked Bit Encoding and Decoding
%% -------------------------------------------------------------------

%% 10-bit simple bit packing (pkEncode)
-spec pack_10([non_neg_integer()]) -> binary().
pack_10([C0, C1, C2, C3 | Rest]) ->
  Val = C0 bor (C1 bsl 10) bor (C2 bsl 20) bor (C3 bsl 30),
  <<Val:40/little, (pack_10(Rest))/binary>>;
pack_10([]) ->
  <<>>.

-spec unpack_10(binary()) -> [non_neg_integer()].
unpack_10(<<Val:40/little, Rest/binary>>) ->
  Mask = 1023,
  [
    Val band Mask,
    (Val bsr 10) band Mask,
    (Val bsr 20) band Mask,
    (Val bsr 30) band Mask
    | unpack_10(Rest)
  ];
unpack_10(<<>>) ->
  [].

%% 3-bit bit packing (skEncode s1, s2 with eta = 2)
-spec pack_3([integer()], integer()) -> binary().
pack_3([C0, C1, C2, C3, C4, C5, C6, C7 | Rest], Eta) ->
  V0 = Eta - C0,
  V1 = Eta - C1,
  V2 = Eta - C2,
  V3 = Eta - C3,
  V4 = Eta - C4,
  V5 = Eta - C5,
  V6 = Eta - C6,
  V7 = Eta - C7,
  Val =
    V0 bor
      (V1 bsl 3) bor
      (V2 bsl 6) bor
      (V3 bsl 9) bor
      (V4 bsl 12) bor
      (V5 bsl 15) bor
      (V6 bsl 18) bor
      (V7 bsl 21),
  <<Val:24/little, (pack_3(Rest, Eta))/binary>>;
pack_3([], _Eta) ->
  <<>>.

-spec unpack_3(binary(), integer()) -> [integer()].
unpack_3(<<Val:24/little, Rest/binary>>, Eta) ->
  Mask = 7,
  [
    Eta - (Val band Mask),
    Eta - ((Val bsr 3) band Mask),
    Eta - ((Val bsr 6) band Mask),
    Eta - ((Val bsr 9) band Mask),
    Eta - ((Val bsr 12) band Mask),
    Eta - ((Val bsr 15) band Mask),
    Eta - ((Val bsr 18) band Mask),
    Eta - ((Val bsr 21) band Mask)
    | unpack_3(Rest, Eta)
  ];
unpack_3(<<>>, _Eta) ->
  [].

%% 4-bit bit packing (skEncode s1, s2 with eta = 4)
-spec pack_4([integer()], integer()) -> binary().
pack_4([C0, C1 | Rest], B) ->
  V0 = B - C0,
  V1 = B - C1,
  <<(V0 bor (V1 bsl 4)):8, (pack_4(Rest, B))/binary>>;
pack_4([], _B) ->
  <<>>.

-spec unpack_4(binary(), integer()) -> [integer()].
unpack_4(<<Byte:8, Rest/binary>>, B) ->
  [B - (Byte band 15), B - (Byte bsr 4) | unpack_4(Rest, B)];
unpack_4(<<>>, _B) ->
  [].

%% 4-bit simple packing for w1 (gamma2 = (q-1)/32)
-spec pack_4_simple([non_neg_integer()]) -> binary().
pack_4_simple([C0, C1 | Rest]) ->
  <<(C0 bor (C1 bsl 4)):8, (pack_4_simple(Rest))/binary>>;
pack_4_simple([]) ->
  <<>>.

%% 6-bit simple packing for w1 (gamma2 = (q-1)/88)
-spec pack_6([non_neg_integer()]) -> binary().
pack_6([C0, C1, C2, C3 | Rest]) ->
  Val = C0 bor (C1 bsl 6) bor (C2 bsl 12) bor (C3 bsl 18),
  <<Val:24/little, (pack_6(Rest))/binary>>;
pack_6([]) ->
  <<>>.

%% 13-bit bit packing (skEncode t0)
-spec pack_13([integer()], integer()) -> binary().
pack_13([C0, C1, C2, C3, C4, C5, C6, C7 | Rest], B) ->
  V0 = B - C0,
  V1 = B - C1,
  V2 = B - C2,
  V3 = B - C3,
  V4 = B - C4,
  V5 = B - C5,
  V6 = B - C6,
  V7 = B - C7,
  Val =
    V0 bor
      (V1 bsl 13) bor
      (V2 bsl 26) bor
      (V3 bsl 39) bor
      (V4 bsl 52) bor
      (V5 bsl 65) bor
      (V6 bsl 78) bor
      (V7 bsl 91),
  <<Val:104/little, (pack_13(Rest, B))/binary>>;
pack_13([], _B) ->
  <<>>.

-spec unpack_13(binary(), integer()) -> [integer()].
unpack_13(<<Val:104/little, Rest/binary>>, B) ->
  Mask = 8191,
  [
    B - (Val band Mask),
    B - ((Val bsr 13) band Mask),
    B - ((Val bsr 26) band Mask),
    B - ((Val bsr 39) band Mask),
    B - ((Val bsr 52) band Mask),
    B - ((Val bsr 65) band Mask),
    B - ((Val bsr 78) band Mask),
    B - ((Val bsr 91) band Mask)
    | unpack_13(Rest, B)
  ];
unpack_13(<<>>, _B) ->
  [].

%% 18-bit bit packing (sigEncode z with gamma1 = 2^17)
-spec pack_18([integer()], integer()) -> binary().
pack_18([C0, C1, C2, C3 | Rest], B) ->
  V0 = B - C0,
  V1 = B - C1,
  V2 = B - C2,
  V3 = B - C3,
  Val = V0 bor (V1 bsl 18) bor (V2 bsl 36) bor (V3 bsl 54),
  <<Val:72/little, (pack_18(Rest, B))/binary>>;
pack_18([], _B) ->
  <<>>.

-spec unpack_18(binary(), integer()) -> [integer()].
unpack_18(<<Val:72/little, Rest/binary>>, B) ->
  Mask = 262143,
  [
    B - (Val band Mask),
    B - ((Val bsr 18) band Mask),
    B - ((Val bsr 36) band Mask),
    B - ((Val bsr 54) band Mask)
    | unpack_18(Rest, B)
  ];
unpack_18(<<>>, _B) ->
  [].

%% 20-bit bit packing (sigEncode z with gamma1 = 2^19)
-spec pack_20([integer()], integer()) -> binary().
pack_20([C0, C1 | Rest], B) ->
  V0 = B - C0,
  V1 = B - C1,
  Val = V0 bor (V1 bsl 20),
  <<Val:40/little, (pack_20(Rest, B))/binary>>;
pack_20([], _B) ->
  <<>>.

-spec unpack_20(binary(), integer()) -> [integer()].
unpack_20(<<Val:40/little, Rest/binary>>, B) ->
  Mask = 1048575,
  [
    B - (Val band Mask),
    B - ((Val bsr 20) band Mask)
    | unpack_20(Rest, B)
  ];
unpack_20(<<>>, _B) ->
  [].

%% ===================================================================
%% Parameter Metadata & XOF Helpers
%% ===================================================================

-spec canonical_set(parameter_set()) -> parameter_set().
canonical_set(ml_dsa_44) -> ml_dsa_44;
canonical_set(mldsa44) -> ml_dsa_44;
canonical_set(ml_dsa_65) -> ml_dsa_65;
canonical_set(mldsa65) -> ml_dsa_65;
canonical_set(ml_dsa_87) -> ml_dsa_87;
canonical_set(mldsa87) -> ml_dsa_87;
canonical_set(_) -> error(badarg).

-spec params(parameter_set()) ->
  {
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer()
  }.
params(ml_dsa_44) -> {4, 4, 2, 39, 78, 131072, 95232, 80, 32};
params(mldsa44) -> params(ml_dsa_44);
params(ml_dsa_65) -> {6, 5, 4, 49, 196, 524288, 261888, 55, 48};
params(mldsa65) -> params(ml_dsa_65);
params(ml_dsa_87) -> {8, 7, 2, 60, 120, 524288, 261888, 75, 64};
params(mldsa87) -> params(ml_dsa_87);
params(_) -> error(badarg).

-spec parameter_set_from_sk(secret_key()) -> parameter_set().
parameter_set_from_sk(SecretKey) ->
  case byte_size(SecretKey) of
    2560 -> ml_dsa_44;
    4032 -> ml_dsa_65;
    4896 -> ml_dsa_87;
    _ -> error(badarg)
  end.

-spec parameter_set_from_pk(public_key()) -> parameter_set().
parameter_set_from_pk(PublicKey) ->
  case byte_size(PublicKey) of
    1312 -> ml_dsa_44;
    1952 -> ml_dsa_65;
    2592 -> ml_dsa_87;
    _ -> error(badarg)
  end.

-spec public_key_size(parameter_set()) -> pos_integer().
public_key_size(ml_dsa_44) -> 1312;
public_key_size(ml_dsa_65) -> 1952;
public_key_size(ml_dsa_87) -> 2592.

-spec signature_size(parameter_set()) -> pos_integer().
signature_size(ml_dsa_44) -> 2420;
signature_size(ml_dsa_65) -> 3309;
signature_size(ml_dsa_87) -> 4627.

-spec shake128(binary(), pos_integer()) -> binary().
shake128(Data, BitLen) ->
  ecu_compat:hash_xof(shake128, Data, BitLen).

-spec shake256(binary(), pos_integer()) -> binary().
shake256(Data, BitLen) ->
  ecu_compat:hash_xof(shake256, Data, BitLen).
