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
  parameter_set/1,
  verify/3,
  verify/4
]).

-export_type([
  parameter_set/0,
  public_key/0,
  signature/0
]).

-define(FN_DSA_Q, 12289).
-define(ROOT_G, 7).
-define(INV_ROOT_G, 8778).

-define(BOUND_512, 34034726).
-define(BOUND_1024, 70265242).

-type parameter_set() :: fn_dsa_512 | fn_dsa_1024.
-type public_key() :: binary().
-type signature() :: binary().

%% ===================================================================
%% Parameter Sets & Inspection
%% ===================================================================

%% @doc Identifies the canonical parameter set from an atom, key, or signature binary.
-spec parameter_set(parameter_set() | public_key() | signature() | atom()) -> parameter_set().
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
parameter_set(<<16#39:8, _:40/binary, _/binary>>) ->
  fn_dsa_512;
parameter_set(<<16#3A:8, _:40/binary, _/binary>>) ->
  fn_dsa_1024;
parameter_set(Bin) when is_binary(Bin) ->
  case byte_size(Bin) of
    897 -> fn_dsa_512;
    1793 -> fn_dsa_1024;
    _ -> error(badarg)
  end;
parameter_set(_) ->
  error(badarg).

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
  {N, LogN, ExpectedPKHead, ExpectedSigHead, MaxSigLen, Bound} = params(Set),
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
%% Internal Helpers: Parameters & Decoding
%% ===================================================================

-spec canonical_set(atom()) -> parameter_set().
canonical_set(fn_dsa_512) -> fn_dsa_512;
canonical_set(falcon512) -> fn_dsa_512;
canonical_set(fn_dsa_1024) -> fn_dsa_1024;
canonical_set(falcon1024) -> fn_dsa_1024;
canonical_set(_) -> error(badarg).

-spec params(parameter_set()) ->
  {pos_integer(), pos_integer(), byte(), byte(), pos_integer(), pos_integer()}.
params(fn_dsa_512) ->
  {512, 9, 16#09, 16#39, 666, ?BOUND_512};
params(fn_dsa_1024) ->
  {1024, 10, 16#0A, 16#3A, 1280, ?BOUND_1024}.

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
  try
    crypto:hash_xof(shake256, Data, BitLen)
  catch
    _:_ ->
      ecu_keccak:shake256(Data, BitLen)
  end.

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

-compile({inline, [zeta/1, inv_zeta/1, poly_get/2]}).

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
