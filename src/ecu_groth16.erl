%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang Groth16 zk-SNARK verifier.
%%%
%%% Implements succinct non-interactive zero-knowledge proof verification
%%% based on the Groth16 protocol (Groth, 2016) over pairing-friendly
%%% elliptic curves:
%%%   - BLS12-381 (Filecoin, Zcash, Aeternity FATE)
%%%   - BN254 / alt_bn128 (Ethereum EVM EIP-196/197, Circom, snarkjs)
%%%
%%% Features:
%%%   - Single-proof verification (`verify/3,4')
%%%   - Multi-scalar accumulation of public inputs in Jacobian coordinates
%%%   - Multi-Miller loop evaluation with a single final exponentiation
%%%   - Randomized batch verification (`verify_batch/2,3')
%%%   - Support for compressed (48/96B on BLS12-381, 32/64B on BN254),
%%%     uncompressed (96/192B on BLS12-381, 64/128B on BN254), and affine points
%%%   - Strict subgroup validation and fail-closed security invariants
%%%
%%% Reference:
%%%   Jens Groth. "On the Size of Pairing-based Non-interactive Arguments"
%%%   EUROCRYPT 2016. https://eprint.iacr.org/2016/260.pdf
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_groth16).

-typing([eqwalizer]).

-include("ecu_groth16.hrl").
-include("ecu_bls12_381.hrl").
-include("ecu_bn254.hrl").

-define(BLS, ecu_bls12_381).
-define(BLS_PAIRING, ecu_bls12_381_pairing).
-define(BN, ecu_bn254).
-define(BN_PAIRING, ecu_bn254_pairing).

-type point_g1() ::
  ?BLS:g1_affine()
  | ?BLS:g1_compressed()
  | ?BLS:g1_uncompressed()
  | ?BN:g1_affine()
  | ?BN:g1_compressed()
  | ?BN:g1_uncompressed().

-type point_g2() ::
  ?BLS:g2_affine()
  | ?BLS:g2_compressed()
  | ?BLS:g2_uncompressed()
  | ?BN:g2_affine()
  | ?BN:g2_compressed()
  | ?BN:g2_uncompressed().

-type scalar() :: integer() | binary().

-type proof_tuple() :: {point_g1(), point_g2(), point_g1()}.

-type proof_map() :: #{
  a := point_g1(),
  b := point_g2(),
  c := point_g1()
}.

-type proof() :: proof_map() | proof_tuple() | #groth16_proof{}.

-type vk_tuple() :: {point_g1(), point_g2(), point_g2(), point_g2(), [point_g1()]}.

-type vk_map() :: #{
  alpha_g1 := point_g1(),
  beta_g2 := point_g2(),
  gamma_g2 := point_g2(),
  delta_g2 := point_g2(),
  ic := [point_g1()]
}.

-type vk_map_short() :: #{
  alpha := point_g1(),
  beta := point_g2(),
  gamma := point_g2(),
  delta := point_g2(),
  ic := [point_g1()]
}.

-type vk_map_bin() :: #{
  binary() => point_g1() | point_g2() | [point_g1()]
}.

-type verification_key() ::
  vk_map() | vk_map_short() | vk_map_bin() | vk_tuple() | #groth16_vk{}.

-type curve() :: bls12_381 | bn254.

-export_type([
  proof/0,
  proof_map/0,
  proof_tuple/0,
  verification_key/0,
  vk_map/0,
  vk_tuple/0,
  point_g1/0,
  point_g2/0,
  scalar/0,
  curve/0
]).

-export([
  verify/3,
  verify/4,
  verify_batch/2,
  verify_batch/3
]).

%%%===================================================================
%%% Public API
%%%===================================================================

%% @doc Verify a Groth16 proof using the default BLS12-381 curve.
-spec verify(verification_key(), [scalar()], proof()) -> boolean().
verify(VK, PublicInputs, Proof) ->
  verify(bls12_381, VK, PublicInputs, Proof).

%% @doc Verify a Groth16 proof under the specified curve.
-spec verify(curve(), verification_key(), [scalar()], proof()) -> boolean().
verify(Curve, VK, PublicInputs, Proof) when Curve =:= bls12_381; Curve =:= bn254 ->
  case {parse_vk(VK, Curve), parse_proof(Proof, Curve), parse_scalars(PublicInputs, Curve)} of
    {{ok, DecVK}, {ok, DecProof}, {ok, Scalars}} ->
      do_verify(Curve, DecVK, Scalars, DecProof);
    _ ->
      false
  end.

%% @doc Verify a batch of Groth16 proofs under the same verification key (default BLS12-381).
-spec verify_batch(verification_key(), [{[scalar()], proof()}]) -> boolean().
verify_batch(VK, Items) ->
  verify_batch(bls12_381, VK, Items).

%% @doc Verify a batch of Groth16 proofs under the specified curve.
-spec verify_batch(curve(), verification_key(), [{[scalar()], proof()}]) -> boolean().
verify_batch(Curve, _VK, []) when Curve =:= bls12_381; Curve =:= bn254 ->
  false;
verify_batch(Curve, VK, [{PublicInputs, Proof}]) when Curve =:= bls12_381; Curve =:= bn254 ->
  verify(Curve, VK, PublicInputs, Proof);
verify_batch(Curve, VK, Items) when
  (Curve =:= bls12_381 orelse Curve =:= bn254), is_list(Items)
->
  case parse_vk(VK, Curve) of
    {ok, DecVK} ->
      do_verify_batch(Curve, DecVK, Items);
    _ ->
      false
  end.

%%%===================================================================
%%% Internal Verification Logic
%%%===================================================================

-spec do_verify(curve(), #groth16_vk{}, [non_neg_integer()], #groth16_proof{}) -> boolean().
do_verify(Curve, #groth16_vk{ic = IC} = VK, Scalars, Proof) ->
  case length(IC) =:= length(Scalars) + 1 of
    false ->
      false;
    true ->
      case compute_k_pub(IC, Scalars, Curve) of
        {ok, KPub} ->
          check_groth16_pairings(Curve, VK, Proof, KPub);
        error ->
          false
      end
  end.

-spec check_groth16_pairings(
  curve(),
  #groth16_vk{},
  #groth16_proof{},
  groth16_g1()
) -> boolean().
check_groth16_pairings(
  bls12_381,
  #groth16_vk{alpha_g1 = Alpha, beta_g2 = Beta, gamma_g2 = Gamma, delta_g2 = Delta},
  #groth16_proof{a = A, b = B, c = C},
  KPub
) ->
  NegA = ?BLS:g1_neg(A),
  Pairs = [
    {NegA, B},
    {Alpha, Beta},
    {KPub, Gamma},
    {C, Delta}
  ],
  ?BLS_PAIRING:pairing_check(Pairs);
check_groth16_pairings(
  bn254,
  #groth16_vk{alpha_g1 = Alpha, beta_g2 = Beta, gamma_g2 = Gamma, delta_g2 = Delta},
  #groth16_proof{a = A, b = B, c = C},
  KPub
) ->
  NegA = ?BN:g1_neg(A),
  Pairs = [
    {NegA, B},
    {Alpha, Beta},
    {KPub, Gamma},
    {C, Delta}
  ],
  ?BN_PAIRING:pairing_check(Pairs).

%% @doc Compute public input linear combination K_pub = IC_0 + sum(x_i * IC_i).
-spec compute_k_pub([groth16_g1()], [non_neg_integer()], curve()) ->
  {ok, groth16_g1()} | error.
compute_k_pub([IC0 | RestIC], Scalars, bls12_381) ->
  J0 = ?BLS:g1_to_jacobian(IC0),
  accumulate_k_pub_bls(Scalars, RestIC, J0);
compute_k_pub([IC0 | RestIC], Scalars, bn254) ->
  J0 = ?BN:g1_to_jacobian(IC0),
  accumulate_k_pub_bn(Scalars, RestIC, J0);
compute_k_pub([], _, _) ->
  error.

-spec accumulate_k_pub_bls([non_neg_integer()], [?BLS:g1_affine()], ?BLS:g1_jacobian()) ->
  {ok, ?BLS:g1_affine()}.
accumulate_k_pub_bls([], [], JAcc) ->
  {ok, ?BLS:g1_from_jacobian(JAcc)};
accumulate_k_pub_bls([X | RestX], [ICi | RestIC], JAcc) ->
  case X of
    0 ->
      accumulate_k_pub_bls(RestX, RestIC, JAcc);
    _ ->
      Term = ?BLS:g1_scalar_mul(ICi, X),
      NewJ =
        case Term of
          infinity -> JAcc;
          {_, _} -> ?BLS:g1_j_add_affine(JAcc, Term)
        end,
      accumulate_k_pub_bls(RestX, RestIC, NewJ)
  end;
accumulate_k_pub_bls(_, _, _JAcc) ->
  {ok, infinity}.

-spec accumulate_k_pub_bn([non_neg_integer()], [?BN:g1_affine()], ?BN:g1_jacobian()) ->
  {ok, ?BN:g1_affine()}.
accumulate_k_pub_bn([], [], JAcc) ->
  {ok, ?BN:g1_from_jacobian(JAcc)};
accumulate_k_pub_bn([X | RestX], [ICi | RestIC], JAcc) ->
  case X of
    0 ->
      accumulate_k_pub_bn(RestX, RestIC, JAcc);
    _ ->
      Term = ?BN:g1_scalar_mul(ICi, X),
      NewJ =
        case Term of
          infinity -> JAcc;
          {_, _} -> ?BN:g1_j_add_affine(JAcc, Term)
        end,
      accumulate_k_pub_bn(RestX, RestIC, NewJ)
  end;
accumulate_k_pub_bn(_, _, _JAcc) ->
  {ok, infinity}.

%%%===================================================================
%%% Batch Verification (Randomized Multi-Pairing)
%%%===================================================================

-spec do_verify_batch(curve(), #groth16_vk{}, [{[scalar()], proof()}]) -> boolean().
do_verify_batch(Curve, VK, Items) ->
  case parse_batch_items(Items, VK#groth16_vk.ic, 1, Curve, []) of
    {ok, Parsed} ->
      execute_batch(Curve, VK, Parsed);
    error ->
      false
  end.

-spec parse_batch_items(
  [{[scalar()], proof()}],
  [groth16_g1()],
  pos_integer(),
  curve(),
  [{non_neg_integer(), #groth16_proof{}, groth16_g1()}]
) ->
  {ok, [{non_neg_integer(), #groth16_proof{}, groth16_g1()}]} | error.
parse_batch_items([], _IC, _Idx, _Curve, Acc) ->
  {ok, lists:reverse(Acc)};
parse_batch_items([{PublicInputs, Proof} | Rest], IC, Idx, Curve, Acc) ->
  case {parse_scalars(PublicInputs, Curve), parse_proof(Proof, Curve)} of
    {{ok, Scalars}, {ok, DecProof}} ->
      case length(IC) =:= length(Scalars) + 1 of
        false ->
          error;
        true ->
          case compute_k_pub(IC, Scalars, Curve) of
            {ok, KPub} ->
              R = sample_batch_weight(Idx, Curve),
              parse_batch_items(Rest, IC, Idx + 1, Curve, [{R, DecProof, KPub} | Acc]);
            error ->
              error
          end
      end;
    _ ->
      error
  end.

-spec sample_batch_weight(pos_integer(), curve()) -> pos_integer().
sample_batch_weight(1, _Curve) ->
  1;
sample_batch_weight(_Idx, bls12_381) ->
  <<W:128>> = ecu_compat:strong_rand_bytes(16),
  case W rem ?BLS12_381_R of
    0 -> 1;
    NonZero -> NonZero
  end;
sample_batch_weight(_Idx, bn254) ->
  <<W:128>> = ecu_compat:strong_rand_bytes(16),
  case W rem ?BN254_R of
    0 -> 1;
    NonZero -> NonZero
  end.

-spec execute_batch(
  curve(),
  #groth16_vk{},
  [{non_neg_integer(), #groth16_proof{}, groth16_g1()}]
) -> boolean().
execute_batch(
  bls12_381,
  #groth16_vk{alpha_g1 = Alpha, beta_g2 = Beta, gamma_g2 = Gamma, delta_g2 = Delta},
  Parsed
) ->
  InitG1 = ?BLS:g1_infinity(),
  {AB_Pairs, SumR, K_Total, C_Total} =
    lists:foldl(
      fun({R, #groth16_proof{a = A, b = B, c = C}, KPub}, {PairsAcc, R_Acc, K_Acc, C_Acc}) ->
        ScaledNegA = ?BLS:g1_scalar_mul(?BLS:g1_neg(A), R),
        Pair = {ScaledNegA, B},
        NewPairs = [Pair | PairsAcc],
        NewR_Acc = (R_Acc + R) rem ?BLS12_381_R,
        ScaledK = ?BLS:g1_scalar_mul(KPub, R),
        ScaledC = ?BLS:g1_scalar_mul(C, R),
        NewK_Acc = ?BLS:g1_add(K_Acc, ScaledK),
        NewC_Acc = ?BLS:g1_add(C_Acc, ScaledC),
        {NewPairs, NewR_Acc, NewK_Acc, NewC_Acc}
      end,
      {[], 0, InitG1, InitG1},
      Parsed
    ),
  AlphaScaled = ?BLS:g1_scalar_mul(Alpha, SumR),
  AllPairs =
    lists:reverse(AB_Pairs) ++
      [
        {AlphaScaled, Beta},
        {K_Total, Gamma},
        {C_Total, Delta}
      ],
  ?BLS_PAIRING:pairing_check(AllPairs);
execute_batch(
  bn254,
  #groth16_vk{alpha_g1 = Alpha, beta_g2 = Beta, gamma_g2 = Gamma, delta_g2 = Delta},
  Parsed
) ->
  InitG1 = ?BN:g1_zero(),
  {AB_Pairs, SumR, K_Total, C_Total} =
    lists:foldl(
      fun({R, #groth16_proof{a = A, b = B, c = C}, KPub}, {PairsAcc, R_Acc, K_Acc, C_Acc}) ->
        ScaledNegA = ?BN:g1_scalar_mul(?BN:g1_neg(A), R),
        Pair = {ScaledNegA, B},
        NewPairs = [Pair | PairsAcc],
        NewR_Acc = (R_Acc + R) rem ?BN254_R,
        ScaledK = ?BN:g1_scalar_mul(KPub, R),
        ScaledC = ?BN:g1_scalar_mul(C, R),
        NewK_Acc = ?BN:g1_add(K_Acc, ScaledK),
        NewC_Acc = ?BN:g1_add(C_Acc, ScaledC),
        {NewPairs, NewR_Acc, NewK_Acc, NewC_Acc}
      end,
      {[], 0, InitG1, InitG1},
      Parsed
    ),
  AlphaScaled = ?BN:g1_scalar_mul(Alpha, SumR),
  AllPairs =
    lists:reverse(AB_Pairs) ++
      [
        {AlphaScaled, Beta},
        {K_Total, Gamma},
        {C_Total, Delta}
      ],
  ?BN_PAIRING:pairing_check(AllPairs).

%%%===================================================================
%%% Decoders & Validators
%%%===================================================================

-spec parse_proof(term(), curve()) -> {ok, #groth16_proof{}} | error.
parse_proof({A, B, C}, Curve) ->
  case {normalize_g1(A, Curve), normalize_g2(B, Curve), normalize_g1(C, Curve)} of
    {{ok, AffA}, {ok, AffB}, {ok, AffC}} ->
      {ok, #groth16_proof{a = AffA, b = AffB, c = AffC}};
    _ ->
      error
  end;
parse_proof(#groth16_proof{a = A, b = B, c = C}, Curve) ->
  parse_proof({A, B, C}, Curve);
parse_proof(#{a := A, b := B, c := C}, Curve) ->
  parse_proof({A, B, C}, Curve);
parse_proof(#{<<"a">> := A, <<"b">> := B, <<"c">> := C}, Curve) ->
  parse_proof({A, B, C}, Curve);
parse_proof(_, _) ->
  error.

-spec parse_vk(term(), curve()) -> {ok, #groth16_vk{}} | error.
parse_vk({A, B, G, D, IC}, Curve) when is_list(IC) ->
  case
    {
      normalize_g1(A, Curve),
      normalize_g2(B, Curve),
      normalize_g2(G, Curve),
      normalize_g2(D, Curve),
      normalize_g1_list(IC, Curve)
    }
  of
    {{ok, AffA}, {ok, AffB}, {ok, AffG}, {ok, AffD}, {ok, AffIC}} ->
      {ok, #groth16_vk{
        alpha_g1 = AffA,
        beta_g2 = AffB,
        gamma_g2 = AffG,
        delta_g2 = AffD,
        ic = AffIC
      }};
    _ ->
      error
  end;
parse_vk(#groth16_vk{alpha_g1 = A, beta_g2 = B, gamma_g2 = G, delta_g2 = D, ic = IC}, Curve) when
  is_list(IC)
->
  parse_vk({A, B, G, D, IC}, Curve);
parse_vk(#{alpha_g1 := A, beta_g2 := B, gamma_g2 := G, delta_g2 := D, ic := IC}, Curve) when
  is_list(IC)
->
  parse_vk({A, B, G, D, IC}, Curve);
parse_vk(#{alpha := A, beta := B, gamma := G, delta := D, ic := IC}, Curve) when
  is_list(IC)
->
  parse_vk({A, B, G, D, IC}, Curve);
parse_vk(
  #{
    <<"alpha_g1">> := A,
    <<"beta_g2">> := B,
    <<"gamma_g2">> := G,
    <<"delta_g2">> := D,
    <<"ic">> := IC
  },
  Curve
) when is_list(IC) ->
  parse_vk({A, B, G, D, IC}, Curve);
parse_vk(
  #{
    <<"alpha">> := A,
    <<"beta">> := B,
    <<"gamma">> := G,
    <<"delta">> := D,
    <<"ic">> := IC
  },
  Curve
) when is_list(IC) ->
  parse_vk({A, B, G, D, IC}, Curve);
parse_vk(_, _) ->
  error.

-spec parse_scalars(term(), curve()) -> {ok, [non_neg_integer()]} | error.
parse_scalars(List, bls12_381) when is_list(List) ->
  parse_scalars_loop(List, ?BLS12_381_R, []);
parse_scalars(List, bn254) when is_list(List) ->
  parse_scalars_loop(List, ?BN254_R, []);
parse_scalars(_, _) ->
  error.

-spec parse_scalars_loop([term()], pos_integer(), [non_neg_integer()]) ->
  {ok, [non_neg_integer()]} | error.
parse_scalars_loop([], _Order, Acc) ->
  {ok, lists:reverse(Acc)};
parse_scalars_loop([X | Rest], Order, Acc) when is_integer(X), X >= 0, X < Order ->
  parse_scalars_loop(Rest, Order, [X | Acc]);
parse_scalars_loop([Bin | Rest], Order, Acc) when is_binary(Bin), byte_size(Bin) > 0 ->
  case decode_scalar_bin(Bin, Order) of
    {ok, Val} ->
      parse_scalars_loop(Rest, Order, [Val | Acc]);
    error ->
      error
  end;
parse_scalars_loop(_, _, _) ->
  error.

-spec decode_scalar_bin(binary(), pos_integer()) -> {ok, non_neg_integer()} | error.
decode_scalar_bin(<<"0x", Hex/binary>>, Order) when byte_size(Hex) > 0 ->
  try binary_to_integer(Hex, 16) of
    Val when Val >= 0, Val < Order -> {ok, Val};
    _ -> error
  catch
    _:_ -> error
  end;
decode_scalar_bin(<<"0X", Hex/binary>>, Order) when byte_size(Hex) > 0 ->
  decode_scalar_bin(<<"0x", Hex/binary>>, Order);
decode_scalar_bin(Bin, Order) when byte_size(Bin) =:= 32 ->
  case is_ascii_digits(Bin) of
    true ->
      try binary_to_integer(Bin, 10) of
        Val when Val >= 0, Val < Order -> {ok, Val};
        _ -> error
      catch
        _:_ -> error
      end;
    false ->
      Val = binary:decode_unsigned(Bin),
      case Val < Order of
        true -> {ok, Val};
        false -> error
      end
  end;
decode_scalar_bin(Bin, Order) ->
  case is_ascii_digits(Bin) of
    true ->
      try binary_to_integer(Bin, 10) of
        Val when Val >= 0, Val < Order -> {ok, Val};
        _ -> error
      catch
        _:_ -> error
      end;
    false ->
      error
  end.

-spec is_ascii_digits(binary()) -> boolean().
is_ascii_digits(<<>>) -> false;
is_ascii_digits(Bin) -> is_ascii_digits_loop(Bin).

-spec is_ascii_digits_loop(binary()) -> boolean().
is_ascii_digits_loop(<<>>) ->
  true;
is_ascii_digits_loop(<<B, Rest/binary>>) when B >= $0, B =< $9 ->
  is_ascii_digits_loop(Rest);
is_ascii_digits_loop(_) ->
  false.

-spec normalize_g1(term(), curve()) -> {ok, groth16_g1()} | error.
normalize_g1(infinity, _Curve) ->
  error;
normalize_g1({X, Y}, bls12_381) when is_integer(X), is_integer(Y) ->
  Pt = {X, Y},
  case ?BLS:g1_on_curve(Pt) andalso ?BLS:g1_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g1({X, Y}, bn254) when is_integer(X), is_integer(Y) ->
  Pt = {X, Y},
  case ?BN:g1_on_curve(Pt) andalso ?BN:g1_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g1(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 48 ->
  case ?BLS:g1_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 96 ->
  case ?BLS:g1_deserialize_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 32 ->
  case ?BN:g1_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 64 ->
  case ?BN:g1_from_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(_, _) ->
  error.

-spec normalize_g2(term(), curve()) -> {ok, groth16_g2()} | error.
normalize_g2(infinity, _Curve) ->
  error;
normalize_g2({{X0, X1}, {Y0, Y1}}, bls12_381) when
  is_integer(X0), is_integer(X1), is_integer(Y0), is_integer(Y1)
->
  Pt = {{X0, X1}, {Y0, Y1}},
  case ?BLS:g2_on_curve(Pt) andalso ?BLS:g2_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g2({{X0, X1}, {Y0, Y1}}, bn254) when
  is_integer(X0), is_integer(X1), is_integer(Y0), is_integer(Y1)
->
  Pt = {{X0, X1}, {Y0, Y1}},
  case ?BN:g2_on_curve(Pt) andalso ?BN:g2_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g2(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 96 ->
  case ?BLS:g2_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(Bin, bls12_381) when is_binary(Bin), byte_size(Bin) =:= 192 ->
  case ?BLS:g2_deserialize_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 64 ->
  case ?BN:g2_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(Bin, bn254) when is_binary(Bin), byte_size(Bin) =:= 128 ->
  case ?BN:g2_from_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(_, _) ->
  error.

-spec normalize_g1_list([term()], curve()) -> {ok, [groth16_g1()]} | error.
normalize_g1_list(List, Curve) when is_list(List), List =/= [] ->
  normalize_g1_list(List, Curve, []);
normalize_g1_list(_, _) ->
  error.

-spec normalize_g1_list([term()], curve(), [groth16_g1()]) -> {ok, [groth16_g1()]} | error.
normalize_g1_list([], _Curve, Acc) ->
  {ok, lists:reverse(Acc)};
normalize_g1_list([Item | Rest], Curve, Acc) ->
  case normalize_g1(Item, Curve) of
    {ok, Pt} ->
      normalize_g1_list(Rest, Curve, [Pt | Acc]);
    error ->
      error
  end.
