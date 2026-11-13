%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang Groth16 zk-SNARK verifier.
%%%
%%% Implements succinct non-interactive zero-knowledge proof verification
%%% based on the Groth16 protocol (Groth, 2016) over pairing-friendly
%%% elliptic curves (BLS12-381).
%%%
%%% Features:
%%%   - Single-proof verification (`verify/3,4')
%%%   - Multi-scalar accumulation of public inputs in Jacobian coordinates
%%%   - Multi-Miller loop evaluation with a single final exponentiation
%%%   - Randomized batch verification (`verify_batch/2,3')
%%%   - Support for compressed (48/96B), uncompressed (96/192B), and affine points
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

-define(BLS, ecu_bls12_381).
-define(PAIRING, ecu_bls12_381_pairing).

-type point_g1() :: ?BLS:g1_affine() | ?BLS:g1_compressed() | ?BLS:g1_uncompressed().
-type point_g2() :: ?BLS:g2_affine() | ?BLS:g2_compressed() | ?BLS:g2_uncompressed().
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

-type verification_key() :: vk_map() | vk_tuple() | #groth16_vk{}.

-type curve() :: bls12_381.

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
verify(bls12_381, VK, PublicInputs, Proof) ->
  case {parse_vk(VK), parse_proof(Proof), parse_scalars(PublicInputs)} of
    {{ok, DecVK}, {ok, DecProof}, {ok, Scalars}} ->
      do_verify_bls12_381(DecVK, Scalars, DecProof);
    _ ->
      false
  end.

%% @doc Verify a batch of Groth16 proofs under the same verification key.
-spec verify_batch(verification_key(), [{[scalar()], proof()}]) -> boolean().
verify_batch(VK, Items) ->
  verify_batch(bls12_381, VK, Items).

%% @doc Verify a batch of Groth16 proofs under the specified curve.
-spec verify_batch(curve(), verification_key(), [{[scalar()], proof()}]) -> boolean().
verify_batch(bls12_381, _VK, []) ->
  true;
verify_batch(bls12_381, VK, [{PublicInputs, Proof}]) ->
  verify(bls12_381, VK, PublicInputs, Proof);
verify_batch(bls12_381, VK, Items) when is_list(Items) ->
  case parse_vk(VK) of
    {ok, DecVK} ->
      do_verify_batch_bls12_381(DecVK, Items);
    _ ->
      false
  end.

%%%===================================================================
%%% Internal Verification Logic
%%%===================================================================

-spec do_verify_bls12_381(#groth16_vk{}, [non_neg_integer()], #groth16_proof{}) -> boolean().
do_verify_bls12_381(#groth16_vk{ic = IC} = VK, Scalars, Proof) ->
  case length(IC) =:= length(Scalars) + 1 of
    false ->
      false;
    true ->
      case compute_k_pub(IC, Scalars) of
        {ok, KPub} ->
          check_groth16_pairings(VK, Proof, KPub);
        error ->
          false
      end
  end.

-spec check_groth16_pairings(#groth16_vk{}, #groth16_proof{}, ?BLS:g1_affine()) -> boolean().
check_groth16_pairings(
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
  ?PAIRING:pairing_check(Pairs).

%% @doc Compute public input linear combination K_pub = IC_0 + sum(x_i * IC_i).
-spec compute_k_pub([?BLS:g1_affine()], [non_neg_integer()]) ->
  {ok, ?BLS:g1_affine()} | error.
compute_k_pub([IC0 | RestIC], Scalars) ->
  J0 = ?BLS:g1_to_jacobian(IC0),
  accumulate_k_pub(Scalars, RestIC, J0);
compute_k_pub([], _) ->
  error.

-spec accumulate_k_pub([non_neg_integer()], [?BLS:g1_affine()], ?BLS:g1_jacobian()) ->
  {ok, ?BLS:g1_affine()}.
accumulate_k_pub([], [], JAcc) ->
  {ok, ?BLS:g1_from_jacobian(JAcc)};
accumulate_k_pub([X | RestX], [ICi | RestIC], JAcc) ->
  case X of
    0 ->
      accumulate_k_pub(RestX, RestIC, JAcc);
    _ ->
      Term = ?BLS:g1_scalar_mul(ICi, X),
      NewJ =
        case Term of
          infinity -> JAcc;
          {_, _} -> ?BLS:g1_j_add_affine(JAcc, Term)
        end,
      accumulate_k_pub(RestX, RestIC, NewJ)
  end;
accumulate_k_pub(_, _, _JAcc) ->
  {ok, infinity}.

%%%===================================================================
%%% Batch Verification (Randomized Multi-Pairing)
%%%===================================================================

-spec do_verify_batch_bls12_381(#groth16_vk{}, [{[scalar()], proof()}]) -> boolean().
do_verify_batch_bls12_381(VK, Items) ->
  case parse_batch_items(Items, VK#groth16_vk.ic, 1, []) of
    {ok, Parsed} ->
      execute_batch_bls12_381(VK, Parsed);
    error ->
      false
  end.

-spec parse_batch_items(
  [{[scalar()], proof()}],
  [?BLS:g1_affine()],
  pos_integer(),
  [{non_neg_integer(), #groth16_proof{}, ?BLS:g1_affine()}]
) ->
  {ok, [{non_neg_integer(), #groth16_proof{}, ?BLS:g1_affine()}]} | error.
parse_batch_items([], _IC, _Idx, Acc) ->
  {ok, lists:reverse(Acc)};
parse_batch_items([{PublicInputs, Proof} | Rest], IC, Idx, Acc) ->
  case {parse_scalars(PublicInputs), parse_proof(Proof)} of
    {{ok, Scalars}, {ok, DecProof}} ->
      case length(IC) =:= length(Scalars) + 1 of
        false ->
          error;
        true ->
          case compute_k_pub(IC, Scalars) of
            {ok, KPub} ->
              R = sample_batch_weight(Idx),
              parse_batch_items(Rest, IC, Idx + 1, [{R, DecProof, KPub} | Acc]);
            error ->
              error
          end
      end;
    _ ->
      error
  end.

-spec sample_batch_weight(pos_integer()) -> pos_integer().
sample_batch_weight(1) ->
  1;
sample_batch_weight(_Idx) ->
  <<W:128>> = ecu_compat:strong_rand_bytes(16),
  case W rem ?BLS12_381_R of
    0 -> 1;
    NonZero -> NonZero
  end.

-spec execute_batch_bls12_381(
  #groth16_vk{},
  [{non_neg_integer(), #groth16_proof{}, ?BLS:g1_affine()}]
) -> boolean().
execute_batch_bls12_381(
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
  ?PAIRING:pairing_check(AllPairs).

%%%===================================================================
%%% Decoders & Validators
%%%===================================================================

-spec parse_proof(term()) -> {ok, #groth16_proof{}} | error.
parse_proof({A, B, C}) ->
  case {normalize_g1(A), normalize_g2(B), normalize_g1(C)} of
    {{ok, AffA}, {ok, AffB}, {ok, AffC}} ->
      {ok, #groth16_proof{a = AffA, b = AffB, c = AffC}};
    _ ->
      error
  end;
parse_proof(#groth16_proof{a = A, b = B, c = C}) ->
  parse_proof({A, B, C});
parse_proof(#{a := A, b := B, c := C}) ->
  parse_proof({A, B, C});
parse_proof(#{<<"a">> := A, <<"b">> := B, <<"c">> := C}) ->
  parse_proof({A, B, C});
parse_proof(_) ->
  error.

-spec parse_vk(term()) -> {ok, #groth16_vk{}} | error.
parse_vk({A, B, G, D, IC}) when is_list(IC) ->
  case
    {
      normalize_g1(A),
      normalize_g2(B),
      normalize_g2(G),
      normalize_g2(D),
      normalize_g1_list(IC)
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
parse_vk(#groth16_vk{alpha_g1 = A, beta_g2 = B, gamma_g2 = G, delta_g2 = D, ic = IC}) when
  is_list(IC)
->
  parse_vk({A, B, G, D, IC});
parse_vk(#{alpha_g1 := A, beta_g2 := B, gamma_g2 := G, delta_g2 := D, ic := IC}) when
  is_list(IC)
->
  parse_vk({A, B, G, D, IC});
parse_vk(#{alpha := A, beta := B, gamma := G, delta := D, ic := IC}) when
  is_list(IC)
->
  parse_vk({A, B, G, D, IC});
parse_vk(#{
  <<"alpha_g1">> := A,
  <<"beta_g2">> := B,
  <<"gamma_g2">> := G,
  <<"delta_g2">> := D,
  <<"ic">> := IC
}) when is_list(IC) ->
  parse_vk({A, B, G, D, IC});
parse_vk(_) ->
  error.

-spec parse_scalars(term()) -> {ok, [non_neg_integer()]} | error.
parse_scalars(List) when is_list(List) ->
  parse_scalars(List, []);
parse_scalars(_) ->
  error.

-spec parse_scalars([term()], [non_neg_integer()]) -> {ok, [non_neg_integer()]} | error.
parse_scalars([], Acc) ->
  {ok, lists:reverse(Acc)};
parse_scalars([X | Rest], Acc) when is_integer(X), X >= 0, X < ?BLS12_381_R ->
  parse_scalars(Rest, [X | Acc]);
parse_scalars([Bin | Rest], Acc) when is_binary(Bin), byte_size(Bin) =< 32 ->
  Val = binary:decode_unsigned(Bin),
  case Val < ?BLS12_381_R of
    true ->
      parse_scalars(Rest, [Val | Acc]);
    false ->
      error
  end;
parse_scalars(_, _) ->
  error.

-spec normalize_g1(term()) -> {ok, ?BLS:g1_affine()} | error.
normalize_g1(infinity) ->
  error;
normalize_g1({X, Y}) when is_integer(X), is_integer(Y) ->
  Pt = {X, Y},
  case ?BLS:g1_on_curve(Pt) andalso ?BLS:g1_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g1(Bin) when is_binary(Bin), byte_size(Bin) =:= 48 ->
  case ?BLS:g1_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(Bin) when is_binary(Bin), byte_size(Bin) =:= 96 ->
  case ?BLS:g1_deserialize_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g1(_) ->
  error.

-spec normalize_g2(term()) -> {ok, ?BLS:g2_affine()} | error.
normalize_g2(infinity) ->
  error;
normalize_g2({{X0, X1}, {Y0, Y1}}) when
  is_integer(X0), is_integer(X1), is_integer(Y0), is_integer(Y1)
->
  Pt = {{X0, X1}, {Y0, Y1}},
  case ?BLS:g2_on_curve(Pt) andalso ?BLS:g2_is_in_subgroup(Pt) of
    true -> {ok, Pt};
    false -> error
  end;
normalize_g2(Bin) when is_binary(Bin), byte_size(Bin) =:= 96 ->
  case ?BLS:g2_decompress(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(Bin) when is_binary(Bin), byte_size(Bin) =:= 192 ->
  case ?BLS:g2_deserialize_uncompressed(Bin) of
    {ok, Pt} when Pt =/= infinity -> {ok, Pt};
    _ -> error
  end;
normalize_g2(_) ->
  error.

-spec normalize_g1_list([term()]) -> {ok, [?BLS:g1_affine()]} | error.
normalize_g1_list(List) when is_list(List), List =/= [] ->
  normalize_g1_list(List, []);
normalize_g1_list(_) ->
  error.

-spec normalize_g1_list([term()], [?BLS:g1_affine()]) -> {ok, [?BLS:g1_affine()]} | error.
normalize_g1_list([], Acc) ->
  {ok, lists:reverse(Acc)};
normalize_g1_list([Item | Rest], Acc) ->
  case normalize_g1(Item) of
    {ok, Pt} ->
      normalize_g1_list(Rest, [Pt | Acc]);
    error ->
      error
  end.
