%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang Kate-Zaverucha-Goldberg (KZG) Polynomial Commitment Scheme
%%% and EIP-4844 Point Evaluation on BLS12-381.
%%%
%%% Features:
%%%   - Structured Reference String (SRS / Powers of Tau) in G1 and G2
%%%   - Polynomial commitment C = [P(tau)]_1 in G1
%%%   - Evaluation proof creation pi = [Q(tau)]_1 where Q(x) = (P(x) - y)/(x - z)
%%%   - Proof verification e(C - [y]_1, [1]_2) = e(pi, [tau]_2 - [z]_2)
%%%     evaluated via a single 2-pair Miller loop and final exponentiation
%%%   - Randomized batch verification reducing N proofs to a single 2-pairing check
%%%   - EIP-4844 Point Evaluation Precompile interface (0x0A format)
%%%
%%% References:
%%%   - Kate, Zaverucha, Goldberg (Asiacrypt 2010):
%%%     https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf
%%%   - EIP-4844 (Proto-Danksharding):
%%%     https://eips.ethereum.org/EIPS/eip-4844
%%%   - Ethereum Consensus Specs (KZG):
%%%     https://github.com/ethereum/consensus-specs
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_kzg).

-typing([eqwalizer]).

-include("ecu_bls12_381.hrl").

-record(kzg_srs, {
  g1 = [] :: [ecu_bls12_381:g1_affine()],
  g2 = [] :: [ecu_bls12_381:g2_affine()]
}).

-type srs() :: #kzg_srs{}.
-type g1_point() :: ecu_bls12_381:g1_affine().
-type g2_point() :: ecu_bls12_381:g2_affine().
-type g1_input() :: g1_point() | <<_:384>>.
-type scalar_input() :: non_neg_integer() | <<_:256>>.

-export_type([srs/0, g1_input/0, scalar_input/0]).

-export([
  setup/2,
  srs_g1/1,
  srs_g2/1,
  commit/2,
  commit_compressed/2,
  create_proof/3,
  create_proof_compressed/3,
  open/3,
  verify/5,
  verify_compressed/5,
  verify_batch/2,
  verify_kzg_proof/5,
  point_evaluation/2
]).

-define(BLS, ecu_bls12_381).
-define(PAIRING, ecu_bls12_381_pairing).
-define(POLY, ecu_poly).
-define(R, ?BLS12_381_R).

%%%-------------------------------------------------------------------
%%% Setup & Structured Reference String (SRS)
%%%-------------------------------------------------------------------

%% @doc Generate a test Structured Reference String (SRS) of a given degree
%% from a toxic waste secret scalar Tau.
-spec setup(non_neg_integer(), integer()) -> srs().
setup(Degree, SecretTau) when Degree >= 0, is_integer(SecretTau) ->
  Tau = ((SecretTau rem ?R) + ?R) rem ?R,
  case Tau of
    0 ->
      error(zero_secret_tau);
    _ ->
      G1Gen = ?BLS:g1_generator(),
      G2Gen = ?BLS:g2_generator(),
      G1Points = generate_powers_g1(Degree, Tau, G1Gen),
      G2Points = [G2Gen, ?BLS:g2_scalar_mul(G2Gen, Tau)],
      #kzg_srs{g1 = G1Points, g2 = G2Points}
  end.

%% @doc Retrieve G1 setup points from SRS.
-spec srs_g1(srs()) -> [g1_point()].
srs_g1(#kzg_srs{g1 = G1}) ->
  G1.

%% @doc Retrieve G2 setup points from SRS.
-spec srs_g2(srs()) -> [g2_point()].
srs_g2(#kzg_srs{g2 = G2}) ->
  G2.

-spec generate_powers_g1(non_neg_integer(), non_neg_integer(), g1_point()) ->
  [g1_point()].
generate_powers_g1(Degree, Tau, G1Gen) ->
  generate_powers_g1_loop(Degree, 0, 1, Tau, G1Gen, []).

-spec generate_powers_g1_loop(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  g1_point(),
  [g1_point()]
) -> [g1_point()].
generate_powers_g1_loop(Degree, I, CurTauPower, Tau, G1Gen, Acc) when I =< Degree ->
  Point =
    case CurTauPower of
      1 -> G1Gen;
      _ -> ?BLS:g1_scalar_mul(G1Gen, CurTauPower)
    end,
  NextPower = (CurTauPower * Tau) rem ?R,
  generate_powers_g1_loop(Degree, I + 1, NextPower, Tau, G1Gen, [Point | Acc]);
generate_powers_g1_loop(_Degree, _I, _Power, _Tau, _G1Gen, Acc) ->
  lists:reverse(Acc).

%%%-------------------------------------------------------------------
%%% Commitment
%%%-------------------------------------------------------------------

%% @doc Compute KZG commitment to polynomial P(x) as C = sum(c_i * [tau^i]_1) in G1.
-spec commit(srs() | [g1_point()], ?POLY:poly()) -> g1_point().
commit(#kzg_srs{g1 = G1Setup}, Poly) ->
  commit(G1Setup, Poly);
commit(G1Setup, Poly) when is_list(G1Setup), is_list(Poly) ->
  Trimmed = ?POLY:trim(Poly),
  case Trimmed of
    [0] ->
      ?BLS:g1_infinity();
    _ ->
      case length(Trimmed) > length(G1Setup) of
        true ->
          error(degree_exceeds_srs);
        false ->
          multi_scalar_mul_g1(Trimmed, G1Setup)
      end
  end.

%% @doc Compute KZG commitment and return as 48-byte compressed G1 binary.
-spec commit_compressed(srs() | [g1_point()], ?POLY:poly()) -> <<_:384>>.
commit_compressed(SRS, Poly) ->
  ?BLS:g1_compress(commit(SRS, Poly)).

%%%-------------------------------------------------------------------
%%% Proof Generation (Open)
%%%-------------------------------------------------------------------

%% @doc Create an evaluation proof for polynomial P(x) at point Z:
%% Returns {ProofPoint, EvaluatedY} where:
%%   EvaluatedY = P(Z) mod r
%%   Q(x) = (P(x) - EvaluatedY) / (x - Z)
%%   ProofPoint = commit(Q(x))
-spec create_proof(srs(), ?POLY:poly(), scalar_input()) ->
  {g1_point(), non_neg_integer()}.
create_proof(SRS, Poly, ZInput) ->
  Z = to_scalar(ZInput),
  Y = ?POLY:eval(Poly, Z, ?R),
  {Q, _Remainder} = ?POLY:divide_by_linear(Poly, Z, ?R),
  Proof = commit(SRS, Q),
  {Proof, Y}.

%% @doc Create evaluation proof returning 48-byte compressed G1 proof.
-spec create_proof_compressed(srs(), ?POLY:poly(), scalar_input()) ->
  {<<_:384>>, non_neg_integer()}.
create_proof_compressed(SRS, Poly, ZInput) ->
  {Proof, Y} = create_proof(SRS, Poly, ZInput),
  {?BLS:g1_compress(Proof), Y}.

%% @doc Alias for create_proof/3.
-spec open(srs(), ?POLY:poly(), scalar_input()) ->
  {g1_point(), non_neg_integer()}.
open(SRS, Poly, Z) ->
  create_proof(SRS, Poly, Z).

%%%-------------------------------------------------------------------
%%% Proof Verification
%%%-------------------------------------------------------------------

%% @doc Verify KZG evaluation proof:
%% Check: e(C - [y]_1, [1]_2) == e(Proof, [tau]_2 - [z]_2)
%% Evaluated via pairing check: e([y]_1 - C, [1]_2) * e(Proof, [tau]_2 - [z]_2) == 1.
-spec verify(srs(), g1_input(), scalar_input(), scalar_input(), g1_input()) ->
  boolean().
verify(#kzg_srs{g2 = G2Setup}, Commitment, ZInput, YInput, Proof) ->
  case parse_g2_setup(G2Setup) of
    {ok, {G2Gen, TauG2}} ->
      case {parse_g1(Commitment), parse_g1(Proof)} of
        {{ok, CPoint}, {ok, PiPoint}} ->
          Z = to_scalar(ZInput),
          Y = to_scalar(YInput),
          case Z < ?R andalso Y < ?R of
            false ->
              false;
            true ->
              %% P1 = [y]_1 - C
              YG1 =
                case Y of
                  0 -> ?BLS:g1_infinity();
                  _ -> ?BLS:g1_scalar_mul(?BLS:g1_generator(), Y)
                end,
              P1 = ?BLS:g1_sub(YG1, CPoint),
              Q1 = G2Gen,

              %% Q2 = [tau]_2 - [z]_2
              ZG2 =
                case Z of
                  0 -> ?BLS:g2_infinity();
                  _ -> ?BLS:g2_scalar_mul(G2Gen, Z)
                end,
              P2 = PiPoint,
              Q2 = ?BLS:g2_sub(TauG2, ZG2),

              ?PAIRING:pairing_check([{P1, Q1}, {P2, Q2}])
          end;
        _ ->
          false
      end;
    error ->
      false
  end.

%% @doc Verify KZG proof taking compressed 48-byte inputs.
-spec verify_compressed(srs(), <<_:384>>, scalar_input(), scalar_input(), <<_:384>>) ->
  boolean().
verify_compressed(SRS, CommitmentBin, ZInput, YInput, ProofBin) ->
  verify(SRS, CommitmentBin, ZInput, YInput, ProofBin).

%% @doc Verify KZG proof matching Ethereum verify_kzg_proof parameter convention.
-spec verify_kzg_proof(srs(), g1_input(), scalar_input(), scalar_input(), g1_input()) ->
  boolean().
verify_kzg_proof(SRS, Commitment, Z, Y, Proof) ->
  verify(SRS, Commitment, Z, Y, Proof).

%%%-------------------------------------------------------------------
%%% Randomized Batch Verification
%%%-------------------------------------------------------------------

%% @doc Simultaneously verify N independent KZG proofs using randomized 128-bit weights.
%% Reduces 2N pairings to a single 2-pairing check:
%%   e( sum(gamma^i * ([y_i]_1 - C_i - z_i * pi_i)), [1]_2 ) * e( sum(gamma^i * pi_i), [tau]_2 ) == 1
-spec verify_batch(srs(), [{g1_input(), scalar_input(), scalar_input(), g1_input()}]) ->
  boolean().
verify_batch(_SRS, []) ->
  true;
verify_batch(#kzg_srs{g2 = G2Setup}, Proofs) ->
  case parse_g2_setup(G2Setup) of
    {ok, {G2Gen, TauG2}} ->
      Parsed = parse_proof_tuples(Proofs, []),
      case Parsed of
        error ->
          false;
        {ok, ValidTuples} ->
          Gamma = rand_128bit_challenge(),
          {PTotalAff, PiTotalAff} = accumulate_batch(ValidTuples, Gamma),
          ?PAIRING:pairing_check([{PTotalAff, G2Gen}, {PiTotalAff, TauG2}])
      end;
    error ->
      false
  end.

-spec parse_proof_tuples(
  [{g1_input(), scalar_input(), scalar_input(), g1_input()}],
  [{g1_point(), non_neg_integer(), non_neg_integer(), g1_point()}]
) -> {ok, [{g1_point(), non_neg_integer(), non_neg_integer(), g1_point()}]} | error.
parse_proof_tuples([], Acc) ->
  {ok, lists:reverse(Acc)};
parse_proof_tuples([{C, ZIn, YIn, Pi} | Rest], Acc) ->
  case {parse_g1(C), parse_g1(Pi)} of
    {{ok, CPoint}, {ok, PiPoint}} ->
      Z = to_scalar(ZIn),
      Y = to_scalar(YIn),
      case Z < ?R andalso Y < ?R of
        true ->
          parse_proof_tuples(Rest, [{CPoint, Z, Y, PiPoint} | Acc]);
        false ->
          error
      end;
    _ ->
      error
  end.

-spec accumulate_batch(
  [{g1_point(), non_neg_integer(), non_neg_integer(), g1_point()}],
  non_neg_integer()
) -> {g1_point(), g1_point()}.
accumulate_batch(Tuples, Gamma) ->
  G1Gen = ?BLS:g1_generator(),
  accumulate_batch_loop(Tuples, Gamma, 1, G1Gen, {1, 1, 0}, {1, 1, 0}).

-spec accumulate_batch_loop(
  [{g1_point(), non_neg_integer(), non_neg_integer(), g1_point()}],
  non_neg_integer(),
  non_neg_integer(),
  g1_point(),
  ecu_bls12_381:g1_jacobian(),
  ecu_bls12_381:g1_jacobian()
) -> {g1_point(), g1_point()}.
accumulate_batch_loop([], _Gamma, _Weight, _G1Gen, AccP, AccPi) ->
  {?BLS:g1_from_jacobian(AccP), ?BLS:g1_from_jacobian(AccPi)};
accumulate_batch_loop(
  [{C, Z, Y, Pi} | Rest],
  Gamma,
  Weight,
  G1Gen,
  AccP,
  AccPi
) ->
  %% Single proof term for P_i = [y]_1 - C - z * pi
  %% Scaled by Weight: Weight * [y]_1 - Weight * C - (Weight * z) * pi
  WeightY = (Weight * Y) rem ?R,
  WeightZ = (Weight * Z) rem ?R,

  TermY =
    case WeightY of
      0 -> {1, 1, 0};
      _ -> ?BLS:g1_to_jacobian(?BLS:g1_scalar_mul(G1Gen, WeightY))
    end,
  TermC =
    case Weight of
      0 -> {1, 1, 0};
      _ -> ?BLS:g1_to_jacobian(?BLS:g1_scalar_mul(C, Weight))
    end,
  TermZPi =
    case WeightZ of
      0 -> {1, 1, 0};
      _ -> ?BLS:g1_to_jacobian(?BLS:g1_scalar_mul(Pi, WeightZ))
    end,

  %% TermPi = Weight * pi
  TermPi =
    case Weight of
      0 -> {1, 1, 0};
      _ -> ?BLS:g1_to_jacobian(?BLS:g1_scalar_mul(Pi, Weight))
    end,

  %% Diff1 = TermY - TermC
  Diff1 = ?BLS:g1_j_add(TermY, ?BLS:g1_to_jacobian(?BLS:g1_neg(?BLS:g1_from_jacobian(TermC)))),
  %% Diff2 = Diff1 - TermZPi
  Diff2 = ?BLS:g1_j_add(Diff1, ?BLS:g1_to_jacobian(?BLS:g1_neg(?BLS:g1_from_jacobian(TermZPi)))),

  NewAccP = ?BLS:g1_j_add(AccP, Diff2),
  NewAccPi = ?BLS:g1_j_add(AccPi, TermPi),

  NextWeight = (Weight * Gamma) rem ?R,
  accumulate_batch_loop(Rest, Gamma, NextWeight, G1Gen, NewAccP, NewAccPi).

%%%-------------------------------------------------------------------
%%% EIP-4844 Point Evaluation Precompile (0x0A)
%%%-------------------------------------------------------------------

%% @doc Evaluates an EIP-4844 Point Evaluation request (192 bytes):
%% Input:  <<VersionedHash:32/binary, Z:32/binary, Y:32/binary, Commitment:48/binary, Proof:48/binary>>
%% Output: {ok, <<FIELD_ELEMENTS_PER_BLOB:256/big, BLS_MODULUS:256/big>>}
-spec point_evaluation(srs(), binary()) -> {ok, <<_:512>>} | {error, term()}.
point_evaluation(
  SRS,
  <<VersionedHash:32/binary, ZBin:32/binary, YBin:32/binary, CommitmentBin:48/binary,
    ProofBin:48/binary>>
) ->
  %% Validate versioned hash matches: 0x01 || sha256(Commitment)[1..31]
  ShaCommitment = ecu_compat:hash(sha256, CommitmentBin),
  <<_:8, RestSha:31/binary>> = ShaCommitment,
  ExpectedHash = <<16#01:8, RestSha:31/binary>>,
  case VersionedHash =:= ExpectedHash of
    false ->
      {error, invalid_versioned_hash};
    true ->
      case verify(SRS, CommitmentBin, ZBin, YBin, ProofBin) of
        true ->
          {ok, <<4096:256/big, ?R:256/big>>};
        false ->
          {error, verification_failed}
      end
  end;
point_evaluation(_SRS, _Invalid) ->
  {error, invalid_input_length}.

%%%-------------------------------------------------------------------
%%% Internal Helpers
%%%-------------------------------------------------------------------

-spec parse_g1(g1_input()) -> {ok, g1_point()} | {error, term()}.
parse_g1(Bin) when is_binary(Bin), byte_size(Bin) =:= 48 ->
  case ?BLS:g1_decompress(Bin) of
    {ok, Point} -> {ok, Point};
    {error, Reason} -> {error, Reason}
  end;
parse_g1(infinity) ->
  {ok, infinity};
parse_g1({X, Y} = Point) when is_integer(X), is_integer(Y) ->
  case ?BLS:g1_on_curve(Point) andalso ?BLS:g1_is_in_subgroup(Point) of
    true -> {ok, Point};
    false -> {error, not_in_subgroup}
  end;
parse_g1(_) ->
  {error, invalid_g1_point}.

-spec parse_g2_setup([g2_point()]) -> {ok, {g2_point(), g2_point()}} | error.
parse_g2_setup([G2Gen, TauG2 | _]) ->
  {ok, {G2Gen, TauG2}};
parse_g2_setup(_) ->
  error.

-spec to_scalar(scalar_input()) -> non_neg_integer().
to_scalar(<<Int:256/big>>) ->
  Int;
to_scalar(Int) when is_integer(Int) ->
  ((Int rem ?R) + ?R) rem ?R.

-spec multi_scalar_mul_g1([non_neg_integer()], [g1_point()]) -> g1_point().
multi_scalar_mul_g1(Coeffs, Points) ->
  Pairs = filter_nonzero_pairs(Coeffs, Points, []),
  case Pairs of
    [] ->
      ?BLS:g1_infinity();
    [{1, P1}] ->
      P1;
    [{C1, P1}] ->
      ?BLS:g1_scalar_mul(P1, C1);
    _ when length(Pairs) < 4 ->
      multi_scalar_mul_loop(Coeffs, Points, {1, 1, 0});
    _ ->
      straus_msm_g1(Pairs)
  end.

-spec filter_nonzero_pairs(
  [non_neg_integer()],
  [g1_point()],
  [{non_neg_integer(), g1_point()}]
) -> [{non_neg_integer(), g1_point()}].
filter_nonzero_pairs([], _Points, Acc) ->
  lists:reverse(Acc);
filter_nonzero_pairs(_Coeffs, [], Acc) ->
  lists:reverse(Acc);
filter_nonzero_pairs([0 | RestC], [_P | RestP], Acc) ->
  filter_nonzero_pairs(RestC, RestP, Acc);
filter_nonzero_pairs([C | RestC], [P | RestP], Acc) ->
  filter_nonzero_pairs(RestC, RestP, [{C, P} | Acc]).

-spec straus_msm_g1([{non_neg_integer(), g1_point()}]) -> g1_point().
straus_msm_g1(Pairs) ->
  Acc = straus_loop(254, Pairs, {1, 1, 0}),
  ?BLS:g1_from_jacobian(Acc).

-spec straus_loop(
  integer(),
  [{non_neg_integer(), g1_point()}],
  ecu_bls12_381:g1_jacobian()
) -> ecu_bls12_381:g1_jacobian().
straus_loop(-1, _Pairs, Acc) ->
  Acc;
straus_loop(BitIdx, Pairs, Acc) ->
  Dbl =
    case Acc of
      {_X, _Y, 0} -> Acc;
      _ -> ?BLS:g1_j_double(Acc)
    end,
  Mask = 1 bsl BitIdx,
  NewAcc = add_points_with_bit(Pairs, Mask, Dbl),
  straus_loop(BitIdx - 1, Pairs, NewAcc).

-spec add_points_with_bit(
  [{non_neg_integer(), g1_point()}],
  non_neg_integer(),
  ecu_bls12_381:g1_jacobian()
) -> ecu_bls12_381:g1_jacobian().
add_points_with_bit([], _Mask, Acc) ->
  Acc;
add_points_with_bit([{_Scalar, infinity} | Rest], Mask, Acc) ->
  add_points_with_bit(Rest, Mask, Acc);
add_points_with_bit([{Scalar, {X, Y}} | Rest], Mask, Acc) ->
  case (Scalar band Mask) =/= 0 of
    true ->
      NewAcc =
        case Acc of
          {_Ax, _Ay, 0} -> ?BLS:g1_to_jacobian({X, Y});
          _ -> ?BLS:g1_j_add_affine(Acc, {X, Y})
        end,
      add_points_with_bit(Rest, Mask, NewAcc);
    false ->
      add_points_with_bit(Rest, Mask, Acc)
  end.

-spec multi_scalar_mul_loop(
  [non_neg_integer()],
  [g1_point()],
  ecu_bls12_381:g1_jacobian()
) -> g1_point().
multi_scalar_mul_loop([], _Points, Acc) ->
  ?BLS:g1_from_jacobian(Acc);
multi_scalar_mul_loop(_Coeffs, [], Acc) ->
  ?BLS:g1_from_jacobian(Acc);
multi_scalar_mul_loop([0 | RestC], [_P | RestP], Acc) ->
  multi_scalar_mul_loop(RestC, RestP, Acc);
multi_scalar_mul_loop([C | RestC], [P | RestP], Acc) ->
  Term =
    case C of
      1 -> ?BLS:g1_to_jacobian(P);
      _ -> ?BLS:g1_to_jacobian(?BLS:g1_scalar_mul(P, C))
    end,
  NewAcc = ?BLS:g1_j_add(Acc, Term),
  multi_scalar_mul_loop(RestC, RestP, NewAcc).

-spec rand_128bit_challenge() -> pos_integer().
rand_128bit_challenge() ->
  <<Val:128/big>> = ecu_compat:strong_rand_bytes(16),
  case Val of
    0 -> 1;
    _ -> Val
  end.
