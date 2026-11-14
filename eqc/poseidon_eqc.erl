%%%-------------------------------------------------------------------
%%% @doc
%%% QuickCheck properties for pure-Erlang Poseidon hash function:
%%%   - Differential equivalence against Rust reference oracle (ecu_poseidon_nif)
%%%   - Consistency between specialized hash3/2,3 and generic hash/2
%%%   - Binary API equivalence with integer API
%%%   - Avalanche / bit sensitivity
%%%   - Strict domain & range boundary enforcement
%%% @end
%%%-------------------------------------------------------------------
-module(poseidon_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

-define(NIF, ecu_poseidon_nif).

%%%-------------------------------------------------------------------
%%% Generators
%%%-------------------------------------------------------------------

gen_curve() ->
  oneof([bls12_381, bn254]).

gen_scalar(Curve) ->
  Q = ecu_poseidon_constants:prime(Curve),
  choose(0, Q - 1).

gen_scalar_pair(Curve) ->
  ?LET({A, B}, {gen_scalar(Curve), gen_scalar(Curve)}, {A, B}).

gen_inputs(Curve) ->
  ?SIZED(
    _Size,
    ?LET(
      Len,
      choose(1, 8),
      vector(Len, gen_scalar(Curve))
    )
  ).

%%%-------------------------------------------------------------------
%%% Properties
%%%-------------------------------------------------------------------

prop_differential_bls12_381() ->
  ?FORALL(
    {A, B},
    gen_scalar_pair(bls12_381),
    case ?NIF:is_available() of
      true ->
        ErlHash = ecu_poseidon:hash3(bls12_381, A, B),
        {ok, <<NifHash:256/big>>} = ?NIF:hash3(bls12_381, <<A:256/big>>, <<B:256/big>>),
        equals(ErlHash, NifHash);
      false ->
        true
    end
  ).

prop_differential_bn254() ->
  ?FORALL(
    {A, B},
    gen_scalar_pair(bn254),
    case ?NIF:is_available() of
      true ->
        ErlHash = ecu_poseidon:hash3(bn254, A, B),
        {ok, <<NifHash:256/big>>} = ?NIF:hash3(bn254, <<A:256/big>>, <<B:256/big>>),
        equals(ErlHash, NifHash);
      false ->
        true
    end
  ).

prop_differential_generic() ->
  ?FORALL(
    Curve,
    gen_curve(),
    ?FORALL(
      Inputs,
      gen_inputs(Curve),
      case ?NIF:is_available() of
        true ->
          ErlHash = ecu_poseidon:hash(Curve, Inputs),
          BinInputs = [<<X:256/big>> || X <- Inputs],
          {ok, <<NifHash:256/big>>} = ?NIF:hash(Curve, BinInputs),
          equals(ErlHash, NifHash);
        false ->
          true
      end
    )
  ).

prop_hash3_vs_hash2() ->
  ?FORALL(
    Curve,
    gen_curve(),
    ?FORALL(
      {A, B},
      gen_scalar_pair(Curve),
      begin
        H3 = ecu_poseidon:hash3(Curve, A, B),
        H2 = ecu_poseidon:hash(Curve, [A, B]),
        equals(H3, H2)
      end
    )
  ).

prop_binary_vs_int() ->
  ?FORALL(
    Curve,
    gen_curve(),
    ?FORALL(
      Inputs,
      gen_inputs(Curve),
      begin
        IntHash = ecu_poseidon:hash(Curve, Inputs),
        BinInputs = [<<X:256/big>> || X <- Inputs],
        BinHash = ecu_poseidon:hash_binary(Curve, BinInputs),
        equals(<<IntHash:256/big>>, BinHash)
      end
    )
  ).

prop_sensitivity() ->
  ?FORALL(
    Curve,
    gen_curve(),
    ?FORALL(
      {A, B},
      gen_scalar_pair(Curve),
      begin
        H0 = ecu_poseidon:hash3(Curve, A, B),
        Q = ecu_poseidon_constants:prime(Curve),
        A_flipped = (A bxor 1) rem Q,
        H1 = ecu_poseidon:hash3(Curve, A_flipped, B),
        H0 =/= H1
      end
    )
  ).

prop_reject_out_of_range() ->
  ?FORALL(
    Curve,
    gen_curve(),
    begin
      Q = ecu_poseidon_constants:prime(Curve),
      ?FORALL(
        Offset,
        choose(0, 1000000),
        begin
          BadScalar = Q + Offset,
          Res1 =
            try
              ecu_poseidon:hash3(Curve, BadScalar, 1)
            catch
              error:badarg -> badarg
            end,
          Res2 =
            try
              ecu_poseidon:hash(Curve, [BadScalar])
            catch
              error:badarg -> badarg
            end,
          Res3 =
            try
              ecu_poseidon:hash_binary(Curve, [<<BadScalar:256>>])
            catch
              error:badarg -> badarg
            end,
          Res1 =:= badarg andalso Res2 =:= badarg andalso Res3 =:= badarg
        end
      )
    end
  ).
