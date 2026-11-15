%%%-------------------------------------------------------------------
%%% @doc
%%% Record and macro definitions for Groth16 zk-SNARK verification.
%%% @end
%%%-------------------------------------------------------------------
-ifndef(ECU_GROTH16_HRL).
-define(ECU_GROTH16_HRL, true).

-type groth16_g1() :: ecu_bls12_381:g1_affine() | ecu_bn254:g1_affine().
-type groth16_g2() :: ecu_bls12_381:g2_affine() | ecu_bn254:g2_affine().

-record(groth16_proof, {
  a :: groth16_g1(),
  b :: groth16_g2(),
  c :: groth16_g1()
}).

-record(groth16_vk, {
  alpha_g1 :: groth16_g1(),
  beta_g2 :: groth16_g2(),
  gamma_g2 :: groth16_g2(),
  delta_g2 :: groth16_g2(),
  ic = [] :: [groth16_g1()]
}).

-type groth16_proof_rec() :: #groth16_proof{}.
-type groth16_vk_rec() :: #groth16_vk{}.

-endif.
