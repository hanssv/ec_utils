%%%-------------------------------------------------------------------
%%% @doc
%%% Record and macro definitions for Groth16 zk-SNARK verification.
%%% @end
%%%-------------------------------------------------------------------
-ifndef(ECU_GROTH16_HRL).
-define(ECU_GROTH16_HRL, true).

-record(groth16_proof, {
  a :: ecu_bls12_381:g1_affine(),
  b :: ecu_bls12_381:g2_affine(),
  c :: ecu_bls12_381:g1_affine()
}).

-record(groth16_vk, {
  alpha_g1 :: ecu_bls12_381:g1_affine(),
  beta_g2 :: ecu_bls12_381:g2_affine(),
  gamma_g2 :: ecu_bls12_381:g2_affine(),
  delta_g2 :: ecu_bls12_381:g2_affine(),
  ic = [] :: [ecu_bls12_381:g1_affine()]
}).

-type groth16_proof_rec() :: #groth16_proof{}.
-type groth16_vk_rec() :: #groth16_vk{}.

-endif.
