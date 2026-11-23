%%%-------------------------------------------------------------------
%%% @doc
%%% Record and macro definitions for PLONK zk-SNARK verification.
%%% Supports BN254 (alt_bn128) and BLS12-381 curves.
%%% @end
%%%-------------------------------------------------------------------
-ifndef(ECU_PLONK_HRL).
-define(ECU_PLONK_HRL, true).

-type plonk_g1() :: ecu_bls12_381:g1_affine() | ecu_bn254:g1_affine().
-type plonk_g2() :: ecu_bls12_381:g2_affine() | ecu_bn254:g2_affine().

-record(plonk_vk, {
  curve = bn254 :: bn254 | bls12_381,
  power = 0 :: non_neg_integer(),
  n_public = 0 :: non_neg_integer(),
  k1 = 2 :: non_neg_integer(),
  k2 = 3 :: non_neg_integer(),
  w = 0 :: non_neg_integer(),
  qm :: plonk_g1(),
  ql :: plonk_g1(),
  qr :: plonk_g1(),
  qo :: plonk_g1(),
  qc :: plonk_g1(),
  s1 :: plonk_g1(),
  s2 :: plonk_g1(),
  s3 :: plonk_g1(),
  x_2 :: plonk_g2()
}).

-record(plonk_proof, {
  a :: plonk_g1(),
  b :: plonk_g1(),
  c :: plonk_g1(),
  z :: plonk_g1(),
  t1 :: plonk_g1(),
  t2 :: plonk_g1(),
  t3 :: plonk_g1(),
  eval_a = 0 :: non_neg_integer(),
  eval_b = 0 :: non_neg_integer(),
  eval_c = 0 :: non_neg_integer(),
  eval_s1 = 0 :: non_neg_integer(),
  eval_s2 = 0 :: non_neg_integer(),
  eval_zw = 0 :: non_neg_integer(),
  wxi :: plonk_g1(),
  wxiw :: plonk_g1()
}).

-record(plonk_challenges, {
  beta = 0 :: non_neg_integer(),
  gamma = 0 :: non_neg_integer(),
  alpha = 0 :: non_neg_integer(),
  xi = 0 :: non_neg_integer(),
  xin = 0 :: non_neg_integer(),
  zh = 0 :: non_neg_integer(),
  v = [] :: [non_neg_integer()],
  u = 0 :: non_neg_integer()
}).

-type plonk_vk_rec() :: #plonk_vk{}.
-type plonk_proof_rec() :: #plonk_proof{}.
-type plonk_challenges_rec() :: #plonk_challenges{}.

-endif.
