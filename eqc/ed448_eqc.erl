-module(ed448_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").
-include("ecu_ed448.hrl").

gen_scalar() ->
  ?LET(<<X:912>>, binary(114), 1 + (X rem (?N - 1))).

gen_scalar_bin() ->
  ?LET(K, gen_scalar(), <<K:456/little>>).

gen_point() ->
  ?LET(S, gen_scalar(), ecu_ed448:scalar_mul_base_noclamp(S)).

gen_context() ->
  ?LET(Len, choose(0, 32), binary(Len)).

%% --- Point Arithmetic Properties ---

prop_compress_decompress() ->
  ?FORALL(P, gen_point(),
    begin
      Comp = ecu_ed448:compress(P),
      Dec  = ecu_ed448:decompress(Comp),
      (Comp == ecu_ed448:compress(Dec)) andalso ecu_ed448:pt_eq(P, Dec)
    end).

prop_add_comm() ->
  ?FORALL({P1, P2}, {gen_point(), gen_point()},
    ecu_ed448:pt_eq(ecu_ed448:p_add(P1, P2), ecu_ed448:p_add(P2, P1))).

prop_add_assoc() ->
  ?FORALL({P1, P2, P3}, {gen_point(), gen_point(), gen_point()},
    ecu_ed448:pt_eq(
      ecu_ed448:p_add(ecu_ed448:p_add(P1, P2), P3),
      ecu_ed448:p_add(P1, ecu_ed448:p_add(P2, P3))
    )).

prop_dbl_matches_add() ->
  ?FORALL(P, gen_point(),
    ecu_ed448:pt_eq(ecu_ed448:p_dbl(P), ecu_ed448:p_add(P, P))).

prop_sub_neg() ->
  ?FORALL({P1, P2}, {gen_point(), gen_point()},
    ecu_ed448:pt_eq(
      ecu_ed448:p_sub(P1, P2),
      ecu_ed448:p_add(P1, ecu_ed448:p_neg(P2))
    )).

prop_scalar_mul_dual_base() ->
  ?FORALL({K1, K2, P}, {gen_scalar(), gen_scalar(), gen_point()},
    begin
      Dual = ecu_ed448:scalar_mul_dual_base(K1, K2, P),
      P1   = ecu_ed448:scalar_mul_base_noclamp(K1),
      P2   = ecu_ed448:scalar_mul_noclamp(K2, P),
      Sum  = ecu_ed448:p_add(P1, P2),
      ecu_ed448:pt_eq(Dual, Sum)
    end).

%% --- EdDSA Properties (Cross-checked with OTP crypto oracle) ---

prop_keypair_seed() ->
  ?FORALL(Seed, binary(57),
    begin
      {CryptoPub, _} = crypto:generate_key(eddsa, ed448, Seed),
      #{public := EcuPub} = ecu_eddsa448:sign_seed_keypair(Seed),
      equals(CryptoPub, EcuPub)
    end).

prop_sign_matches_crypto() ->
  ?FORALL({Seed, Msg}, {binary(57), binary()},
    begin
      CryptoSig = crypto:sign(eddsa, none, Msg, [Seed, ed448]),
      EcuSig    = ecu_eddsa448:sign_detached(Msg, Seed),
      equals(CryptoSig, EcuSig)
    end).

prop_verify_crypto_signature() ->
  ?FORALL({Seed, Msg}, {binary(57), binary()},
    begin
      {Pub, _} = crypto:generate_key(eddsa, ed448, Seed),
      CryptoSig = crypto:sign(eddsa, none, Msg, [Seed, ed448]),
      ecu_eddsa448:sign_verify_detached(CryptoSig, Msg, Pub)
    end).

prop_crypto_verifies_our_signature() ->
  ?FORALL({Seed, Msg}, {binary(57), binary()},
    begin
      #{public := Pub, secret := SK} = ecu_eddsa448:sign_seed_keypair(Seed),
      EcuSig = ecu_eddsa448:sign_detached(Msg, SK),
      crypto:verify(eddsa, none, Msg, EcuSig, [Pub, ed448])
    end).

prop_sign_open() ->
  ?FORALL({Seed, Msg}, {binary(57), binary()},
    begin
      #{public := Pub, secret := SK} = ecu_eddsa448:sign_seed_keypair(Seed),
      SM = ecu_eddsa448:sign(Msg, SK),
      equals({ok, Msg}, ecu_eddsa448:sign_open(SM, Pub))
    end).

prop_context_signing() ->
  ?FORALL({Seed, Msg, Ctx1, Ctx2}, {binary(57), binary(), gen_context(), gen_context()},
    begin
      #{public := Pub, secret := SK} = ecu_eddsa448:sign_seed_keypair(Seed),
      Sig = ecu_eddsa448:sign_detached(Msg, SK, Ctx1),
      ValidSame = ecu_eddsa448:sign_verify_detached(Sig, Msg, Pub, Ctx1),
      case Ctx1 == Ctx2 of
        true  -> ValidSame;
        false -> ValidSame andalso not ecu_eddsa448:sign_verify_detached(Sig, Msg, Pub, Ctx2)
      end
    end).

prop_batch_verify() ->
  ?FORALL(Items, non_empty(list({binary(57), binary(), gen_context()})),
    begin
      Batch = [ begin
                  #{public := Pub, secret := SK} = ecu_eddsa448:sign_seed_keypair(Seed),
                  Sig = ecu_eddsa448:sign_detached(Msg, SK, Ctx),
                  {Sig, Msg, Pub, Ctx}
                end || {Seed, Msg, Ctx} <- Items ],
      ecu_eddsa448:sign_verify_batch(Batch)
    end).
