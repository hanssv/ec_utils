%%% File        : schnorr_eqc.erl
%%% Description : QuickCheck properties for BIP-340 Schnorr signatures
-module(schnorr_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

-include("ecu_secp256k1.hrl").

gen_privkey() ->
  ?LET(N, choose(1, ?N - 1), <<N:256>>).

prop_keypair_derivation() ->
  ?FORALL(Priv, gen_privkey(),
  begin
    #{public := Pub, secret := Sec} = ecu_schnorr:sign_keypair_from_secret(Priv),
    <<SecInt:256>> = Sec,
    <<PrivInt:256>> = Priv,
    ValidSec = (SecInt == PrivInt orelse SecInt == (?N - PrivInt)),
    case ecu_schnorr:lift_x(Pub) of
      {ok, {X, Y}} ->
        ValidSec andalso (Y rem 2 == 0) andalso (<<X:256>> == Pub);
      error ->
        false
    end
  end).

prop_sign_verify() ->
  ?FORALL({Priv, Msg, Aux}, {gen_privkey(), binary(), binary(32)},
  begin
    #{public := Pub, secret := Sec} = ecu_schnorr:sign_keypair_from_secret(Priv),
    Sig = ecu_schnorr:sign(Msg, Sec, Aux),
    ecu_schnorr:verify(Sig, Msg, Pub)
  end).

prop_sign_verify_random_aux() ->
  ?FORALL({Priv, Msg}, {gen_privkey(), binary()},
  begin
    #{public := Pub, secret := Sec} = ecu_schnorr:sign_keypair_from_secret(Priv),
    Sig = ecu_schnorr:sign(Msg, Sec),
    ecu_schnorr:verify(Sig, Msg, Pub)
  end).

prop_verify_tampered_sig() ->
  ?FORALL({Priv, Msg, Aux, TamperPart},
          {gen_privkey(), binary(), binary(32), elements([r, s])},
  begin
    #{public := Pub, secret := Sec} = ecu_schnorr:sign_keypair_from_secret(Priv),
    Sig = ecu_schnorr:sign(Msg, Sec, Aux),
    <<R:256, S:256>> = Sig,
    TamperedSig =
      case TamperPart of
        r ->
          <<((R + 1) rem ?P):256, S:256>>;
        s ->
          <<R:256, ((S + 1) rem ?N):256>>
      end,
    case TamperedSig == Sig of
      true  -> true;
      false -> not ecu_schnorr:verify(TamperedSig, Msg, Pub)
    end
  end).

prop_verify_tampered_msg() ->
  ?FORALL({Priv, Msg, Aux}, {gen_privkey(), binary(), binary(32)},
  begin
    #{public := Pub, secret := Sec} = ecu_schnorr:sign_keypair_from_secret(Priv),
    Sig = ecu_schnorr:sign(Msg, Sec, Aux),
    CorruptedMsg = <<Msg/binary, 1>>,
    not ecu_schnorr:verify(Sig, CorruptedMsg, Pub)
  end).

prop_verify_tampered_pubkey() ->
  ?FORALL({Priv1, Priv2, Msg, Aux},
          {gen_privkey(), gen_privkey(), binary(), binary(32)},
  begin
    #{public := Pub1, secret := Sec1} = ecu_schnorr:sign_keypair_from_secret(Priv1),
    #{public := Pub2} = ecu_schnorr:sign_keypair_from_secret(Priv2),
    Sig1 = ecu_schnorr:sign(Msg, Sec1, Aux),
    case Pub1 == Pub2 of
      true  -> true;
      false -> not ecu_schnorr:verify(Sig1, Msg, Pub2)
    end
  end).

%% Cross-validation against Rust k256 reference NIF (when available)
prop_k256_reference_equivalence() ->
  case ecu_schnorr_nif:is_available() of
    false ->
      true;
    true ->
      ?FORALL({Priv, Msg, Aux}, {gen_privkey(), binary(), binary(32)},
      begin
        #{public := EcuPub, secret := Sec} = ecu_schnorr:sign_keypair_from_secret(Priv),
        NifPub = ecu_schnorr_nif:public_key(Priv),

        EcuSig = ecu_schnorr:sign(Msg, Sec, Aux),
        NifSig = ecu_schnorr_nif:sign(Priv, Msg, Aux),

        conjunction([
          {pubkeys_match, equals(EcuPub, NifPub)},
          {signatures_match, equals(EcuSig, NifSig)},
          {ecu_verifies_nif, equals(true, ecu_schnorr:verify(NifSig, Msg, EcuPub))},
          {nif_verifies_ecu, equals(true, ecu_schnorr_nif:verify(EcuSig, Msg, NifPub))}
        ])
      end)
  end.
