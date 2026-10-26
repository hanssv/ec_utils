%%% File        : frost_eqc.erl
%%% Description : QuickCheck properties for FROST (RFC 9591) threshold signatures
-module(frost_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

gen_ciphersuite() ->
  elements([ed25519, secp256k1, bip340]).

gen_params() ->
  ?LET(T, choose(2, 4),
       ?LET(N, choose(T, 5),
            {T, N})).

pub_from_priv(ed25519, Share) ->
  ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Share));
pub_from_priv(bip340, Share) ->
  <<S:256>> = Share,
  {X, _} = ecu_secp256k1:scalar_mul_base(S),
  <<X:256/big>>;
pub_from_priv(secp256k1, Share) ->
  ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(Share)).

pub_share_for_verify(ed25519, Share) ->
  ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Share));
pub_share_for_verify(bip340, Share) ->
  ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(Share));
pub_share_for_verify(secp256k1, Share) ->
  ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(Share)).

prop_trusted_dealer_vss() ->
  ?FORALL({CS, {T, N}}, {gen_ciphersuite(), gen_params()},
  begin
    {Shares, _GroupPubKey, VSSCommitment} = ecu_frost:trusted_dealer_keygen(CS, T, N),
    length(Shares) == N andalso
      length(VSSCommitment) == T andalso
      lists:all(fun({Id, Share}) ->
                  ecu_frost:vss_verify(CS, Id, Share, VSSCommitment)
                end, Shares)
  end).

prop_trusted_dealer_reconstruct() ->
  ?FORALL({CS, {T, N}}, {gen_ciphersuite(), gen_params()},
  begin
    {Shares, GroupPubKey, _VSSCommitment} = ecu_frost:trusted_dealer_keygen(CS, T, N),
    %% Shuffle and take exactly T shares
    Shuffled = [ X || {_, X} <- lists:sort([ {rand:uniform(), S} || S <- Shares ]) ],
    Selected = lists:sublist(Shuffled, T),
    Secret = ecu_frost:secret_share_combine(CS, Selected),
    ComputedPubKey = pub_from_priv(CS, Secret),
    ComputedPubKey == GroupPubKey
  end).

prop_frost_sign_verify() ->
  ?FORALL({CS, {T, N}, Msg}, {gen_ciphersuite(), gen_params(), binary()},
  begin
    {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(CS, T, N),
    %% Pick T random signers
    Shuffled = [ X || {_, X} <- lists:sort([ {rand:uniform(), S} || S <- Shares ]) ],
    Selected = lists:sublist(Shuffled, T),

    %% Round 1: Commitments
    Nonces = [ {Id, Share, ecu_frost:commit(CS, Share)} || {Id, Share} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

    %% Round 2: Signature shares
    SigShares = [ begin
                    PubShare = pub_share_for_verify(CS, Share),
                    SigShare = ecu_frost:sign(CS, Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList),
                    true = ecu_frost:verify_signature_share(CS, Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg),
                    SigShare
                  end || {Id, Share, {NoncePair, NonceComm}} <- Nonces ],

    %% Aggregation & Verification
    Signature = ecu_frost:aggregate(CS, CommitmentList, Msg, GroupPubKey, SigShares),
    ecu_frost:verify(CS, Signature, Msg, GroupPubKey)
  end).

prop_frost_tampered_sig() ->
  ?FORALL({CS, {T, N}, Msg}, {gen_ciphersuite(), gen_params(), binary()},
  begin
    {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(CS, T, N),
    Selected = lists:sublist(Shares, T),
    Nonces = [ {Id, Share, ecu_frost:commit(CS, Share)} || {Id, Share} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],
    SigShares = [ ecu_frost:sign(CS, Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList)
                  || {Id, Share, {NoncePair, _}} <- Nonces ],
    Signature = ecu_frost:aggregate(CS, CommitmentList, Msg, GroupPubKey, SigShares),
    ?FORALL(TamperByte, choose(0, byte_size(Signature) - 1),
    begin
      <<SigHead:TamperByte/binary, Byte:8, SigTail/binary>> = Signature,
      TamperedSig = <<SigHead/binary, (Byte bxor 16#ff):8, SigTail/binary>>,
      not ecu_frost:verify(CS, TamperedSig, Msg, GroupPubKey)
    end)
  end).

prop_frost_tampered_msg() ->
  ?FORALL({CS, {T, N}, Msg}, {gen_ciphersuite(), gen_params(), binary()},
  begin
    {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(CS, T, N),
    Selected = lists:sublist(Shares, T),
    Nonces = [ {Id, Share, ecu_frost:commit(CS, Share)} || {Id, Share} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],
    SigShares = [ ecu_frost:sign(CS, Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList)
                  || {Id, Share, {NoncePair, _}} <- Nonces ],
    Signature = ecu_frost:aggregate(CS, CommitmentList, Msg, GroupPubKey, SigShares),
    CorruptedMsg = <<Msg/binary, 1>>,
    not ecu_frost:verify(CS, Signature, CorruptedMsg, GroupPubKey)
  end).

prop_dkg_e2e() ->
  ?FORALL({CS, Msg}, {gen_ciphersuite(), binary()},
  begin
    T = 2,
    N = 3,
    CtxString = <<"dkg_eqc_test">>,
    KeyGen1 = [ {I, ecu_frost_dkg:round1(CS, I, T, CtxString)} || I <- lists:seq(1, N) ],

    %% Verify round 1
    R1Ok = lists:all(fun({I, {_, PoK, PubC}}) ->
                       ecu_frost_dkg:round1_check(CS, I, CtxString, PoK, PubC)
                     end, KeyGen1),

    %% Round 2 shares
    KeyGen2 = [ {I, ecu_frost_dkg:round2(CS, N, Cs)} || {I, {Cs, _, _}} <- KeyGen1 ],
    Secrets = [ {I, [ {J, element(2, lists:keyfind(I, 1, Shares))} || {J, Shares} <- KeyGen2 ]}
                || I <- lists:seq(1, N) ],

    %% Verify round 2
    R2Ok = lists:all(fun({I, Shares}) ->
                       lists:all(fun({J, Share}) ->
                                   I == J orelse
                                   ecu_frost_dkg:round2_check(CS, I, Share, element(3, element(2, lists:keyfind(J, 1, KeyGen1))))
                                 end, Shares)
                     end, Secrets),

    PubCs = [ PubC || {_, {_, _, PubC}} <- KeyGen1 ],
    GroupPubKey = ecu_frost_dkg:compute_public_key(CS, PubCs),
    SignShares = [ {I, ecu_frost_dkg:compute_private_sign_share(CS, Shares, PubCs),
                       ecu_frost_dkg:compute_public_verification_share(CS, Shares, PubCs)}
                   || {I, Shares} <- Secrets ],

    %% Sign with signers 1 and 3
    Selected = [lists:nth(1, SignShares), lists:nth(3, SignShares)],
    Nonces = [ {Id, PrivShare, PubShare, ecu_frost:commit(CS, PrivShare)}
               || {Id, PrivShare, PubShare} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, _, {_, {HC, BC}}} <- Nonces ],
    SigShares = [ begin
                    SigShare = ecu_frost:sign(CS, Id, PrivShare, GroupPubKey, NoncePair, Msg, CommitmentList),
                    true = ecu_frost:verify_signature_share(CS, Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg),
                    SigShare
                  end || {Id, PrivShare, PubShare, {NoncePair, NonceComm}} <- Nonces ],
    Signature = ecu_frost:aggregate(CS, CommitmentList, Msg, GroupPubKey, SigShares),
    Valid = ecu_frost:verify(CS, Signature, Msg, GroupPubKey),

    R1Ok andalso R2Ok andalso Valid
  end).

prop_default_ed25519() ->
  ?FORALL({{T, N}, Msg}, {gen_params(), binary()},
  begin
    {Shares, GroupPubKey, VSSCommitment} = ecu_frost:trusted_dealer_keygen(T, N),
    true = ecu_frost:vss_verify(1, element(2, hd(Shares)), VSSCommitment),
    Selected = lists:sublist(Shares, T),
    Secret = ecu_frost:secret_share_combine(Selected),
    Pub = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Secret)),
    true = (Pub == GroupPubKey),
    Nonces = [ {Id, S, ecu_frost:commit(S)} || {Id, S} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],
    SigShares = [ ecu_frost:sign(Id, S, GroupPubKey, NP, Msg, CommitmentList)
                  || {Id, S, {NP, _}} <- Nonces ],
    Sig = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, SigShares),
    ecu_frost:verify(Sig, Msg, GroupPubKey)
  end).
