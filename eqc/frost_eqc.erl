%%% File        : frost_eqc.erl
%%% Description : QuickCheck properties for FROST (RFC 9591) threshold signatures
-module(frost_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

gen_params() ->
  ?LET(T, choose(2, 4),
       ?LET(N, choose(T, 5),
            {T, N})).

prop_trusted_dealer_vss() ->
  ?FORALL({T, N}, gen_params(),
  begin
    {Shares, _GroupPubKey, VSSCommitment} = ecu_frost:trusted_dealer_keygen(T, N),
    length(Shares) == N andalso
      length(VSSCommitment) == T andalso
      lists:all(fun({Id, Share}) ->
                  ecu_frost:vss_verify(Id, Share, VSSCommitment)
                end, Shares)
  end).

prop_trusted_dealer_reconstruct() ->
  ?FORALL({T, N}, gen_params(),
  begin
    {Shares, GroupPubKey, _VSSCommitment} = ecu_frost:trusted_dealer_keygen(T, N),
    %% Shuffle and take exactly T shares
    Shuffled = [ X || {_, X} <- lists:sort([ {rand:uniform(), S} || S <- Shares ]) ],
    Selected = lists:sublist(Shuffled, T),
    Secret = ecu_frost:secret_share_combine(Selected),
    ComputedPubKey = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Secret)),
    ComputedPubKey == GroupPubKey
  end).

prop_frost_sign_verify() ->
  ?FORALL({{T, N}, Msg}, {gen_params(), binary()},
  begin
    {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(T, N),
    %% Pick T random signers
    Shuffled = [ X || {_, X} <- lists:sort([ {rand:uniform(), S} || S <- Shares ]) ],
    Selected = lists:sublist(Shuffled, T),

    %% Round 1: Commitments
    Nonces = [ {Id, Share, ecu_frost:commit(Share)} || {Id, Share} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

    %% Round 2: Signature shares
    SigShares = [ begin
                    PubShare = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Share)),
                    SigShare = ecu_frost:sign(Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList),
                    true = ecu_frost:verify_signature_share(Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg),
                    SigShare
                  end || {Id, Share, {NoncePair, NonceComm}} <- Nonces ],

    %% Aggregation & Verification
    Signature = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, SigShares),
    ecu_eddsa:sign_verify_detached(Signature, Msg, GroupPubKey)
  end).

prop_frost_tampered_sig() ->
  ?FORALL({{T, N}, Msg, TamperByte}, {gen_params(), binary(), choose(0, 63)},
  begin
    {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(T, N),
    Selected = lists:sublist(Shares, T),
    Nonces = [ {Id, Share, ecu_frost:commit(Share)} || {Id, Share} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],
    SigShares = [ ecu_frost:sign(Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList)
                  || {Id, Share, {NoncePair, _}} <- Nonces ],
    <<SigHead:TamperByte/binary, Byte:8, SigTail/binary>> = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, SigShares),
    TamperedSig = <<SigHead/binary, (Byte bxor 16#ff):8, SigTail/binary>>,
    not ecu_eddsa:sign_verify_detached(TamperedSig, Msg, GroupPubKey)
  end).

prop_frost_tampered_msg() ->
  ?FORALL({{T, N}, Msg}, {gen_params(), binary()},
  begin
    {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(T, N),
    Selected = lists:sublist(Shares, T),
    Nonces = [ {Id, Share, ecu_frost:commit(Share)} || {Id, Share} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],
    SigShares = [ ecu_frost:sign(Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList)
                  || {Id, Share, {NoncePair, _}} <- Nonces ],
    Signature = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, SigShares),
    CorruptedMsg = <<Msg/binary, 1>>,
    not ecu_eddsa:sign_verify_detached(Signature, CorruptedMsg, GroupPubKey)
  end).

prop_dkg_e2e() ->
  ?FORALL(Msg, binary(),
  begin
    T = 2,
    N = 3,
    CtxString = <<"dkg_eqc_test">>,
    KeyGen1 = [ {I, ecu_frost_dkg:round1(I, T, CtxString)} || I <- lists:seq(1, N) ],

    %% Verify round 1
    R1Ok = lists:all(fun({I, {_, PoK, PubC}}) ->
                       ecu_frost_dkg:round1_check(I, CtxString, PoK, PubC)
                     end, KeyGen1),

    %% Round 2 shares
    KeyGen2 = [ {I, ecu_frost_dkg:round2(N, Cs)} || {I, {Cs, _, _}} <- KeyGen1 ],
    Secrets = [ {I, [ {J, element(2, lists:keyfind(I, 1, Shares))} || {J, Shares} <- KeyGen2 ]}
                || I <- lists:seq(1, N) ],

    %% Verify round 2
    R2Ok = lists:all(fun({I, Shares}) ->
                       lists:all(fun({J, Share}) ->
                                   I == J orelse
                                   ecu_frost_dkg:round2_check(I, Share, element(3, element(2, lists:keyfind(J, 1, KeyGen1))))
                                 end, Shares)
                     end, Secrets),

    GroupPubKey = ecu_frost_dkg:compute_public_key([ PubC || {_, {_, _, PubC}} <- KeyGen1 ]),
    SignShares = [ {I, ecu_frost_dkg:compute_private_sign_share(Shares),
                       ecu_frost_dkg:compute_public_verification_share(Shares)}
                   || {I, Shares} <- Secrets ],

    %% Sign with signers 1 and 3
    Selected = [lists:nth(1, SignShares), lists:nth(3, SignShares)],
    Nonces = [ {Id, PrivShare, PubShare, ecu_frost:commit(PrivShare)}
               || {Id, PrivShare, PubShare} <- Selected ],
    CommitmentList = [ {Id, HC, BC} || {Id, _, _, {_, {HC, BC}}} <- Nonces ],
    SigShares = [ begin
                    SigShare = ecu_frost:sign(Id, PrivShare, GroupPubKey, NoncePair, Msg, CommitmentList),
                    true = ecu_frost:verify_signature_share(Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg),
                    SigShare
                  end || {Id, PrivShare, PubShare, {NoncePair, NonceComm}} <- Nonces ],
    Signature = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, SigShares),
    Valid = ecu_eddsa:sign_verify_detached(Signature, Msg, GroupPubKey),

    R1Ok andalso R2Ok andalso Valid
  end).
