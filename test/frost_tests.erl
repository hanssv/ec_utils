%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit tests and RFC 9591 test vectors for ecu_frost and ecu_frost_dkg.
%%% @end
%%%-------------------------------------------------------------------
-module(frost_tests).

-include_lib("eunit/include/eunit.hrl").

%% ===================================================================
%% RFC 9591 Appendix E.1 Test Vector
%% ===================================================================

rfc9591_ed25519_test() ->
  TestFile = filename:join([code:priv_dir(ec_utils), "..", "test", "data", "frost_ed25519_sha512_rfc9591.json"]),
  File = case filelib:is_file(TestFile) of
           true -> TestFile;
           false -> "test/data/frost_ed25519_sha512_rfc9591.json"
         end,
  {ok, Bin} = file:read_file(File),
  Data = json:decode(Bin),

  Inputs = maps:get(<<"inputs">>, Data),
  GroupPubKey = hex_to_bin(maps:get(<<"group_public_key">>, Inputs)),
  Msg = hex_to_bin(maps:get(<<"message">>, Inputs)),

  ParticipantsInputs = maps:get(<<"participants">>, Inputs),
  P1Data = maps:get(<<"1">>, ParticipantsInputs),
  P3Data = maps:get(<<"3">>, ParticipantsInputs),
  Secret1 = hex_to_bin(maps:get(<<"participant_share">>, P1Data)),
  Secret3 = hex_to_bin(maps:get(<<"participant_share">>, P3Data)),

  Pub1 = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Secret1)),
  Pub3 = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Secret3)),

  Round1Outputs = maps:get(<<"round_one_outputs">>, Data),
  R1Participants = maps:get(<<"participants">>, Round1Outputs),
  P1R1 = maps:get(<<"1">>, R1Participants),
  P3R1 = maps:get(<<"3">>, R1Participants),

  HidingRand1  = hex_to_bin(maps:get(<<"hiding_nonce_randomness">>, P1R1)),
  BindingRand1 = hex_to_bin(maps:get(<<"binding_nonce_randomness">>, P1R1)),
  HidingRand3  = hex_to_bin(maps:get(<<"hiding_nonce_randomness">>, P3R1)),
  BindingRand3 = hex_to_bin(maps:get(<<"binding_nonce_randomness">>, P3R1)),

  {NoncePair1, NonceComm1 = {HC1, BC1}} = ecu_frost:commit(Secret1, {HidingRand1, BindingRand1}),
  {NoncePair3, NonceComm3 = {HC3, BC3}} = ecu_frost:commit(Secret3, {HidingRand3, BindingRand3}),

  %% Verify nonces and commitments against test vector
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce">>, P1R1)), element(1, NoncePair1)),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce">>, P1R1)), element(2, NoncePair1)),
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce_commitment">>, P1R1)), HC1),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce_commitment">>, P1R1)), BC1),

  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce">>, P3R1)), element(1, NoncePair3)),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce">>, P3R1)), element(2, NoncePair3)),
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce_commitment">>, P3R1)), HC3),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce_commitment">>, P3R1)), BC3),

  CommitmentList = [{1, HC1, BC1}, {3, HC3, BC3}],

  %% Verify binding factors
  BindingFactorList = ecu_frost:compute_binding_factors(GroupPubKey, CommitmentList, Msg),
  {1, BF1} = lists:keyfind(1, 1, BindingFactorList),
  {3, BF3} = lists:keyfind(3, 1, BindingFactorList),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_factor">>, P1R1)), BF1),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_factor">>, P3R1)), BF3),

  %% Verify signature shares
  SigShare1 = ecu_frost:sign(1, Secret1, GroupPubKey, NoncePair1, Msg, CommitmentList),
  SigShare3 = ecu_frost:sign(3, Secret3, GroupPubKey, NoncePair3, Msg, CommitmentList),

  Round2Outputs = maps:get(<<"round_two_outputs">>, Data),
  R2Participants = maps:get(<<"participants">>, Round2Outputs),
  ExpSigShare1 = hex_to_bin(maps:get(<<"sig_share">>, maps:get(<<"1">>, R2Participants))),
  ExpSigShare3 = hex_to_bin(maps:get(<<"sig_share">>, maps:get(<<"3">>, R2Participants))),

  ?assertEqual(ExpSigShare1, SigShare1),
  ?assertEqual(ExpSigShare3, SigShare3),

  %% Verify individual signature shares
  ?assert(ecu_frost:verify_signature_share(1, Pub1, NonceComm1, SigShare1, CommitmentList, GroupPubKey, Msg)),
  ?assert(ecu_frost:verify_signature_share(3, Pub3, NonceComm3, SigShare3, CommitmentList, GroupPubKey, Msg)),

  %% Aggregate signature
  Signature = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, [SigShare1, SigShare3]),
  ExpSig = hex_to_bin(maps:get(<<"sig">>, maps:get(<<"final_output">>, Data))),
  ?assertEqual(ExpSig, Signature),

  %% Verify with standard Ed25519 detached verify
  ?assert(ecu_eddsa:sign_verify_detached(Signature, Msg, GroupPubKey)).

%% ===================================================================
%% RFC 9591 Appendix E.2 Test Vector (Ed448)
%% ===================================================================

rfc9591_ed448_test() ->
  TestFile = filename:join([code:priv_dir(ec_utils), "..", "test", "data", "frost_ed448_shake256_rfc9591.json"]),
  File = case filelib:is_file(TestFile) of
           true -> TestFile;
           false -> "test/data/frost_ed448_shake256_rfc9591.json"
         end,
  {ok, Bin} = file:read_file(File),
  Data = json:decode(Bin),

  Inputs = maps:get(<<"inputs">>, Data),
  GroupPubKey = hex_to_bin(maps:get(<<"group_public_key">>, Inputs)),
  Msg = hex_to_bin(maps:get(<<"message">>, Inputs)),

  ParticipantsInputs = maps:get(<<"participants">>, Inputs),
  P1Data = maps:get(<<"1">>, ParticipantsInputs),
  P3Data = maps:get(<<"3">>, ParticipantsInputs),
  Secret1 = hex_to_bin(maps:get(<<"participant_share">>, P1Data)),
  Secret3 = hex_to_bin(maps:get(<<"participant_share">>, P3Data)),

  Pub1 = ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(Secret1)),
  Pub3 = ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(Secret3)),

  Round1Outputs = maps:get(<<"round_one_outputs">>, Data),
  R1Participants = maps:get(<<"participants">>, Round1Outputs),
  P1R1 = maps:get(<<"1">>, R1Participants),
  P3R1 = maps:get(<<"3">>, R1Participants),

  HidingRand1  = hex_to_bin(maps:get(<<"hiding_nonce_randomness">>, P1R1)),
  BindingRand1 = hex_to_bin(maps:get(<<"binding_nonce_randomness">>, P1R1)),
  HidingRand3  = hex_to_bin(maps:get(<<"hiding_nonce_randomness">>, P3R1)),
  BindingRand3 = hex_to_bin(maps:get(<<"binding_nonce_randomness">>, P3R1)),

  {NoncePair1, NonceComm1 = {HC1, BC1}} = ecu_frost:commit(ed448, Secret1, {HidingRand1, BindingRand1}),
  {NoncePair3, NonceComm3 = {HC3, BC3}} = ecu_frost:commit(ed448, Secret3, {HidingRand3, BindingRand3}),

  %% Verify nonces and commitments against test vector
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce">>, P1R1)), element(1, NoncePair1)),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce">>, P1R1)), element(2, NoncePair1)),
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce_commitment">>, P1R1)), HC1),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce_commitment">>, P1R1)), BC1),

  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce">>, P3R1)), element(1, NoncePair3)),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce">>, P3R1)), element(2, NoncePair3)),
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce_commitment">>, P3R1)), HC3),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce_commitment">>, P3R1)), BC3),

  CommitmentList = [{1, HC1, BC1}, {3, HC3, BC3}],

  %% Verify binding factors
  BindingFactorList = ecu_frost:compute_binding_factors(ed448, GroupPubKey, CommitmentList, Msg),
  {1, BF1} = lists:keyfind(1, 1, BindingFactorList),
  {3, BF3} = lists:keyfind(3, 1, BindingFactorList),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_factor">>, P1R1)), BF1),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_factor">>, P3R1)), BF3),

  %% Verify signature shares
  SigShare1 = ecu_frost:sign(ed448, 1, Secret1, GroupPubKey, NoncePair1, Msg, CommitmentList),
  SigShare3 = ecu_frost:sign(ed448, 3, Secret3, GroupPubKey, NoncePair3, Msg, CommitmentList),

  Round2Outputs = maps:get(<<"round_two_outputs">>, Data),
  R2Participants = maps:get(<<"participants">>, Round2Outputs),
  ExpSigShare1 = hex_to_bin(maps:get(<<"sig_share">>, maps:get(<<"1">>, R2Participants))),
  ExpSigShare3 = hex_to_bin(maps:get(<<"sig_share">>, maps:get(<<"3">>, R2Participants))),

  ?assertEqual(ExpSigShare1, SigShare1),
  ?assertEqual(ExpSigShare3, SigShare3),

  %% Verify individual signature shares
  ?assert(ecu_frost:verify_signature_share(ed448, 1, Pub1, NonceComm1, SigShare1, CommitmentList, GroupPubKey, Msg)),
  ?assert(ecu_frost:verify_signature_share(ed448, 3, Pub3, NonceComm3, SigShare3, CommitmentList, GroupPubKey, Msg)),

  %% Aggregate signature
  Signature = ecu_frost:aggregate(ed448, CommitmentList, Msg, GroupPubKey, [SigShare1, SigShare3]),
  ExpSig = hex_to_bin(maps:get(<<"sig">>, maps:get(<<"final_output">>, Data))),
  ?assertEqual(ExpSig, Signature),

  %% Verify with standard Ed448 detached verify and ecu_frost:verify
  ?assert(ecu_frost:verify(ed448, Signature, Msg, GroupPubKey)),
  ?assert(ecu_eddsa448:sign_verify_detached(Signature, Msg, GroupPubKey, <<>>)).

%% ===================================================================
%% RFC 9591 Appendix E.5 Test Vector (secp256k1)
%% ===================================================================

rfc9591_secp256k1_test() ->
  TestFile = filename:join([code:priv_dir(ec_utils), "..", "test", "data", "frost_secp256k1_sha256_rfc9591.json"]),
  File = case filelib:is_file(TestFile) of
           true -> TestFile;
           false -> "test/data/frost_secp256k1_sha256_rfc9591.json"
         end,
  {ok, Bin} = file:read_file(File),
  Data = json:decode(Bin),

  Inputs = maps:get(<<"inputs">>, Data),
  GroupPubKey = hex_to_bin(maps:get(<<"group_public_key">>, Inputs)),
  Msg = hex_to_bin(maps:get(<<"message">>, Inputs)),

  ParticipantsInputs = maps:get(<<"participants">>, Inputs),
  P1Data = maps:get(<<"1">>, ParticipantsInputs),
  P3Data = maps:get(<<"3">>, ParticipantsInputs),
  Secret1 = hex_to_bin(maps:get(<<"participant_share">>, P1Data)),
  Secret3 = hex_to_bin(maps:get(<<"participant_share">>, P3Data)),

  <<S1_int:256>> = Secret1,
  <<S3_int:256>> = Secret3,
  Pub1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(S1_int)),
  Pub3 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(S3_int)),

  Round1Outputs = maps:get(<<"round_one_outputs">>, Data),
  R1Participants = maps:get(<<"participants">>, Round1Outputs),
  P1R1 = maps:get(<<"1">>, R1Participants),
  P3R1 = maps:get(<<"3">>, R1Participants),

  HidingRand1  = hex_to_bin(maps:get(<<"hiding_nonce_randomness">>, P1R1)),
  BindingRand1 = hex_to_bin(maps:get(<<"binding_nonce_randomness">>, P1R1)),
  HidingRand3  = hex_to_bin(maps:get(<<"hiding_nonce_randomness">>, P3R1)),
  BindingRand3 = hex_to_bin(maps:get(<<"binding_nonce_randomness">>, P3R1)),

  {NoncePair1, NonceComm1 = {HC1, BC1}} = ecu_frost:commit(secp256k1, Secret1, {HidingRand1, BindingRand1}),
  {NoncePair3, NonceComm3 = {HC3, BC3}} = ecu_frost:commit(secp256k1, Secret3, {HidingRand3, BindingRand3}),

  %% Verify nonces and commitments against test vector
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce">>, P1R1)), element(1, NoncePair1)),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce">>, P1R1)), element(2, NoncePair1)),
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce_commitment">>, P1R1)), HC1),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce_commitment">>, P1R1)), BC1),

  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce">>, P3R1)), element(1, NoncePair3)),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce">>, P3R1)), element(2, NoncePair3)),
  ?assertEqual(hex_to_bin(maps:get(<<"hiding_nonce_commitment">>, P3R1)), HC3),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_nonce_commitment">>, P3R1)), BC3),

  CommitmentList = [{1, HC1, BC1}, {3, HC3, BC3}],

  %% Verify binding factors
  BindingFactorList = ecu_frost:compute_binding_factors(secp256k1, GroupPubKey, CommitmentList, Msg),
  {1, BF1} = lists:keyfind(1, 1, BindingFactorList),
  {3, BF3} = lists:keyfind(3, 1, BindingFactorList),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_factor">>, P1R1)), BF1),
  ?assertEqual(hex_to_bin(maps:get(<<"binding_factor">>, P3R1)), BF3),

  %% Verify signature shares
  SigShare1 = ecu_frost:sign(secp256k1, 1, Secret1, GroupPubKey, NoncePair1, Msg, CommitmentList),
  SigShare3 = ecu_frost:sign(secp256k1, 3, Secret3, GroupPubKey, NoncePair3, Msg, CommitmentList),

  Round2Outputs = maps:get(<<"round_two_outputs">>, Data),
  R2Participants = maps:get(<<"participants">>, Round2Outputs),
  ExpSigShare1 = hex_to_bin(maps:get(<<"sig_share">>, maps:get(<<"1">>, R2Participants))),
  ExpSigShare3 = hex_to_bin(maps:get(<<"sig_share">>, maps:get(<<"3">>, R2Participants))),

  ?assertEqual(ExpSigShare1, SigShare1),
  ?assertEqual(ExpSigShare3, SigShare3),

  %% Verify individual signature shares
  ?assert(ecu_frost:verify_signature_share(secp256k1, 1, Pub1, NonceComm1, SigShare1, CommitmentList, GroupPubKey, Msg)),
  ?assert(ecu_frost:verify_signature_share(secp256k1, 3, Pub3, NonceComm3, SigShare3, CommitmentList, GroupPubKey, Msg)),

  %% Aggregate signature
  Signature = ecu_frost:aggregate(secp256k1, CommitmentList, Msg, GroupPubKey, [SigShare1, SigShare3]),
  ExpSig = hex_to_bin(maps:get(<<"sig">>, maps:get(<<"final_output">>, Data))),
  ?assertEqual(ExpSig, Signature),

  %% Verify with RFC 9591 prime order verification
  ?assert(ecu_frost:verify(secp256k1, Signature, Msg, GroupPubKey)).

%% ===================================================================
%% Trusted Dealer Keygen Tests (RFC 9591 Appendix C)
%% ===================================================================

trusted_dealer_keygen_test() ->
  T = 3,
  N = 5,
  {Shares, GroupPubKey, VSSCommitment} = ecu_frost:trusted_dealer_keygen(T, N),
  ?assertEqual(N, length(Shares)),
  ?assertEqual(T, length(VSSCommitment)),

  %% All participants can verify their share
  [ ?assert(ecu_frost:vss_verify(Id, Share, VSSCommitment)) || {Id, Share} <- Shares ],

  %% Any T shares reconstruct the secret
  Selected3 = [lists:nth(1, Shares), lists:nth(3, Shares), lists:nth(5, Shares)],
  Secret = ecu_frost:secret_share_combine(Selected3),
  ?assertEqual(GroupPubKey, ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Secret))),

  %% Sign with the 3 selected participants
  Msg = <<"Hello, FROST RFC 9591!">>,
  Nonces = [ {Id, Share, ecu_frost:commit(Share)} || {Id, Share} <- Selected3 ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  PubShare = ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(Share)),
                  SigShare = ecu_frost:sign(Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList),
                  ?assert(ecu_frost:verify_signature_share(Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg)),
                  SigShare
                end || {Id, Share, {NoncePair, NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, SigShares),
  ?assert(ecu_eddsa:sign_verify_detached(Signature, Msg, GroupPubKey)),

  %% Tampered message should fail
  ?assertNot(ecu_eddsa:sign_verify_detached(Signature, <<"Wrong msg">>, GroupPubKey)).

%% ===================================================================
%% Distributed Key Generation (DKG) End-to-End Scenario
%% ===================================================================

dkg_scenario_test() ->
  N = 5,
  T = 3,
  CtxString = crypto:strong_rand_bytes(32),

  %% Round 1: Each participant generates polynomial and PoK
  KeyGen1 = [ {I, ecu_frost_dkg:round1(I, T, CtxString)} || I <- lists:seq(1, N) ],

  %% Round 1 check: Every participant checks each other's PoK
  [ ?assert(ecu_frost_dkg:round1_check(I, CtxString, PoK, PubC))
    || {I, {_, PoK, PubC}} <- KeyGen1 ],

  %% Round 2: Each participant generates secret shares for all participants
  KeyGen2 = [ {I, ecu_frost_dkg:round2(N, Cs)} || {I, {Cs, _, _}} <- KeyGen1 ],

  %% Participant I collects shares meant for I from all J
  Secrets = [ {I, [ {J, S} || {J, Shares} <- KeyGen2, {Ix, S} <- Shares, Ix =:= I ]}
              || I <- lists:seq(1, N) ],

  %% Round 2 check: Participant I verifies share received from J
  [ begin
      {J, {_, _, PubC_J}} = lists:keyfind(J, 1, KeyGen1),
      ?assert(ecu_frost_dkg:round2_check(I, Share, PubC_J))
    end
    || {I, Shares} <- Secrets, {J, Share} <- Shares, I =/= J ],

  %% Compute signing shares and verification shares
  SignShares = [ {I, ecu_frost_dkg:compute_private_sign_share(Shares),
                     ecu_frost_dkg:compute_public_verification_share(Shares)}
                 || {I, Shares} <- Secrets ],

  %% Joint public key
  GroupPubKey = ecu_frost_dkg:compute_public_key([ PubC || {_, {_, _, PubC}} <- KeyGen1 ]),

  %% 3 of the 5 sign a message
  SigningGroup = [lists:nth(2, SignShares), lists:nth(4, SignShares), lists:nth(5, SignShares)],
  Msg = <<"Consensus block proposal #1024">>,

  Nonces = [ {Id, PrivShare, PubShare, ecu_frost:commit(PrivShare)}
             || {Id, PrivShare, PubShare} <- SigningGroup ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  SigShare = ecu_frost:sign(Id, PrivShare, GroupPubKey, NoncePair, Msg, CommitmentList),
                  ?assert(ecu_frost:verify_signature_share(Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg)),
                  SigShare
                end || {Id, PrivShare, PubShare, {NoncePair, NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(CommitmentList, Msg, GroupPubKey, SigShares),
  ?assert(ecu_eddsa:sign_verify_detached(Signature, Msg, GroupPubKey)).

trusted_dealer_ed448_test() ->
  T = 3,
  N = 5,
  {Shares, GroupPubKey, VSSCommitment} = ecu_frost:trusted_dealer_keygen(ed448, T, N),
  ?assertEqual(N, length(Shares)),
  ?assertEqual(T, length(VSSCommitment)),

  [ ?assert(ecu_frost:vss_verify(ed448, Id, Share, VSSCommitment)) || {Id, Share} <- Shares ],

  Selected3 = [lists:nth(1, Shares), lists:nth(3, Shares), lists:nth(5, Shares)],
  Secret = ecu_frost:secret_share_combine(ed448, Selected3),
  ?assertEqual(GroupPubKey, ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(Secret))),

  Msg = <<"FROST ed448 test message">>,
  Nonces = [ {Id, Share, ecu_frost:commit(ed448, Share)} || {Id, Share} <- Selected3 ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  PubShare = ecu_ed448:compress(ecu_ed448:scalar_mul_base_noclamp(Share)),
                  SigShare = ecu_frost:sign(ed448, Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList),
                  ?assert(ecu_frost:verify_signature_share(ed448, Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg)),
                  SigShare
                end || {Id, Share, {NoncePair, NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(ed448, CommitmentList, Msg, GroupPubKey, SigShares),
  ?assert(ecu_frost:verify(ed448, Signature, Msg, GroupPubKey)),
  ?assert(ecu_eddsa448:sign_verify_detached(Signature, Msg, GroupPubKey, <<>>)),
  ?assertNot(ecu_frost:verify(ed448, Signature, <<"Corrupted">>, GroupPubKey)).

dkg_ed448_test() ->
  N = 3,
  T = 2,
  CtxString = <<"ed448_dkg_test">>,
  KeyGen1 = [ {I, ecu_frost_dkg:round1(ed448, I, T, CtxString)} || I <- lists:seq(1, N) ],

  [ ?assert(ecu_frost_dkg:round1_check(ed448, I, CtxString, PoK, PubC))
    || {I, {_, PoK, PubC}} <- KeyGen1 ],

  KeyGen2 = [ {I, ecu_frost_dkg:round2(ed448, N, Cs)} || {I, {Cs, _, _}} <- KeyGen1 ],
  Secrets = [ {I, [ {J, S} || {J, Shares} <- KeyGen2, {Ix, S} <- Shares, Ix =:= I ]}
              || I <- lists:seq(1, N) ],

  [ begin
      {J, {_, _, PubC_J}} = lists:keyfind(J, 1, KeyGen1),
      ?assert(ecu_frost_dkg:round2_check(ed448, I, Share, PubC_J))
    end
    || {I, Shares} <- Secrets, {J, Share} <- Shares, I =/= J ],

  SignShares = [ {I, ecu_frost_dkg:compute_private_sign_share(ed448, Shares),
                     ecu_frost_dkg:compute_public_verification_share(ed448, Shares)}
                 || {I, Shares} <- Secrets ],

  GroupPubKey = ecu_frost_dkg:compute_public_key(ed448, [ PubC || {_, {_, _, PubC}} <- KeyGen1 ]),

  SigningGroup = [lists:nth(1, SignShares), lists:nth(2, SignShares)],
  Msg = <<"Consensus block on ed448">>,

  Nonces = [ {Id, PrivShare, PubShare, ecu_frost:commit(ed448, PrivShare)}
             || {Id, PrivShare, PubShare} <- SigningGroup ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  SigShare = ecu_frost:sign(ed448, Id, PrivShare, GroupPubKey, NoncePair, Msg, CommitmentList),
                  ?assert(ecu_frost:verify_signature_share(ed448, Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg)),
                  SigShare
                end || {Id, PrivShare, PubShare, {NoncePair, NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(ed448, CommitmentList, Msg, GroupPubKey, SigShares),
  ?assert(ecu_frost:verify(ed448, Signature, Msg, GroupPubKey)),
  ?assert(ecu_eddsa448:sign_verify_detached(Signature, Msg, GroupPubKey, <<>>)).

trusted_dealer_secp256k1_test() ->
  T = 3,
  N = 5,
  {Shares, GroupPubKey, VSSCommitment} = ecu_frost:trusted_dealer_keygen(secp256k1, T, N),
  ?assertEqual(N, length(Shares)),
  ?assertEqual(T, length(VSSCommitment)),

  [ ?assert(ecu_frost:vss_verify(secp256k1, Id, Share, VSSCommitment)) || {Id, Share} <- Shares ],

  Selected3 = [lists:nth(1, Shares), lists:nth(3, Shares), lists:nth(5, Shares)],
  Secret = ecu_frost:secret_share_combine(secp256k1, Selected3),
  <<SecInt:256>> = Secret,
  ?assertEqual(GroupPubKey, ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SecInt))),

  Msg = <<"FROST secp256k1 test message">>,
  Nonces = [ {Id, Share, ecu_frost:commit(secp256k1, Share)} || {Id, Share} <- Selected3 ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  <<S:256>> = Share,
                  PubShare = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(S)),
                  SigShare = ecu_frost:sign(secp256k1, Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList),
                  ?assert(ecu_frost:verify_signature_share(secp256k1, Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg)),
                  SigShare
                end || {Id, Share, {NoncePair, NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(secp256k1, CommitmentList, Msg, GroupPubKey, SigShares),
  ?assert(ecu_frost:verify(secp256k1, Signature, Msg, GroupPubKey)),
  ?assertNot(ecu_frost:verify(secp256k1, Signature, <<"Corrupted">>, GroupPubKey)).

dkg_secp256k1_test() ->
  N = 3,
  T = 2,
  CtxString = <<"secp256k1_dkg_test">>,
  KeyGen1 = [ {I, ecu_frost_dkg:round1(secp256k1, I, T, CtxString)} || I <- lists:seq(1, N) ],

  [ ?assert(ecu_frost_dkg:round1_check(secp256k1, I, CtxString, PoK, PubC))
    || {I, {_, PoK, PubC}} <- KeyGen1 ],

  KeyGen2 = [ {I, ecu_frost_dkg:round2(secp256k1, N, Cs)} || {I, {Cs, _, _}} <- KeyGen1 ],
  Secrets = [ {I, [ {J, S} || {J, Shares} <- KeyGen2, {Ix, S} <- Shares, Ix =:= I ]}
              || I <- lists:seq(1, N) ],

  [ begin
      {J, {_, _, PubC_J}} = lists:keyfind(J, 1, KeyGen1),
      ?assert(ecu_frost_dkg:round2_check(secp256k1, I, Share, PubC_J))
    end
    || {I, Shares} <- Secrets, {J, Share} <- Shares, I =/= J ],

  SignShares = [ {I, ecu_frost_dkg:compute_private_sign_share(secp256k1, Shares),
                     ecu_frost_dkg:compute_public_verification_share(secp256k1, Shares)}
                 || {I, Shares} <- Secrets ],

  GroupPubKey = ecu_frost_dkg:compute_public_key(secp256k1, [ PubC || {_, {_, _, PubC}} <- KeyGen1 ]),

  SigningGroup = [lists:nth(1, SignShares), lists:nth(2, SignShares)],
  Msg = <<"Consensus block on secp256k1">>,

  Nonces = [ {Id, PrivShare, PubShare, ecu_frost:commit(secp256k1, PrivShare)}
             || {Id, PrivShare, PubShare} <- SigningGroup ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  SigShare = ecu_frost:sign(secp256k1, Id, PrivShare, GroupPubKey, NoncePair, Msg, CommitmentList),
                  ?assert(ecu_frost:verify_signature_share(secp256k1, Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg)),
                  SigShare
                end || {Id, PrivShare, PubShare, {NoncePair, NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(secp256k1, CommitmentList, Msg, GroupPubKey, SigShares),
  ?assert(ecu_frost:verify(secp256k1, Signature, Msg, GroupPubKey)).

trusted_dealer_bip340_test() ->
  N = 5,
  T = 3,
  {Shares, GroupPubKey, VSSCommitment} = ecu_frost:trusted_dealer_keygen(bip340, T, N),
  ?assertEqual(32, byte_size(GroupPubKey)),
  ?assertEqual(N, length(Shares)),
  ?assertEqual(T, length(VSSCommitment)),

  [ ?assert(ecu_frost:vss_verify(bip340, Id, Share, VSSCommitment))
    || {Id, Share} <- Shares ],

  Selected = [lists:nth(1, Shares), lists:nth(3, Shares), lists:nth(5, Shares)],
  Msg = <<"BIP-340 Taproot threshold transaction">>,

  Nonces = [ {Id, Share, ecu_frost:commit(bip340, Share)} || {Id, Share} <- Selected ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  <<S:256>> = Share,
                  PubShare = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(S)),
                  SigShare = ecu_frost:sign(bip340, Id, Share, GroupPubKey, NoncePair, Msg, CommitmentList),
                  ?assert(ecu_frost:verify_signature_share(bip340, Id, PubShare, NonceComm, SigShare, CommitmentList, GroupPubKey, Msg)),
                  SigShare
                end || {Id, Share, {NoncePair, NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(bip340, CommitmentList, Msg, GroupPubKey, SigShares),
  ?assertEqual(64, byte_size(Signature)),
  ?assert(ecu_frost:verify(bip340, Signature, Msg, GroupPubKey)),
  ?assert(ecu_schnorr:verify(Signature, Msg, GroupPubKey)),
  ?assertNot(ecu_frost:verify(bip340, Signature, <<"Wrong msg">>, GroupPubKey)).

dkg_bip340_test() ->
  N = 3,
  T = 2,
  CtxString = <<"bip340_dkg_test">>,
  KeyGen1 = [ {I, ecu_frost_dkg:round1(bip340, I, T, CtxString)} || I <- lists:seq(1, N) ],

  [ ?assert(ecu_frost_dkg:round1_check(bip340, I, CtxString, PoK, PubC))
    || {I, {_, PoK, PubC}} <- KeyGen1 ],

  KeyGen2 = [ {I, ecu_frost_dkg:round2(bip340, N, Cs)} || {I, {Cs, _, _}} <- KeyGen1 ],
  Secrets = [ {I, [ {J, S} || {J, Shares} <- KeyGen2, {Ix, S} <- Shares, Ix =:= I ]}
              || I <- lists:seq(1, N) ],

  PubCs = [ PubC || {_, {_, _, PubC}} <- KeyGen1 ],
  GroupPubKey = ecu_frost_dkg:compute_public_key(bip340, PubCs),
  ?assertEqual(32, byte_size(GroupPubKey)),

  SignShares = [ {I, ecu_frost_dkg:compute_private_sign_share(bip340, Shares, PubCs),
                     ecu_frost_dkg:compute_public_verification_share(bip340, Shares)}
                 || {I, Shares} <- Secrets ],

  SigningGroup = [lists:nth(1, SignShares), lists:nth(2, SignShares)],
  Msg = <<"BIP-340 DKG threshold signing test">>,

  Nonces = [ {Id, PrivShare, PubShare, ecu_frost:commit(bip340, PrivShare)}
             || {Id, PrivShare, PubShare} <- SigningGroup ],
  CommitmentList = [ {Id, HC, BC} || {Id, _, _, {_, {HC, BC}}} <- Nonces ],

  SigShares = [ begin
                  SigShare = ecu_frost:sign(bip340, Id, PrivShare, GroupPubKey, NoncePair, Msg, CommitmentList),
                  SigShare
                end || {Id, PrivShare, _PubShare, {NoncePair, _NonceComm}} <- Nonces ],

  Signature = ecu_frost:aggregate(bip340, CommitmentList, Msg, GroupPubKey, SigShares),
  ?assertEqual(64, byte_size(Signature)),
  ?assert(ecu_frost:verify(bip340, Signature, Msg, GroupPubKey)),
  ?assert(ecu_schnorr:verify(Signature, Msg, GroupPubKey)).

%% ===================================================================
%% Benchmarks
%% ===================================================================

benchmark_frost_ed25519_test() ->
  T = 3,
  N = 5,
  {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(ed25519, T, N),
  Selected = lists:sublist(Shares, T),
  Msg = <<"Benchmark FROST message">>,

  %% Nonce commit benchmark
  {CommitTime, Nonces} = timer:tc(fun() ->
    [ {Id, S, ecu_frost:commit(ed25519, S)} || {Id, S} <- Selected ]
  end),

  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  %% Partial sign benchmark
  {SignTime, SigShares} = timer:tc(fun() ->
    [ ecu_frost:sign(ed25519, Id, S, GroupPubKey, NoncePair, Msg, CommitmentList)
      || {Id, S, {NoncePair, _}} <- Nonces ]
  end),

  %% Aggregate benchmark
  {AggTime, Signature} = timer:tc(fun() ->
    ecu_frost:aggregate(ed25519, CommitmentList, Msg, GroupPubKey, SigShares)
  end),

  %% Detached verify benchmark
  {VerifyTime, Valid} = timer:tc(fun() ->
    ecu_frost:verify(ed25519, Signature, Msg, GroupPubKey)
  end),

  ?assert(Valid),
  case ecu_frost_nif:is_available() of
    true -> ?assert(ecu_frost_nif:verify(ed25519, Signature, Msg, GroupPubKey));
    false -> ok
  end,
  report_frost_bench(ed25519, T, CommitTime, SignTime, AggTime, VerifyTime).

benchmark_frost_secp256k1_test() ->
  T = 3,
  N = 5,
  {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(secp256k1, T, N),
  Selected = lists:sublist(Shares, T),
  Msg = <<"Benchmark FROST secp256k1 message">>,

  %% Nonce commit benchmark
  {CommitTime, Nonces} = timer:tc(fun() ->
    [ {Id, S, ecu_frost:commit(secp256k1, S)} || {Id, S} <- Selected ]
  end),

  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  %% Partial sign benchmark
  {SignTime, SigShares} = timer:tc(fun() ->
    [ ecu_frost:sign(secp256k1, Id, S, GroupPubKey, NoncePair, Msg, CommitmentList)
      || {Id, S, {NoncePair, _}} <- Nonces ]
  end),

  %% Aggregate benchmark
  {AggTime, Signature} = timer:tc(fun() ->
    ecu_frost:aggregate(secp256k1, CommitmentList, Msg, GroupPubKey, SigShares)
  end),

  %% Prime order verify benchmark
  {VerifyTime, Valid} = timer:tc(fun() ->
    ecu_frost:verify(secp256k1, Signature, Msg, GroupPubKey)
  end),

  ?assert(Valid),
  case ecu_frost_nif:is_available() of
    true -> ?assert(ecu_frost_nif:verify(secp256k1, Signature, Msg, GroupPubKey));
    false -> ok
  end,
  report_frost_bench(secp256k1, T, CommitTime, SignTime, AggTime, VerifyTime).

benchmark_frost_bip340_test() ->
  T = 3,
  N = 5,
  {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(bip340, T, N),
  Selected = lists:sublist(Shares, T),
  Msg = <<"Benchmark FROST bip340 message">>,

  %% Nonce commit benchmark
  {CommitTime, Nonces} = timer:tc(fun() ->
    [ {Id, S, ecu_frost:commit(bip340, S)} || {Id, S} <- Selected ]
  end),

  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  %% Partial sign benchmark
  {SignTime, SigShares} = timer:tc(fun() ->
    [ ecu_frost:sign(bip340, Id, S, GroupPubKey, NoncePair, Msg, CommitmentList)
      || {Id, S, {NoncePair, _}} <- Nonces ]
  end),

  %% Aggregate benchmark
  {AggTime, Signature} = timer:tc(fun() ->
    ecu_frost:aggregate(bip340, CommitmentList, Msg, GroupPubKey, SigShares)
  end),

  %% BIP-340 verify benchmark
  {VerifyTime, Valid} = timer:tc(fun() ->
    ecu_frost:verify(bip340, Signature, Msg, GroupPubKey)
  end),

  ?assert(Valid),
  case ecu_frost_nif:is_available() of
    true -> ?assert(ecu_frost_nif:verify(bip340, Signature, Msg, GroupPubKey));
    false -> ok
  end,
  report_frost_bench(bip340, T, CommitTime, SignTime, AggTime, VerifyTime).

benchmark_frost_ed448_test() ->
  T = 3,
  N = 5,
  {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(ed448, T, N),
  Selected = lists:sublist(Shares, T),
  Msg = <<"Benchmark FROST ed448 message">>,

  %% Nonce commit benchmark
  {CommitTime, Nonces} = timer:tc(fun() ->
    [ {Id, S, ecu_frost:commit(ed448, S)} || {Id, S} <- Selected ]
  end),

  CommitmentList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],

  %% Partial sign benchmark
  {SignTime, SigShares} = timer:tc(fun() ->
    [ ecu_frost:sign(ed448, Id, S, GroupPubKey, NoncePair, Msg, CommitmentList)
      || {Id, S, {NoncePair, _}} <- Nonces ]
  end),

  %% Aggregate benchmark
  {AggTime, Signature} = timer:tc(fun() ->
    ecu_frost:aggregate(ed448, CommitmentList, Msg, GroupPubKey, SigShares)
  end),

  %% Ed448 verify benchmark
  {VerifyTime, Valid} = timer:tc(fun() ->
    ecu_frost:verify(ed448, Signature, Msg, GroupPubKey)
  end),

  ?assert(Valid),
  case ecu_frost_nif:is_available() of
    true -> ?assert(ecu_frost_nif:verify(ed448, Signature, Msg, GroupPubKey));
    false -> ok
  end,
  report_frost_bench(ed448, T, CommitTime, SignTime, AggTime, VerifyTime).

report_frost_bench(Suite, T, CommitTime, SignTime, AggTime, VerifyTime) ->
  SuiteName = case Suite of
                ed25519 -> "Ed25519";
                secp256k1 -> "secp256k1";
                bip340 -> "BIP-340";
                ed448 -> "Ed448"
              end,
  ?debugFmt("~nFROST ~s (t=~p, n=5) Benchmarks:", [SuiteName, T]),
  ?debugFmt("Commit (x~p):     ~.2f us/op (~.2f us/participant)", [T, CommitTime / 1, CommitTime / T]),
  ?debugFmt("Part Sign (x~p):  ~.2f us/op (~.2f us/participant)", [T, SignTime / 1, SignTime / T]),
  ?debugFmt("Aggregate:        ~.2f us/op", [AggTime / 1]),
  ?debugFmt("Final Verify:     ~.2f us/op", [VerifyTime / 1]),
  case ecu_frost_nif:is_available() of
    true ->
      {RefCommit, RefSign, RefAgg, RefVerify} = ecu_frost_nif:bench_round(Suite, T, 5),
      ?debugFmt("Reference (Rust RFC 9591 NIF):", []),
      ?debugFmt("  Commit:     ~.2f us/op (diff x~.2f)", [RefCommit, (CommitTime / T) / RefCommit]),
      ?debugFmt("  Part Sign:  ~.2f us/op (diff x~.2f)", [RefSign, (SignTime / T) / RefSign]),
      ?debugFmt("  Aggregate:  ~.2f us/op (diff x~.2f)", [RefAgg, AggTime / RefAgg]),
      ?debugFmt("  Verify:     ~.2f us/op (diff x~.2f)", [RefVerify, VerifyTime / RefVerify]);
    false ->
      ok
  end.

%% ===================================================================
%% Security Regression Tests (Audit Findings)
%% ===================================================================

sec01_bip340_odd_y_signing_test() ->
  FindOddY =
    fun Loop() ->
      Cs = [ ecu_frost_dkg:round1(bip340, I, 2, <<"ctx">>) || I <- [1, 2, 3] ],
      PubCs = [ element(3, C) || C <- Cs ],
      FullPub = ecu_frost_dkg:compute_public_key(secp256k1, PubCs),
      case FullPub of
        <<3:8, _:32/binary>> -> {Cs, PubCs, FullPub};
        _ -> Loop()
      end
    end,
  {Cs, PubCs, GroupPub33} = FindOddY(),
  GroupPub32 = ecu_frost_dkg:compute_public_key(bip340, PubCs),

  R2 = [ ecu_frost_dkg:round2(bip340, 3, element(1, C)) || C <- Cs ],
  Shares = [ [ lists:nth(I, R2_i) || R2_i <- R2 ] || I <- [1, 2, 3] ],
  PrivShares = [ ecu_frost_dkg:compute_private_sign_share(bip340, S, PubCs) || S <- Shares ],

  Msg = <<"Test odd-Y BIP-340 signing">>,
  Signers = [1, 2],
  Noncess = [ ecu_frost:commit(bip340, lists:nth(I, PrivShares)) || I <- Signers ],
  CommitList = [ {I, element(1, element(2, lists:nth(Idx, Noncess))), element(2, element(2, lists:nth(Idx, Noncess)))}
                 || {Idx, I} <- lists:zip([1, 2], Signers) ],

  SigShares33 = [ ecu_frost:sign(bip340, I, lists:nth(I, PrivShares), GroupPub33,
                                 element(1, lists:nth(Idx, Noncess)), Msg, CommitList)
                  || {Idx, I} <- lists:zip([1, 2], Signers) ],
  AggSig33 = ecu_frost:aggregate(bip340, CommitList, Msg, GroupPub33, SigShares33),
  ?assert(ecu_frost:verify(bip340, AggSig33, Msg, GroupPub33)),

  SigShares32 = [ ecu_frost:sign(bip340, I, lists:nth(I, PrivShares), GroupPub32,
                                 element(1, lists:nth(Idx, Noncess)), Msg, CommitList)
                  || {Idx, I} <- lists:zip([1, 2], Signers) ],
  AggSig32 = ecu_frost:aggregate(bip340, CommitList, Msg, GroupPub32, SigShares32),
  ?assert(ecu_frost:verify(bip340, AggSig32, Msg, GroupPub32)).

sec02_defensive_decompression_test() ->
  BogusPt = <<255:8, 0:248>>,
  ?assertEqual(false, ecu_frost_dkg:round1_check(ed25519, 1, <<"ctx">>, <<0:512>>, [BogusPt])),
  ?assertEqual(false, ecu_frost_dkg:round2_check(ed25519, 1, <<1:256>>, [BogusPt])),
  ?assertEqual(false, ecu_frost:verify_signature_share(ed25519, 1, BogusPt, {BogusPt, BogusPt},
                                                       <<1:256>>, [{1, BogusPt, BogusPt}], BogusPt, <<"msg">>)),
  ?assertEqual(false, ecu_frost:vss_verify(ed25519, 1, <<1:256>>, [BogusPt])).

sec03_participant_validation_test() ->
  ?assertError({participant_not_in_list, 999},
               ecu_frost:derive_lagrange_coefficient(ed25519, 999, [1, 2, 3])),
  ?assertError({duplicate_participant_ids, _},
               ecu_frost:derive_lagrange_coefficient(ed25519, 1, [2, 1, 2])),
  ?assertError({invalid_participant_ids, _},
               ecu_frost:derive_lagrange_coefficient(ed25519, 0, [0, 1, 2])),
  ValidComm = {1, <<0:256>>, <<0:256>>},
  ?assertError({duplicate_participant_ids, _},
               ecu_frost:aggregate(ed25519, [ValidComm, ValidComm], <<"msg">>, <<0:256>>, [<<0:256>>, <<0:256>>])),
  InvalidComm = {0, <<0:256>>, <<0:256>>},
  ?assertError({invalid_participant_ids, _},
               ecu_frost:aggregate(ed25519, [InvalidComm], <<"msg">>, <<0:256>>, [<<0:256>>])).

sec04_comb_bounds_test() ->
  Large256 = 1 bsl 256,
  Large456 = 1 bsl 456,
  ?assertMatch({_, _, _, _}, ecu_ed25519:scalar_mul_base(Large256)),
  ?assertMatch({_, _, _, _}, ecu_ed25519:scalar_mul_base_noclamp(Large256)),
  ?assertMatch({_, _, _}, ecu_ed448:scalar_mul_base(Large456)),
  ?assertMatch({_, _, _}, ecu_ed448:scalar_mul_base_noclamp(Large456)).

sec06_aggregate_share_count_test() ->
  CommitList = [{1, <<0:256>>, <<0:256>>}, {2, <<0:256>>, <<0:256>>}],
  ?assertError({mismatched_shares_and_commitments, 1, 2},
               ecu_frost:aggregate(ed25519, CommitList, <<"msg">>, <<0:256>>, [<<0:256>>])).

argon01_secp256k1_signature_malleability_test() ->
  T = 2,
  N = 3,
  {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(secp256k1, T, N),
  Selected = lists:sublist(Shares, T),
  Msg = <<"Test malleability">>,
  Nonces = [ {Id, S, ecu_frost:commit(secp256k1, S)} || {Id, S} <- Selected ],
  CommitList = [ {Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces ],
  SigShares = [ ecu_frost:sign(secp256k1, Id, S, GroupPubKey, NoncePair, Msg, CommitList)
                || {Id, S, {NoncePair, _}} <- Nonces ],
  <<R_enc:33/binary, Z_bin:32/binary>> = ecu_frost:aggregate(secp256k1, CommitList, Msg, GroupPubKey, SigShares),
  <<Z_int:256>> = Z_bin,
  Secp256k1N = 16#fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
  ?assert(Z_int < Secp256k1N),
  ?assert(ecu_frost:verify(secp256k1, <<R_enc:33/binary, Z_bin:32/binary>>, Msg, GroupPubKey)),
  case Z_int + Secp256k1N < (1 bsl 256) of
    true ->
      MalleatedZ = Z_int + Secp256k1N,
      MalleatedSig = <<R_enc:33/binary, MalleatedZ:256/big>>,
      ?assertEqual(false, ecu_frost:verify(secp256k1, MalleatedSig, Msg, GroupPubKey));
    false ->
      ok
  end,
  NonCanonicalShare = <<(Secp256k1N + 1):256/big>>,
  {Id1, S1, {_NoncePair1, _}} = hd(Nonces),
  {HC1, BC1} = hd([ {HC, BC} || {Id, HC, BC} <- CommitList, Id =:= Id1 ]),
  PubShare1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(binary:decode_unsigned(S1, big))),
  ?assertEqual(false, ecu_frost:verify_signature_share(secp256k1, Id1, PubShare1, {HC1, BC1},
                                                       NonCanonicalShare, CommitList, GroupPubKey, Msg)).

argon02_identity_and_small_order_rejection_test() ->
  ?assertError(badarg, ecu_secp256k1:compress({0, 0})),
  IdentityEd25519 = <<1:8, 0:248>>,
  ZeroPoK = <<IdentityEd25519/binary, 0:256>>,
  ?assertEqual(false, ecu_frost_dkg:round1_check(ed25519, 1, <<"ctx">>, ZeroPoK, [IdentityEd25519])),
  IdentityEd448 = <<1:8, 0:448>>,
  ZeroPoK448 = <<IdentityEd448/binary, 0:456>>,
  ?assertEqual(false, ecu_frost_dkg:round1_check(ed448, 1, <<"ctx">>, ZeroPoK448, [IdentityEd448])).

argon05_participant_id_bounds_test() ->
  Ed25519N = 16#1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed,
  ?assertError({invalid_participant_ids, _},
               ecu_frost:derive_lagrange_coefficient(ed25519, 1, [1, Ed25519N + 1])),
  ?assertError({invalid_participant_id, _},
               ecu_frost_dkg:round1(ed25519, Ed25519N + 1, 2, <<"ctx">>)),
  ?assertError(badarg, ecu_ed25519:s_inv(<<0:256>>)),
  ?assertError(badarg, ecu_ed448:s_inv(<<0:456>>)),
  ?assertError(badarg, ecu_frost:trusted_dealer_keygen(ed25519, <<0:256>>, 2, 3)).

argon06_empty_pubc_rejection_test() ->
  ?assertEqual(false, ecu_frost_dkg:round2_check(ed25519, 1, <<0:256>>, [])),
  ?assertEqual(false, ecu_frost:vss_verify(ed25519, 1, <<0:256>>, [])),
  PubC1 = [<<1:8, 0:248>>],
  PubC2 = [<<1:8, 0:248>>, <<1:8, 0:248>>],
  ?assertError({mismatched_pubc_lengths, _},
               ecu_frost_dkg:compute_public_verification_share(ed25519, 1, [PubC1, PubC2])).

%% ===================================================================
%% Helpers
%% ===================================================================

-spec hex_to_bin(binary() | string()) -> binary().
hex_to_bin(Bin) when is_binary(Bin) ->
  hex_to_bin(binary_to_list(Bin));
hex_to_bin(S) ->
  hex_to_bin(S, []).

hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X, Y | T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X, Y]),
  hex_to_bin(T, [V | Acc]).
