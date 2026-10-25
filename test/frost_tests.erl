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
  ?debugFmt("~nFROST Ed25519 (t=~p, n=~p) Benchmarks:", [T, N]),
  ?debugFmt("Commit (x~p):     ~.2f us/op (~.2f us/participant)", [T, CommitTime / 1, CommitTime / T]),
  ?debugFmt("Part Sign (x~p):  ~.2f us/op (~.2f us/participant)", [T, SignTime / 1, SignTime / T]),
  ?debugFmt("Aggregate:        ~.2f us/op", [AggTime / 1]),
  ?debugFmt("Final Verify:     ~.2f us/op", [VerifyTime / 1]).

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
  ?debugFmt("~nFROST secp256k1 (t=~p, n=~p) Benchmarks:", [T, N]),
  ?debugFmt("Commit (x~p):     ~.2f us/op (~.2f us/participant)", [T, CommitTime / 1, CommitTime / T]),
  ?debugFmt("Part Sign (x~p):  ~.2f us/op (~.2f us/participant)", [T, SignTime / 1, SignTime / T]),
  ?debugFmt("Aggregate:        ~.2f us/op", [AggTime / 1]),
  ?debugFmt("Final Verify:     ~.2f us/op", [VerifyTime / 1]).

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
