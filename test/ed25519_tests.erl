-module(ed25519_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

point_encode_test() ->
  CompressedP = enacl:crypto_ed25519_scalarmult_base(<<123:256>>),
  D = ecu_ed25519:decompress(CompressedP),
  ?assertEqual(CompressedP, ecu_ed25519:compress(D)).

exp_mod_zero_test() ->
  %% 0^B mod P should be 0 when B > 0
  ?assertEqual(0, ecu_misc:exp_mod(0, 5, 7)).

decompress_identity_test() ->
  %% Identity point y = 1, x = 0 encoded as <<1:8, 0:248>>
  Ident = <<1:8, 0:248>>,
  %% This calls xrecover(1) -> exp_mod(0, ...), which previously went into infinite recursion / OOM
  ?assertEqual({0, 1, 1, 0}, ecu_ed25519:decompress(Ident)).

-include("ecu_ed25519.hrl").

malleable_s_test() ->
  #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
  Msg = <<"test message">>,
  Sig = ecu_eddsa:sign_detached(Msg, Priv),
  <<R:32/binary, S:256/little-unsigned-integer>> = Sig,
  S1 = S + ?N,
  ?assert(S1 < (1 bsl 256)),
  MalleableSig = <<R:32/binary, S1:256/little-unsigned-integer>>,
  %% enacl rejects S >= N (malleable signature)
  ?assertEqual(false, enacl:sign_verify_detached(MalleableSig, Msg, Pub)),
  %% ecu_eddsa should also reject S >= N
  ?assertEqual(false, ecu_eddsa:sign_verify_detached(MalleableSig, Msg, Pub)),
  SignedMsg = <<MalleableSig/binary, Msg/binary>>,
  ?assertEqual({error, failed_verification}, enacl:sign_open(SignedMsg, Pub)),
  ?assertEqual({error, failed_verification}, ecu_eddsa:sign_open(SignedMsg, Pub)).

small_order_pubkey_test() ->
  %% Order-4 point y = 0
  WeakA = <<0:256>>,
  Msg = <<"1">>,
  Sig = <<0:512>>,
  ?assertEqual(false, enacl:sign_verify_detached(Sig, Msg, WeakA)),
  ?assertEqual(false, ecu_eddsa:sign_verify_detached(Sig, Msg, WeakA)),
  ?assertEqual({error, failed_verification}, enacl:sign_open(<<Sig/binary, Msg/binary>>, WeakA)),
  ?assertEqual({error, failed_verification}, ecu_eddsa:sign_open(<<Sig/binary, Msg/binary>>, WeakA)).

decompress_canonical_test() ->
  %% y >= P is non-canonical
  NonCanonicalY = <<(?P + 1):256/little-unsigned-integer>>,
  ?assertError(badarg, ecu_ed25519:decompress(NonCanonicalY)),
  %% x = 0 with high bit (sign bit) set is non-canonical
  SignBitX0 = <<1:8, 0:30/unit:8, 128:8>>,
  ?assertError(badarg, ecu_ed25519:decompress(SignBitX0)),
  %% y not on curve (quadratic non-residue)
  NotOnCurve = <<2:256/little-unsigned-integer>>,
  ?assertError(badarg, ecu_ed25519:decompress(NotOnCurve)).

invalid_pubkey_no_crash_test() ->
  %% Point not on curve passed as public key
  BadPK = <<2:256/little-unsigned-integer>>,
  Msg = <<"test message">>,
  Sig = <<0:512>>,
  ?assertEqual(false, ecu_eddsa:sign_verify_detached(Sig, Msg, BadPK)),
  ?assertEqual({error, failed_verification}, ecu_eddsa:sign_open(<<Sig/binary, Msg/binary>>, BadPK)).

mismatched_pubkey_in_sk_test() ->
  #{secret := <<Sec:32/binary, _RealPub:32/binary>>} = ecu_eddsa:sign_keypair(),
  FakePub = crypto:strong_rand_bytes(32),
  BadSK = <<Sec/binary, FakePub/binary>>,
  Msg = <<"test message">>,
  ?assertError(badarg, ecu_eddsa:sign_detached(Msg, BadSK)),
  ?assertError(badarg, ecu_eddsa:sign(Msg, BadSK)).

scalar_mul_base_benchmark_test() ->
  Scalars = [ begin
                <<K:256>> = crypto:strong_rand_bytes(32),
                K rem ?N
              end || _ <- lists:seq(1, 10) ],
  {T, Results} = timer:tc(fun() ->
    [ ecu_ed25519:scalar_mul_base(K) || K <- Scalars ]
  end),
  ?debugFmt("Average time for ed25519 scalar_mul_base: ~.3f ms", [(T / 1000) / length(Scalars)]),
  [ ?assert(ecu_ed25519:on_curve(Pt)) || Pt <- Results ].

scalar_mul_benchmark_test() ->
  Points = [ ecu_ed25519:scalar_mul_base(K) || K <- lists:seq(11, 20) ],
  Scalars = [ begin
                <<K:256>> = crypto:strong_rand_bytes(32),
                K rem ?N
              end || _ <- lists:seq(1, 10) ],
  {T, Results} = timer:tc(fun() ->
    [ ecu_ed25519:scalar_mul(K, Pt) || {K, Pt} <- lists:zip(Scalars, Points) ]
  end),
  ?debugFmt("Average time for ed25519 scalar_mul: ~.3f ms", [(T / 1000) / length(Scalars)]),
  [ ?assert(ecu_ed25519:on_curve(Pt)) || Pt <- Results ].

multi_scalar_mul_test() ->
  %% Empty MSM returns identity
  ?assertEqual({0, 1, 1, 0}, ecu_ed25519:multi_scalar_mul([])),
  %% Single point MSM matches scalar_mul_noclamp
  P = ecu_ed25519:scalar_mul_base(42),
  K1 = 12345,
  Expected1 = ecu_ed25519:scalar_mul_noclamp(K1, P),
  Actual1 = ecu_ed25519:multi_scalar_mul([{K1, P}]),
  ?assert(ecu_ed25519:pt_eq(Expected1, Actual1)),
  %% Multi-point MSM matches sum of scalar_mul_noclamp
  P2 = ecu_ed25519:scalar_mul_base(99),
  K2 = 67890,
  Expected2 = ecu_ed25519:p_add(Expected1, ecu_ed25519:scalar_mul_noclamp(K2, P2)),
  Actual2 = ecu_ed25519:multi_scalar_mul([{K1, P}, {K2, P2}]),
  ?assert(ecu_ed25519:pt_eq(Expected2, Actual2)).

batch_verify_empty_test() ->
  ?assertEqual(true, ecu_eddsa:sign_verify_batch([])).

batch_verify_single_test() ->
  #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
  Msg = <<"single batch message">>,
  Sig = ecu_eddsa:sign_detached(Msg, Priv),
  ?assertEqual(true, ecu_eddsa:sign_verify_batch([{Sig, Msg, Pub}])),
  <<_R:32/binary, S:32/binary>> = Sig,
  CorruptedSig = <<(crypto:strong_rand_bytes(32))/binary, S/binary>>,
  ?assertEqual(false, ecu_eddsa:sign_verify_batch([{CorruptedSig, Msg, Pub}])).

batch_verify_valid_batch_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 5) ],
  ?assertEqual(true, ecu_eddsa:sign_verify_batch(Batch)).

batch_verify_tampered_sig_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 5) ],
  %% Corrupt the 3rd signature
  {Sig3, Msg3, Pub3} = lists:nth(3, Batch),
  <<R3:32/binary, S3:256/little-unsigned-integer>> = Sig3,
  CorruptedSig3 = <<R3/binary, ((S3 + 1) rem ?N):256/little>>,
  TamperedBatch = lists:sublist(Batch, 2) ++ [{CorruptedSig3, Msg3, Pub3}] ++ lists:nthtail(3, Batch),
  ?assertEqual(false, ecu_eddsa:sign_verify_batch(TamperedBatch)).

batch_verify_tampered_msg_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 5) ],
  %% Corrupt the 2nd message
  {Sig2, Msg2, Pub2} = lists:nth(2, Batch),
  TamperedBatch = lists:sublist(Batch, 1) ++ [{Sig2, <<Msg2/binary, "!">>, Pub2}] ++ lists:nthtail(2, Batch),
  ?assertEqual(false, ecu_eddsa:sign_verify_batch(TamperedBatch)).

batch_verify_tampered_pk_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 5) ],
  %% Replace 4th public key with another valid public key
  #{public := OtherPub} = ecu_eddsa:sign_keypair(),
  {Sig4, Msg4, _Pub4} = lists:nth(4, Batch),
  TamperedBatch = lists:sublist(Batch, 3) ++ [{Sig4, Msg4, OtherPub}] ++ lists:nthtail(4, Batch),
  ?assertEqual(false, ecu_eddsa:sign_verify_batch(TamperedBatch)).

batch_verify_malleable_s_test() ->
  Batch = [ begin
              #{secret := Priv, public := Pub} = ecu_eddsa:sign_keypair(),
              Msg = <<"message ", (integer_to_binary(I))/binary>>,
              Sig = ecu_eddsa:sign_detached(Msg, Priv),
              {Sig, Msg, Pub}
            end || I <- lists:seq(1, 3) ],
  %% Make 2nd signature non-canonical (S >= N)
  {Sig2, Msg2, Pub2} = lists:nth(2, Batch),
  <<R2:32/binary, S2:256/little-unsigned-integer>> = Sig2,
  MalleableSig = <<R2/binary, (S2 + ?N):256/little-unsigned-integer>>,
  TamperedBatch = lists:sublist(Batch, 1) ++ [{MalleableSig, Msg2, Pub2}] ++ lists:nthtail(2, Batch),
  ?assertEqual(false, ecu_eddsa:sign_verify_batch(TamperedBatch)).

batch_verify_malformed_test() ->
  Bad1 = id([not_a_tuple]),
  Bad2 = id(not_a_list),
  ?assertEqual(false, ecu_eddsa:sign_verify_batch(Bad1)),
  ?assertEqual(false, ecu_eddsa:sign_verify_batch([{<<0:256>>, <<"msg">>, <<0:256>>}])),
  ?assertEqual(false, ecu_eddsa:sign_verify_batch(Bad2)).

id(X) -> X.
