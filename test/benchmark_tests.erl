%%%-------------------------------------------------------------------
%%% @doc
%%% EUnit performance benchmarks comparing ec_utils pure-Erlang routines
%%% against C/Rust reference implementations.
%%% @end
%%%-------------------------------------------------------------------
-module(benchmark_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

gen_scalar() ->
  <<X:256>> = crypto:strong_rand_bytes(32),
  1 + X rem (ecu_ed25519:n() - 1).

bench_point_add_test() ->
  Pts = [enacl:crypto_ed25519_scalarmult_base(<<(gen_scalar()):256/little>>) || _ <- lists:seq(1, 100)],

  PtsEnacl0 = lists:zip(Pts, tl(Pts) ++ [hd(Pts)]),
  PtsEd255190 = [
    {ecu_ed25519:to_ext_hom(P1), ecu_ed25519:to_ext_hom(P2)}
   || {P1, P2} <- lists:zip(Pts, tl(Pts) ++ [hd(Pts)])
  ],
  %%   PtsEd255190 = lists:zip(Pts, tl(Pts) ++ [hd(Pts)]),

  PtsEnacl = lists:append(lists:duplicate(1000, PtsEnacl0)),
  PtsEd25519 = lists:append(lists:duplicate(100, PtsEd255190)),

  {TimeEnacl, _} = timer:tc(fun() ->
    [enacl:crypto_ed25519_add(P1, P2) || {P1, P2} <- PtsEnacl],
    ok
  end),
  {TimeEd25519, _} = timer:tc(fun() ->
    [ecu_ed25519:p_add(P1, P2) || {P1, P2} <- PtsEd25519],
    ok
  end),
  %%   {TimeEd25519, _} = timer:tc(fun() -> [ecu_ed25519:compress(ecu_ed25519:p_add(P1, P2)) || {P1, P2} <- PtsEd25519], ok end),

  ?debugFmt("", []),
  stats("Point add", "enacl/libsodium", length(PtsEnacl), TimeEnacl),
  stats("Point add", "ecu_ed25519    ", length(PtsEd25519), TimeEd25519),
  diff(TimeEnacl / length(PtsEnacl), TimeEd25519 / length(PtsEd25519)),
  ok.

bench_scalar_mul_base_test() ->
  Scalars0 = [<<(gen_scalar()):256/little>> || _ <- lists:seq(1, 100)],
  ScalarsSecp = lists:append(lists:duplicate(1, Scalars0)),
  ScalarsSecpRef = lists:append(lists:duplicate(10, Scalars0)),
  ScalarsEnacl = lists:append(lists:duplicate(100, Scalars0)),
  ScalarsEd25519 = lists:append(lists:duplicate(30, Scalars0)),
  Scalars448 = [crypto:strong_rand_bytes(57) || _ <- lists:seq(1, 50)],
  ScalarsEd448 = Scalars448,
  ScalarsEd448Ref = lists:append(lists:duplicate(4, Scalars448)),

  {TimeSecp, _} = timer:tc(fun() -> [ecu_secp256k1:scalar_mul_base(S) || S <- ScalarsSecp] end),
  {TimeSecpRef, _} = timer:tc(fun() -> [crypto:generate_key(ecdh, secp256k1) || _ <- ScalarsSecpRef] end),
  {TimeEnacl, _} = timer:tc(fun() -> [enacl:crypto_ed25519_scalarmult_base(S) || S <- ScalarsEnacl] end),
  {TimeEd25519, _} = timer:tc(fun() -> [ecu_ed25519:scalar_mul_base(S) || S <- ScalarsEd25519] end),
  {TimeEd448, _} = timer:tc(fun() -> [ecu_ed448:scalar_mul_base(S) || S <- ScalarsEd448] end),
  {TimeEd448Ref, _} = timer:tc(fun() ->
    [crypto:generate_key(eddsa, ed448, S) || S <- ScalarsEd448Ref]
  end),

  ?debugFmt("", []),
  stats("Scalar mul base", "ecu_secp256k1   ", length(ScalarsSecp), TimeSecp),
  stats("Scalar mul base", "crypto (secp256k1)", length(ScalarsSecpRef), TimeSecpRef),
  stats("Scalar mul base", "enacl/libsodium ", length(ScalarsEnacl), TimeEnacl),
  stats("Scalar mul base", "ecu_ed25519     ", length(ScalarsEd25519), TimeEd25519),
  stats("Scalar mul base", "crypto (ed448)  ", length(ScalarsEd448Ref), TimeEd448Ref),
  stats("Scalar mul base", "ecu_ed448       ", length(ScalarsEd448), TimeEd448),
  diff(TimeSecpRef / length(ScalarsSecpRef), TimeSecp / length(ScalarsSecp)),
  diff(TimeEnacl / length(ScalarsEnacl), TimeEd25519 / length(ScalarsEd25519)),
  diff(TimeEd448Ref / length(ScalarsEd448Ref), TimeEd448 / length(ScalarsEd448)),
  ok.

bench_scalar_mul_test() ->
  Scalars0 = [<<(gen_scalar()):256/little>> || _ <- lists:seq(1, 100)],
  ScalarsSecp = lists:append(lists:duplicate(1, Scalars0)),
  ScalarsSecpRef = lists:append(lists:duplicate(10, Scalars0)),
  ScalarsEnacl = lists:append(lists:duplicate(100, Scalars0)),
  ScalarsEd25519 = lists:append(lists:duplicate(10, Scalars0)),

  Test = fun(F, P0, Ss) -> lists:foldl(fun(S, P) -> F(S, P) end, P0, Ss) end,

  {TimeSecp, _} = timer:tc(fun() ->
    Test(fun ecu_secp256k1:scalar_mul/2, ecu_secp256k1:scalar_mul_base(hd(ScalarsSecp)), tl(ScalarsSecp))
  end),
  {TimeSecpRef, _} = timer:tc(fun() ->
    BasePub = ecu_ecdsa:private_to_public(secp256k1, hd(ScalarsSecp)),
    [crypto:compute_key(ecdh, BasePub, S, secp256k1) || S <- ScalarsSecpRef]
  end),
  {TimeEnacl, _} = timer:tc(fun() ->
    Test(
      fun enacl:crypto_ed25519_scalarmult/2,
      enacl:crypto_ed25519_scalarmult_base(hd(ScalarsEnacl)),
      tl(ScalarsEnacl)
    )
  end),
  {TimeEd25519, _} = timer:tc(fun() ->
    Test(
      fun ecu_ed25519:scalar_mul/2, ecu_ed25519:scalar_mul_base(hd(ScalarsEd25519)), tl(ScalarsEd25519)
    )
  end),

  ?debugFmt("", []),
  stats("Scalar mul", "ecu_secp256k1   ", length(ScalarsSecp), TimeSecp),
  stats("Scalar mul", "crypto (secp256k1)", length(ScalarsSecpRef), TimeSecpRef),
  stats("Scalar mul", "enacl/libsodium ", length(ScalarsEnacl), TimeEnacl),
  stats("Scalar mul", "ecu_ed25519     ", length(ScalarsEd25519), TimeEd25519),
  diff(TimeSecpRef / length(ScalarsSecpRef), TimeSecp / length(ScalarsSecp)),
  diff(TimeEnacl / length(ScalarsEnacl), TimeEd25519 / length(ScalarsEd25519)),
  ok.

bench_sign_test() ->
  KeyPairs = [enacl:sign_keypair() || _ <- lists:seq(1, 10)],
  Messages = [crypto:strong_rand_bytes(X) || X <- lists:seq(20, 49)],

  Data = [{K, Msg} || {Msg, K} <- lists:zip(Messages, lists:append(lists:duplicate(3, KeyPairs)))],

  DataEnacl = lists:append(lists:duplicate(1000, Data)),
  DataEd25519 = lists:append(lists:duplicate(20, Data)),

  {TimeEnacl, _} = timer:tc(fun() ->
    [enacl:sign_detached(Msg, maps:get(secret, K)) || {K, Msg} <- DataEnacl],
    ok
  end),
  {TimeEd25519, _} = timer:tc(fun() ->
    [ecu_eddsa:sign_detached(Msg, maps:get(secret, K)) || {K, Msg} <- DataEd25519],
    ok
  end),

  ?debugFmt("", []),
  stats("Message sign", "enacl/libsodium", length(DataEnacl), TimeEnacl),
  stats("Message sign", "ecu_ed25519    ", length(DataEd25519), TimeEd25519),
  diff(TimeEnacl / length(DataEnacl), TimeEd25519 / length(DataEd25519)),
  ok.

bench_verify_test() ->
  KeyPairs = [enacl:sign_keypair() || _ <- lists:seq(1, 10)],
  Messages = [crypto:strong_rand_bytes(X) || X <- lists:seq(20, 49)],

  Data = [
    {K, Msg, enacl:sign_detached(Msg, maps:get(secret, K))}
   || {Msg, K} <- lists:zip(Messages, lists:append(lists:duplicate(3, KeyPairs)))
  ],

  DataEnacl = lists:append(lists:duplicate(1000, Data)),
  DataEd25519 = lists:append(lists:duplicate(20, Data)),

  {TimeEnacl, _} = timer:tc(fun() ->
    [enacl:sign_verify_detached(Sig, Msg, maps:get(public, K)) || {K, Msg, Sig} <- DataEnacl],
    ok
  end),
  {TimeEd25519, _} = timer:tc(fun() ->
    [ecu_eddsa:sign_verify_detached(Sig, Msg, maps:get(public, K)) || {K, Msg, Sig} <- DataEd25519],
    ok
  end),

  ?debugFmt("", []),
  stats("Message verify", "enacl/libsodium", length(DataEnacl), TimeEnacl),
  stats("Message verify", "ecu_ed25519    ", length(DataEd25519), TimeEd25519),
  diff(TimeEnacl / length(DataEnacl), TimeEd25519 / length(DataEd25519)),
  ok.

bench_batch_verify_test() ->
  N = 32,
  Batch = [
    begin
      K = ecu_eddsa:sign_keypair(),
      Msg = crypto:strong_rand_bytes(32),
      Sig = ecu_eddsa:sign_detached(Msg, maps:get(secret, K)),
      {Sig, Msg, maps:get(public, K)}
    end
   || _ <- lists:seq(1, N)
  ],
  Iters = 5,
  {TimeIndiv, _} = timer:tc(fun() ->
    [
      [ecu_eddsa:sign_verify_detached(Sig, Msg, PK) || {Sig, Msg, PK} <- Batch]
     || _ <- lists:seq(1, Iters)
    ]
  end),
  {TimeBatch, _} = timer:tc(fun() ->
    [ecu_eddsa:sign_verify_batch(Batch) || _ <- lists:seq(1, Iters)]
  end),
  ?debugFmt("", []),
  stats("Ed25519 verify x32", "individual  ", N * Iters, TimeIndiv),
  stats("Ed25519 verify x32", "batch verify", N * Iters, TimeBatch),
  diff(TimeBatch / (N * Iters), TimeIndiv / (N * Iters)),
  ok.

gen_ecdsa_secp256k1_privkey() ->
  <<P0:256>> = crypto:strong_rand_bytes(32),
  P = (P0 rem (ecu_secp256k1:n() - 1)) + 1,
  <<P:256>>.

bench_ecverify_test() ->
  Data0 = [{gen_ecdsa_secp256k1_privkey(), crypto:strong_rand_bytes(32)} || _ <- lists:seq(1, 10)],
  Data1 = [
    {Pr, Msg, ecu_crypto:private_to_short(ethereum, Pr), ecu_crypto:eth_sign(Msg, Pr)}
   || {Pr, Msg} <- Data0
  ],

  RustData = lists:append(lists:duplicate(100, Data1)),
  ECUData = lists:append(lists:duplicate(5, Data1)),

  %% ensure loading
  ecrecover:recover(<<0:256>>, <<123:520>>),

  {TimeRust, _} = timer:tc(fun() ->
    [ecrecover:recover(Msg, Sig) || {_, Msg, _, Sig} <- RustData],
    ok
  end),
  {TimeECU, _} = timer:tc(fun() ->
    [ecu_crypto:eth_recover(Msg, Sig) || {_, Msg, _, Sig} <- ECUData],
    ok
  end),

  ?debugFmt("", []),
  stats("Message verify", "ecrecover (Rust)", length(RustData), TimeRust),
  stats("Message verify", "ecu_crypto      ", length(ECUData), TimeECU),
  diff(TimeRust / length(RustData), TimeECU / length(ECUData)),
  ok.

bench_ed448_sign_verify_test() ->
  Seeds = [crypto:strong_rand_bytes(57) || _ <- lists:seq(1, 10)],
  KeyPairs = [ecu_eddsa448:sign_seed_keypair(S) || S <- Seeds],
  Messages = [crypto:strong_rand_bytes(X) || X <- lists:seq(20, 49)],
  Data = [
    {maps:get(secret, K), maps:get(public, K), Seed, Msg}
   || {{K, Seed}, Msg} <- lists:zip(
      lists:append(lists:duplicate(3, lists:zip(KeyPairs, Seeds))),
      Messages
    )
  ],

  CryptoData = lists:append(lists:duplicate(10, Data)),
  ECUData = lists:append(lists:duplicate(1, Data)),

  %% Sign
  {TimeSignCrypto, _} = timer:tc(fun() ->
    [crypto:sign(eddsa, none, Msg, [Seed, ed448]) || {_, _, Seed, Msg} <- CryptoData]
  end),
  {TimeSignECU, _} = timer:tc(fun() ->
    [ecu_eddsa448:sign_detached(Msg, Sec) || {Sec, _, _, Msg} <- ECUData]
  end),

  ?debugFmt("", []),
  stats("Ed448 sign", "crypto (OpenSSL)", length(CryptoData), TimeSignCrypto),
  stats("Ed448 sign", "ecu_eddsa448   ", length(ECUData), TimeSignECU),
  diff(TimeSignCrypto / length(CryptoData), TimeSignECU / length(ECUData)),

  %% Verify
  Sigs = [{Sec, Pub, Msg, ecu_eddsa448:sign_detached(Msg, Sec)} || {Sec, Pub, _, Msg} <- Data],
  CryptoVerifyData = lists:append(lists:duplicate(10, Sigs)),
  ECUVerifyData = lists:append(lists:duplicate(1, Sigs)),

  {TimeVerifyCrypto, _} = timer:tc(fun() ->
    [crypto:verify(eddsa, none, Msg, Sig, [Pub, ed448]) || {_, Pub, Msg, Sig} <- CryptoVerifyData]
  end),
  {TimeVerifyECU, _} = timer:tc(fun() ->
    [ecu_eddsa448:sign_verify_detached(Sig, Msg, Pub) || {_, Pub, Msg, Sig} <- ECUVerifyData]
  end),

  ?debugFmt("", []),
  stats("Ed448 verify", "crypto (OpenSSL)", length(CryptoVerifyData), TimeVerifyCrypto),
  stats("Ed448 verify", "ecu_eddsa448   ", length(ECUVerifyData), TimeVerifyECU),
  diff(TimeVerifyCrypto / length(CryptoVerifyData), TimeVerifyECU / length(ECUVerifyData)),
  ok.

bench_ecdh_test() ->
  %% X25519
  {_PubA25519, PrivA25519} = ecu_ecdh:keypair(x25519),
  {PubB25519, _PrivB25519} = ecu_ecdh:keypair(x25519),
  N25519 = 50,
  N25519Ref = 500,

  {TimeX25519Enacl, _} = timer:tc(fun() ->
    [enacl:curve25519_scalarmult(PrivA25519, PubB25519) || _ <- lists:seq(1, N25519Ref)]
  end),
  {TimeX25519Crypto, _} = timer:tc(fun() ->
    [crypto:compute_key(ecdh, PubB25519, PrivA25519, x25519) || _ <- lists:seq(1, N25519Ref)]
  end),
  {TimeX25519ECU, _} = timer:tc(fun() ->
    [ecu_ecdh:compute_key(x25519, PubB25519, PrivA25519) || _ <- lists:seq(1, N25519)]
  end),

  ?debugFmt("", []),
  stats("X25519 compute_key", "enacl/libsodium ", N25519Ref, TimeX25519Enacl),
  stats("X25519 compute_key", "crypto (OpenSSL)", N25519Ref, TimeX25519Crypto),
  stats("X25519 compute_key", "ecu_ecdh        ", N25519, TimeX25519ECU),
  diff(TimeX25519Enacl / N25519Ref, TimeX25519ECU / N25519),

  %% X448
  {_PubA448, PrivA448} = ecu_ecdh:keypair(x448),
  {PubB448, _PrivB448} = ecu_ecdh:keypair(x448),
  N448 = 20,
  N448Ref = 200,

  {TimeX448Crypto, _} = timer:tc(fun() ->
    [crypto:compute_key(ecdh, PubB448, PrivA448, x448) || _ <- lists:seq(1, N448Ref)]
  end),
  {TimeX448ECU, _} = timer:tc(fun() ->
    [ecu_ecdh:compute_key(x448, PubB448, PrivA448) || _ <- lists:seq(1, N448)]
  end),

  ?debugFmt("", []),
  stats("X448 compute_key", "crypto (OpenSSL)", N448Ref, TimeX448Crypto),
  stats("X448 compute_key", "ecu_ecdh        ", N448, TimeX448ECU),
  diff(TimeX448Crypto / N448Ref, TimeX448ECU / N448),

  %% secp256k1 ECDH
  {_PubA256, PrivA256} = ecu_ecdh:keypair(secp256k1),
  {PubB256, _PrivB256} = ecu_ecdh:keypair(secp256k1),
  N256 = 30,
  N256Ref = 300,

  {TimeSecpCrypto, _} = timer:tc(fun() ->
    [crypto:compute_key(ecdh, PubB256, PrivA256, secp256k1) || _ <- lists:seq(1, N256Ref)]
  end),
  {TimeSecpECU, _} = timer:tc(fun() ->
    [ecu_ecdh:compute_key(secp256k1, PubB256, PrivA256) || _ <- lists:seq(1, N256)]
  end),

  ?debugFmt("", []),
  stats("secp256k1 ECDH", "crypto (OpenSSL)", N256Ref, TimeSecpCrypto),
  stats("secp256k1 ECDH", "ecu_ecdh        ", N256, TimeSecpECU),
  diff(TimeSecpCrypto / N256Ref, TimeSecpECU / N256),
  ok.

bench_bip340_test() ->
  Priv = <<1:256>>,
  Msg = <<"Benchmark BIP-340 Schnorr">>,
  Aux = <<0:256>>,
  #{public := Pub} = ecu_schnorr:sign_keypair_from_secret(Priv),
  Sig = ecu_schnorr:sign(Msg, Priv, Aux),

  case ecu_schnorr_nif:is_available() of
    true ->
      NRef = 1000,
      NECU = 50,
      {TimeNifSign, _} = timer:tc(fun() ->
        [ecu_schnorr_nif:sign(Priv, Msg, Aux) || _ <- lists:seq(1, NRef)]
      end),
      {TimeEcuSign, _} = timer:tc(fun() ->
        [ecu_schnorr:sign(Msg, Priv, Aux) || _ <- lists:seq(1, NECU)]
      end),

      {TimeNifVerify, _} = timer:tc(fun() ->
        [ecu_schnorr_nif:verify(Sig, Msg, Pub) || _ <- lists:seq(1, NRef)]
      end),
      {TimeEcuVerify, _} = timer:tc(fun() ->
        [ecu_schnorr:verify(Sig, Msg, Pub) || _ <- lists:seq(1, NECU)]
      end),

      ?debugFmt("", []),
      stats("BIP-340 sign", "k256 (Rust NIF) ", NRef, TimeNifSign),
      stats("BIP-340 sign", "ecu_schnorr     ", NECU, TimeEcuSign),
      diff(TimeNifSign / NRef, TimeEcuSign / NECU),

      stats("BIP-340 verify", "k256 (Rust NIF) ", NRef, TimeNifVerify),
      stats("BIP-340 verify", "ecu_schnorr     ", NECU, TimeEcuVerify),
      diff(TimeNifVerify / NRef, TimeEcuVerify / NECU);
    false ->
      ?debugFmt("BIP-340: k256 reference NIF not built (run 'make schnorr_reference' to enable)", [])
  end,
  ok.

bench_frost_test() ->
  case ecu_frost_nif:is_available() of
    true ->
      lists:foreach(
        fun(Suite) ->
          {Shares, GroupPubKey, _} = ecu_frost:trusted_dealer_keygen(Suite, 3, 5),
          Selected = lists:sublist(Shares, 3),
          Msg = <<"Benchmark FROST message">>,
          {CommitTime, Nonces} = timer:tc(fun() ->
            [{Id, S, ecu_frost:commit(Suite, S)} || {Id, S} <- Selected]
          end),
          CommitmentList = [{Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces],
          {SignTime, SigShares} = timer:tc(fun() ->
            [
              ecu_frost:sign(Suite, Id, S, GroupPubKey, NoncePair, Msg, CommitmentList)
             || {Id, S, {NoncePair, _}} <- Nonces
            ]
          end),
          {AggTime, Signature} = timer:tc(fun() ->
            ecu_frost:aggregate(Suite, CommitmentList, Msg, GroupPubKey, SigShares)
          end),
          {VerifyTime, _} = timer:tc(fun() ->
            ecu_frost:verify(Suite, Signature, Msg, GroupPubKey)
          end),
          {RefCommit, RefSign, RefAgg, RefVerify} = ecu_frost_nif:bench_round(Suite, 3, 5),
          SuiteStr = atom_to_list(Suite),
          ?debugFmt("", []),
          stats("FROST " ++ SuiteStr ++ " commit", "ecu_frost       ", 3, CommitTime),
          stats("FROST " ++ SuiteStr ++ " commit", "frost (Rust NIF)", 1, RefCommit),
          diff(RefCommit, CommitTime / 3),
          stats("FROST " ++ SuiteStr ++ " part sign", "ecu_frost       ", 3, SignTime),
          stats("FROST " ++ SuiteStr ++ " part sign", "frost (Rust NIF)", 1, RefSign),
          diff(RefSign, SignTime / 3),
          stats("FROST " ++ SuiteStr ++ " aggregate", "ecu_frost       ", 1, AggTime),
          stats("FROST " ++ SuiteStr ++ " aggregate", "frost (Rust NIF)", 1, RefAgg),
          diff(RefAgg, AggTime),
          stats("FROST " ++ SuiteStr ++ " verify", "ecu_frost       ", 1, VerifyTime),
          stats("FROST " ++ SuiteStr ++ " verify", "frost (Rust NIF)", 1, RefVerify),
          diff(RefVerify, VerifyTime)
        end,
        [ed25519, secp256k1, bip340, ed448]
      );
    false ->
      ?debugFmt("FROST: reference NIF not built (run 'make frost_reference' to enable)", [])
  end,
  ok.

bench_keccak_test() ->
  N = 500,
  Msgs = [crypto:strong_rand_bytes(100) || _ <- lists:seq(1, N)],
  {TimeEcuKek, _} = timer:tc(fun() -> [ecu_keccak:keccak256(M) || M <- Msgs] end),
  {TimeEcuSha3, _} = timer:tc(fun() -> [ecu_keccak:sha3_256(M) || M <- Msgs] end),
  {TimeCryptoSha3, _} = timer:tc(fun() -> [crypto:hash(sha3_256, M) || M <- Msgs] end),

  ?debugFmt("", []),
  stats("NIST SHA3-256", "crypto (OpenSSL)", N, TimeCryptoSha3),
  stats("NIST SHA3-256", "ecu_keccak      ", N, TimeEcuSha3),
  diff(TimeCryptoSha3 / N, TimeEcuSha3 / N),

  case ecu_rustcrypto_nif:is_available() of
    true ->
      {TimeRustKek, _} = timer:tc(fun() -> [ecu_rustcrypto_nif:keccak256(M) || M <- Msgs] end),
      stats("Keccak-256", "rustcrypto (NIF)", N, TimeRustKek),
      stats("Keccak-256", "ecu_keccak      ", N, TimeEcuKek),
      diff(TimeRustKek / N, TimeEcuKek / N);
    false ->
      stats("Keccak-256", "ecu_keccak      ", N, TimeEcuKek)
  end,
  ok.

bench_musig2_test() ->
  Iters = 50,
  SKs = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 3)],
  PKs = [ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK)) || SK <- SKs],
  Msg = <<"Benchmark BIP-327">>,

  %% 1. Key Aggregation
  {TimeKeyAgg, _} = timer:tc(fun() -> [ecu_musig2:key_agg(PKs) || _ <- lists:seq(1, Iters)] end),
  {ok, Ctx} = ecu_musig2:key_agg(PKs),

  %% 2. Nonce Gen
  {TimeNonceGen, _} = timer:tc(fun() -> [ecu_musig2:nonce_gen(hd(SKs)) || _ <- lists:seq(1, Iters)] end),

  %% 3. Nonce Agg
  NoncesList = [
    [
      begin
        {SN, <<_:33/binary, _:33/binary>> = PN} = ecu_musig2:nonce_gen(SK),
        {SN, PN}
      end
     || SK <- SKs
    ]
   || _ <- lists:seq(1, Iters)
  ],
  {TimeNonceAgg, _} = timer:tc(fun() ->
    [ecu_musig2:nonce_agg([PN || {_, PN} <- Ns]) || Ns <- NoncesList]
  end),

  {<<_:97/binary>> = SN1, <<_:33/binary, _:33/binary>> = PN1} = hd(hd(NoncesList)),
  {ok, <<_:33/binary, _:33/binary>> = AggN} = ecu_musig2:nonce_agg([PN || {_, PN} <- hd(NoncesList)]),

  %% 4. Sign Partial
  {TimeSignPart, _} = timer:tc(fun() ->
    [ecu_musig2:sign_partial(Ctx, hd(SKs), SN1, AggN, Msg) || _ <- lists:seq(1, Iters)]
  end),
  {ok, Psig1} = ecu_musig2:sign_partial(Ctx, hd(SKs), SN1, AggN, Msg),

  %% 5. Verify Partial
  {TimeVerifyPart, _} = timer:tc(fun() ->
    [ecu_musig2:verify_partial(Ctx, Psig1, PN1, hd(PKs), AggN, Msg) || _ <- lists:seq(1, Iters)]
  end),

  Psigs = [
    begin
      {ok, P} = ecu_musig2:sign_partial(Ctx, SK, SN, AggN, Msg),
      P
    end
   || {SK, {SN, _}} <- lists:zip(SKs, hd(NoncesList))
  ],

  %% 6. Aggregate
  {TimeAggPart, _} = timer:tc(fun() ->
    [ecu_musig2:aggregate_partial(Ctx, AggN, Msg, Psigs) || _ <- lists:seq(1, Iters)]
  end),

  ?debugFmt("", []),
  stats("MuSig2 BIP-327 key_agg", "ecu_musig2      ", Iters, TimeKeyAgg),
  stats("MuSig2 BIP-327 nonce_gen", "ecu_musig2    ", Iters, TimeNonceGen),
  stats("MuSig2 BIP-327 nonce_agg", "ecu_musig2    ", Iters, TimeNonceAgg),
  stats("MuSig2 BIP-327 sign_part", "ecu_musig2    ", Iters, TimeSignPart),
  stats("MuSig2 BIP-327 verify_part", "ecu_musig2  ", Iters, TimeVerifyPart),
  stats("MuSig2 BIP-327 aggregate", "ecu_musig2    ", Iters, TimeAggPart),

  case ecu_musig2_nif:is_available() of
    true ->
      {TimeNifKeyAgg, _} = timer:tc(fun() ->
        [ecu_musig2_nif:key_agg(PKs) || _ <- lists:seq(1, Iters)]
      end),
      {ok, {_, NifCtx}} = ecu_musig2_nif:key_agg(PKs),
      {TimeNifNonceGen, _} = timer:tc(fun() ->
        [ecu_musig2_nif:nonce_gen(hd(SKs)) || _ <- lists:seq(1, Iters)]
      end),
      {TimeNifNonceAgg, _} = timer:tc(fun() ->
        [ecu_musig2_nif:nonce_agg([PN || {_, PN} <- Ns]) || Ns <- NoncesList]
      end),
      {TimeNifSignPart, _} = timer:tc(fun() ->
        [ecu_musig2_nif:sign(NifCtx, hd(SKs), SN1, AggN, Msg) || _ <- lists:seq(1, Iters)]
      end),
      {TimeNifVerifyPart, _} = timer:tc(fun() ->
        [ecu_musig2_nif:verify(NifCtx, Psig1, PN1, hd(PKs), AggN, Msg) || _ <- lists:seq(1, Iters)]
      end),
      {TimeNifAggPart, _} = timer:tc(fun() ->
        [ecu_musig2_nif:aggregate(NifCtx, AggN, Msg, Psigs) || _ <- lists:seq(1, Iters)]
      end),

      stats("MuSig2 BIP-327 key_agg", "musig2 (Rust NIF)", Iters, TimeNifKeyAgg),
      diff(TimeNifKeyAgg / Iters, TimeKeyAgg / Iters),
      stats("MuSig2 BIP-327 nonce_gen", "musig2 (Rust NIF)", Iters, TimeNifNonceGen),
      diff(TimeNifNonceGen / Iters, TimeNonceGen / Iters),
      stats("MuSig2 BIP-327 nonce_agg", "musig2 (Rust NIF)", Iters, TimeNifNonceAgg),
      diff(TimeNifNonceAgg / Iters, TimeNonceAgg / Iters),
      stats("MuSig2 BIP-327 sign_part", "musig2 (Rust NIF)", Iters, TimeNifSignPart),
      diff(TimeNifSignPart / Iters, TimeSignPart / Iters),
      stats("MuSig2 BIP-327 verify_part", "musig2 (Rust NIF)", Iters, TimeNifVerifyPart),
      diff(TimeNifVerifyPart / Iters, TimeVerifyPart / Iters),
      stats("MuSig2 BIP-327 aggregate", "musig2 (Rust NIF)", Iters, TimeNifAggPart),
      diff(TimeNifAggPart / Iters, TimeAggPart / Iters);
    false ->
      ok
  end,
  ok.

bench_hd_and_base58_test() ->
  Iters = 2000,
  Payload = crypto:strong_rand_bytes(78),
  B58Str = ecu_base58:encode_check(Payload),

  {TimeB58Enc, _} = timer:tc(fun() ->
    [ecu_base58:encode(Payload) || _ <- lists:seq(1, Iters)]
  end),
  {TimeB58Dec, _} = timer:tc(fun() ->
    [ecu_base58:decode(B58Str) || _ <- lists:seq(1, Iters)]
  end),
  {TimeB58CheckEnc, _} = timer:tc(fun() ->
    [ecu_base58:encode_check(Payload) || _ <- lists:seq(1, Iters)]
  end),
  {TimeB58CheckDec, _} = timer:tc(fun() ->
    [ecu_base58:decode_check(B58Str) || _ <- lists:seq(1, Iters)]
  end),

  Seed = crypto:strong_rand_bytes(32),
  {ok, MSecp} = ecu_hd:master_key(secp256k1, Seed),
  MSecpPub = ecu_hd:to_public(MSecp),
  {ok, MEd} = ecu_hd:master_key(ed25519, Seed),

  {TimeSecpPriv, _} = timer:tc(fun() ->
    [ecu_hd:ckd_priv(MSecp, 1) || _ <- lists:seq(1, Iters)]
  end),
  {TimeSecpPub, _} = timer:tc(fun() ->
    [ecu_hd:ckd_pub(MSecpPub, 1) || _ <- lists:seq(1, Iters)]
  end),
  {TimeEdPriv, _} = timer:tc(fun() ->
    [ecu_hd:ckd_priv(MEd, 16#80000001) || _ <- lists:seq(1, Iters)]
  end),

  ?debugFmt("", []),
  stats("Base58 encode (78B)", "ecu_base58   ", Iters, TimeB58Enc),
  stats("Base58 decode (78B)", "ecu_base58   ", Iters, TimeB58Dec),
  stats("Base58Check encode (78B)", "ecu_base58   ", Iters, TimeB58CheckEnc),
  stats("Base58Check decode (78B)", "ecu_base58   ", Iters, TimeB58CheckDec),
  stats("BIP-32 CKDpriv (secp256k1)", "ecu_hd       ", Iters, TimeSecpPriv),
  stats("BIP-32 CKDpub (secp256k1)", "ecu_hd       ", Iters, TimeSecpPub),
  stats("SLIP-0010 CKDpriv (Ed25519)", "ecu_hd       ", Iters, TimeEdPriv),
  ok.

bench_bip39_test() ->
  Iters = 2000,
  Entropy16 = crypto:strong_rand_bytes(16),
  {ok, Mnemonic12} = ecu_bip39:entropy_to_mnemonic(Entropy16),

  {TimeGenMnemonic, _} = timer:tc(fun() ->
    [ecu_bip39:generate_mnemonic(128) || _ <- lists:seq(1, Iters)]
  end),
  {TimeEntropyToMnemonic, _} = timer:tc(fun() ->
    [ecu_bip39:entropy_to_mnemonic(Entropy16) || _ <- lists:seq(1, Iters)]
  end),
  {TimeMnemonicToEntropy, _} = timer:tc(fun() ->
    [ecu_bip39:mnemonic_to_entropy(Mnemonic12) || _ <- lists:seq(1, Iters)]
  end),
  {TimeValidateMnemonic, _} = timer:tc(fun() ->
    [ecu_bip39:validate_mnemonic(Mnemonic12) || _ <- lists:seq(1, Iters)]
  end),

  Pbkdf2Iters = 100,
  {TimeMnemonicToSeed, _} = timer:tc(fun() ->
    [ecu_bip39:mnemonic_to_seed(Mnemonic12, "TREZOR") || _ <- lists:seq(1, Pbkdf2Iters)]
  end),

  ?debugFmt("", []),
  stats("BIP-39 generate_mnemonic (12w)", "ecu_bip39    ", Iters, TimeGenMnemonic),
  stats("BIP-39 entropy_to_mnemonic (16B)", "ecu_bip39    ", Iters, TimeEntropyToMnemonic),
  stats("BIP-39 mnemonic_to_entropy (12w)", "ecu_bip39    ", Iters, TimeMnemonicToEntropy),
  stats("BIP-39 validate_mnemonic (12w)", "ecu_bip39    ", Iters, TimeValidateMnemonic),
  stats("BIP-39 mnemonic_to_seed (2048 iters)", "ecu_bip39    ", Pbkdf2Iters, TimeMnemonicToSeed),
  ok.

bench_bech32_test() ->
  Iters = 2000,
  Prog = crypto:strong_rand_bytes(32),
  {ok, Addr} = ecu_bech32:encode_segwit_address(<<"bc">>, 1, Prog),

  {TimeSegwitEnc, _} = timer:tc(fun() ->
    [ecu_bech32:encode_segwit_address(<<"bc">>, 1, Prog) || _ <- lists:seq(1, Iters)]
  end),
  {TimeSegwitDec, _} = timer:tc(fun() ->
    [ecu_bech32:decode_segwit_address(<<"bc">>, Addr) || _ <- lists:seq(1, Iters)]
  end),

  ?debugFmt("", []),
  stats("SegWit v1 encode (Taproot 32B)", "ecu_bech32   ", Iters, TimeSegwitEnc),
  stats("SegWit v1 decode (Taproot 32B)", "ecu_bech32   ", Iters, TimeSegwitDec),

  case ecu_rustcrypto_nif:is_available() of
    true ->
      {TimeNifEnc, _} = timer:tc(fun() ->
        [ecu_rustcrypto_nif:bech32_segwit_encode(<<"bc">>, 1, Prog) || _ <- lists:seq(1, Iters)]
      end),
      {TimeNifDec, _} = timer:tc(fun() ->
        [ecu_rustcrypto_nif:bech32_segwit_decode(Addr) || _ <- lists:seq(1, Iters)]
      end),
      stats("SegWit v1 encode (Taproot 32B)", "bech32 (NIF) ", Iters, TimeNifEnc),
      diff(TimeSegwitEnc, TimeNifEnc),
      stats("SegWit v1 decode (Taproot 32B)", "bech32 (NIF) ", Iters, TimeNifDec),
      diff(TimeSegwitDec, TimeNifDec);
    false ->
      ok
  end,
  ok.

stats(What, Who, N, T) ->
  ?debugFmt("~s with ~s ~.2f us/op", [What, Who, T / N]).

diff(T1, T2) when T1 > T2 ->
  diff(T2, T1);
diff(T1, T2) ->
  ?debugFmt("Speed difference x~.2f", [T2 / T1]).
