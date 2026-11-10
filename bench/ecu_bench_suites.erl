%%%-------------------------------------------------------------------
%%% @doc
%%% Benchmark definitions and suite registry for all ec_utils
%%% cryptographic modules.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_bench_suites).

-export([
  list_suites/0,
  get_benchmarks/1
]).

-spec list_suites() -> [atom()].
list_suites() ->
  [
    all,
    ed25519,
    secp256k1,
    ed448,
    ecdh,
    ml_kem,
    ml_dsa,
    frost,
    musig2,
    h2c,
    keccak,
    hash,
    hd,
    bls12_381
  ].

-spec get_benchmarks(atom() | string() | binary()) -> [ecu_bench_runner:bench_def()].
get_benchmarks(Filter) ->
  All = all_benchmarks(),
  filter_benchmarks(Filter, All).

filter_benchmarks(all, All) ->
  All;
filter_benchmarks("all", All) ->
  All;
filter_benchmarks(<<"all">>, All) ->
  All;
filter_benchmarks(GroupAtom, All) when is_atom(GroupAtom) ->
  GroupBin = atom_to_binary(GroupAtom, utf8),
  filter_benchmarks(GroupBin, All);
filter_benchmarks(FilterStr, All) when is_list(FilterStr) ->
  filter_benchmarks(list_to_binary(FilterStr), All);
filter_benchmarks(FilterBin, All) when is_binary(FilterBin) ->
  lists:filter(
    fun(#{id := Id, group := Group, name := Name}) ->
      IdBin = to_bin(Id),
      GroupBin = to_bin(Group),
      binary:match(IdBin, FilterBin) =/= nomatch orelse
        binary:match(GroupBin, FilterBin) =/= nomatch orelse
        binary:match(Name, FilterBin) =/= nomatch
    end,
    All
  ).

to_bin(B) when is_binary(B) -> B;
to_bin(A) when is_atom(A) -> atom_to_binary(A, utf8).

all_benchmarks() ->
  lists:flatten([
    ed25519_benchmarks(),
    secp256k1_benchmarks(),
    ed448_benchmarks(),
    ecdh_benchmarks(),
    ml_kem_benchmarks(),
    ml_dsa_benchmarks(),
    frost_benchmarks(),
    musig2_benchmarks(),
    h2c_benchmarks(),
    keccak_benchmarks(),
    hash_benchmarks(),
    hd_benchmarks(),
    bls12_381_benchmarks()
  ]).

%% ===================================================================
%% Ed25519
%% ===================================================================

ed25519_benchmarks() ->
  Scalar = crypto:strong_rand_bytes(32),
  P1 = ecu_ed25519:scalar_mul_base(crypto:strong_rand_bytes(32)),
  P2 = ecu_ed25519:scalar_mul_base(crypto:strong_rand_bytes(32)),
  #{public := EdPub, secret := EdPriv} = ecu_eddsa:sign_keypair(),
  Msg = crypto:strong_rand_bytes(32),
  EdSig = ecu_eddsa:sign_detached(Msg, EdPriv),

  Batch32 = [
    begin
      #{public := PK, secret := SK} = ecu_eddsa:sign_keypair(),
      M = crypto:strong_rand_bytes(32),
      {ecu_eddsa:sign_detached(M, SK), M, PK}
    end
   || _ <- lists:seq(1, 32)
  ],

  [
    #{
      id => ed25519_point_add,
      name => <<"Ed25519 Point Add">>,
      group => ed25519,
      run => {fun({A, B}) -> ecu_ed25519:p_add(A, B) end, {P1, P2}}
    },
    #{
      id => ed25519_scalar_mul_base,
      name => <<"Ed25519 ScalarMul Base">>,
      group => ed25519,
      run => {fun(S) -> ecu_ed25519:scalar_mul_base(S) end, Scalar}
    },
    #{
      id => ed25519_scalar_mul,
      name => <<"Ed25519 ScalarMul Arbitrary">>,
      group => ed25519,
      run => {fun({S, P}) -> ecu_ed25519:scalar_mul(S, P) end, {Scalar, P1}}
    },
    #{
      id => ed25519_sign,
      name => <<"Ed25519 Sign">>,
      group => ed25519,
      run => {fun({M, SK}) -> ecu_eddsa:sign_detached(M, SK) end, {Msg, EdPriv}}
    },
    #{
      id => ed25519_verify,
      name => <<"Ed25519 Verify">>,
      group => ed25519,
      run =>
        {fun({Sig, M, PK}) -> ecu_eddsa:sign_verify_detached(Sig, M, PK) end, {EdSig, Msg, EdPub}}
    },
    #{
      id => ed25519_batch_verify_32,
      name => <<"Ed25519 Batch Verify (32)">>,
      group => ed25519,
      run => {fun(Batch) -> ecu_eddsa:sign_verify_batch(Batch) end, Batch32}
    }
  ].

%% ===================================================================
%% secp256k1 & BIP-340
%% ===================================================================

secp256k1_benchmarks() ->
  SecpPriv = crypto:strong_rand_bytes(32),
  SecpPub = ecu_secp256k1:scalar_mul_base(SecpPriv),
  MsgHash = crypto:strong_rand_bytes(32),
  {SecpSig, _} = ecu_ecdsa:sign_secp256k1(MsgHash, SecpPriv),
  EthMsg = crypto:strong_rand_bytes(32),
  EthSig = ecu_crypto:eth_sign(EthMsg, SecpPriv),

  #{public := Bip340Pub, secret := Bip340Priv} = ecu_schnorr:sign_keypair(),
  Bip340Sig = ecu_schnorr:sign(MsgHash, Bip340Priv),

  [
    #{
      id => secp256k1_scalar_mul_base,
      name => <<"secp256k1 ScalarMul Base">>,
      group => secp256k1,
      run => {fun(S) -> ecu_secp256k1:scalar_mul_base(S) end, SecpPriv}
    },
    #{
      id => secp256k1_scalar_mul,
      name => <<"secp256k1 ScalarMul Arbitrary">>,
      group => secp256k1,
      run => {fun({S, P}) -> ecu_secp256k1:scalar_mul(S, P) end, {SecpPriv, SecpPub}}
    },
    #{
      id => secp256k1_sign,
      name => <<"secp256k1 ECDSA Sign">>,
      group => secp256k1,
      run => {fun({H, SK}) -> ecu_ecdsa:sign_secp256k1(H, SK) end, {MsgHash, SecpPriv}}
    },
    #{
      id => secp256k1_verify,
      name => <<"secp256k1 ECDSA Verify">>,
      group => secp256k1,
      run =>
        {fun({Sig, H, PK}) -> ecu_ecdsa:verify(secp256k1, H, PK, Sig) end, {SecpSig, MsgHash, SecpPub}}
    },
    #{
      id => secp256k1_eth_recover,
      name => <<"secp256k1 Ethereum ecrecover">>,
      group => secp256k1,
      run => {fun({M, Sig}) -> ecu_crypto:eth_recover(M, Sig) end, {EthMsg, EthSig}}
    },
    #{
      id => bip340_sign,
      name => <<"BIP-340 Schnorr Sign">>,
      group => secp256k1,
      run => {fun({M, SK}) -> ecu_schnorr:sign(M, SK) end, {MsgHash, Bip340Priv}}
    },
    #{
      id => bip340_verify,
      name => <<"BIP-340 Schnorr Verify">>,
      group => secp256k1,
      run => {fun({Sig, M, PK}) -> ecu_schnorr:verify(Sig, M, PK) end, {Bip340Sig, MsgHash, Bip340Pub}}
    }
  ].

%% ===================================================================
%% Ed448
%% ===================================================================

ed448_benchmarks() ->
  Scalar448 = crypto:strong_rand_bytes(57),
  Point448 = ecu_ed448:scalar_mul_base(Scalar448),
  #{public := Ed448Pub, secret := Ed448Priv} = ecu_eddsa448:sign_keypair(),
  Msg448 = crypto:strong_rand_bytes(32),
  Ed448Sig = ecu_eddsa448:sign_detached(Msg448, Ed448Priv),

  [
    #{
      id => ed448_scalar_mul_base,
      name => <<"Ed448 ScalarMul Base">>,
      group => ed448,
      run => {fun(S) -> ecu_ed448:scalar_mul_base(S) end, Scalar448}
    },
    #{
      id => ed448_scalar_mul,
      name => <<"Ed448 ScalarMul Arbitrary">>,
      group => ed448,
      run => {fun({S, P}) -> ecu_ed448:scalar_mul(S, P) end, {Scalar448, Point448}}
    },
    #{
      id => ed448_sign,
      name => <<"Ed448 Sign">>,
      group => ed448,
      run => {fun({M, SK}) -> ecu_eddsa448:sign_detached(M, SK) end, {Msg448, Ed448Priv}}
    },
    #{
      id => ed448_verify,
      name => <<"Ed448 Verify">>,
      group => ed448,
      run =>
        {
          fun({Sig, M, PK}) -> ecu_eddsa448:sign_verify_detached(Sig, M, PK) end,
          {Ed448Sig, Msg448, Ed448Pub}
        }
    }
  ].

%% ===================================================================
%% ECDH (Key Exchange)
%% ===================================================================

ecdh_benchmarks() ->
  {_PubA25519, PrivA25519} = ecu_ecdh:keypair(x25519),
  {PubB25519, _PrivB25519} = ecu_ecdh:keypair(x25519),
  {_PubA448, PrivA448} = ecu_ecdh:keypair(x448),
  {PubB448, _PrivB448} = ecu_ecdh:keypair(x448),
  {_PubA256, PrivA256} = ecu_ecdh:keypair(secp256k1),
  {PubB256, _PrivB256} = ecu_ecdh:keypair(secp256k1),

  {HybridPK, HybridSK} = ecu_ecdh:hybrid_keypair(x25519_mlkem768),
  {_SS, HybridCT} = ecu_ecdh:hybrid_encaps(HybridPK),

  [
    #{
      id => ecdh_x25519,
      name => <<"ECDH X25519">>,
      group => ecdh,
      run => {fun({Pub, Priv}) -> ecu_ecdh:compute_key(x25519, Pub, Priv) end, {PubB25519, PrivA25519}}
    },
    #{
      id => ecdh_x448,
      name => <<"ECDH X448">>,
      group => ecdh,
      run => {fun({Pub, Priv}) -> ecu_ecdh:compute_key(x448, Pub, Priv) end, {PubB448, PrivA448}}
    },
    #{
      id => ecdh_secp256k1,
      name => <<"ECDH secp256k1">>,
      group => ecdh,
      run => {fun({Pub, Priv}) -> ecu_ecdh:compute_key(secp256k1, Pub, Priv) end, {PubB256, PrivA256}}
    },
    #{
      id => ecdh_hybrid_x25519_mlkem768_encaps,
      name => <<"Hybrid X25519+MLKEM768 Encaps">>,
      group => ecdh,
      run => {fun(PK) -> ecu_ecdh:hybrid_encaps(PK) end, HybridPK}
    },
    #{
      id => ecdh_hybrid_x25519_mlkem768_decaps,
      name => <<"Hybrid X25519+MLKEM768 Decaps">>,
      group => ecdh,
      run => {fun({SK, CT}) -> ecu_ecdh:hybrid_decaps(SK, CT) end, {HybridSK, HybridCT}}
    }
  ].

%% ===================================================================
%% Post-Quantum: ML-KEM (FIPS 203)
%% ===================================================================

ml_kem_benchmarks() ->
  SeedD = <<1:256>>,
  SeedZ = <<2:256>>,
  {PK512, SK512} = ecu_ml_kem:keypair_from_seed(ml_kem_512, SeedD, SeedZ),
  {_SS512, CT512} = ecu_ml_kem:encaps(PK512, SeedD),

  {PK768, SK768} = ecu_ml_kem:keypair_from_seed(ml_kem_768, SeedD, SeedZ),
  {_SS768, CT768} = ecu_ml_kem:encaps(PK768, SeedD),

  {PK1024, SK1024} = ecu_ml_kem:keypair_from_seed(ml_kem_1024, SeedD, SeedZ),
  {_SS1024, CT1024} = ecu_ml_kem:encaps(PK1024, SeedD),

  [
    #{
      id => ml_kem_512_keypair,
      name => <<"ML-KEM-512 Keypair">>,
      group => ml_kem,
      run => fun() -> ecu_ml_kem:keypair(ml_kem_512) end
    },
    #{
      id => ml_kem_512_encaps,
      name => <<"ML-KEM-512 Encaps">>,
      group => ml_kem,
      run => {fun(PK) -> ecu_ml_kem:encaps(PK) end, PK512}
    },
    #{
      id => ml_kem_512_decaps,
      name => <<"ML-KEM-512 Decaps">>,
      group => ml_kem,
      run => {fun({SK, CT}) -> ecu_ml_kem:decaps(SK, CT) end, {SK512, CT512}}
    },
    #{
      id => ml_kem_768_keypair,
      name => <<"ML-KEM-768 Keypair">>,
      group => ml_kem,
      run => fun() -> ecu_ml_kem:keypair(ml_kem_768) end
    },
    #{
      id => ml_kem_768_encaps,
      name => <<"ML-KEM-768 Encaps">>,
      group => ml_kem,
      run => {fun(PK) -> ecu_ml_kem:encaps(PK) end, PK768}
    },
    #{
      id => ml_kem_768_decaps,
      name => <<"ML-KEM-768 Decaps">>,
      group => ml_kem,
      run => {fun({SK, CT}) -> ecu_ml_kem:decaps(SK, CT) end, {SK768, CT768}}
    },
    #{
      id => ml_kem_1024_keypair,
      name => <<"ML-KEM-1024 Keypair">>,
      group => ml_kem,
      run => fun() -> ecu_ml_kem:keypair(ml_kem_1024) end
    },
    #{
      id => ml_kem_1024_encaps,
      name => <<"ML-KEM-1024 Encaps">>,
      group => ml_kem,
      run => {fun(PK) -> ecu_ml_kem:encaps(PK) end, PK1024}
    },
    #{
      id => ml_kem_1024_decaps,
      name => <<"ML-KEM-1024 Decaps">>,
      group => ml_kem,
      run => {fun({SK, CT}) -> ecu_ml_kem:decaps(SK, CT) end, {SK1024, CT1024}}
    }
  ].

%% ===================================================================
%% Post-Quantum: ML-DSA (FIPS 204)
%% ===================================================================

ml_dsa_benchmarks() ->
  Msg = <<"ec_utils ML-DSA benchmark message">>,
  Seed44 = <<1:256>>,
  #{public := PK44, secret := SK44} = ecu_ml_dsa:keypair_from_seed(ml_dsa_44, Seed44),
  Sig44 = ecu_ml_dsa:sign_deterministic(Msg, SK44),

  Seed65 = <<2:256>>,
  #{public := PK65, secret := SK65} = ecu_ml_dsa:keypair_from_seed(ml_dsa_65, Seed65),
  Sig65 = ecu_ml_dsa:sign_deterministic(Msg, SK65),

  Seed87 = <<3:256>>,
  #{public := PK87, secret := SK87} = ecu_ml_dsa:keypair_from_seed(ml_dsa_87, Seed87),
  Sig87 = ecu_ml_dsa:sign_deterministic(Msg, SK87),

  [
    #{
      id => ml_dsa_44_keypair,
      name => <<"ML-DSA-44 Keypair">>,
      group => ml_dsa,
      run => fun() -> ecu_ml_dsa:keypair(ml_dsa_44) end
    },
    #{
      id => ml_dsa_44_sign,
      name => <<"ML-DSA-44 Sign">>,
      group => ml_dsa,
      run => {fun({M, SK}) -> ecu_ml_dsa:sign_deterministic(M, SK) end, {Msg, SK44}}
    },
    #{
      id => ml_dsa_44_verify,
      name => <<"ML-DSA-44 Verify">>,
      group => ml_dsa,
      run => {fun({M, Sig, PK}) -> ecu_ml_dsa:verify(M, Sig, PK) end, {Msg, Sig44, PK44}}
    },
    #{
      id => ml_dsa_65_keypair,
      name => <<"ML-DSA-65 Keypair">>,
      group => ml_dsa,
      run => fun() -> ecu_ml_dsa:keypair(ml_dsa_65) end
    },
    #{
      id => ml_dsa_65_sign,
      name => <<"ML-DSA-65 Sign">>,
      group => ml_dsa,
      run => {fun({M, SK}) -> ecu_ml_dsa:sign_deterministic(M, SK) end, {Msg, SK65}}
    },
    #{
      id => ml_dsa_65_verify,
      name => <<"ML-DSA-65 Verify">>,
      group => ml_dsa,
      run => {fun({M, Sig, PK}) -> ecu_ml_dsa:verify(M, Sig, PK) end, {Msg, Sig65, PK65}}
    },
    #{
      id => ml_dsa_87_keypair,
      name => <<"ML-DSA-87 Keypair">>,
      group => ml_dsa,
      run => fun() -> ecu_ml_dsa:keypair(ml_dsa_87) end
    },
    #{
      id => ml_dsa_87_sign,
      name => <<"ML-DSA-87 Sign">>,
      group => ml_dsa,
      run => {fun({M, SK}) -> ecu_ml_dsa:sign_deterministic(M, SK) end, {Msg, SK87}}
    },
    #{
      id => ml_dsa_87_verify,
      name => <<"ML-DSA-87 Verify">>,
      group => ml_dsa,
      run => {fun({M, Sig, PK}) -> ecu_ml_dsa:verify(M, Sig, PK) end, {Msg, Sig87, PK87}}
    }
  ].

%% ===================================================================
%% FROST (RFC 9591)
%% ===================================================================

frost_benchmarks() ->
  Msg = <<"FROST benchmark message">>,
  {Shares, GroupPK, _} = ecu_frost:trusted_dealer_keygen(ed25519, 2, 3),
  Selected = lists:sublist(Shares, 2),
  Nonces = [{Id, S, ecu_frost:commit(ed25519, S)} || {Id, S} <- Selected],
  CommitList = [{Id, HC, BC} || {Id, _, {_, {HC, BC}}} <- Nonces],
  SigShares = [
    ecu_frost:sign(ed25519, Id, S, GroupPK, NP, Msg, CommitList)
   || {Id, S, {NP, _}} <- Nonces
  ],
  {_, FirstS, {FirstNP, _}} = hd(Nonces),
  Sig = ecu_frost:aggregate(ed25519, CommitList, Msg, GroupPK, SigShares),

  [
    #{
      id => frost_ed25519_commit,
      name => <<"FROST Ed25519 Commit">>,
      group => frost,
      run => {fun(S) -> ecu_frost:commit(ed25519, S) end, FirstS}
    },
    #{
      id => frost_ed25519_sign,
      name => <<"FROST Ed25519 Sign Share">>,
      group => frost,
      run =>
        {
          fun({Id, S, GPK, NP, M, CL}) ->
            ecu_frost:sign(ed25519, Id, S, GPK, NP, M, CL)
          end,
          {1, FirstS, GroupPK, FirstNP, Msg, CommitList}
        }
    },
    #{
      id => frost_ed25519_aggregate,
      name => <<"FROST Ed25519 Aggregate">>,
      group => frost,
      run =>
        {
          fun({CL, M, GPK, SS}) -> ecu_frost:aggregate(ed25519, CL, M, GPK, SS) end,
          {CommitList, Msg, GroupPK, SigShares}
        }
    },
    #{
      id => frost_ed25519_verify,
      name => <<"FROST Ed25519 Verify">>,
      group => frost,
      run =>
        {fun({S, M, GPK}) -> ecu_frost:verify(ed25519, S, M, GPK) end, {Sig, Msg, GroupPK}}
    }
  ].

%% ===================================================================
%% MuSig2 (BIP-327)
%% ===================================================================

musig2_benchmarks() ->
  Msg = crypto:strong_rand_bytes(32),
  SKs = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 3)],
  PKs = [ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK)) || SK <- SKs],
  {ok, Ctx} = ecu_musig2:key_agg(PKs),

  Nonces = [
    begin
      {SN, PN} = ecu_musig2:nonce_gen(SK),
      {SN, PN}
    end
   || SK <- SKs
  ],
  PubNonces = [PN || {_, PN} <- Nonces],
  {ok, AggNonce} = ecu_musig2:nonce_agg(PubNonces),

  {SN1, PN1} = hd(Nonces),
  SK1 = hd(SKs),
  PK1 = hd(PKs),

  {ok, Psig1} = ecu_musig2:sign_partial(Ctx, SK1, SN1, AggNonce, Msg),

  Psigs = [
    begin
      {ok, P} = ecu_musig2:sign_partial(Ctx, SK, SN, AggNonce, Msg),
      P
    end
   || {SK, {SN, _}} <- lists:zip(SKs, Nonces)
  ],

  [
    #{
      id => musig2_key_agg,
      name => <<"MuSig2 Key Agg (3 signers)">>,
      group => musig2,
      run => {fun(Keys) -> ecu_musig2:key_agg(Keys) end, PKs}
    },
    #{
      id => musig2_nonce_gen,
      name => <<"MuSig2 Nonce Gen">>,
      group => musig2,
      run => {fun(SK) -> ecu_musig2:nonce_gen(SK) end, SK1}
    },
    #{
      id => musig2_nonce_agg,
      name => <<"MuSig2 Nonce Agg">>,
      group => musig2,
      run => {fun(PNs) -> ecu_musig2:nonce_agg(PNs) end, PubNonces}
    },
    #{
      id => musig2_sign_partial,
      name => <<"MuSig2 Partial Sign">>,
      group => musig2,
      run =>
        {
          fun({C, SK, SN, AN, M}) -> ecu_musig2:sign_partial(C, SK, SN, AN, M) end,
          {Ctx, SK1, SN1, AggNonce, Msg}
        }
    },
    #{
      id => musig2_verify_partial,
      name => <<"MuSig2 Partial Verify">>,
      group => musig2,
      run =>
        {
          fun({C, Sig, PN, PK, AN, M}) ->
            ecu_musig2:verify_partial(C, Sig, PN, PK, AN, M)
          end,
          {Ctx, Psig1, PN1, PK1, AggNonce, Msg}
        }
    },
    #{
      id => musig2_aggregate,
      name => <<"MuSig2 Aggregate Partials">>,
      group => musig2,
      run =>
        {
          fun({C, AN, M, Sigs}) -> ecu_musig2:aggregate_partial(C, AN, M, Sigs) end,
          {Ctx, AggNonce, Msg, Psigs}
        }
    }
  ].

%% ===================================================================
%% Hash-to-Curve (RFC 9380)
%% ===================================================================

h2c_benchmarks() ->
  Msg = <<"Hash to Curve message string">>,

  [
    #{
      id => h2c_secp256k1,
      name => <<"Hash-to-Curve (secp256k1)">>,
      group => h2c,
      run => {fun(M) -> ecu_h2c:hash_to_curve(secp256k1_xmd_sha256_sswu_ro, M) end, Msg}
    },
    #{
      id => h2c_edwards25519,
      name => <<"Hash-to-Curve (edwards25519)">>,
      group => h2c,
      run => {fun(M) -> ecu_h2c:hash_to_curve(edwards25519_xmd_sha512_ell2_ro, M) end, Msg}
    },
    #{
      id => h2c_edwards448,
      name => <<"Hash-to-Curve (edwards448)">>,
      group => h2c,
      run => {fun(M) -> ecu_h2c:hash_to_curve(edwards448_xof_shake256_ell2_ro, M) end, Msg}
    }
  ].

%% ===================================================================
%% Keccak & SHA-3
%% ===================================================================

keccak_benchmarks() ->
  Data32 = crypto:strong_rand_bytes(32),
  Data1024 = crypto:strong_rand_bytes(1024),

  [
    #{
      id => keccak_256_32b,
      name => <<"Keccak-256 (32 bytes)">>,
      group => keccak,
      run => {fun(D) -> ecu_keccak:keccak256(D) end, Data32}
    },
    #{
      id => keccak_256_1kb,
      name => <<"Keccak-256 (1 KB)">>,
      group => keccak,
      run => {fun(D) -> ecu_keccak:keccak256(D) end, Data1024}
    },
    #{
      id => sha3_256_32b,
      name => <<"SHA3-256 (32 bytes)">>,
      group => keccak,
      run => {fun(D) -> ecu_keccak:sha3_256(D) end, Data32}
    },
    #{
      id => shake256_64b,
      name => <<"SHAKE256 (64 bytes output)">>,
      group => keccak,
      run => {fun(D) -> ecu_keccak:shake256(D, 64) end, Data32}
    }
  ].

%% ===================================================================
%% SHA-2, RIPEMD, HMAC & PBKDF2
%% ===================================================================

hash_benchmarks() ->
  Data64 = crypto:strong_rand_bytes(64),
  Key32 = crypto:strong_rand_bytes(32),
  Key64 = crypto:strong_rand_bytes(64),
  Pass = <<"password">>,
  Salt = <<"salt">>,

  [
    #{
      id => sha2_256_64b,
      name => <<"SHA-256 (64 bytes)">>,
      group => hash,
      run => {fun(D) -> ecu_sha2:sha256(D) end, Data64}
    },
    #{
      id => sha2_512_64b,
      name => <<"SHA-512 (64 bytes)">>,
      group => hash,
      run => {fun(D) -> ecu_sha2:sha512(D) end, Data64}
    },
    #{
      id => ripemd160_64b,
      name => <<"RIPEMD-160 (64 bytes)">>,
      group => hash,
      run => {fun(D) -> ecu_ripemd160:ripemd160(D) end, Data64}
    },
    #{
      id => hmac_sha256_64b,
      name => <<"HMAC-SHA256 (64 bytes)">>,
      group => hash,
      run => {fun({K, D}) -> ecu_hmac:hmac(sha256, K, D) end, {Key32, Data64}}
    },
    #{
      id => hmac_sha512_64b,
      name => <<"HMAC-SHA512 (64 bytes)">>,
      group => hash,
      run => {fun({K, D}) -> ecu_hmac:hmac(sha512, K, D) end, {Key64, Data64}}
    },
    #{
      id => pbkdf2_hmac_sha512_2048,
      name => <<"PBKDF2-HMAC-SHA512 (2048 iters)">>,
      group => hash,
      run =>
        {fun({P, S}) -> ecu_pbkdf2:pbkdf2_hmac(sha512, P, S, 2048, 64) end, {Pass, Salt}}
    }
  ].

%% ===================================================================
%% Wallets & Encodings (HD, Base58, BIP-39)
%% ===================================================================

hd_benchmarks() ->
  Payload = crypto:strong_rand_bytes(78),
  B58Str = ecu_base58:encode_check(Payload),
  Seed = crypto:strong_rand_bytes(32),
  {ok, MSecp} = ecu_hd:master_key(secp256k1, Seed),
  MSecpPub = ecu_hd:to_public(MSecp),
  {ok, MEd} = ecu_hd:master_key(ed25519, Seed),
  Mnemonic12 =
    <<"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about">>,

  [
    #{
      id => base58_encode_check,
      name => <<"Base58Check Encode (78B)">>,
      group => hd,
      run => {fun(B) -> ecu_base58:encode_check(B) end, Payload}
    },
    #{
      id => base58_decode_check,
      name => <<"Base58Check Decode (78B)">>,
      group => hd,
      run => {fun(S) -> ecu_base58:decode_check(S) end, B58Str}
    },
    #{
      id => bip39_mnemonic_to_seed,
      name => <<"BIP-39 Mnemonic to Seed">>,
      group => hd,
      run => {fun(M) -> ecu_bip39:mnemonic_to_seed(M, "TREZOR") end, Mnemonic12}
    },
    #{
      id => hd_ckd_priv_secp256k1,
      name => <<"BIP-32 CKDpriv (secp256k1)">>,
      group => hd,
      run => {fun(K) -> ecu_hd:ckd_priv(K, 1) end, MSecp}
    },
    #{
      id => hd_ckd_pub_secp256k1,
      name => <<"BIP-32 CKDpub (secp256k1)">>,
      group => hd,
      run => {fun(K) -> ecu_hd:ckd_pub(K, 1) end, MSecpPub}
    },
    #{
      id => hd_ckd_priv_ed25519,
      name => <<"SLIP-0010 CKDpriv (Ed25519)">>,
      group => hd,
      run => {fun(K) -> ecu_hd:ckd_priv(K, 16#80000001) end, MEd}
    }
  ].

%% ===================================================================
%% BLS12-381
%% ===================================================================

bls12_381_benchmarks() ->
  Scalar =
    16#123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0 rem (ecu_bls12_381:r() - 1) +
      1,
  G1Gen = ecu_bls12_381:g1_generator(),
  G2Gen = ecu_bls12_381:g2_generator(),
  G1Pt = ecu_bls12_381:g1_scalar_mul(G1Gen, 3),
  G2Pt = ecu_bls12_381:g2_scalar_mul(G2Gen, 3),
  Msg = <<"BLS12-381 benchmark payload">>,
  {ok, {MinPkPub, MinPkPriv}} =
    ecu_bls12_381_sig:min_pk_keygen(<<"benchmark-ikm-32-bytes-minimum!!">>),
  MinPkSig = ecu_bls12_381_sig:sign(min_pk, MinPkPriv, Msg),

  [
    #{
      id => bls12_381_g1_point_add,
      name => <<"BLS12-381 G1 Point Add">>,
      group => bls12_381,
      run => {fun({A, B}) -> ecu_bls12_381:g1_add(A, B) end, {G1Gen, G1Pt}}
    },
    #{
      id => bls12_381_g1_scalar_mul,
      name => <<"BLS12-381 G1 ScalarMul">>,
      group => bls12_381,
      run => {fun({P, S}) -> ecu_bls12_381:g1_scalar_mul(P, S) end, {G1Gen, Scalar}}
    },
    #{
      id => bls12_381_g2_point_add,
      name => <<"BLS12-381 G2 Point Add">>,
      group => bls12_381,
      run => {fun({A, B}) -> ecu_bls12_381:g2_add(A, B) end, {G2Gen, G2Pt}}
    },
    #{
      id => bls12_381_g2_scalar_mul,
      name => <<"BLS12-381 G2 ScalarMul">>,
      group => bls12_381,
      run => {fun({P, S}) -> ecu_bls12_381:g2_scalar_mul(P, S) end, {G2Gen, Scalar}}
    },
    #{
      id => bls12_381_pairing,
      name => <<"BLS12-381 Optimal Ate Pairing">>,
      group => bls12_381,
      run => {fun({P, Q}) -> ecu_bls12_381_pairing:pairing(P, Q) end, {G1Gen, G2Gen}}
    },
    #{
      id => bls12_381_g1_hash_to_curve,
      name => <<"BLS12-381 G1 Hash to Curve">>,
      group => bls12_381,
      run => {fun(M) -> ecu_bls12_381:g1_hash_to_curve(M) end, Msg}
    },
    #{
      id => bls12_381_g2_hash_to_curve,
      name => <<"BLS12-381 G2 Hash to Curve">>,
      group => bls12_381,
      run => {fun(M) -> ecu_bls12_381:g2_hash_to_curve(M) end, Msg}
    },
    #{
      id => bls_min_pk_sign,
      name => <<"BLS min_pk Sign">>,
      group => bls12_381,
      run => {fun({SK, M}) -> ecu_bls12_381_sig:sign(min_pk, SK, M) end, {MinPkPriv, Msg}}
    },
    #{
      id => bls_min_pk_verify,
      name => <<"BLS min_pk Verify">>,
      group => bls12_381,
      run =>
        {fun({PK, M, S}) -> ecu_bls12_381_sig:verify(min_pk, PK, M, S) end, {MinPkPub, Msg, MinPkSig}}
    }
  ].
