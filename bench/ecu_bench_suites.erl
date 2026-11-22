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
    slh_dsa,
    frost,
    musig2,
    h2c,
    keccak,
    hash,
    hd,
    bls12_381,
    bn254,
    groth16,
    poseidon,
    vrf,
    babyjubjub,
    kzg,
    circom
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
    slh_dsa_benchmarks(),
    frost_benchmarks(),
    musig2_benchmarks(),
    h2c_benchmarks(),
    keccak_benchmarks(),
    hash_benchmarks(),
    hd_benchmarks(),
    bls12_381_benchmarks(),
    bn254_benchmarks(),
    groth16_benchmarks(),
    poseidon_benchmarks(),
    vrf_benchmarks(),
    babyjubjub_benchmarks(),
    kzg_benchmarks(),
    circom_benchmarks()
  ]).

%% ===================================================================
%% Ed25519
%% ===================================================================

ed25519_benchmarks() ->
  Scalar = <<1:256>>,
  P1 = ecu_ed25519:scalar_mul_base(<<1:256>>),
  P2 = ecu_ed25519:scalar_mul_base(<<2:256>>),
  #{public := EdPub, secret := EdPriv} = ecu_eddsa:sign_seed_keypair(<<3:256>>),
  Msg = <<"ec_utils Ed25519 benchmark message payload">>,
  EdSig = ecu_eddsa:sign_detached(Msg, EdPriv),

  Batch32 = [
    begin
      #{public := PK, secret := SK} = ecu_eddsa:sign_seed_keypair(<<I:256>>),
      M = <<I:64, "benchmark_message_data_bytes_24">>,
      {ecu_eddsa:sign_detached(M, SK), M, PK}
    end
   || I <- lists:seq(1, 32)
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
  SecpPriv = <<1:256>>,
  SecpPub = ecu_secp256k1:scalar_mul_base(SecpPriv),
  MsgHash = <<2:256>>,
  {SecpSig, _} = ecu_ecdsa:sign_secp256k1(MsgHash, SecpPriv),
  EthMsg = <<"ethereum message hash 32 bytes!!">>,
  EthSig = ecu_crypto:eth_sign(EthMsg, SecpPriv),

  Bip340Priv = <<3:256>>,
  Bip340Pub = ecu_secp256k1:scalar_mul_base(Bip340Priv),
  AuxRand0 = <<0:256>>,
  Bip340Sig = ecu_schnorr:sign(MsgHash, Bip340Priv, AuxRand0),

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
      run => {fun({M, SK, AR}) -> ecu_schnorr:sign(M, SK, AR) end, {MsgHash, Bip340Priv, AuxRand0}}
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
  Scalar448 = binary:copy(<<16#33>>, 57),
  Point448 = ecu_ed448:scalar_mul_base(Scalar448),
  #{public := Ed448Pub, secret := Ed448Priv} =
    ecu_eddsa448:sign_seed_keypair(binary:copy(<<16#55>>, 57)),
  Msg448 = <<"ec_utils Ed448 benchmark message">>,
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
  {_PubA25519, PrivA25519} = ecu_ecdh:keypair_from_seed(x25519, <<1:256>>),
  {PubB25519, _PrivB25519} = ecu_ecdh:keypair_from_seed(x25519, <<2:256>>),
  {_PubA448, PrivA448} = ecu_ecdh:keypair_from_seed(x448, binary:copy(<<1>>, 56)),
  {PubB448, _PrivB448} = ecu_ecdh:keypair_from_seed(x448, binary:copy(<<2>>, 56)),
  {_PubA256, PrivA256} = ecu_ecdh:keypair_from_seed(secp256k1, <<1:256>>),
  {PubB256, _PrivB256} = ecu_ecdh:keypair_from_seed(secp256k1, <<2:256>>),

  {XPub, _} = ecu_ecdh:keypair_from_seed(x25519, <<1:256>>),
  {KemPub, KemPriv} =
    ecu_ml_kem:keypair_from_seed(ml_kem_768, binary:copy(<<1>>, 32), binary:copy(<<2>>, 32)),
  {EphPub, _} = ecu_ecdh:keypair_from_seed(x25519, <<3:256>>),
  {_SSKem, CTKem} = ecu_ml_kem:encaps(KemPub, binary:copy(<<4>>, 32)),
  HybridPK = <<XPub/binary, KemPub/binary>>,
  HybridSK = <<PrivA25519/binary, KemPriv/binary>>,
  HybridCT = <<EphPub/binary, CTKem/binary>>,

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
      run =>
        {
          fun({<<XP:32/binary, KP:1184/binary>>, SeedX, SeedM}) ->
            {EphP, EphS} = ecu_ecdh:keypair_from_seed(x25519, SeedX),
            {SS_k, CT_k} = ecu_ml_kem:encaps(KP, SeedM),
            SS_e = ecu_ecdh:compute_key(x25519, XP, EphS),
            SharedSecret = ecu_compat:hash(sha3_256, <<SS_k/binary, SS_e/binary>>),
            {SharedSecret, <<EphP/binary, CT_k/binary>>}
          end,
          {HybridPK, binary:copy(<<16#44>>, 32), binary:copy(<<16#55>>, 32)}
        }
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
      run => {fun({D, Z}) -> ecu_ml_kem:keypair_from_seed(ml_kem_512, D, Z) end, {SeedD, SeedZ}}
    },
    #{
      id => ml_kem_512_encaps,
      name => <<"ML-KEM-512 Encaps">>,
      group => ml_kem,
      run => {fun({PK, M}) -> ecu_ml_kem:encaps(PK, M) end, {PK512, SeedD}}
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
      run => {fun({D, Z}) -> ecu_ml_kem:keypair_from_seed(ml_kem_768, D, Z) end, {SeedD, SeedZ}}
    },
    #{
      id => ml_kem_768_encaps,
      name => <<"ML-KEM-768 Encaps">>,
      group => ml_kem,
      run => {fun({PK, M}) -> ecu_ml_kem:encaps(PK, M) end, {PK768, SeedD}}
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
      run => {fun({D, Z}) -> ecu_ml_kem:keypair_from_seed(ml_kem_1024, D, Z) end, {SeedD, SeedZ}}
    },
    #{
      id => ml_kem_1024_encaps,
      name => <<"ML-KEM-1024 Encaps">>,
      group => ml_kem,
      run => {fun({PK, M}) -> ecu_ml_kem:encaps(PK, M) end, {PK1024, SeedD}}
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
      run => {fun(S) -> ecu_ml_dsa:keypair_from_seed(ml_dsa_44, S) end, Seed44}
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
      run => {fun(S) -> ecu_ml_dsa:keypair_from_seed(ml_dsa_65, S) end, Seed65}
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
      run => {fun(S) -> ecu_ml_dsa:keypair_from_seed(ml_dsa_87, S) end, Seed87}
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
%% SLH-DSA (FIPS 205)
%% ===================================================================

slh_dsa_benchmarks() ->
  case code:ensure_loaded(ecu_slh_dsa) of
    {module, ecu_slh_dsa} ->
      Msg = <<"ec_utils SLH-DSA benchmark message">>,
      Seed = <<1:128>>,
      #{public := PK_sha2, secret := SK_sha2} =
        ecu_slh_dsa:keypair_from_seeds(slh_dsa_sha2_128f, Seed, Seed, Seed),
      Sig_sha2 = ecu_slh_dsa:sign_deterministic(slh_dsa_sha2_128f, Msg, SK_sha2),

      [
        #{
          id => slh_dsa_sha2_128f_keypair,
          name => <<"SLH-DSA-SHA2-128f Keypair">>,
          group => slh_dsa,
          run =>
            {
              fun(S) -> ecu_slh_dsa:keypair_from_seeds(slh_dsa_sha2_128f, S, S, S) end,
              Seed
            }
        },
        #{
          id => slh_dsa_sha2_128f_sign,
          name => <<"SLH-DSA-SHA2-128f Sign">>,
          group => slh_dsa,
          run =>
            {
              fun({M, SK}) -> ecu_slh_dsa:sign_deterministic(slh_dsa_sha2_128f, M, SK) end,
              {Msg, SK_sha2}
            }
        },
        #{
          id => slh_dsa_sha2_128f_verify,
          name => <<"SLH-DSA-SHA2-128f Verify">>,
          group => slh_dsa,
          run =>
            {
              fun({M, Sig, PK}) -> ecu_slh_dsa:verify(slh_dsa_sha2_128f, Sig, M, PK) end,
              {Msg, Sig_sha2, PK_sha2}
            }
        }
      ];
    _ ->
      []
  end.

%% ===================================================================
%% FROST (RFC 9591)
%% ===================================================================

frost_benchmarks() ->
  Msg = <<"FROST benchmark message">>,
  Coeffs = [<<1:256/little>>, <<2:256/little>>],
  Shares = [{I, ecu_frost:polynomial_evaluate(ed25519, I, Coeffs)} || I <- lists:seq(1, 3)],
  VSSCommitment = [ecu_ed25519:compress(ecu_ed25519:scalar_mul_base_noclamp(C)) || C <- Coeffs],
  GroupPK = hd(VSSCommitment),
  Selected = lists:sublist(Shares, 2),
  Nonces = [
    {Id, S, ecu_frost:commit(ed25519, S, {<<Id:256>>, <<(Id + 10):256>>})}
   || {Id, S} <- Selected
  ],
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
      run =>
        {
          fun({S, RP}) -> ecu_frost:commit(ed25519, S, RP) end,
          {FirstS, {<<1:256>>, <<2:256>>}}
        }
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
  Msg = <<42:256>>,
  SKs = [<<1:256>>, <<2:256>>, <<3:256>>],
  PKs = [ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK)) || SK <- SKs],
  {ok, Ctx} = ecu_musig2:key_agg(PKs),

  Nonces = [
    begin
      K1 = I * 10 + 1,
      K2 = I * 10 + 2,
      R1 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(K1)),
      R2 = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(K2)),
      SignerPub = ecu_secp256k1:compress(ecu_secp256k1:scalar_mul_base(SK)),
      {<<K1:256, K2:256, SignerPub/binary>>, <<R1/binary, R2/binary>>}
    end
   || {I, SK} <- lists:zip(lists:seq(1, length(SKs)), SKs)
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
  Data32 = binary:copy(<<"0123456789abcdef">>, 2),
  Data1024 = binary:copy(<<"0123456789abcdef">>, 64),

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
  Data64 = binary:copy(<<"0123456789abcdef">>, 4),
  Key32 = binary:copy(<<16#aa>>, 32),
  Key64 = binary:copy(<<16#bb>>, 64),
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
  Payload = binary:copy(<<16#42>>, 78),
  B58Str = ecu_base58:encode_check(Payload),
  Seed = binary:copy(<<16#33>>, 32),
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

%% ===================================================================
%% BN254
%% ===================================================================

bn254_benchmarks() ->
  case code:ensure_loaded(ecu_bn254) of
    {module, ecu_bn254} ->
      Scalar =
        16#123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0 rem (ecu_bn254:r() - 1) + 1,
      ScalarBin = <<Scalar:256/big>>,
      G1Gen = ecu_bn254:g1_generator(),
      G2Gen = ecu_bn254:g2_generator(),
      G1Pt = ecu_bn254:g1_scalar_mul(G1Gen, 3),
      G2Pt = ecu_bn254:g2_scalar_mul(G2Gen, 3),
      G1GenBin = ecu_bn254:g1_to_uncompressed(G1Gen),
      G1PtBin = ecu_bn254:g1_to_uncompressed(G1Pt),
      G2GenBin = ecu_bn254:g2_to_uncompressed(G2Gen),
      G2PtBin = ecu_bn254:g2_to_uncompressed(G2Pt),

      NifAvail =
        case code:ensure_loaded(ecu_bn254_nif) of
          {module, ecu_bn254_nif} ->
            erlang:function_exported(ecu_bn254_nif, is_available, 0) andalso
              ecu_bn254_nif:is_available();
          _ ->
            false
        end,

      Base = [
        #{
          id => bn254_g1_point_add,
          name => <<"BN254 G1 Point Add">>,
          group => bn254,
          run => {fun({A, B}) -> ecu_bn254:g1_add(A, B) end, {G1Gen, G1Pt}}
        },
        #{
          id => bn254_g1_scalar_mul,
          name => <<"BN254 G1 ScalarMul">>,
          group => bn254,
          run => {fun({P, S}) -> ecu_bn254:g1_scalar_mul(P, S) end, {G1Gen, Scalar}}
        },
        #{
          id => bn254_g2_point_add,
          name => <<"BN254 G2 Point Add">>,
          group => bn254,
          run => {fun({A, B}) -> ecu_bn254:g2_add(A, B) end, {G2Gen, G2Pt}}
        },
        #{
          id => bn254_g2_scalar_mul,
          name => <<"BN254 G2 ScalarMul">>,
          group => bn254,
          run => {fun({P, S}) -> ecu_bn254:g2_scalar_mul(P, S) end, {G2Gen, Scalar}}
        },
        #{
          id => bn254_pairing,
          name => <<"BN254 Optimal Ate Pairing">>,
          group => bn254,
          run => {fun({P, Q}) -> ecu_bn254_pairing:pairing(P, Q) end, {G1Gen, G2Gen}}
        }
      ],
      NifBenches =
        case NifAvail of
          true ->
            [
              #{
                id => bn254_g1_point_add_rust,
                name => <<"BN254 G1 Point Add (Rust NIF arkworks)">>,
                group => bn254,
                run => {fun({A, B}) -> ecu_bn254_nif:g1_add(A, B) end, {G1GenBin, G1PtBin}}
              },
              #{
                id => bn254_g1_scalar_mul_rust,
                name => <<"BN254 G1 ScalarMul (Rust NIF arkworks)">>,
                group => bn254,
                run => {fun({P, S}) -> ecu_bn254_nif:g1_mult(P, S) end, {G1GenBin, ScalarBin}}
              },
              #{
                id => bn254_g2_point_add_rust,
                name => <<"BN254 G2 Point Add (Rust NIF arkworks)">>,
                group => bn254,
                run => {fun({A, B}) -> ecu_bn254_nif:g2_add(A, B) end, {G2GenBin, G2PtBin}}
              },
              #{
                id => bn254_g2_scalar_mul_rust,
                name => <<"BN254 G2 ScalarMul (Rust NIF arkworks)">>,
                group => bn254,
                run => {fun({P, S}) -> ecu_bn254_nif:g2_mult(P, S) end, {G2GenBin, ScalarBin}}
              },
              #{
                id => bn254_pairing_rust,
                name => <<"BN254 Optimal Ate Pairing (Rust NIF arkworks)">>,
                group => bn254,
                run => {fun({P, Q}) -> ecu_bn254_nif:pairing(P, Q) end, {G1GenBin, G2GenBin}}
              }
            ];
          false ->
            []
        end,
      Base ++ NifBenches;
    _ ->
      []
  end.

groth16_benchmarks() ->
  Inputs = [12345, 67890],
  AlphaVal = 123456789123456789,
  BetaVal = 987654321987654321,
  GammaVal = 112233445566778899,
  DeltaVal = 998877665544332211,
  G1 = ecu_bls12_381:g1_generator(),
  G2 = ecu_bls12_381:g2_generator(),
  AlphaG1 = ecu_bls12_381:g1_scalar_mul(G1, AlphaVal),
  BetaG2 = ecu_bls12_381:g2_scalar_mul(G2, BetaVal),
  GammaG2 = ecu_bls12_381:g2_scalar_mul(G2, GammaVal),
  DeltaG2 = ecu_bls12_381:g2_scalar_mul(G2, DeltaVal),
  IC = [
    ecu_bls12_381:g1_scalar_mul(G1, 314159265),
    ecu_bls12_381:g1_scalar_mul(G1, 314169272),
    ecu_bls12_381:g1_scalar_mul(G1, 314179279)
  ],
  VK = #{
    alpha_g1 => AlphaG1,
    beta_g2 => BetaG2,
    gamma_g2 => GammaG2,
    delta_g2 => DeltaG2,
    ic => IC
  },
  R = ecu_bls12_381:r(),
  AVal = 777777777,
  BVal = 888888888,
  A = ecu_bls12_381:g1_scalar_mul(G1, AVal),
  B = ecu_bls12_381:g2_scalar_mul(G2, BVal),
  KPubScalar = (314159265 + 12345 * 314169272 + 67890 * 314179279) rem R,
  DeltaInvBin =
    case ecu_compat:mod_pow(DeltaVal, R - 2, R) of
      error -> error(mod_pow_failed);
      Bin when is_binary(Bin) -> Bin
    end,
  DeltaInv = binary:decode_unsigned(DeltaInvBin),
  Num = ((AVal * BVal) - (AlphaVal * BetaVal) - (KPubScalar * GammaVal)) rem R,
  CVal = (((Num rem R + R) rem R) * DeltaInv) rem R,
  C = ecu_bls12_381:g1_scalar_mul(G1, CVal),
  Proof = #{a => A, b => B, c => C},
  Batch = [{Inputs, Proof}, {Inputs, Proof}, {Inputs, Proof}, {Inputs, Proof}],

  BLSBenches = [
    #{
      id => groth16_verify,
      name => <<"Groth16 Verify (BLS12-381)">>,
      group => groth16,
      run => {fun({V, In, P}) -> ecu_groth16:verify(V, In, P) end, {VK, Inputs, Proof}}
    },
    #{
      id => groth16_verify_batch_4,
      name => <<"Groth16 Batch Verify (4 proofs, BLS12-381)">>,
      group => groth16,
      run => {fun({V, Bth}) -> ecu_groth16:verify_batch(V, Bth) end, {VK, Batch}}
    }
  ],

  BNBenches =
    case code:ensure_loaded(ecu_bn254) of
      {module, ecu_bn254} ->
        BN_G1 = ecu_bn254:g1_generator(),
        BN_G2 = ecu_bn254:g2_generator(),
        BN_R = ecu_bn254:r(),
        BN_AlphaVal = AlphaVal rem BN_R,
        BN_BetaVal = BetaVal rem BN_R,
        BN_GammaVal = GammaVal rem BN_R,
        BN_DeltaVal = DeltaVal rem BN_R,
        BN_AlphaG1 = ecu_bn254:g1_scalar_mul(BN_G1, BN_AlphaVal),
        BN_BetaG2 = ecu_bn254:g2_scalar_mul(BN_G2, BN_BetaVal),
        BN_GammaG2 = ecu_bn254:g2_scalar_mul(BN_G2, BN_GammaVal),
        BN_DeltaG2 = ecu_bn254:g2_scalar_mul(BN_G2, BN_DeltaVal),
        BN_IC = [
          ecu_bn254:g1_scalar_mul(BN_G1, 314159265 rem BN_R),
          ecu_bn254:g1_scalar_mul(BN_G1, 314169272 rem BN_R),
          ecu_bn254:g1_scalar_mul(BN_G1, 314179279 rem BN_R)
        ],
        BN_VK = #{
          alpha_g1 => BN_AlphaG1,
          beta_g2 => BN_BetaG2,
          gamma_g2 => BN_GammaG2,
          delta_g2 => BN_DeltaG2,
          ic => BN_IC
        },
        BN_AVal = AVal rem BN_R,
        BN_BVal = BVal rem BN_R,
        BN_A = ecu_bn254:g1_scalar_mul(BN_G1, BN_AVal),
        BN_B = ecu_bn254:g2_scalar_mul(BN_G2, BN_BVal),
        BN_KPubScalar = (314159265 + 12345 * 314169272 + 67890 * 314179279) rem BN_R,
        BN_DeltaInv =
          case ecu_misc:eea(BN_DeltaVal, BN_R) of
            {1, XInv, _} -> (XInv rem BN_R + BN_R) rem BN_R
          end,
        BN_Num =
          ((BN_AVal * BN_BVal) - (BN_AlphaVal * BN_BetaVal) - (BN_KPubScalar * BN_GammaVal)) rem BN_R,
        BN_CVal = (((BN_Num rem BN_R + BN_R) rem BN_R) * BN_DeltaInv) rem BN_R,
        BN_C = ecu_bn254:g1_scalar_mul(BN_G1, BN_CVal),
        BN_Proof = #{a => BN_A, b => BN_B, c => BN_C},
        BN_Batch = [{Inputs, BN_Proof}, {Inputs, BN_Proof}, {Inputs, BN_Proof}, {Inputs, BN_Proof}],

        BN_NifAvail =
          case code:ensure_loaded(ecu_bn254_nif) of
            {module, ecu_bn254_nif} ->
              erlang:function_exported(ecu_bn254_nif, is_available, 0) andalso
                ecu_bn254_nif:is_available();
            _ ->
              false
          end,

        BNBaseBenches = [
          #{
            id => groth16_verify_bn254,
            name => <<"Groth16 Verify (BN254)">>,
            group => groth16,
            run => {
              fun({V, In, P}) -> ecu_groth16:verify(bn254, V, In, P) end, {BN_VK, Inputs, BN_Proof}
            }
          },
          #{
            id => groth16_verify_batch_4_bn254,
            name => <<"Groth16 Batch Verify (4 proofs, BN254)">>,
            group => groth16,
            run => {fun({V, Bth}) -> ecu_groth16:verify_batch(bn254, V, Bth) end, {BN_VK, BN_Batch}}
          }
        ],
        BNNifBenches =
          case BN_NifAvail of
            true ->
              AlphaBin = ecu_bn254:g1_to_uncompressed(BN_AlphaG1),
              BetaBin = ecu_bn254:g2_to_uncompressed(BN_BetaG2),
              GammaBin = ecu_bn254:g2_to_uncompressed(BN_GammaG2),
              DeltaBin = ecu_bn254:g2_to_uncompressed(BN_DeltaG2),
              ICBins = [ecu_bn254:g1_to_uncompressed(Pt) || Pt <- BN_IC],
              InputBins = [<<X:256/big>> || X <- Inputs],
              ABin = ecu_bn254:g1_to_uncompressed(BN_A),
              BBin = ecu_bn254:g2_to_uncompressed(BN_B),
              CBin = ecu_bn254:g1_to_uncompressed(BN_C),
              NifArgs = {AlphaBin, BetaBin, GammaBin, DeltaBin, ICBins, InputBins, ABin, BBin, CBin},
              [
                #{
                  id => groth16_verify_bn254_rust,
                  name => <<"Groth16 Verify (BN254, Rust NIF arkworks)">>,
                  group => groth16,
                  run =>
                    {
                      fun({A1, B1, Gam1, D1, IC1, In1, PA, PB, PC}) ->
                        ecu_bn254_nif:groth16_verify(A1, B1, Gam1, D1, IC1, In1, PA, PB, PC)
                      end,
                      NifArgs
                    }
                }
              ];
            false ->
              []
          end,
        BNBaseBenches ++ BNNifBenches;
      _ ->
        []
    end,
  BLSBenches ++ BNBenches.

%% ===================================================================
%% Poseidon Hash (BLS12-381 and BN254)
%% ===================================================================

poseidon_benchmarks() ->
  A = 12345678901234567890,
  B = 98765432109876543210,
  BinA = <<A:256>>,
  BinB = <<B:256>>,
  In4 = [A, B, A + B, A * 2],
  InBin4 = [<<X:256>> || X <- In4],
  NifAvail =
    case code:ensure_loaded(ecu_poseidon_nif) of
      {module, ecu_poseidon_nif} ->
        erlang:function_exported(ecu_poseidon_nif, is_available, 0) andalso
          ecu_poseidon_nif:is_available();
      _ ->
        false
    end,

  Base = [
    #{
      id => poseidon_hash3_bls12_381,
      name => <<"Poseidon Hash3 (BLS12-381, Pure Erlang)">>,
      group => poseidon,
      run => {fun({X, Y}) -> ecu_poseidon:hash3(bls12_381, X, Y) end, {A, B}}
    },
    #{
      id => poseidon_hash3_bn254,
      name => <<"Poseidon Hash3 (BN254, Pure Erlang)">>,
      group => poseidon,
      run => {fun({X, Y}) -> ecu_poseidon:hash3(bn254, X, Y) end, {A, B}}
    },
    #{
      id => poseidon_hash_4_bls12_381,
      name => <<"Poseidon Hash 4-input (BLS12-381, Pure Erlang)">>,
      group => poseidon,
      run => {fun(In) -> ecu_poseidon:hash(bls12_381, In) end, In4}
    },
    #{
      id => poseidon_hash_4_bn254,
      name => <<"Poseidon Hash 4-input (BN254, Pure Erlang)">>,
      group => poseidon,
      run => {fun(In) -> ecu_poseidon:hash(bn254, In) end, In4}
    }
  ],

  NifBenches =
    case NifAvail of
      true ->
        [
          #{
            id => poseidon_hash3_bls12_381_rust,
            name => <<"Poseidon Hash3 (BLS12-381, Rust NIF)">>,
            group => poseidon,
            run => {fun({X, Y}) -> ecu_poseidon_nif:hash3(bls12_381, X, Y) end, {BinA, BinB}}
          },
          #{
            id => poseidon_hash3_bn254_rust,
            name => <<"Poseidon Hash3 (BN254, Rust NIF light-poseidon)">>,
            group => poseidon,
            run => {fun({X, Y}) -> ecu_poseidon_nif:hash3(bn254, X, Y) end, {BinA, BinB}}
          },
          #{
            id => poseidon_hash_4_bls12_381_rust,
            name => <<"Poseidon Hash 4-input (BLS12-381, Rust NIF)">>,
            group => poseidon,
            run => {fun(In) -> ecu_poseidon_nif:hash(bls12_381, In) end, InBin4}
          },
          #{
            id => poseidon_hash_4_bn254_rust,
            name => <<"Poseidon Hash 4-input (BN254, Rust NIF light-poseidon)">>,
            group => poseidon,
            run => {fun(In) -> ecu_poseidon_nif:hash(bn254, In) end, InBin4}
          }
        ];
      false ->
        []
    end,

  Base ++ NifBenches.

%% ===================================================================
%% VRF (RFC 9381)
%% ===================================================================

vrf_benchmarks() ->
  case code:ensure_loaded(ecu_vrf) of
    {module, ecu_vrf} ->
      SK_Ed = <<1:256>>,
      PK_Ed_Ell2 = ecu_vrf:derive_public_key(edwards25519_sha512_ell2, SK_Ed),
      PK_Ed_Tai = ecu_vrf:derive_public_key(edwards25519_sha512_tai, SK_Ed),

      SK_Secp = <<1:256>>,
      PK_Secp = ecu_vrf:derive_public_key(secp256k1_sha256_tai, SK_Secp),

      Msg = <<"Verifiable Random Function non-random benchmark input message payload">>,

      {ok, Proof_Ed_Ell2} = ecu_vrf:prove(edwards25519_sha512_ell2, SK_Ed, Msg),
      {ok, Proof_Ed_Tai} = ecu_vrf:prove(edwards25519_sha512_tai, SK_Ed, Msg),
      {ok, Proof_Secp_Tai} = ecu_vrf:prove(secp256k1_sha256_tai, SK_Secp, Msg),
      {ok, Proof_Secp_Sswu} = ecu_vrf:prove(secp256k1_sha256_sswu, SK_Secp, Msg),

      Base = [
        #{
          id => vrf_prove_ed25519_ell2,
          name => <<"VRF Prove (Ed25519 Elligator 2)">>,
          group => vrf,
          run => {fun({S, K, M}) -> ecu_vrf:prove(S, K, M) end, {edwards25519_sha512_ell2, SK_Ed, Msg}}
        },
        #{
          id => vrf_verify_ed25519_ell2,
          name => <<"VRF Verify (Ed25519 Elligator 2)">>,
          group => vrf,
          run =>
            {
              fun({S, P, Pr, M}) -> ecu_vrf:verify(S, P, Pr, M) end,
              {edwards25519_sha512_ell2, PK_Ed_Ell2, Proof_Ed_Ell2, Msg}
            }
        },
        #{
          id => vrf_prove_ed25519_tai,
          name => <<"VRF Prove (Ed25519 Try-and-Increment)">>,
          group => vrf,
          run => {fun({S, K, M}) -> ecu_vrf:prove(S, K, M) end, {edwards25519_sha512_tai, SK_Ed, Msg}}
        },
        #{
          id => vrf_verify_ed25519_tai,
          name => <<"VRF Verify (Ed25519 Try-and-Increment)">>,
          group => vrf,
          run =>
            {
              fun({S, P, Pr, M}) -> ecu_vrf:verify(S, P, Pr, M) end,
              {edwards25519_sha512_tai, PK_Ed_Tai, Proof_Ed_Tai, Msg}
            }
        },
        #{
          id => vrf_prove_secp256k1_tai,
          name => <<"VRF Prove (secp256k1 Try-and-Increment)">>,
          group => vrf,
          run => {fun({S, K, M}) -> ecu_vrf:prove(S, K, M) end, {secp256k1_sha256_tai, SK_Secp, Msg}}
        },
        #{
          id => vrf_verify_secp256k1_tai,
          name => <<"VRF Verify (secp256k1 Try-and-Increment)">>,
          group => vrf,
          run =>
            {
              fun({S, P, Pr, M}) -> ecu_vrf:verify(S, P, Pr, M) end,
              {secp256k1_sha256_tai, PK_Secp, Proof_Secp_Tai, Msg}
            }
        },
        #{
          id => vrf_prove_secp256k1_sswu,
          name => <<"VRF Prove (secp256k1 Simplified SWU)">>,
          group => vrf,
          run => {fun({S, K, M}) -> ecu_vrf:prove(S, K, M) end, {secp256k1_sha256_sswu, SK_Secp, Msg}}
        },
        #{
          id => vrf_verify_secp256k1_sswu,
          name => <<"VRF Verify (secp256k1 Simplified SWU)">>,
          group => vrf,
          run =>
            {
              fun({S, P, Pr, M}) -> ecu_vrf:verify(S, P, Pr, M) end,
              {secp256k1_sha256_sswu, PK_Secp, Proof_Secp_Sswu, Msg}
            }
        }
      ],

      NifAvail =
        case code:ensure_loaded(ecu_vrf_nif) of
          {module, ecu_vrf_nif} ->
            erlang:function_exported(ecu_vrf_nif, is_available, 0) andalso
              ecu_vrf_nif:is_available();
          _ ->
            false
        end,

      NifBenches =
        case NifAvail of
          true ->
            [
              #{
                id => vrf_prove_ed25519_ell2_rust,
                name => <<"VRF Prove (Ed25519 Elligator 2) (Rust NIF)">>,
                group => vrf,
                run =>
                  {
                    fun({S, K, M}) -> ecu_vrf_nif:prove(S, K, M) end,
                    {edwards25519_sha512_ell2, SK_Ed, Msg}
                  }
              },
              #{
                id => vrf_verify_ed25519_ell2_rust,
                name => <<"VRF Verify (Ed25519 Elligator 2) (Rust NIF)">>,
                group => vrf,
                run =>
                  {
                    fun({S, P, Pr, M}) -> ecu_vrf_nif:verify(S, P, Pr, M) end,
                    {edwards25519_sha512_ell2, PK_Ed_Ell2, Proof_Ed_Ell2, Msg}
                  }
              },
              #{
                id => vrf_prove_ed25519_tai_rust,
                name => <<"VRF Prove (Ed25519 Try-and-Increment) (Rust NIF)">>,
                group => vrf,
                run =>
                  {
                    fun({S, K, M}) -> ecu_vrf_nif:prove(S, K, M) end,
                    {edwards25519_sha512_tai, SK_Ed, Msg}
                  }
              },
              #{
                id => vrf_verify_ed25519_tai_rust,
                name => <<"VRF Verify (Ed25519 Try-and-Increment) (Rust NIF)">>,
                group => vrf,
                run =>
                  {
                    fun({S, P, Pr, M}) -> ecu_vrf_nif:verify(S, P, Pr, M) end,
                    {edwards25519_sha512_tai, PK_Ed_Tai, Proof_Ed_Tai, Msg}
                  }
              },
              #{
                id => vrf_prove_secp256k1_tai_rust,
                name => <<"VRF Prove (secp256k1 Try-and-Increment) (Rust NIF)">>,
                group => vrf,
                run =>
                  {
                    fun({S, K, M}) -> ecu_vrf_nif:prove(S, K, M) end,
                    {secp256k1_sha256_tai, SK_Secp, Msg}
                  }
              },
              #{
                id => vrf_verify_secp256k1_tai_rust,
                name => <<"VRF Verify (secp256k1 Try-and-Increment) (Rust NIF)">>,
                group => vrf,
                run =>
                  {
                    fun({S, P, Pr, M}) -> ecu_vrf_nif:verify(S, P, Pr, M) end,
                    {secp256k1_sha256_tai, PK_Secp, Proof_Secp_Tai, Msg}
                  }
              }
            ];
          false ->
            []
        end,
      Base ++ NifBenches;
    _ ->
      []
  end.

%% ===================================================================
%% BabyJubjub
%% ===================================================================

babyjubjub_benchmarks() ->
  case code:ensure_loaded(ecu_babyjubjub) of
    {module, ecu_babyjubjub} ->
      SK =
        <<0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
          1>>,
      P1 = ecu_babyjubjub:base8(),
      P2 = ecu_babyjubjub:double(P1),
      P1Comp = ecu_babyjubjub:compress(P1),
      P2Comp = ecu_babyjubjub:compress(P2),
      Scalar = 12345678901234567890,
      ScalarBE = <<Scalar:256/big>>,
      Msg = 987654321012345,
      MsgBE = <<Msg:256/big>>,
      PK = ecu_babyjubjub:derive_public_key(SK),
      Sig = ecu_babyjubjub:sign(SK, Msg),

      Base = [
        #{
          id => babyjubjub_point_add,
          name => <<"BabyJubjub Point Addition">>,
          group => babyjubjub,
          run => {fun({A, B}) -> ecu_babyjubjub:add(A, B) end, {P1, P2}}
        },
        #{
          id => babyjubjub_scalar_mul,
          name => <<"BabyJubjub Scalar Multiplication">>,
          group => babyjubjub,
          run => {fun({P, K}) -> ecu_babyjubjub:mul(P, K) end, {P1, Scalar}}
        },
        #{
          id => babyjubjub_compress,
          name => <<"BabyJubjub Point Compress">>,
          group => babyjubjub,
          run => {fun(P) -> ecu_babyjubjub:compress(P) end, P1}
        },
        #{
          id => babyjubjub_decompress,
          name => <<"BabyJubjub Point Decompress">>,
          group => babyjubjub,
          run => {fun(C) -> ecu_babyjubjub:decompress(C) end, P1Comp}
        },
        #{
          id => babyjubjub_eddsa_sign,
          name => <<"BabyJubjub EdDSA Sign (Poseidon)">>,
          group => babyjubjub,
          run => {fun({K, M}) -> ecu_babyjubjub:sign(K, M) end, {SK, Msg}}
        },
        #{
          id => babyjubjub_eddsa_verify,
          name => <<"BabyJubjub EdDSA Verify (Poseidon)">>,
          group => babyjubjub,
          run => {fun({P, S, M}) -> ecu_babyjubjub:verify(P, S, M) end, {PK, Sig, Msg}}
        }
      ],

      NifAvail =
        case code:ensure_loaded(ecu_babyjubjub_nif) of
          {module, ecu_babyjubjub_nif} ->
            erlang:function_exported(ecu_babyjubjub_nif, is_available, 0) andalso
              ecu_babyjubjub_nif:is_available();
          _ ->
            false
        end,

      NifBenches =
        case NifAvail of
          true ->
            [
              #{
                id => babyjubjub_point_add_rust,
                name => <<"BabyJubjub Point Addition (Rust NIF)">>,
                group => babyjubjub,
                run => {fun({A, B}) -> ecu_babyjubjub_nif:point_add(A, B) end, {P1Comp, P2Comp}}
              },
              #{
                id => babyjubjub_scalar_mul_rust,
                name => <<"BabyJubjub Scalar Multiplication (Rust NIF)">>,
                group => babyjubjub,
                run => {fun({P, K}) -> ecu_babyjubjub_nif:point_mul(P, K) end, {P1Comp, ScalarBE}}
              },
              #{
                id => babyjubjub_decompress_rust,
                name => <<"BabyJubjub Point Decompress (Rust NIF)">>,
                group => babyjubjub,
                run => {fun(C) -> ecu_babyjubjub_nif:decompress_point(C) end, P1Comp}
              },
              #{
                id => babyjubjub_eddsa_sign_rust,
                name => <<"BabyJubjub EdDSA Sign (Poseidon) (Rust NIF)">>,
                group => babyjubjub,
                run => {fun({K, M}) -> ecu_babyjubjub_nif:eddsa_sign(K, M) end, {SK, MsgBE}}
              },
              #{
                id => babyjubjub_eddsa_verify_rust,
                name => <<"BabyJubjub EdDSA Verify (Poseidon) (Rust NIF)">>,
                group => babyjubjub,
                run => {fun({P, S, M}) -> ecu_babyjubjub_nif:eddsa_verify(P, S, M) end, {PK, Sig, MsgBE}}
              }
            ];
          false ->
            []
        end,
      Base ++ NifBenches;
    _ ->
      []
  end.

%% ===================================================================
%% KZG Polynomial Commitments & EIP-4844
%% ===================================================================

kzg_benchmarks() ->
  case code:ensure_loaded(ecu_kzg) of
    {module, ecu_kzg} ->
      SecretTau = 1234567890987654321,
      SRS = ecu_kzg:setup(16, SecretTau),
      Poly = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
      Z = 12345,
      C = ecu_kzg:commit(SRS, Poly),
      CompC = ecu_kzg:commit_compressed(SRS, Poly),
      {Proof, Y} = ecu_kzg:create_proof(SRS, Poly, Z),
      CompProof = ecu_bls12_381:g1_compress(Proof),

      BatchTuples =
        lists:map(
          fun(I) ->
            P = [I, I * 2, I * 3, I * 4, I * 5, I * 6, I * 7, I * 8],
            Comm = ecu_kzg:commit(SRS, P),
            PtZ = I * 100 + 7,
            {Prf, ValY} = ecu_kzg:create_proof(SRS, P, PtZ),
            {Comm, PtZ, ValY, Prf}
          end,
          [1, 2, 3, 4]
        ),

      Sha = ecu_compat:hash(sha256, CompC),
      <<_:8, RestSha:31/binary>> = Sha,
      VersionedHash = <<16#01:8, RestSha:31/binary>>,
      Eip4844Input =
        <<VersionedHash:32/binary, Z:256/big, Y:256/big, CompC:48/binary, CompProof:48/binary>>,

      Base = [
        #{
          id => poly_eval,
          name => <<"Polynomial Evaluation (deg 16, Horner)">>,
          group => kzg,
          run => {fun({P, X}) -> ecu_poly:eval(P, X) end, {Poly, Z}}
        },
        #{
          id => poly_divide_linear,
          name => <<"Polynomial Synthetic Division (deg 16, Ruffini)">>,
          group => kzg,
          run => {fun({P, X}) -> ecu_poly:divide_by_linear(P, X) end, {Poly, Z}}
        },
        #{
          id => kzg_commit,
          name => <<"KZG Commitment (deg 16, G1)">>,
          group => kzg,
          run => {fun({S, P}) -> ecu_kzg:commit(S, P) end, {SRS, Poly}}
        },
        #{
          id => kzg_create_proof,
          name => <<"KZG Proof Creation (deg 16)">>,
          group => kzg,
          run => {fun({S, P, Pt}) -> ecu_kzg:create_proof(S, P, Pt) end, {SRS, Poly, Z}}
        },
        #{
          id => kzg_verify,
          name => <<"KZG Proof Verification (Pure Erlang)">>,
          group => kzg,
          run =>
            {
              fun({S, Comm, Pt, Val, Prf}) -> ecu_kzg:verify(S, Comm, Pt, Val, Prf) end,
              {SRS, C, Z, Y, Proof}
            }
        },
        #{
          id => kzg_verify_batch,
          name => <<"KZG Batch Verification (4 proofs, Pure Erlang)">>,
          group => kzg,
          run => {fun({S, Tuples}) -> ecu_kzg:verify_batch(S, Tuples) end, {SRS, BatchTuples}}
        },
        #{
          id => kzg_eip4844_point_eval,
          name => <<"EIP-4844 Point Evaluation (192 bytes, Pure Erlang)">>,
          group => kzg,
          run => {fun({S, In}) -> ecu_kzg:point_evaluation(S, In) end, {SRS, Eip4844Input}}
        }
      ],

      NifAvail =
        case code:ensure_loaded(ecu_bls12_381_nif) of
          {module, ecu_bls12_381_nif} ->
            erlang:function_exported(ecu_bls12_381_nif, is_available, 0) andalso
              ecu_bls12_381_nif:is_available() andalso
              erlang:function_exported(ecu_bls12_381_nif, kzg_verify, 6);
          _ ->
            false
        end,

      NifBenches =
        case NifAvail of
          true ->
            [G2Gen, TauG2] = ecu_kzg:srs_g2(SRS),
            CompG2Gen = ecu_bls12_381:g2_compress(G2Gen),
            CompTauG2 = ecu_bls12_381:g2_compress(TauG2),
            ZBin = <<Z:256/big>>,
            YBin = <<Y:256/big>>,
            G1Bins = [ecu_bls12_381:g1_compress(Pt) || Pt <- ecu_kzg:srs_g1(SRS)],
            PolyBins = [<<Coeff:256/big>> || Coeff <- Poly],
            BatchTuplesBin =
              [
                {
                  ecu_bls12_381:g1_compress(Comm),
                  <<PtZ:256/big>>,
                  <<ValY:256/big>>,
                  ecu_bls12_381:g1_compress(Prf)
                }
               || {Comm, PtZ, ValY, Prf} <- BatchTuples
              ],
            CommitBenches =
              case erlang:function_exported(ecu_bls12_381_nif, kzg_commit, 2) of
                true ->
                  [
                    #{
                      id => kzg_commit_rust,
                      name => <<"KZG Commitment (deg 16, Rust blst NIF)">>,
                      group => kzg,
                      run =>
                        {
                          fun({Points, Scalars}) ->
                            ecu_bls12_381_nif:kzg_commit(Points, Scalars)
                          end,
                          {G1Bins, PolyBins}
                        }
                    }
                  ];
                false ->
                  []
              end,
            ProofBenches =
              case erlang:function_exported(ecu_bls12_381_nif, kzg_create_proof, 3) of
                true ->
                  [
                    #{
                      id => kzg_create_proof_rust,
                      name => <<"KZG Proof Creation (deg 16, Rust blst NIF)">>,
                      group => kzg,
                      run =>
                        {
                          fun({Points, Scalars, Pt}) ->
                            ecu_bls12_381_nif:kzg_create_proof(Points, Scalars, Pt)
                          end,
                          {G1Bins, PolyBins, ZBin}
                        }
                    }
                  ];
                false ->
                  []
              end,
            BatchBenches =
              case erlang:function_exported(ecu_bls12_381_nif, kzg_batch_verify, 3) of
                true ->
                  [
                    #{
                      id => kzg_verify_batch_rust,
                      name => <<"KZG Batch Verification (4 proofs, Rust blst NIF)">>,
                      group => kzg,
                      run =>
                        {
                          fun({Tuples, G2G, TauG}) ->
                            ecu_bls12_381_nif:kzg_batch_verify(Tuples, G2G, TauG)
                          end,
                          {BatchTuplesBin, CompG2Gen, CompTauG2}
                        }
                    }
                  ];
                false ->
                  []
              end,
            PointEvalBenches =
              case erlang:function_exported(ecu_bls12_381_nif, kzg_eip4844_point_eval, 3) of
                true ->
                  [
                    #{
                      id => kzg_eip4844_point_eval_rust,
                      name => <<"EIP-4844 Point Evaluation (192 bytes, Rust blst NIF)">>,
                      group => kzg,
                      run =>
                        {
                          fun({Input, G2G, TauG}) ->
                            ecu_bls12_381_nif:kzg_eip4844_point_eval(Input, G2G, TauG)
                          end,
                          {Eip4844Input, CompG2Gen, CompTauG2}
                        }
                    }
                  ];
                false ->
                  []
              end,
            CommitBenches ++
              ProofBenches ++
              [
                #{
                  id => kzg_verify_rust,
                  name => <<"KZG Proof Verification (Rust blst NIF)">>,
                  group => kzg,
                  run =>
                    {
                      fun({Comm, Pt, Val, Prf, G2G, TauG}) ->
                        ecu_bls12_381_nif:kzg_verify(Comm, Pt, Val, Prf, G2G, TauG)
                      end,
                      {CompC, ZBin, YBin, CompProof, CompG2Gen, CompTauG2}
                    }
                }
              ] ++
              BatchBenches ++
              PointEvalBenches;
          false ->
            []
        end,
      Base ++ NifBenches;
    _ ->
      []
  end.

%% ===================================================================
%% Circom R1CS & WTNS Tooling
%% ===================================================================

circom_benchmarks() ->
  case code:ensure_loaded(ecu_circom) of
    {module, ecu_circom} ->
      Prime = ecu_circom:default_prime(bn254),
      NGates = 100,
      {R1CS, WTNS} = create_bench_circom_circuit(NGates, Prime),
      R1CSBin = ecu_circom:serialize_r1cs(R1CS),
      WTNSBin = ecu_circom:serialize_wtns(WTNS),
      Base = [
        #{
          id => circom_r1cs_parse,
          name => <<"Circom R1CS Parse (100 constraints, pure Erlang)">>,
          group => circom,
          run => {fun(Bin) -> ecu_circom:parse_r1cs(Bin) end, R1CSBin}
        },
        #{
          id => circom_r1cs_serialize,
          name => <<"Circom R1CS Serialize (100 constraints, pure Erlang)">>,
          group => circom,
          run => {fun(R) -> ecu_circom:serialize_r1cs(R) end, R1CS}
        },
        #{
          id => circom_wtns_parse,
          name => <<"Circom WTNS Parse (104 wires, pure Erlang)">>,
          group => circom,
          run => {fun(Bin) -> ecu_circom:parse_wtns(Bin) end, WTNSBin}
        },
        #{
          id => circom_wtns_serialize,
          name => <<"Circom WTNS Serialize (104 wires, pure Erlang)">>,
          group => circom,
          run => {fun(W) -> ecu_circom:serialize_wtns(W) end, WTNS}
        },
        #{
          id => circom_check_constraints,
          name => <<"Circom Check Constraints (100 constraints, pure Erlang)">>,
          group => circom,
          run => {fun({R, W}) -> ecu_circom:check_constraints(R, W) end, {R1CS, WTNS}}
        }
      ],
      NifBenches =
        case code:ensure_loaded(ecu_circom_nif) of
          {module, ecu_circom_nif} ->
            case ecu_circom_nif:is_available() of
              true ->
                [
                  #{
                    id => circom_r1cs_parse_rust,
                    name => <<"Circom R1CS Parse (100 constraints, Rust r1cs-file NIF)">>,
                    group => circom,
                    run => {fun(Bin) -> ecu_circom_nif:r1cs_info(Bin) end, R1CSBin}
                  },
                  #{
                    id => circom_r1cs_roundtrip_rust,
                    name => <<"Circom R1CS Roundtrip (100 constraints, Rust r1cs-file NIF)">>,
                    group => circom,
                    run => {fun(Bin) -> ecu_circom_nif:r1cs_roundtrip(Bin) end, R1CSBin}
                  },
                  #{
                    id => circom_wtns_parse_rust,
                    name => <<"Circom WTNS Parse (104 wires, Rust wtns-file NIF)">>,
                    group => circom,
                    run => {fun(Bin) -> ecu_circom_nif:wtns_info(Bin) end, WTNSBin}
                  },
                  #{
                    id => circom_wtns_roundtrip_rust,
                    name => <<"Circom WTNS Roundtrip (104 wires, Rust wtns-file NIF)">>,
                    group => circom,
                    run => {fun(Bin) -> ecu_circom_nif:wtns_roundtrip(Bin) end, WTNSBin}
                  },
                  #{
                    id => circom_check_constraints_rust,
                    name => <<"Circom Check Constraints (100 constraints, Rust NIF)">>,
                    group => circom,
                    run =>
                      {
                        fun({RBin, WBin}) ->
                          ecu_circom_nif:check_constraints(RBin, WBin)
                        end,
                        {R1CSBin, WTNSBin}
                      }
                  }
                ];
              false ->
                []
            end;
          _ ->
            []
        end,
      Base ++ NifBenches;
    _ ->
      []
  end.

create_bench_circom_circuit(NGates, Prime) ->
  Inputs = [2, 3, 5],
  InitialWitness = [1 | Inputs],
  build_bench_gates(NGates, InitialWitness, [], Prime).

build_bench_gates(0, Witness, Constraints, Prime) ->
  NWires = length(Witness),
  Header = #{
    field_size => 32,
    prime => Prime,
    n_wires => NWires,
    n_pub_out => 1,
    n_pub_in => 2,
    n_prvt_in => 1,
    n_labels => NWires,
    n_constraints => length(Constraints)
  },
  R1CS = ecu_circom:new_r1cs(Header, lists:reverse(Constraints)),
  WTNS = ecu_circom:new_wtns(Witness, Prime, 32),
  {R1CS, WTNS};
build_bench_gates(Remaining, Witness, Constraints, Prime) ->
  WireA = (length(Witness) - 1) rem length(Witness),
  WireB = (length(Witness) - 2) rem length(Witness),
  ValA = lists:nth(WireA + 1, Witness),
  ValB = lists:nth(WireB + 1, Witness),
  OutWire = length(Witness),
  OutVal = (ValA * ValB + 1) rem Prime,
  NewWitness = Witness ++ [OutVal],
  NewConstraint = {
    [{WireA, 1}],
    [{WireB, 1}],
    [{OutWire, 1}, {0, -1}]
  },
  build_bench_gates(Remaining - 1, NewWitness, [NewConstraint | Constraints], Prime).
