%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang implementation of SLH-DSA (NIST FIPS 205).
%%%
%%% Stateless Hash-Based Digital Signature Standard (SLH-DSA), standardized
%%% in NIST FIPS 205 (August 2024), based on the SPHINCS+ signature scheme.
%%%
%%% Supported parameter sets (all 12 FIPS 205 parameter sets):
%%%   - `slh_dsa_shake_128s', `slh_dsa_shake_128f' (Security Category 1)
%%%   - `slh_dsa_shake_192s', `slh_dsa_shake_192f' (Security Category 3)
%%%   - `slh_dsa_shake_256s', `slh_dsa_shake_256f' (Security Category 5)
%%%   - `slh_dsa_sha2_128s', `slh_dsa_sha2_128f'   (Security Category 1)
%%%   - `slh_dsa_sha2_192s', `slh_dsa_sha2_192f'   (Security Category 3)
%%%   - `slh_dsa_sha2_256s', `slh_dsa_sha2_256f'   (Security Category 5)
%%%
%%% Provides key generation (`keypair/1', `keypair_from_seed/2'), randomized
%%% signing (`sign/2,3,4'), deterministic signing (`sign_deterministic/2,3,4'),
%%% and verification (`verify/3,4,5') with zero external C/NIF dependencies.
%%%
%%% Performance Note:
%%%   SLH-DSA signing evaluates ~80,000 hash invocations per signature. In pure Erlang,
%%%   SHA-2 parameter sets (e.g. `slh_dsa_sha2_128f' ~346 ms) are ~24x faster than SHAKE
%%%   parameter sets (`slh_dsa_shake_128f' ~8.20 s). Keccak-f[1600] maps unfavorably to BEAM
%%%   scalar registers because 64-bit uint operations exceed BEAM's 60-bit smallint range and
%%%   lack hardware SIMD vectorization. In contrast, native reference implementations (e.g.
%%%   OpenSSL) achieve ~27 ms signing via multi-buffer Keccak SIMD (AVX2/AVX-512) evaluating
%%%   4–8 tree leaves concurrently. For pure-Erlang workloads, SHA-2 parameter sets are strongly
%%%   recommended.
%%%
%%% Reference:
%%%   NIST FIPS 205: Stateless Hash-Based Digital Signature Standard (August 2024)
%%%   https://doi.org/10.6028/NIST.FIPS.205
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_slh_dsa).

-typing([eqwalizer]).

-include("ecu_slh_dsa.hrl").

-export([
  keypair/1,
  keypair_from_seed/2,
  keypair_from_seeds/4,
  sign/2,
  sign/3,
  sign/4,
  sign_deterministic/2,
  sign_deterministic/3,
  sign_deterministic/4,
  verify/3,
  verify/4,
  verify/5,
  parameter_set/1
]).

-export_type([
  parameter_set/0,
  keypair/0
]).

-type parameter_set() ::
  slh_dsa_shake_128s
  | slh_dsa_shake_128f
  | slh_dsa_shake_192s
  | slh_dsa_shake_192f
  | slh_dsa_shake_256s
  | slh_dsa_shake_256f
  | slh_dsa_sha2_128s
  | slh_dsa_sha2_128f
  | slh_dsa_sha2_192s
  | slh_dsa_sha2_192f
  | slh_dsa_sha2_256s
  | slh_dsa_sha2_256f.

-type keypair() :: #{
  param := parameter_set(),
  public := binary(),
  secret := binary()
}.

-type adrs() :: binary().
-type slh_params() :: #slh_params{}.

%%%===================================================================
%%% Parameter Sets (FIPS 205 Table 2)
%%%===================================================================

-spec parameter_set(atom()) -> slh_params().
parameter_set(slh_dsa_shake_128s) ->
  #slh_params{
    name = slh_dsa_shake_128s,
    hash = shake,
    n = 16,
    h = 63,
    d = 7,
    hp = 9,
    a = 12,
    k = 14,
    len1 = 32,
    len = 35,
    pk_bytes = 32,
    sk_bytes = 64,
    sig_bytes = 7856,
    m = 30,
    m_md = 21,
    m_tree = 7,
    m_leaf = 2
  };
parameter_set(slh_dsa_shake_128f) ->
  #slh_params{
    name = slh_dsa_shake_128f,
    hash = shake,
    n = 16,
    h = 66,
    d = 22,
    hp = 3,
    a = 6,
    k = 33,
    len1 = 32,
    len = 35,
    pk_bytes = 32,
    sk_bytes = 64,
    sig_bytes = 17088,
    m = 34,
    m_md = 25,
    m_tree = 8,
    m_leaf = 1
  };
parameter_set(slh_dsa_shake_192s) ->
  #slh_params{
    name = slh_dsa_shake_192s,
    hash = shake,
    n = 24,
    h = 63,
    d = 7,
    hp = 9,
    a = 14,
    k = 17,
    len1 = 48,
    len = 51,
    pk_bytes = 48,
    sk_bytes = 96,
    sig_bytes = 16224,
    m = 39,
    m_md = 30,
    m_tree = 7,
    m_leaf = 2
  };
parameter_set(slh_dsa_shake_192f) ->
  #slh_params{
    name = slh_dsa_shake_192f,
    hash = shake,
    n = 24,
    h = 66,
    d = 22,
    hp = 3,
    a = 8,
    k = 33,
    len1 = 48,
    len = 51,
    pk_bytes = 48,
    sk_bytes = 96,
    sig_bytes = 35664,
    m = 42,
    m_md = 33,
    m_tree = 8,
    m_leaf = 1
  };
parameter_set(slh_dsa_shake_256s) ->
  #slh_params{
    name = slh_dsa_shake_256s,
    hash = shake,
    n = 32,
    h = 64,
    d = 8,
    hp = 8,
    a = 14,
    k = 22,
    len1 = 64,
    len = 67,
    pk_bytes = 64,
    sk_bytes = 128,
    sig_bytes = 29792,
    m = 47,
    m_md = 39,
    m_tree = 7,
    m_leaf = 1
  };
parameter_set(slh_dsa_shake_256f) ->
  #slh_params{
    name = slh_dsa_shake_256f,
    hash = shake,
    n = 32,
    h = 68,
    d = 17,
    hp = 4,
    a = 9,
    k = 35,
    len1 = 64,
    len = 67,
    pk_bytes = 64,
    sk_bytes = 128,
    sig_bytes = 49856,
    m = 49,
    m_md = 40,
    m_tree = 8,
    m_leaf = 1
  };
parameter_set(slh_dsa_sha2_128s) ->
  #slh_params{
    name = slh_dsa_sha2_128s,
    hash = sha2,
    n = 16,
    h = 63,
    d = 7,
    hp = 9,
    a = 12,
    k = 14,
    len1 = 32,
    len = 35,
    pk_bytes = 32,
    sk_bytes = 64,
    sig_bytes = 7856,
    m = 30,
    m_md = 21,
    m_tree = 7,
    m_leaf = 2
  };
parameter_set(slh_dsa_sha2_128f) ->
  #slh_params{
    name = slh_dsa_sha2_128f,
    hash = sha2,
    n = 16,
    h = 66,
    d = 22,
    hp = 3,
    a = 6,
    k = 33,
    len1 = 32,
    len = 35,
    pk_bytes = 32,
    sk_bytes = 64,
    sig_bytes = 17088,
    m = 34,
    m_md = 25,
    m_tree = 8,
    m_leaf = 1
  };
parameter_set(slh_dsa_sha2_192s) ->
  #slh_params{
    name = slh_dsa_sha2_192s,
    hash = sha2,
    n = 24,
    h = 63,
    d = 7,
    hp = 9,
    a = 14,
    k = 17,
    len1 = 48,
    len = 51,
    pk_bytes = 48,
    sk_bytes = 96,
    sig_bytes = 16224,
    m = 39,
    m_md = 30,
    m_tree = 7,
    m_leaf = 2
  };
parameter_set(slh_dsa_sha2_192f) ->
  #slh_params{
    name = slh_dsa_sha2_192f,
    hash = sha2,
    n = 24,
    h = 66,
    d = 22,
    hp = 3,
    a = 8,
    k = 33,
    len1 = 48,
    len = 51,
    pk_bytes = 48,
    sk_bytes = 96,
    sig_bytes = 35664,
    m = 42,
    m_md = 33,
    m_tree = 8,
    m_leaf = 1
  };
parameter_set(slh_dsa_sha2_256s) ->
  #slh_params{
    name = slh_dsa_sha2_256s,
    hash = sha2,
    n = 32,
    h = 64,
    d = 8,
    hp = 8,
    a = 14,
    k = 22,
    len1 = 64,
    len = 67,
    pk_bytes = 64,
    sk_bytes = 128,
    sig_bytes = 29792,
    m = 47,
    m_md = 39,
    m_tree = 7,
    m_leaf = 1
  };
parameter_set(slh_dsa_sha2_256f) ->
  #slh_params{
    name = slh_dsa_sha2_256f,
    hash = sha2,
    n = 32,
    h = 68,
    d = 17,
    hp = 4,
    a = 9,
    k = 35,
    len1 = 64,
    len = 67,
    pk_bytes = 64,
    sk_bytes = 128,
    sig_bytes = 49856,
    m = 49,
    m_md = 40,
    m_tree = 8,
    m_leaf = 1
  };
parameter_set(Other) when is_atom(Other) ->
  error({unknown_parameter_set, Other}).

%%%===================================================================
%%% Key Generation (FIPS 205 Algorithm 18 / 21)
%%%===================================================================

-spec keypair(parameter_set()) -> keypair().
keypair(ParamSet) ->
  #slh_params{n = N} = Params = parameter_set(ParamSet),
  SKSeed = ecu_compat:strong_rand_bytes(N),
  SKPrf = ecu_compat:strong_rand_bytes(N),
  PKSeed = ecu_compat:strong_rand_bytes(N),
  keypair_from_seeds_internal(Params, SKSeed, SKPrf, PKSeed).

-spec keypair_from_seed(parameter_set(), binary()) -> keypair().
keypair_from_seed(ParamSet, Seed) when is_binary(Seed) ->
  #slh_params{n = N} = Params = parameter_set(ParamSet),
  SeedLen = 3 * N,
  case Seed of
    <<SKSeed:N/binary, SKPrf:N/binary, PKSeed:N/binary>> when byte_size(Seed) =:= SeedLen ->
      keypair_from_seeds_internal(Params, SKSeed, SKPrf, PKSeed);
    _ ->
      error({invalid_seed_length, byte_size(Seed), expected, SeedLen})
  end.

-spec keypair_from_seeds(parameter_set(), binary(), binary(), binary()) -> keypair().
keypair_from_seeds(ParamSet, SKSeed, SKPrf, PKSeed) when
  is_binary(SKSeed), is_binary(SKPrf), is_binary(PKSeed)
->
  #slh_params{n = N} = Params = parameter_set(ParamSet),
  if
    byte_size(SKSeed) =:= N, byte_size(SKPrf) =:= N, byte_size(PKSeed) =:= N ->
      keypair_from_seeds_internal(Params, SKSeed, SKPrf, PKSeed);
    true ->
      error({invalid_seed_sizes, {byte_size(SKSeed), byte_size(SKPrf), byte_size(PKSeed)}, expected, N})
  end.

-spec keypair_from_seeds_internal(slh_params(), binary(), binary(), binary()) -> keypair().
keypair_from_seeds_internal(
  #slh_params{name = Name, n = N, d = D, hp = Hp} = Params, SKSeed, SKPrf, PKSeed
) ->
  ADRS0 = adrs_new(),
  ADRS1 = adrs_set_layer(D - 1, ADRS0),
  PKRoot = xmss_node(SKSeed, 0, Hp, PKSeed, ADRS1, Params),
  PK = <<PKSeed:N/binary, PKRoot:N/binary>>,
  SK = <<SKSeed:N/binary, SKPrf:N/binary, PKSeed:N/binary, PKRoot:N/binary>>,
  #{
    param => Name,
    public => PK,
    secret => SK
  }.

%%%===================================================================
%%% Signing (FIPS 205 Algorithm 19 / 22)
%%%===================================================================

-spec sign(binary(), keypair()) -> binary().
sign(Msg, #{param := ParamSet, secret := SK}) ->
  sign(ParamSet, Msg, SK, <<>>).

-spec sign(parameter_set(), binary(), binary()) -> binary().
sign(ParamSet, Msg, SK) when is_atom(ParamSet), is_binary(Msg), is_binary(SK) ->
  sign(ParamSet, Msg, SK, <<>>).

-spec sign(parameter_set(), binary(), binary(), binary()) -> binary().
sign(ParamSet, Msg, SK, Ctx) when
  is_atom(ParamSet), is_binary(Msg), is_binary(SK), is_binary(Ctx)
->
  #slh_params{n = N} = Params = parameter_set(ParamSet),
  if
    byte_size(Ctx) > 255 ->
      error({context_too_long, byte_size(Ctx)});
    true ->
      AddRnd = ecu_compat:strong_rand_bytes(N),
      Mprime = <<0:8, (byte_size(Ctx)):8, Ctx/binary, Msg/binary>>,
      slh_sign_internal(Mprime, SK, AddRnd, Params)
  end.

-spec sign_deterministic(binary(), keypair()) -> binary().
sign_deterministic(Msg, #{param := ParamSet, secret := SK}) ->
  sign_deterministic(ParamSet, Msg, SK, <<>>).

-spec sign_deterministic(parameter_set(), binary(), binary()) -> binary().
sign_deterministic(ParamSet, Msg, SK) when is_atom(ParamSet), is_binary(Msg), is_binary(SK) ->
  sign_deterministic(ParamSet, Msg, SK, <<>>).

-spec sign_deterministic(parameter_set(), binary(), binary(), binary()) -> binary().
sign_deterministic(ParamSet, Msg, SK, Ctx) when
  is_atom(ParamSet), is_binary(Msg), is_binary(SK), is_binary(Ctx)
->
  #slh_params{n = N} = Params = parameter_set(ParamSet),
  if
    byte_size(Ctx) > 255 ->
      error({context_too_long, byte_size(Ctx)});
    byte_size(SK) =/= 4 * N ->
      error({invalid_secret_key_length, byte_size(SK), expected, 4 * N});
    true ->
      <<_SKSeed:N/binary, _SKPrf:N/binary, PKSeed:N/binary, _PKRoot:N/binary>> = SK,
      Mprime = <<0:8, (byte_size(Ctx)):8, Ctx/binary, Msg/binary>>,
      slh_sign_internal(Mprime, SK, PKSeed, Params)
  end.

-spec slh_sign_internal(binary(), binary(), binary(), slh_params()) -> binary().
slh_sign_internal(
  Mprime,
  SK,
  AddRnd,
  #slh_params{n = N, h = H, hp = Hp, m_md = MMd, m_tree = MTree, m_leaf = MLeaf} = Params
) ->
  case SK of
    <<SKSeed:N/binary, SKPrf:N/binary, PKSeed:N/binary, PKRoot:N/binary>> ->
      R = prf_msg(SKPrf, AddRnd, Mprime, Params),
      Digest = h_msg(R, PKSeed, PKRoot, Mprime, Params),
      <<Md:MMd/binary, TmpTree:MTree/binary, TmpLeaf:MLeaf/binary>> = Digest,
      IdxTree = binary:decode_unsigned(TmpTree) band ((1 bsl (H - Hp)) - 1),
      IdxLeaf = binary:decode_unsigned(TmpLeaf) band ((1 bsl Hp) - 1),

      ADRS0 = adrs_new(),
      ADRS1 = adrs_set_tree(IdxTree, ADRS0),
      ADRS2 = adrs_set_type_and_clear(?SLH_ADRS_FORS_TREE, ADRS1),
      ADRS3 = adrs_set_keypair(IdxLeaf, ADRS2),
      SigFors = fors_sign(Md, SKSeed, PKSeed, ADRS3, Params),
      PkFors = fors_pkFromSig(SigFors, Md, PKSeed, ADRS3, Params),
      SigHT = ht_sign(PkFors, SKSeed, PKSeed, IdxTree, IdxLeaf, Params),
      <<R:N/binary, SigFors/binary, SigHT/binary>>;
    _ ->
      error({invalid_secret_key_length, byte_size(SK), expected, 4 * N})
  end.

%%%===================================================================
%%% Verification (FIPS 205 Algorithm 20 / 24)
%%%===================================================================

-spec verify(binary(), binary(), keypair()) -> boolean().
verify(Sig, Msg, #{param := ParamSet, public := PK}) ->
  verify(ParamSet, Sig, Msg, PK, <<>>).

-spec verify(parameter_set(), binary(), binary(), binary()) -> boolean().
verify(ParamSet, Sig, Msg, PK) ->
  verify(ParamSet, Sig, Msg, PK, <<>>).

-spec verify(parameter_set(), binary(), binary(), binary(), binary()) -> boolean().
verify(ParamSet, Sig, Msg, PK, Ctx) when
  is_atom(ParamSet), is_binary(Sig), is_binary(Msg), is_binary(PK), is_binary(Ctx)
->
  #slh_params{sig_bytes = SigLen, pk_bytes = PKLen} = Params = parameter_set(ParamSet),
  if
    byte_size(Ctx) > 255 ->
      false;
    byte_size(PK) =/= PKLen ->
      false;
    byte_size(Sig) =/= SigLen ->
      false;
    true ->
      Mprime = <<0:8, (byte_size(Ctx)):8, Ctx/binary, Msg/binary>>,
      slh_verify_internal(Mprime, Sig, PK, Params)
  end.

-spec slh_verify_internal(binary(), binary(), binary(), slh_params()) -> boolean().
slh_verify_internal(
  Mprime,
  Sig,
  PK,
  #slh_params{
    n = N,
    k = K,
    a = A,
    h = H,
    hp = Hp,
    len = Len,
    d = D,
    m_md = MMd,
    m_tree = MTree,
    m_leaf = MLeaf
  } = Params
) ->
  <<PKSeed:N/binary, PKRoot:N/binary>> = PK,
  ForsBytes = K * (A + 1) * N,
  HtBytes = D * (Len + Hp) * N,
  case Sig of
    <<R:N/binary, SigFors:ForsBytes/binary, SigHT:HtBytes/binary>> ->
      Digest = h_msg(R, PKSeed, PKRoot, Mprime, Params),
      <<Md:MMd/binary, TmpTree:MTree/binary, TmpLeaf:MLeaf/binary>> = Digest,
      IdxTree = binary:decode_unsigned(TmpTree) band ((1 bsl (H - Hp)) - 1),
      IdxLeaf = binary:decode_unsigned(TmpLeaf) band ((1 bsl Hp) - 1),

      ADRS0 = adrs_new(),
      ADRS1 = adrs_set_tree(IdxTree, ADRS0),
      ADRS2 = adrs_set_type_and_clear(?SLH_ADRS_FORS_TREE, ADRS1),
      ADRS3 = adrs_set_keypair(IdxLeaf, ADRS2),
      PkFors = fors_pkFromSig(SigFors, Md, PKSeed, ADRS3, Params),
      ht_verify(PkFors, SigHT, PKSeed, IdxTree, IdxLeaf, PKRoot, Params);
    _ ->
      false
  end.

%%%===================================================================
%%% WOTS+ (Winternitz One-Time Signatures, FIPS 205 Section 5)
%%%===================================================================

-spec wots_pkGen(binary(), binary(), adrs(), slh_params()) -> binary().
wots_pkGen(SKSeed, PKSeed, ADRS, #slh_params{len = Len, w = W} = Params) ->
  KP = adrs_get_keypair(ADRS),
  PrfADRS0 = adrs_set_type_and_clear(?SLH_ADRS_WOTS_PRF, ADRS),
  PrfADRS = adrs_set_keypair(KP, PrfADRS0),
  PkWots = [
    begin
      ChainADRS_prf = adrs_set_chain(I, PrfADRS),
      SkI = prf(PKSeed, SKSeed, ChainADRS_prf, Params),
      ChainADRS_hash = adrs_set_chain(I, ADRS),
      chain(SkI, 0, W - 1, PKSeed, ChainADRS_hash, Params)
    end
   || I <- lists:seq(0, Len - 1)
  ],
  PkBin = iolist_to_binary(PkWots),
  PkADRS0 = adrs_set_type_and_clear(?SLH_ADRS_WOTS_PK, ADRS),
  PkADRS = adrs_set_keypair(KP, PkADRS0),
  t_l(PKSeed, PkADRS, PkBin, Params).

-spec wots_sign(binary(), binary(), binary(), adrs(), slh_params()) -> binary().
wots_sign(M, SKSeed, PKSeed, ADRS, #slh_params{len = Len, w = W} = Params) ->
  AllDigits = wots_message_digits(M, W),
  KP = adrs_get_keypair(ADRS),
  PrfADRS0 = adrs_set_type_and_clear(?SLH_ADRS_WOTS_PRF, ADRS),
  PrfADRS = adrs_set_keypair(KP, PrfADRS0),
  SigChains = [
    begin
      ChainADRS_prf = adrs_set_chain(I, PrfADRS),
      SkI = prf(PKSeed, SKSeed, ChainADRS_prf, Params),
      ChainADRS_hash = adrs_set_chain(I, ADRS),
      chain(SkI, 0, Digit, PKSeed, ChainADRS_hash, Params)
    end
   || {I, Digit} <- lists:zip(lists:seq(0, Len - 1), AllDigits)
  ],
  iolist_to_binary(SigChains).

-spec wots_pkFromSig(binary(), binary(), binary(), adrs(), slh_params()) -> binary().
wots_pkFromSig(Sig, M, PKSeed, ADRS, #slh_params{n = N, len = Len, w = W} = Params) ->
  AllDigits = wots_message_digits(M, W),
  KP = adrs_get_keypair(ADRS),
  PkWots = [
    begin
      <<_:(I * N)/binary, SigI:N/binary, _/binary>> = Sig,
      ChainADRS = adrs_set_chain(I, ADRS),
      chain(SigI, Digit, W - 1 - Digit, PKSeed, ChainADRS, Params)
    end
   || {I, Digit} <- lists:zip(lists:seq(0, Len - 1), AllDigits)
  ],
  PkBin = iolist_to_binary(PkWots),
  PkADRS0 = adrs_set_type_and_clear(?SLH_ADRS_WOTS_PK, ADRS),
  PkADRS = adrs_set_keypair(KP, PkADRS0),
  t_l(PKSeed, PkADRS, PkBin, Params).

-spec wots_message_digits(binary(), pos_integer()) -> [non_neg_integer()].
wots_message_digits(M, W) ->
  MsgDigits = [Digit || <<Digit:4>> <= M],
  Csum = lists:sum([W - 1 - D || D <- MsgDigits]),
  <<C0:4, C1:4, C2:4, _:4>> = <<(Csum bsl 4):16>>,
  MsgDigits ++ [C0, C1, C2].

-spec chain(binary(), non_neg_integer(), non_neg_integer(), binary(), adrs(), slh_params()) -> binary().
chain(X, _I, 0, _PKSeed, _ADRS, _Params) ->
  X;
chain(X, I, S, PKSeed, ADRS, Params) ->
  chain_loop(X, I, S, PKSeed, ADRS, Params).

-spec chain_loop(binary(), non_neg_integer(), non_neg_integer(), binary(), adrs(), slh_params()) ->
  binary().
chain_loop(X, _I, 0, _PKSeed, _ADRS, _Params) ->
  X;
chain_loop(X, I, S, PKSeed, ADRS, Params) ->
  ADRS1 = adrs_set_hash(I, ADRS),
  Step = f(PKSeed, ADRS1, X, Params),
  chain_loop(Step, I + 1, S - 1, PKSeed, ADRS, Params).

%%%===================================================================
%%% XMSS (eXtended Merkle Signature Scheme, FIPS 205 Section 6)
%%%===================================================================

-spec xmss_node(binary(), non_neg_integer(), non_neg_integer(), binary(), adrs(), slh_params()) ->
  binary().
xmss_node(SKSeed, I, 0, PKSeed, ADRS, Params) ->
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_WOTS_HASH, ADRS),
  ADRS2 = adrs_set_keypair(I, ADRS1),
  wots_pkGen(SKSeed, PKSeed, ADRS2, Params);
xmss_node(SKSeed, I, Z, PKSeed, ADRS, Params) ->
  LNode = xmss_node(SKSeed, 2 * I, Z - 1, PKSeed, ADRS, Params),
  RNode = xmss_node(SKSeed, 2 * I + 1, Z - 1, PKSeed, ADRS, Params),
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_TREE, ADRS),
  ADRS2 = adrs_set_tree_height(Z, ADRS1),
  ADRS3 = adrs_set_tree_index(I, ADRS2),
  h(PKSeed, ADRS3, <<LNode/binary, RNode/binary>>, Params).

-spec xmss_sign(binary(), binary(), non_neg_integer(), binary(), adrs(), slh_params()) -> binary().
xmss_sign(M, SKSeed, Idx, PKSeed, ADRS, #slh_params{hp = Hp} = Params) ->
  Auth = [
    begin
      K = (Idx bsr J) bxor 1,
      xmss_node(SKSeed, K, J, PKSeed, ADRS, Params)
    end
   || J <- lists:seq(0, Hp - 1)
  ],
  AuthBin = iolist_to_binary(Auth),
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_WOTS_HASH, ADRS),
  ADRS2 = adrs_set_keypair(Idx, ADRS1),
  SigWots = wots_sign(M, SKSeed, PKSeed, ADRS2, Params),
  <<SigWots/binary, AuthBin/binary>>.

-spec xmss_pkFromSig(non_neg_integer(), binary(), binary(), binary(), adrs(), slh_params()) -> binary().
xmss_pkFromSig(Idx, SigXMSS, M, PKSeed, ADRS, #slh_params{n = N, len = Len, hp = Hp} = Params) ->
  WotsBytes = Len * N,
  <<SigWots:WotsBytes/binary, AuthBin/binary>> = SigXMSS,
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_WOTS_HASH, ADRS),
  ADRS2 = adrs_set_keypair(Idx, ADRS1),
  Node0 = wots_pkFromSig(SigWots, M, PKSeed, ADRS2, Params),
  xmss_auth_path(0, Hp, Idx, Node0, AuthBin, PKSeed, ADRS, Params).

-spec xmss_auth_path(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  binary(),
  binary(),
  binary(),
  adrs(),
  slh_params()
) -> binary().
xmss_auth_path(J, Hp, _Idx, Node, <<>>, _PKSeed, _ADRS, _Params) when J =:= Hp ->
  Node;
xmss_auth_path(
  J,
  Hp,
  Idx,
  Node,
  AuthBin,
  PKSeed,
  ADRS,
  #slh_params{n = N} = Params
) ->
  <<AuthJ:N/binary, Rest/binary>> = AuthBin,
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_TREE, ADRS),
  ADRS2 = adrs_set_tree_height(J + 1, ADRS1),
  IsRight = (Idx bsr J) band 1,
  TreeIdx = Idx bsr (J + 1),
  ADRS3 = adrs_set_tree_index(TreeIdx, ADRS2),
  Combined =
    if
      IsRight =:= 0 -> <<Node/binary, AuthJ/binary>>;
      true -> <<AuthJ/binary, Node/binary>>
    end,
  Parent = h(PKSeed, ADRS3, Combined, Params),
  xmss_auth_path(J + 1, Hp, Idx, Parent, Rest, PKSeed, ADRS, Params).

%%%===================================================================
%%% Hypertree (FIPS 205 Section 7)
%%%===================================================================

-spec ht_sign(binary(), binary(), binary(), non_neg_integer(), non_neg_integer(), slh_params()) ->
  binary().
ht_sign(M, SKSeed, PKSeed, IdxTree0, IdxLeaf0, #slh_params{d = D} = Params) ->
  ADRS0 = adrs_new(),
  ADRS_l0 = adrs_set_layer(0, ADRS0),
  ADRS_t0 = adrs_set_tree(IdxTree0, ADRS_l0),
  Sig0 = xmss_sign(M, SKSeed, IdxLeaf0, PKSeed, ADRS_t0, Params),
  Root0 = xmss_pkFromSig(IdxLeaf0, Sig0, M, PKSeed, ADRS_t0, Params),
  ht_sign_layers(1, D, Root0, IdxTree0, [Sig0], SKSeed, PKSeed, ADRS0, Params).

-spec ht_sign_layers(
  pos_integer(),
  pos_integer(),
  binary(),
  non_neg_integer(),
  [binary()],
  binary(),
  binary(),
  adrs(),
  slh_params()
) -> binary().
ht_sign_layers(J, D, _Root, _IdxTree, Acc, _SKSeed, _PKSeed, _ADRS, _Params) when J =:= D ->
  iolist_to_binary(lists:reverse(Acc));
ht_sign_layers(J, D, Root, IdxTree, Acc, SKSeed, PKSeed, ADRS, #slh_params{hp = Hp} = Params) ->
  IdxLeaf = IdxTree band ((1 bsl Hp) - 1),
  NextIdxTree = IdxTree bsr Hp,
  ADRS_l = adrs_set_layer(J, ADRS),
  ADRS_t = adrs_set_tree(NextIdxTree, ADRS_l),
  SigJ = xmss_sign(Root, SKSeed, IdxLeaf, PKSeed, ADRS_t, Params),
  NextRoot =
    if
      J < D - 1 ->
        xmss_pkFromSig(IdxLeaf, SigJ, Root, PKSeed, ADRS_t, Params);
      true ->
        Root
    end,
  ht_sign_layers(J + 1, D, NextRoot, NextIdxTree, [SigJ | Acc], SKSeed, PKSeed, ADRS, Params).

-spec ht_verify(
  binary(), binary(), binary(), non_neg_integer(), non_neg_integer(), binary(), slh_params()
) -> boolean().
ht_verify(
  M,
  SigHT,
  PKSeed,
  IdxTree0,
  IdxLeaf0,
  PKRoot,
  #slh_params{n = N, len = Len, hp = Hp, d = D} = Params
) ->
  XmssSigBytes = (Len + Hp) * N,
  <<Sig0:XmssSigBytes/binary, RestSig/binary>> = SigHT,
  ADRS0 = adrs_new(),
  ADRS_l0 = adrs_set_layer(0, ADRS0),
  ADRS_t0 = adrs_set_tree(IdxTree0, ADRS_l0),
  Node0 = xmss_pkFromSig(IdxLeaf0, Sig0, M, PKSeed, ADRS_t0, Params),
  ht_verify_layers(1, D, Node0, IdxTree0, RestSig, XmssSigBytes, PKSeed, PKRoot, ADRS0, Params).

-spec ht_verify_layers(
  pos_integer(),
  pos_integer(),
  binary(),
  non_neg_integer(),
  binary(),
  pos_integer(),
  binary(),
  binary(),
  adrs(),
  slh_params()
) -> boolean().
ht_verify_layers(J, D, Node, _IdxTree, <<>>, _SigBytes, _PKSeed, PKRoot, _ADRS, _Params) when
  J =:= D
->
  Node =:= PKRoot;
ht_verify_layers(
  J,
  D,
  Node,
  IdxTree,
  RestSigAll,
  SigBytes,
  PKSeed,
  PKRoot,
  ADRS,
  #slh_params{hp = Hp} = Params
) ->
  <<SigJ:SigBytes/binary, RestSig/binary>> = RestSigAll,
  IdxLeaf = IdxTree band ((1 bsl Hp) - 1),
  NextIdxTree = IdxTree bsr Hp,
  ADRS_l = adrs_set_layer(J, ADRS),
  ADRS_t = adrs_set_tree(NextIdxTree, ADRS_l),
  NextNode = xmss_pkFromSig(IdxLeaf, SigJ, Node, PKSeed, ADRS_t, Params),
  ht_verify_layers(J + 1, D, NextNode, NextIdxTree, RestSig, SigBytes, PKSeed, PKRoot, ADRS, Params).

%%%===================================================================
%%% FORS (Forest of Random Subsets, FIPS 205 Section 8)
%%%===================================================================

-spec fors_skGen(binary(), binary(), adrs(), non_neg_integer(), slh_params()) -> binary().
fors_skGen(SKSeed, PKSeed, ADRS, Idx, Params) ->
  KP = adrs_get_keypair(ADRS),
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_FORS_PRF, ADRS),
  ADRS2 = adrs_set_keypair(KP, ADRS1),
  ADRS3 = adrs_set_tree_index(Idx, ADRS2),
  prf(PKSeed, SKSeed, ADRS3, Params).

-spec fors_node(binary(), non_neg_integer(), non_neg_integer(), binary(), adrs(), slh_params()) ->
  binary().
fors_node(SKSeed, I, 0, PKSeed, ADRS, Params) ->
  Sk = fors_skGen(SKSeed, PKSeed, ADRS, I, Params),
  KP = adrs_get_keypair(ADRS),
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_FORS_TREE, ADRS),
  ADRS2 = adrs_set_keypair(KP, ADRS1),
  ADRS3 = adrs_set_tree_height(0, ADRS2),
  ADRS4 = adrs_set_tree_index(I, ADRS3),
  f(PKSeed, ADRS4, Sk, Params);
fors_node(SKSeed, I, Z, PKSeed, ADRS, Params) ->
  LNode = fors_node(SKSeed, 2 * I, Z - 1, PKSeed, ADRS, Params),
  RNode = fors_node(SKSeed, 2 * I + 1, Z - 1, PKSeed, ADRS, Params),
  KP = adrs_get_keypair(ADRS),
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_FORS_TREE, ADRS),
  ADRS2 = adrs_set_keypair(KP, ADRS1),
  ADRS3 = adrs_set_tree_height(Z, ADRS2),
  ADRS4 = adrs_set_tree_index(I, ADRS3),
  h(PKSeed, ADRS4, <<LNode/binary, RNode/binary>>, Params).

-spec fors_sign(binary(), binary(), binary(), adrs(), slh_params()) -> binary().
fors_sign(Md, SKSeed, PKSeed, ADRS, #slh_params{k = K, a = A} = Params) ->
  Indices = extract_bits(Md, K, A),
  TreeNodes = (1 bsl A),
  ForsSigChunks = [
    begin
      GlobalIdx = J * TreeNodes + IdxJ,
      SkJ = fors_skGen(SKSeed, PKSeed, ADRS, GlobalIdx, Params),
      AuthJ = [
        begin
          Sib = (IdxJ bsr S) bxor 1,
          GlobalSib = J * (1 bsl (A - S)) + Sib,
          fors_node(SKSeed, GlobalSib, S, PKSeed, ADRS, Params)
        end
       || S <- lists:seq(0, A - 1)
      ],
      [SkJ | AuthJ]
    end
   || {J, IdxJ} <- lists:zip(lists:seq(0, K - 1), Indices)
  ],
  iolist_to_binary(ForsSigChunks).

-spec fors_pkFromSig(binary(), binary(), binary(), adrs(), slh_params()) -> binary().
fors_pkFromSig(SigFors, Md, PKSeed, ADRS, #slh_params{n = N, k = K, a = A} = Params) ->
  Indices = extract_bits(Md, K, A),
  TreeNodes = (1 bsl A),
  ChunkBytes = (A + 1) * N,
  Roots = [
    begin
      <<_:(J * ChunkBytes)/binary, Chunk:ChunkBytes/binary, _/binary>> = SigFors,
      <<SkJ:N/binary, AuthBin/binary>> = Chunk,
      KP = adrs_get_keypair(ADRS),
      GlobalIdx = J * TreeNodes + IdxJ,
      ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_FORS_TREE, ADRS),
      ADRS2 = adrs_set_keypair(KP, ADRS1),
      ADRS3 = adrs_set_tree_height(0, ADRS2),
      ADRS4 = adrs_set_tree_index(GlobalIdx, ADRS3),
      Leaf0 = f(PKSeed, ADRS4, SkJ, Params),
      fors_pk_path(0, A, J, IdxJ, Leaf0, AuthBin, PKSeed, ADRS, Params)
    end
   || {J, IdxJ} <- lists:zip(lists:seq(0, K - 1), Indices)
  ],
  AllRoots = iolist_to_binary(Roots),
  KP_adrs = adrs_get_keypair(ADRS),
  ADRS_roots0 = adrs_set_type_and_clear(?SLH_ADRS_FORS_ROOTS, ADRS),
  ADRS_roots = adrs_set_keypair(KP_adrs, ADRS_roots0),
  t_l(PKSeed, ADRS_roots, AllRoots, Params).

-spec fors_pk_path(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  binary(),
  binary(),
  binary(),
  adrs(),
  slh_params()
) -> binary().
fors_pk_path(S, A, _J, _IdxJ, Node, <<>>, _PKSeed, _ADRS, _Params) when S =:= A ->
  Node;
fors_pk_path(
  S,
  A,
  J,
  IdxJ,
  Node,
  AuthBin,
  PKSeed,
  ADRS,
  #slh_params{n = N} = Params
) ->
  <<AuthS:N/binary, Rest/binary>> = AuthBin,
  KP = adrs_get_keypair(ADRS),
  ADRS1 = adrs_set_type_and_clear(?SLH_ADRS_FORS_TREE, ADRS),
  ADRS2 = adrs_set_keypair(KP, ADRS1),
  ADRS3 = adrs_set_tree_height(S + 1, ADRS2),
  IsRight = (IdxJ bsr S) band 1,
  ParentIdx = J * (1 bsl (A - S - 1)) + (IdxJ bsr (S + 1)),
  ADRS4 = adrs_set_tree_index(ParentIdx, ADRS3),
  Combined =
    if
      IsRight =:= 0 -> <<Node/binary, AuthS/binary>>;
      true -> <<AuthS/binary, Node/binary>>
    end,
  Parent = h(PKSeed, ADRS4, Combined, Params),
  fors_pk_path(S + 1, A, J, IdxJ, Parent, Rest, PKSeed, ADRS, Params).

-spec extract_bits(binary(), pos_integer(), pos_integer()) -> [non_neg_integer()].
extract_bits(Bin, Count, Bits) ->
  extract_bits_loop(Bin, Count, Bits, []).

-spec extract_bits_loop(bitstring(), non_neg_integer(), pos_integer(), [non_neg_integer()]) ->
  [non_neg_integer()].
extract_bits_loop(_Bin, 0, _Bits, Acc) ->
  lists:reverse(Acc);
extract_bits_loop(Bin, Count, Bits, Acc) ->
  <<Val:Bits, Rest/bitstring>> = Bin,
  extract_bits_loop(Rest, Count - 1, Bits, [Val | Acc]).

%%%===================================================================
%%% ADRS Operations (FIPS 205 Section 4.2)
%%%===================================================================

-spec adrs_new() -> adrs().
adrs_new() ->
  <<0:256>>.

-spec adrs_set_layer(non_neg_integer(), adrs()) -> adrs().
adrs_set_layer(Layer, <<_:4/binary, Rest:28/binary>>) ->
  <<Layer:32, Rest/binary>>.

-spec adrs_set_tree(non_neg_integer(), adrs()) -> adrs().
adrs_set_tree(Tree, <<Layer:32, _:12/binary, Rest:16/binary>>) ->
  <<Layer:32, Tree:96, Rest/binary>>.

-spec adrs_set_type_and_clear(non_neg_integer(), adrs()) -> adrs().
adrs_set_type_and_clear(Type, <<Layer:32, Tree:96, _:16/binary>>) ->
  <<Layer:32, Tree:96, Type:32, 0:96>>.

-spec adrs_set_keypair(non_neg_integer(), adrs()) -> adrs().
adrs_set_keypair(KP, <<Layer:32, Tree:96, Type:32, _:4/binary, Rest:8/binary>>) ->
  <<Layer:32, Tree:96, Type:32, KP:32, Rest/binary>>.

-spec adrs_get_keypair(adrs()) -> non_neg_integer().
adrs_get_keypair(<<_:20/binary, KP:32, _:8/binary>>) ->
  KP.

-spec adrs_set_chain(non_neg_integer(), adrs()) -> adrs().
adrs_set_chain(Chain, <<Layer:32, Tree:96, Type:32, KP:32, _:32, W28:32>>) ->
  <<Layer:32, Tree:96, Type:32, KP:32, Chain:32, W28:32>>.

-spec adrs_set_hash(non_neg_integer(), adrs()) -> adrs().
adrs_set_hash(Hash, <<Layer:32, Tree:96, Type:32, KP:32, Chain:32, _:32>>) ->
  <<Layer:32, Tree:96, Type:32, KP:32, Chain:32, Hash:32>>.

-spec adrs_set_tree_height(non_neg_integer(), adrs()) -> adrs().
adrs_set_tree_height(H, <<Layer:32, Tree:96, Type:32, W20:32, _:32, W28:32>>) ->
  <<Layer:32, Tree:96, Type:32, W20:32, H:32, W28:32>>.

-spec adrs_set_tree_index(non_neg_integer(), adrs()) -> adrs().
adrs_set_tree_index(Idx, <<Layer:32, Tree:96, Type:32, W20:32, W24:32, _:32>>) ->
  <<Layer:32, Tree:96, Type:32, W20:32, W24:32, Idx:32>>.

-spec compress_adrs(adrs()) -> binary().
compress_adrs(
  <<_LayerH:24, LayerL:8, _TreeH:32, TreeL:64, _TypeH:24, TypeL:8, Words:12/binary>>
) ->
  <<LayerL:8, TreeL:64, TypeL:8, Words/binary>>.

%%%===================================================================
%%% Tweakable Hash Functions (FIPS 205 Section 10)
%%%===================================================================

-spec prf(binary(), binary(), adrs(), slh_params()) -> binary().
prf(PKSeed, SKSeed, ADRS, #slh_params{hash = shake, n = N}) ->
  ecu_keccak:shake256(<<PKSeed/binary, ADRS:32/binary, SKSeed/binary>>, N * 8);
prf(PKSeed, SKSeed, ADRS, #slh_params{hash = sha2, n = N}) ->
  PKPad = <<PKSeed:N/binary, 0:(64 - N)/unit:8>>,
  ADRSc = compress_adrs(ADRS),
  <<Res:N/binary, _/binary>> = ecu_sha2:sha256(<<PKPad/binary, ADRSc/binary, SKSeed/binary>>),
  Res.

-spec prf_msg(binary(), binary(), binary(), slh_params()) -> binary().
prf_msg(SKPrf, OptRand, M, #slh_params{hash = shake, n = N}) ->
  ecu_keccak:shake256(<<SKPrf/binary, OptRand/binary, M/binary>>, N * 8);
prf_msg(SKPrf, OptRand, M, #slh_params{hash = sha2, n = 16}) ->
  <<Res:16/binary, _/binary>> = ecu_compat:mac(hmac, sha256, SKPrf, <<OptRand/binary, M/binary>>),
  Res;
prf_msg(SKPrf, OptRand, M, #slh_params{hash = sha2, n = N}) when N =:= 24; N =:= 32 ->
  <<Res:N/binary, _/binary>> = ecu_compat:mac(hmac, sha512, SKPrf, <<OptRand/binary, M/binary>>),
  Res.

-spec h_msg(binary(), binary(), binary(), binary(), slh_params()) -> binary().
h_msg(R, PKSeed, PKRoot, M, #slh_params{hash = shake, m = OutBytes}) ->
  ecu_keccak:shake256(<<R/binary, PKSeed/binary, PKRoot/binary, M/binary>>, OutBytes * 8);
h_msg(R, PKSeed, PKRoot, M, #slh_params{hash = sha2, n = 16, m = OutBytes}) ->
  Inner = ecu_sha2:sha256(<<R/binary, PKSeed/binary, PKRoot/binary, M/binary>>),
  mgf1(sha256, <<R/binary, PKSeed/binary, Inner/binary>>, OutBytes);
h_msg(R, PKSeed, PKRoot, M, #slh_params{hash = sha2, n = N, m = OutBytes}) when
  N =:= 24; N =:= 32
->
  Inner = ecu_sha2:sha512(<<R/binary, PKSeed/binary, PKRoot/binary, M/binary>>),
  mgf1(sha512, <<R/binary, PKSeed/binary, Inner/binary>>, OutBytes).

-spec f(binary(), adrs(), binary(), slh_params()) -> binary().
f(PKSeed, ADRS, M1, #slh_params{hash = shake, n = N}) ->
  ecu_keccak:shake256(<<PKSeed/binary, ADRS:32/binary, M1/binary>>, N * 8);
f(PKSeed, ADRS, M1, #slh_params{hash = sha2, n = N}) ->
  PKPad = <<PKSeed:N/binary, 0:(64 - N)/unit:8>>,
  ADRSc = compress_adrs(ADRS),
  <<Res:N/binary, _/binary>> = ecu_sha2:sha256(<<PKPad/binary, ADRSc/binary, M1/binary>>),
  Res.

-spec h(binary(), adrs(), binary(), slh_params()) -> binary().
h(PKSeed, ADRS, M1_M2, #slh_params{hash = shake, n = N}) ->
  ecu_keccak:shake256(<<PKSeed/binary, ADRS:32/binary, M1_M2/binary>>, N * 8);
h(PKSeed, ADRS, M1_M2, #slh_params{hash = sha2, n = 16}) ->
  PKPad = <<PKSeed:16/binary, 0:48/unit:8>>,
  ADRSc = compress_adrs(ADRS),
  <<Res:16/binary, _/binary>> = ecu_sha2:sha256(<<PKPad/binary, ADRSc/binary, M1_M2/binary>>),
  Res;
h(PKSeed, ADRS, M1_M2, #slh_params{hash = sha2, n = N}) when N =:= 24; N =:= 32 ->
  PKPad = <<PKSeed:N/binary, 0:(128 - N)/unit:8>>,
  ADRSc = compress_adrs(ADRS),
  <<Res:N/binary, _/binary>> = ecu_sha2:sha512(<<PKPad/binary, ADRSc/binary, M1_M2/binary>>),
  Res.

-spec t_l(binary(), adrs(), binary(), slh_params()) -> binary().
t_l(PKSeed, ADRS, M, #slh_params{hash = shake, n = N}) ->
  ecu_keccak:shake256(<<PKSeed/binary, ADRS:32/binary, M/binary>>, N * 8);
t_l(PKSeed, ADRS, M, #slh_params{hash = sha2, n = 16}) ->
  PKPad = <<PKSeed:16/binary, 0:48/unit:8>>,
  ADRSc = compress_adrs(ADRS),
  <<Res:16/binary, _/binary>> = ecu_sha2:sha256(<<PKPad/binary, ADRSc/binary, M/binary>>),
  Res;
t_l(PKSeed, ADRS, M, #slh_params{hash = sha2, n = N}) when N =:= 24; N =:= 32 ->
  PKPad = <<PKSeed:N/binary, 0:(128 - N)/unit:8>>,
  ADRSc = compress_adrs(ADRS),
  <<Res:N/binary, _/binary>> = ecu_sha2:sha512(<<PKPad/binary, ADRSc/binary, M/binary>>),
  Res.

%%%===================================================================
%%% MGF1 Mask Generation Function (RFC 8017 / FIPS 205 §10.2)
%%%===================================================================

-spec mgf1(sha256 | sha512, binary(), pos_integer()) -> binary().
mgf1(Alg, Seed, Length) ->
  mgf1_loop(Alg, Seed, 0, Length, <<>>).

-spec mgf1_loop(sha256 | sha512, binary(), non_neg_integer(), pos_integer(), binary()) -> binary().
mgf1_loop(_Alg, _Seed, _Counter, Length, Acc) when byte_size(Acc) >= Length ->
  binary:part(Acc, 0, Length);
mgf1_loop(sha256, Seed, Counter, Length, Acc) ->
  Block = ecu_sha2:sha256(<<Seed/binary, Counter:32/big>>),
  mgf1_loop(sha256, Seed, Counter + 1, Length, <<Acc/binary, Block/binary>>);
mgf1_loop(sha512, Seed, Counter, Length, Acc) ->
  Block = ecu_sha2:sha512(<<Seed/binary, Counter:32/big>>),
  mgf1_loop(sha512, Seed, Counter + 1, Length, <<Acc/binary, Block/binary>>).
