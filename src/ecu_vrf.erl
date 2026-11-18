%%%-------------------------------------------------------------------
%%% @doc Pure-Erlang Verifiable Random Functions (VRFs).
%%%
%%% Implements Elliptic Curve VRFs (ECVRF) conforming to RFC 9381:
%%%   - `edwards25519_sha512_ell2' (Suite 0x04: ECVRF-EDWARDS25519-SHA512-ELL2)
%%%   - `edwards25519_sha512_tai'  (Suite 0x03: ECVRF-EDWARDS25519-SHA512-TAI)
%%%   - `secp256k1_sha256_tai'     (Suite 0xFE: ECVRF-SECP256K1-SHA256-TAI)
%%%   - `secp256k1_sha256_sswu'    (Suite 0xFE: ECVRF-SECP256K1-SHA256-SSWU)
%%%
%%% RFC 9381: https://www.rfc-editor.org/rfc/rfc9381.html
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_vrf).

-typing([eqwalizer]).

-export_type([
  suite/0,
  proof/0,
  vrf_hash/0,
  secret_key/0,
  public_key/0,
  alpha/0,
  options/0
]).

-export([
  keypair/1,
  derive_public_key/2,
  prove/3,
  prove/4,
  verify/4,
  verify/5,
  proof_to_hash/2
]).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-type suite() ::
  edwards25519_sha512_ell2
  | edwards25519_sha512_tai
  | secp256k1_sha256_tai
  | secp256k1_sha256_sswu.

-type proof() :: binary().
-type vrf_hash() :: binary().
-type secret_key() :: binary().
-type public_key() :: binary().
-type alpha() :: binary().
-type options() :: #{
  salt => binary(),
  validate_key => boolean()
}.

%% Curve orders
-define(Q_ED25519, 16#1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED).
-define(Q_SECP256K1, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141).

%% Domain separation octets (RFC 9381)
-define(SUITE_ED25519_TAI, 16#03).
-define(SUITE_ED25519_ELL2, 16#04).
-define(SUITE_SECP256K1, 16#FE).

-define(SEP_ENCODE_FRONT, 16#01).
-define(SEP_CHALLENGE_FRONT, 16#02).
-define(SEP_HASH_FRONT, 16#03).
-define(SEP_BACK, 16#00).

%% @doc Generates a fresh random keypair for the given VRF suite.
-spec keypair(suite()) -> {public_key(), secret_key()}.
keypair(Suite) ->
  SK = random_sk(Suite),
  PK = derive_public_key(Suite, SK),
  {PK, SK}.

%% @doc Derives the public key from a secret key.
-spec derive_public_key(suite(), secret_key()) -> public_key().
derive_public_key(Suite, SK) when is_binary(SK) ->
  case normalize_suite(Suite) of
    edwards25519_sha512_ell2 ->
      derive_pk_ed25519(SK);
    edwards25519_sha512_tai ->
      derive_pk_ed25519(SK);
    secp256k1_sha256_tai ->
      derive_pk_secp256k1(SK);
    secp256k1_sha256_sswu ->
      derive_pk_secp256k1(SK)
  end.

%% @doc Generates a deterministic VRF proof for input message Alpha.
-spec prove(suite(), secret_key(), alpha()) -> {ok, proof()} | {error, term()}.
prove(Suite, SK, Alpha) ->
  prove(Suite, SK, Alpha, #{}).

%% @doc Generates a deterministic VRF proof for input message Alpha with options.
-spec prove(suite(), secret_key(), alpha(), options()) -> {ok, proof()} | {error, term()}.
prove(Suite, SK, Alpha, Opts) when is_binary(SK), is_binary(Alpha), is_map(Opts) ->
  NormalizedSuite = normalize_suite(Suite),
  try
    PK = derive_public_key(NormalizedSuite, SK),
    Salt = maps:get(salt, Opts, PK),
    prove_internal(NormalizedSuite, SK, PK, Alpha, Salt)
  catch
    error:badarg ->
      {error, bad_key};
    error:Reason ->
      {error, Reason}
  end.

%% @doc Verifies a VRF proof and returns the deterministic VRF hash.
-spec verify(suite(), public_key(), proof(), alpha()) -> {ok, vrf_hash()} | {error, term()}.
verify(Suite, PK, Proof, Alpha) ->
  verify(Suite, PK, Proof, Alpha, #{}).

%% @doc Verifies a VRF proof and returns the deterministic VRF hash with options.
-spec verify(suite(), public_key(), proof(), alpha(), options()) -> {ok, vrf_hash()} | {error, term()}.
verify(Suite, PK, Proof, Alpha, Opts) when
  is_binary(PK), is_binary(Proof), is_binary(Alpha), is_map(Opts)
->
  NormalizedSuite = normalize_suite(Suite),
  ValidateKey = maps:get(validate_key, Opts, true),
  Salt = maps:get(salt, Opts, PK),
  try
    case validate_pk(NormalizedSuite, PK, ValidateKey) of
      {ok, PtY} ->
        verify_internal(NormalizedSuite, PK, PtY, Proof, Alpha, Salt);
      {error, _} = Err ->
        Err
    end
  catch
    error:_ ->
      {error, invalid_proof}
  end.

%% @doc Derives the deterministic VRF output hash from a validated proof.
-spec proof_to_hash(suite(), proof()) -> {ok, vrf_hash()} | {error, term()}.
proof_to_hash(Suite, Proof) when is_binary(Proof) ->
  NormalizedSuite = normalize_suite(Suite),
  try
    case NormalizedSuite of
      Ed when Ed =:= edwards25519_sha512_ell2; Ed =:= edwards25519_sha512_tai ->
        proof_to_hash_ed25519(Ed, Proof);
      Secp when Secp =:= secp256k1_sha256_tai; Secp =:= secp256k1_sha256_sswu ->
        proof_to_hash_secp256k1(Secp, Proof)
    end
  catch
    error:_ ->
      {error, invalid_proof}
  end.

%%%-------------------------------------------------------------------
%%% Internal Proving Implementation
%%%-------------------------------------------------------------------

-spec prove_internal(suite(), secret_key(), public_key(), alpha(), binary()) ->
  {ok, proof()} | {error, term()}.
prove_internal(Suite, SK, PK, Alpha, Salt) ->
  case Suite of
    edwards25519_sha512_ell2 ->
      prove_ed25519(Suite, SK, PK, Alpha, Salt, fun encode_to_curve_ell2/2);
    edwards25519_sha512_tai ->
      prove_ed25519(Suite, SK, PK, Alpha, Salt, fun encode_to_curve_tai_ed25519/2);
    secp256k1_sha256_tai ->
      prove_secp256k1(Suite, SK, PK, Alpha, Salt, fun encode_to_curve_tai_secp256k1/2);
    secp256k1_sha256_sswu ->
      prove_secp256k1(Suite, SK, PK, Alpha, Salt, fun encode_to_curve_sswu_secp256k1/2)
  end.

-spec prove_ed25519(
  suite(),
  secret_key(),
  public_key(),
  alpha(),
  binary(),
  fun((binary(), binary()) -> ecu_ed25519:pt())
) -> {ok, proof()}.
prove_ed25519(Suite, SK, PK, Alpha, Salt, EncodeFun) ->
  {XInt, TruncatedHashedSK} = derive_scalar_ed25519(SK),
  PtH = EncodeFun(Salt, Alpha),
  HStr = ecu_ed25519:compress(PtH),
  PtGamma = ecu_ed25519:scalar_mul_noclamp(XInt, PtH),
  GammaStr = ecu_ed25519:compress(PtGamma),
  K = nonce_rfc8032(TruncatedHashedSK, HStr),
  PtU = ecu_ed25519:scalar_mul_base_noclamp(K),
  PtV = ecu_ed25519:scalar_mul_noclamp(K, PtH),
  UStr = ecu_ed25519:compress(PtU),
  VStr = ecu_ed25519:compress(PtV),
  SuiteByte = suite_byte(Suite),
  CStr = challenge_points(SuiteByte, PK, HStr, GammaStr, UStr, VStr, 16),
  <<CInt:128/little>> = CStr,
  S = (K + CInt * XInt) rem ?Q_ED25519,
  Proof = <<GammaStr/binary, CStr/binary, S:256/little>>,
  {ok, Proof}.

-spec prove_secp256k1(
  suite(),
  secret_key(),
  public_key(),
  alpha(),
  binary(),
  fun((binary(), binary()) -> ecu_secp256k1:pt_affine())
) -> {ok, proof()}.
prove_secp256k1(Suite, SK, PK, Alpha, Salt, EncodeFun) ->
  <<XInt:256>> = SK,
  PtH = EncodeFun(Salt, Alpha),
  HStr = ecu_secp256k1:compress(PtH),
  PtGamma = ecu_secp256k1:scalar_mul(XInt, PtH),
  GammaStr = ecu_secp256k1:compress(PtGamma),
  K = nonce_rfc6979_secp256k1(SK, HStr),
  PtU = ecu_secp256k1:scalar_mul_base(K),
  PtV = ecu_secp256k1:scalar_mul(K, PtH),
  UStr = ecu_secp256k1:compress(PtU),
  VStr = ecu_secp256k1:compress(PtV),
  SuiteByte = suite_byte(Suite),
  CStr = challenge_points(SuiteByte, PK, HStr, GammaStr, UStr, VStr, 16),
  <<CInt:128>> = CStr,
  S = (K + CInt * XInt) rem ?Q_SECP256K1,
  Proof = <<GammaStr/binary, CStr/binary, S:256>>,
  {ok, Proof}.

%%%-------------------------------------------------------------------
%%% Internal Verification Implementation
%%%-------------------------------------------------------------------

-spec verify_internal(
  suite(),
  public_key(),
  ecu_ed25519:pt_hom_ext() | ecu_secp256k1:pt_affine(),
  proof(),
  alpha(),
  binary()
) -> {ok, vrf_hash()} | {error, term()}.
verify_internal(edwards25519_sha512_ell2, PK, {_, _, _, _} = PtY, Proof, Alpha, Salt) ->
  verify_ed25519(edwards25519_sha512_ell2, PK, PtY, Proof, Alpha, Salt, fun encode_to_curve_ell2/2);
verify_internal(edwards25519_sha512_tai, PK, {_, _, _, _} = PtY, Proof, Alpha, Salt) ->
  verify_ed25519(
    edwards25519_sha512_tai, PK, PtY, Proof, Alpha, Salt, fun encode_to_curve_tai_ed25519/2
  );
verify_internal(secp256k1_sha256_tai, PK, {_, _} = PtY, Proof, Alpha, Salt) ->
  verify_secp256k1(
    secp256k1_sha256_tai, PK, PtY, Proof, Alpha, Salt, fun encode_to_curve_tai_secp256k1/2
  );
verify_internal(secp256k1_sha256_sswu, PK, {_, _} = PtY, Proof, Alpha, Salt) ->
  verify_secp256k1(
    secp256k1_sha256_sswu, PK, PtY, Proof, Alpha, Salt, fun encode_to_curve_sswu_secp256k1/2
  );
verify_internal(_Suite, _PK, _PtY, _Proof, _Alpha, _Salt) ->
  {error, invalid_public_key}.

-spec verify_ed25519(
  suite(),
  public_key(),
  ecu_ed25519:pt_hom_ext(),
  proof(),
  alpha(),
  binary(),
  fun((binary(), binary()) -> ecu_ed25519:pt())
) -> {ok, vrf_hash()} | {error, term()}.
verify_ed25519(Suite, PK, PtY, Proof, Alpha, Salt, EncodeFun) ->
  case Proof of
    <<GammaStr:32/binary, CStr:16/binary, SInt:256/little>> when SInt < ?Q_ED25519 ->
      try ecu_ed25519:decompress(GammaStr) of
        PtGamma ->
          PtH = EncodeFun(Salt, Alpha),
          HStr = ecu_ed25519:compress(PtH),
          <<CInt:128/little>> = CStr,
          PtSB = ecu_ed25519:scalar_mul_base_noclamp(SInt),
          PtCY = ecu_ed25519:scalar_mul_noclamp(CInt, PtY),
          PtU = ecu_ed25519:p_sub(PtSB, PtCY),
          PtSH = ecu_ed25519:scalar_mul_noclamp(SInt, PtH),
          PtCGamma = ecu_ed25519:scalar_mul_noclamp(CInt, PtGamma),
          PtV = ecu_ed25519:p_sub(PtSH, PtCGamma),
          UStr = ecu_ed25519:compress(PtU),
          VStr = ecu_ed25519:compress(PtV),
          SuiteByte = suite_byte(Suite),
          ExpectedC = challenge_points(SuiteByte, PK, HStr, GammaStr, UStr, VStr, 16),
          case ExpectedC =:= CStr of
            true ->
              proof_to_hash_ed25519(Suite, Proof);
            false ->
              {error, invalid_proof}
          end
      catch
        error:_ ->
          {error, invalid_proof}
      end;
    _ ->
      {error, invalid_proof}
  end.

-spec verify_secp256k1(
  suite(),
  public_key(),
  ecu_secp256k1:pt_affine(),
  proof(),
  alpha(),
  binary(),
  fun((binary(), binary()) -> ecu_secp256k1:pt_affine())
) -> {ok, vrf_hash()} | {error, term()}.
verify_secp256k1(Suite, PK, PtY, Proof, Alpha, Salt, EncodeFun) ->
  case Proof of
    <<GammaStr:33/binary, CStr:16/binary, SInt:256>> when SInt < ?Q_SECP256K1 ->
      try ecu_secp256k1:decompress(GammaStr) of
        PtGamma ->
          PtH = EncodeFun(Salt, Alpha),
          HStr = ecu_secp256k1:compress(PtH),
          <<CInt:128>> = CStr,
          PtSB = ecu_secp256k1:scalar_mul_base(SInt),
          PtCY = ecu_secp256k1:scalar_mul(CInt, PtY),
          PtU = ecu_secp256k1:p_add(PtSB, ecu_secp256k1:p_neg(PtCY)),
          PtSH = ecu_secp256k1:scalar_mul(SInt, PtH),
          PtCGamma = ecu_secp256k1:scalar_mul(CInt, PtGamma),
          PtV = ecu_secp256k1:p_add(PtSH, ecu_secp256k1:p_neg(PtCGamma)),
          UStr = ecu_secp256k1:compress(PtU),
          VStr = ecu_secp256k1:compress(PtV),
          SuiteByte = suite_byte(Suite),
          ExpectedC = challenge_points(SuiteByte, PK, HStr, GammaStr, UStr, VStr, 16),
          case ExpectedC =:= CStr of
            true ->
              proof_to_hash_secp256k1(Suite, Proof);
            false ->
              {error, invalid_proof}
          end
      catch
        error:_ ->
          {error, invalid_proof}
      end;
    _ ->
      {error, invalid_proof}
  end.

%%%-------------------------------------------------------------------
%%% Proof-to-Hash Helpers
%%%-------------------------------------------------------------------

-spec proof_to_hash_ed25519(suite(), proof()) -> {ok, vrf_hash()} | {error, term()}.
proof_to_hash_ed25519(Suite, <<GammaStr:32/binary, _CStr:16/binary, SInt:256/little>>) when
  SInt < ?Q_ED25519
->
  PtGamma = ecu_ed25519:decompress(GammaStr),
  PtGamma8 = ecu_ed25519:scalar_mul_noclamp(8, PtGamma),
  Gamma8Str = ecu_ed25519:compress(PtGamma8),
  SuiteByte = suite_byte(Suite),
  Hash = ecu_compat:hash(sha512, <<SuiteByte, ?SEP_HASH_FRONT, Gamma8Str/binary, ?SEP_BACK>>),
  {ok, Hash};
proof_to_hash_ed25519(_Suite, _Proof) ->
  {error, invalid_proof}.

-spec proof_to_hash_secp256k1(suite(), proof()) -> {ok, vrf_hash()} | {error, term()}.
proof_to_hash_secp256k1(Suite, <<GammaStr:33/binary, _CStr:16/binary, SInt:256>>) when
  SInt < ?Q_SECP256K1
->
  _PtGamma = ecu_secp256k1:decompress(GammaStr),
  SuiteByte = suite_byte(Suite),
  Hash = ecu_compat:hash(sha256, <<SuiteByte, ?SEP_HASH_FRONT, GammaStr/binary, ?SEP_BACK>>),
  {ok, Hash};
proof_to_hash_secp256k1(_Suite, _Proof) ->
  {error, invalid_proof}.

%%%-------------------------------------------------------------------
%%% Encoding to Curve Functions
%%%-------------------------------------------------------------------

-spec encode_to_curve_ell2(binary(), binary()) -> ecu_ed25519:pt_affine().
encode_to_curve_ell2(Salt, Alpha) ->
  StringToHash = <<Salt/binary, Alpha/binary>>,
  DST = <<"ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_\x04">>,
  ecu_h2c:encode_to_curve(edwards25519_xmd_sha512_ell2_nu, StringToHash, DST).

-spec encode_to_curve_tai_ed25519(binary(), binary()) -> ecu_ed25519:pt_hom_ext().
encode_to_curve_tai_ed25519(Salt, Alpha) ->
  find_h_tai_ed25519(Salt, Alpha, 0).

-spec find_h_tai_ed25519(binary(), binary(), non_neg_integer()) -> ecu_ed25519:pt_hom_ext().
find_h_tai_ed25519(Salt, Alpha, Ctr) when Ctr < 256 ->
  HashInput = <<?SUITE_ED25519_TAI, ?SEP_ENCODE_FRONT, Salt/binary, Alpha/binary, Ctr:8, ?SEP_BACK>>,
  <<CandBytes:32/binary, _/binary>> = ecu_compat:hash(sha512, HashInput),
  try ecu_ed25519:decompress(CandBytes) of
    CandPt ->
      H = ecu_ed25519:scalar_mul_noclamp(8, CandPt),
      case ecu_ed25519:pt_eq(H, {0, 1, 1, 0}) of
        true -> find_h_tai_ed25519(Salt, Alpha, Ctr + 1);
        false -> H
      end
  catch
    error:badarg ->
      find_h_tai_ed25519(Salt, Alpha, Ctr + 1)
  end;
find_h_tai_ed25519(_Salt, _Alpha, _Ctr) ->
  error({tai_failed, max_counter_reached}).

-spec encode_to_curve_tai_secp256k1(binary(), binary()) -> ecu_secp256k1:pt_affine().
encode_to_curve_tai_secp256k1(Salt, Alpha) ->
  find_h_tai_secp256k1(Salt, Alpha, 0).

-spec find_h_tai_secp256k1(binary(), binary(), non_neg_integer()) -> ecu_secp256k1:pt_affine().
find_h_tai_secp256k1(Salt, Alpha, Ctr) when Ctr < 256 ->
  HashInput = <<?SUITE_SECP256K1, ?SEP_ENCODE_FRONT, Salt/binary, Alpha/binary, Ctr:8, ?SEP_BACK>>,
  Hash = ecu_compat:hash(sha256, HashInput),
  CandBytes = <<2, Hash/binary>>,
  try ecu_secp256k1:decompress(CandBytes) of
    {0, 0} -> find_h_tai_secp256k1(Salt, Alpha, Ctr + 1);
    Pt -> Pt
  catch
    error:badarg ->
      find_h_tai_secp256k1(Salt, Alpha, Ctr + 1)
  end;
find_h_tai_secp256k1(_Salt, _Alpha, _Ctr) ->
  error({tai_failed, max_counter_reached}).

-spec encode_to_curve_sswu_secp256k1(binary(), binary()) -> ecu_secp256k1:pt_affine().
encode_to_curve_sswu_secp256k1(Salt, Alpha) ->
  StringToHash = <<Salt/binary, Alpha/binary>>,
  DST = <<"ECVRF_secp256k1_XMD:SHA-256_SSWU_NU_\xfe">>,
  ecu_h2c:encode_to_curve(secp256k1_xmd_sha256_sswu_nu, StringToHash, DST).

%%%-------------------------------------------------------------------
%%% Nonce & Challenge Helpers
%%%-------------------------------------------------------------------

-spec nonce_rfc8032(binary(), binary()) -> pos_integer().
nonce_rfc8032(TruncatedHashedSK, HStr) ->
  KHash = ecu_compat:hash(sha512, <<TruncatedHashedSK/binary, HStr/binary>>),
  <<KRaw:512/little>> = KHash,
  KRaw rem ?Q_ED25519.

-spec nonce_rfc6979_secp256k1(secret_key(), binary()) -> pos_integer().
nonce_rfc6979_secp256k1(SK, HStr) ->
  MsgHash = ecu_compat:hash(sha256, HStr),
  ecu_ecdsa:rfc6979_k(secp256k1, MsgHash, SK).

-spec challenge_points(byte(), binary(), binary(), binary(), binary(), binary(), pos_integer()) ->
  binary().
challenge_points(SuiteByte, PK, HStr, GammaStr, UStr, VStr, CLen) ->
  CInput =
    <<SuiteByte, ?SEP_CHALLENGE_FRONT, PK/binary, HStr/binary, GammaStr/binary, UStr/binary, VStr/binary,
      ?SEP_BACK>>,
  Hash =
    case SuiteByte of
      ?SUITE_SECP256K1 -> ecu_compat:hash(sha256, CInput);
      _ -> ecu_compat:hash(sha512, CInput)
    end,
  binary:part(Hash, 0, CLen).

%%%-------------------------------------------------------------------
%%% Key Validation & Conversion
%%%-------------------------------------------------------------------

-spec derive_pk_ed25519(secret_key()) -> public_key().
derive_pk_ed25519(SK) when byte_size(SK) =:= 32 ->
  {XInt, _} = derive_scalar_ed25519(SK),
  PtY = ecu_ed25519:scalar_mul_base_noclamp(XInt),
  ecu_ed25519:compress(PtY);
derive_pk_ed25519(_) ->
  error(badarg).

-spec derive_pk_secp256k1(secret_key()) -> public_key().
derive_pk_secp256k1(<<XInt:256>>) when XInt >= 1, XInt < ?Q_SECP256K1 ->
  PtY = ecu_secp256k1:scalar_mul_base(XInt),
  ecu_secp256k1:compress(PtY);
derive_pk_secp256k1(_) ->
  error(badarg).

-spec derive_scalar_ed25519(secret_key()) -> {non_neg_integer(), binary()}.
derive_scalar_ed25519(SK) ->
  <<RawX:32/binary, TruncatedHashedSK:32/binary>> = ecu_compat:hash(sha512, SK),
  <<X0:8, XMid:30/binary, X31:8>> = RawX,
  ClampedX = <<(X0 band 248):8, XMid/binary, ((X31 band 127) bor 64):8>>,
  <<XInt:256/little>> = ClampedX,
  {XInt, TruncatedHashedSK}.

-spec validate_pk(suite(), public_key(), boolean()) ->
  {ok, ecu_ed25519:pt_hom_ext() | ecu_secp256k1:pt_affine()} | {error, term()}.
validate_pk(Suite, PK, ValidateKey) ->
  case Suite of
    Ed when Ed =:= edwards25519_sha512_ell2; Ed =:= edwards25519_sha512_tai ->
      try ecu_ed25519:decompress(PK) of
        PtY ->
          case ValidateKey of
            true ->
              case ecu_ed25519:is_small_order(PtY) of
                true -> {error, small_order_public_key};
                false -> {ok, PtY}
              end;
            false ->
              {ok, PtY}
          end
      catch
        error:_ ->
          {error, invalid_public_key}
      end;
    Secp when Secp =:= secp256k1_sha256_tai; Secp =:= secp256k1_sha256_sswu ->
      try ecu_secp256k1:decompress(PK) of
        {0, 0} ->
          {error, invalid_public_key};
        PtY ->
          case ValidateKey of
            true ->
              case ecu_secp256k1:on_curve(PtY) of
                true -> {ok, PtY};
                false -> {error, invalid_public_key}
              end;
            false ->
              {ok, PtY}
          end
      catch
        error:_ ->
          {error, invalid_public_key}
      end
  end.

-spec random_sk(suite()) -> secret_key().
random_sk(Suite) ->
  case Suite of
    Ed when Ed =:= edwards25519_sha512_ell2; Ed =:= edwards25519_sha512_tai ->
      ecu_compat:strong_rand_bytes(32);
    Secp when Secp =:= secp256k1_sha256_tai; Secp =:= secp256k1_sha256_sswu ->
      random_secp256k1_sk()
  end.

-spec random_secp256k1_sk() -> secret_key().
random_secp256k1_sk() ->
  Bytes = ecu_compat:strong_rand_bytes(32),
  <<Scalar:256>> = Bytes,
  if
    Scalar >= 1 andalso Scalar < ?Q_SECP256K1 -> Bytes;
    true -> random_secp256k1_sk()
  end.

-spec normalize_suite(suite()) -> suite().
normalize_suite(edwards25519_sha512_ell2) -> edwards25519_sha512_ell2;
normalize_suite(edwards25519_sha512_tai) -> edwards25519_sha512_tai;
normalize_suite(secp256k1_sha256_tai) -> secp256k1_sha256_tai;
normalize_suite(secp256k1_sha256_sswu) -> secp256k1_sha256_sswu;
normalize_suite(_) -> error(badarg).

-spec suite_byte(suite()) -> byte().
suite_byte(edwards25519_sha512_ell2) -> ?SUITE_ED25519_ELL2;
suite_byte(edwards25519_sha512_tai) -> ?SUITE_ED25519_TAI;
suite_byte(secp256k1_sha256_tai) -> ?SUITE_SECP256K1;
suite_byte(secp256k1_sha256_sswu) -> ?SUITE_SECP256K1.
