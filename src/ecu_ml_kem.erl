%%%-------------------------------------------------------------------
%%% @doc
%%% Pure Erlang implementation of ML-KEM (FIPS 203).
%%%
%%% Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM), formerly
%%% known as CRYSTALS-Kyber, standardized in NIST FIPS 203 (August 2024).
%%%
%%% Supported parameter sets:
%%%   - `ml_kem_512' (or `mlkem512'): NIST Category 1 (~AES-128)
%%%   - `ml_kem_768' (or `mlkem768'): NIST Category 3 (~AES-192)
%%%   - `ml_kem_1024' (or `mlkem1024'): NIST Category 5 (~AES-256)
%%%
%%% Provides IND-CCA2 secure key encapsulation (`encaps/1,2', `decaps/2')
%%% with implicit rejection on tampered or corrupted ciphertexts, and
%%% deterministic keypair derivation (`keypair_from_seed/3').
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_ml_kem).

-typing([eqwalizer]).

-include("ecu_ml_kem.hrl").

-export([
  keypair/1,
  keypair_from_seed/3,
  encaps/1,
  encaps/2,
  decaps/2,
  parameter_set/1
]).

-ifdef(TEST).
-export([
  ntt/1,
  inv_ntt/1,
  multiply_ntts/2,
  sample_ntt/3,
  sample_poly_cbd/2,
  byte_encode/2,
  byte_decode/2,
  compress/2,
  decompress/2,
  k_pke_keygen/3,
  k_pke_encrypt/8,
  k_pke_decrypt/5
]).
-endif.

-type parameter_set() ::
  ml_kem_512 | ml_kem_768 | ml_kem_1024 | mlkem512 | mlkem768 | mlkem1024.

-type public_key() :: binary().
-type secret_key() :: binary().
-type ciphertext() :: binary().
-type shared_secret() :: <<_:256>>.
-type poly() :: [non_neg_integer()].
-type poly_tuple() :: tuple().

-export_type([
  parameter_set/0,
  public_key/0,
  secret_key/0,
  ciphertext/0,
  shared_secret/0
]).

%% ===================================================================
%% API Functions
%% ===================================================================

%% @doc Generate a new random keypair for the specified parameter set.
-spec keypair(parameter_set()) -> {public_key(), secret_key()}.
keypair(ParamSet) ->
  SeedD = ecu_compat:strong_rand_bytes(32),
  SeedZ = ecu_compat:strong_rand_bytes(32),
  keypair_from_seed(ParamSet, SeedD, SeedZ).

%% @doc Deterministically derive a keypair from two 32-byte seeds (d, z) per FIPS 203.
-spec keypair_from_seed(parameter_set(), <<_:256>>, <<_:256>>) -> {public_key(), secret_key()}.
keypair_from_seed(ParamSet, SeedD, SeedZ) when
  is_binary(SeedD), byte_size(SeedD) =:= 32, is_binary(SeedZ), byte_size(SeedZ) =:= 32
->
  {K, Eta1, _, _, _, _, _, _} = params(ParamSet),
  {EkPke, DkPke} = k_pke_keygen(K, Eta1, SeedD),
  HEk = ecu_compat:hash(sha3_256, EkPke),
  Dk = <<DkPke/binary, EkPke/binary, HEk/binary, SeedZ/binary>>,
  {EkPke, Dk};
keypair_from_seed(_, _, _) ->
  error(badarg).

%% @doc Encapsulate against a public key, generating a shared secret and ciphertext.
-spec encaps(public_key()) -> {shared_secret(), ciphertext()}.
encaps(PublicKey) ->
  SeedM = ecu_compat:strong_rand_bytes(32),
  encaps(PublicKey, SeedM).

%% @doc Deterministically encapsulate using a fixed 32-byte seed m per FIPS 203.
-spec encaps(public_key(), <<_:256>>) -> {shared_secret(), ciphertext()}.
encaps(PublicKey, SeedM) when
  is_binary(PublicKey), is_binary(SeedM), byte_size(SeedM) =:= 32
->
  ParamSet = parameter_set(PublicKey),
  {K, Eta1, Eta2, Du, Dv, EkLen, _, _} = params(ParamSet),
  case byte_size(PublicKey) =:= EkLen of
    true ->
      case validate_public_key(K, PublicKey) of
        ok ->
          HPk = ecu_compat:hash(sha3_256, PublicKey),
          <<SharedSecret:32/binary, R:32/binary>> = ecu_compat:hash(
            sha3_512, <<SeedM/binary, HPk/binary>>
          ),
          Ciphertext = k_pke_encrypt(K, Eta1, Eta2, Du, Dv, PublicKey, SeedM, R),
          {SharedSecret, Ciphertext};
        error ->
          error(invalid_public_key)
      end;
    false ->
      error(badarg)
  end;
encaps(_, _) ->
  error(badarg).

%% @doc Decapsulate a ciphertext with the secret key, recovering the shared secret.
%% If the ciphertext is invalid or tampered, returns a pseudorandom key (implicit rejection).
-spec decaps(secret_key(), ciphertext()) -> shared_secret().
decaps(SecretKey, Ciphertext) when is_binary(SecretKey), is_binary(Ciphertext) ->
  ParamSet = parameter_set_from_sk(SecretKey),
  {K, Eta1, Eta2, Du, Dv, EkLen, CtLen, DkLen} = params(ParamSet),
  case byte_size(SecretKey) =:= DkLen andalso byte_size(Ciphertext) =:= CtLen of
    true ->
      DkPkeLen = 384 * K,
      <<
        DkPke:DkPkeLen/binary,
        EkPke:EkLen/binary,
        HPk:32/binary,
        Z:32/binary
      >> = SecretKey,
      MPrime = k_pke_decrypt(K, Du, Dv, DkPke, Ciphertext),
      <<KPrime:32/binary, RPrime:32/binary>> = ecu_compat:hash(sha3_512, <<MPrime/binary, HPk/binary>>),
      KBar = shake256(<<Z/binary, Ciphertext/binary>>, 256),
      CPrime = k_pke_encrypt(K, Eta1, Eta2, Du, Dv, EkPke, MPrime, RPrime),
      case subtle_eq(Ciphertext, CPrime) of
        true -> KPrime;
        false -> KBar
      end;
    false ->
      error(badarg)
  end;
decaps(_, _) ->
  error(badarg).

%% @doc Determine parameter set from public key byte size.
-spec parameter_set(public_key()) -> parameter_set().
parameter_set(PublicKey) when is_binary(PublicKey) ->
  case byte_size(PublicKey) of
    800 -> ml_kem_512;
    1184 -> ml_kem_768;
    1568 -> ml_kem_1024;
    _ -> error(badarg)
  end;
parameter_set(_) ->
  error(badarg).

%% ===================================================================
%% K-PKE Layer (Internal Public Key Encryption)
%% ===================================================================

-spec k_pke_keygen(pos_integer(), pos_integer(), <<_:256>>) -> {binary(), binary()}.
k_pke_keygen(K, Eta1, SeedD) ->
  <<Rho:32/binary, Sigma:32/binary>> = ecu_compat:hash(sha3_512, SeedD),
  {S_vec, N1} = sample_poly_vector(K, Eta1, Sigma, 0),
  {E_vec, _N2} = sample_poly_vector(K, Eta1, Sigma, N1),
  S_hat = [ntt(S) || S <- S_vec],
  E_hat = [ntt(E) || E <- E_vec],
  A_hat = sample_matrix_a(K, Rho),
  T_hat = [
    p_add(
      lists:nth(I + 1, E_hat),
      matrix_row_mul(lists:nth(I + 1, A_hat), S_hat)
    )
   || I <- lists:seq(0, K - 1)
  ],
  EkPke = <<(iolist_to_binary([byte_encode(12, T) || T <- T_hat]))/binary, Rho/binary>>,
  DkPke = iolist_to_binary([byte_encode(12, S) || S <- S_hat]),
  {EkPke, DkPke}.

-spec k_pke_encrypt(
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  pos_integer(),
  binary(),
  <<_:256>>,
  <<_:256>>
) -> binary().
k_pke_encrypt(K, Eta1, Eta2, Du, Dv, EkPke, Msg, R) ->
  TBytesLen = 384 * K,
  <<TBytes:TBytesLen/binary, Rho:32/binary>> = EkPke,
  T_hat = decode_poly_vector(12, K, TBytes),
  A_hat_T = sample_matrix_a_transpose(K, Rho),
  {Y_vec, N1} = sample_poly_vector(K, Eta1, R, 0),
  {E1_vec, N2} = sample_poly_vector(K, Eta2, R, N1),
  E2 = sample_poly_cbd(Eta2, prf(Eta2, R, N2)),
  Y_hat = [ntt(Y) || Y <- Y_vec],
  U_vec = [
    p_add(
      inv_ntt(matrix_row_mul(lists:nth(I + 1, A_hat_T), Y_hat)),
      lists:nth(I + 1, E1_vec)
    )
   || I <- lists:seq(0, K - 1)
  ],
  Mu = decompress(1, byte_decode(1, Msg)),
  V = p_add(
    p_add(inv_ntt(matrix_row_mul(T_hat, Y_hat)), E2),
    Mu
  ),
  C1 = iolist_to_binary([byte_encode(Du, compress(Du, U)) || U <- U_vec]),
  C2 = byte_encode(Dv, compress(Dv, V)),
  <<C1/binary, C2/binary>>.

-spec k_pke_decrypt(pos_integer(), pos_integer(), pos_integer(), binary(), binary()) -> <<_:256>>.
k_pke_decrypt(K, Du, Dv, DkPke, Ciphertext) ->
  C1Len = 32 * Du * K,
  <<C1:C1Len/binary, C2/binary>> = Ciphertext,
  U_vec = [decompress(Du, P) || P <- decode_poly_vector(Du, K, C1)],
  V = decompress(Dv, byte_decode(Dv, C2)),
  S_hat = decode_poly_vector(12, K, DkPke),
  U_hat = [ntt(U) || U <- U_vec],
  W = p_sub(V, inv_ntt(matrix_row_mul(S_hat, U_hat))),
  Res = byte_encode(1, compress(1, W)),
  case Res of
    <<Msg:32/binary>> -> Msg
  end.

%% ===================================================================
%% Polynomial Arithmetic & NTT
%% ===================================================================

-spec p_add(poly(), poly()) -> poly().
p_add([X | Xs], [Y | Ys]) ->
  [(X + Y) rem ?ML_KEM_Q | p_add(Xs, Ys)];
p_add([], []) ->
  [].

-spec p_sub(poly(), poly()) -> poly().
p_sub([X | Xs], [Y | Ys]) ->
  [(X - Y + ?ML_KEM_Q) rem ?ML_KEM_Q | p_sub(Xs, Ys)];
p_sub([], []) ->
  [].

%% @doc Number Theoretic Transform (NTT) mapping R_q -> T_q.
-spec ntt(poly()) -> poly().
ntt(P) ->
  A0 = list_to_tuple(P),
  step_ntt_len(128, 1, A0).

-spec step_ntt_len(pos_integer(), pos_integer(), poly_tuple()) -> poly().
step_ntt_len(Len, K0, A) when Len >= 2 ->
  {K_next, A_next} = step_ntt_start(0, Len, K0, A),
  step_ntt_len(Len div 2, K_next, A_next);
step_ntt_len(_, _, A) ->
  tuple_to_list(A).

-spec step_ntt_start(non_neg_integer(), pos_integer(), pos_integer(), poly_tuple()) ->
  {pos_integer(), poly_tuple()}.
step_ntt_start(Start, Len, K, A) when Start < 256 ->
  Z = zeta(K + 1),
  A_step = step_ntt_j(Start, Start + Len, Len, Z, A),
  step_ntt_start(Start + 2 * Len, Len, K + 1, A_step);
step_ntt_start(_, _, K, A) ->
  {K, A}.

-spec step_ntt_j(
  non_neg_integer(),
  pos_integer(),
  pos_integer(),
  non_neg_integer(),
  poly_tuple()
) -> poly_tuple().
step_ntt_j(J, End, Len, Z, A) when J < End ->
  Idx1 = J + 1,
  Idx2 = J + Len + 1,
  AJ = poly_get(Idx1, A),
  AJLen = poly_get(Idx2, A),
  T = (Z * AJLen) rem ?ML_KEM_Q,
  A1 = setelement(Idx2, A, (AJ - T + ?ML_KEM_Q) rem ?ML_KEM_Q),
  A2 = setelement(Idx1, A1, (AJ + T) rem ?ML_KEM_Q),
  step_ntt_j(J + 1, End, Len, Z, A2);
step_ntt_j(_, _, _, _, A) ->
  A.

%% @doc Inverse Number Theoretic Transform (NTT^-1) mapping T_q -> R_q.
-spec inv_ntt(poly()) -> poly().
inv_ntt(P_hat) ->
  A0 = list_to_tuple(P_hat),
  A_res = step_inv_len(2, 127, A0),
  [(poly_get(I, A_res) * ?ML_KEM_INV_128) rem ?ML_KEM_Q || I <- lists:seq(1, 256)].

-spec step_inv_len(pos_integer(), integer(), poly_tuple()) -> poly_tuple().
step_inv_len(Len, K0, A) when Len =< 128 ->
  {K_next, A_next} = step_inv_start(0, Len, K0, A),
  step_inv_len(Len * 2, K_next, A_next);
step_inv_len(_, _, A) ->
  A.

-spec step_inv_start(non_neg_integer(), pos_integer(), integer(), poly_tuple()) ->
  {integer(), poly_tuple()}.
step_inv_start(Start, Len, K, A) when Start < 256 ->
  Z = zeta(K + 1),
  A_step = step_inv_j(Start, Start + Len, Len, Z, A),
  step_inv_start(Start + 2 * Len, Len, K - 1, A_step);
step_inv_start(_, _, K, A) ->
  {K, A}.

-spec step_inv_j(
  non_neg_integer(),
  pos_integer(),
  pos_integer(),
  non_neg_integer(),
  poly_tuple()
) -> poly_tuple().
step_inv_j(J, End, Len, Z, A) when J < End ->
  Idx1 = J + 1,
  Idx2 = J + Len + 1,
  T = poly_get(Idx1, A),
  AJLen = poly_get(Idx2, A),
  A1 = setelement(Idx1, A, (T + AJLen) rem ?ML_KEM_Q),
  A2 = setelement(Idx2, A1, (Z * (AJLen - T + ?ML_KEM_Q)) rem ?ML_KEM_Q),
  step_inv_j(J + 1, End, Len, Z, A2);
step_inv_j(_, _, _, _, A) ->
  A.

-spec poly_get(pos_integer(), poly_tuple()) -> integer().
poly_get(Idx, A) ->
  case element(Idx, A) of
    V when is_integer(V) -> V
  end.

%% @doc Pointwise multiplication of two polynomials in the NTT domain.
-spec multiply_ntts(poly(), poly()) -> poly().
multiply_ntts(F_hat, G_hat) ->
  multiply_ntts_loop(F_hat, G_hat, 1).

-spec multiply_ntts_loop([non_neg_integer()], [non_neg_integer()], pos_integer()) -> poly().
multiply_ntts_loop([A0, A1 | As], [B0, B1 | Bs], I) ->
  Gamma = gamma(I),
  C0 = (A0 * B0 + A1 * B1 * Gamma) rem ?ML_KEM_Q,
  C1 = (A0 * B1 + A1 * B0) rem ?ML_KEM_Q,
  [C0, C1 | multiply_ntts_loop(As, Bs, I + 1)];
multiply_ntts_loop([], [], 129) ->
  [].

-spec zeta(pos_integer()) -> non_neg_integer().
zeta(Idx) ->
  case element(Idx, zetas()) of
    V when is_integer(V) -> V
  end.

-spec zetas() -> tuple().
zetas() ->
  ?ML_KEM_ZETAS.

-spec gamma(pos_integer()) -> non_neg_integer().
gamma(Idx) ->
  case element(Idx, gammas()) of
    V when is_integer(V) -> V
  end.

-spec gammas() -> tuple().
gammas() ->
  ?ML_KEM_GAMMAS.

-spec matrix_row_mul([poly()], [poly()]) -> poly().
matrix_row_mul(Row, Vec) ->
  ZeroPoly = [0 || _ <- lists:seq(1, 256)],
  lists:foldl(
    fun({A_elem, S_elem}, Acc) ->
      p_add(Acc, multiply_ntts(A_elem, S_elem))
    end,
    ZeroPoly,
    lists:zip(Row, Vec)
  ).

%% ===================================================================
%% Sampling & Compression Functions
%% ===================================================================

-spec sample_matrix_a(pos_integer(), <<_:256>>) -> [[poly()]].
sample_matrix_a(K, Rho) ->
  [
    [sample_ntt(Rho, J, I) || J <- lists:seq(0, K - 1)]
   || I <- lists:seq(0, K - 1)
  ].

-spec sample_matrix_a_transpose(pos_integer(), <<_:256>>) -> [[poly()]].
sample_matrix_a_transpose(K, Rho) ->
  [
    [sample_ntt(Rho, I, J) || J <- lists:seq(0, K - 1)]
   || I <- lists:seq(0, K - 1)
  ].

-spec sample_ntt(<<_:256>>, non_neg_integer(), non_neg_integer()) -> poly().
sample_ntt(Rho, J, I) ->
  sample_ntt_stream(Rho, J, I, 672, []).

-spec sample_ntt_stream(
  <<_:256>>,
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  [non_neg_integer()]
) -> poly().
sample_ntt_stream(Rho, J, I, ByteLen, Acc) ->
  Bytes = shake128(<<Rho/binary, J:8, I:8>>, ByteLen * 8),
  case sample_ntt_bytes(Bytes, Acc) of
    {ok, Coeffs} -> Coeffs;
    {need_more, PartialAcc} -> sample_ntt_stream(Rho, J, I, ByteLen + 168, PartialAcc)
  end.

-spec sample_ntt_bytes(binary(), [non_neg_integer()]) ->
  {ok, poly()} | {need_more, [non_neg_integer()]}.
sample_ntt_bytes(<<B0:8, B1:8, B2:8, Rest/binary>>, Acc) ->
  D1 = B0 bor ((B1 band 16#0F) bsl 8),
  D2 = (B1 bsr 4) bor (B2 bsl 4),
  Acc1 =
    if
      D1 < ?ML_KEM_Q -> [D1 | Acc];
      true -> Acc
    end,
  if
    length(Acc1) =:= 256 ->
      {ok, lists:reverse(Acc1)};
    true ->
      Acc2 =
        if
          D2 < ?ML_KEM_Q -> [D2 | Acc1];
          true -> Acc1
        end,
      if
        length(Acc2) =:= 256 ->
          {ok, lists:reverse(Acc2)};
        true ->
          sample_ntt_bytes(Rest, Acc2)
      end
  end;
sample_ntt_bytes(_, Acc) ->
  {need_more, Acc}.

-spec sample_poly_vector(pos_integer(), pos_integer(), <<_:256>>, non_neg_integer()) ->
  {[poly()], non_neg_integer()}.
sample_poly_vector(K, Eta, Seed, N0) ->
  sample_poly_vector_loop(K, Eta, Seed, N0, []).

-spec sample_poly_vector_loop(
  non_neg_integer(),
  pos_integer(),
  <<_:256>>,
  non_neg_integer(),
  [poly()]
) -> {[poly()], non_neg_integer()}.
sample_poly_vector_loop(0, _Eta, _Seed, N, Acc) ->
  {lists:reverse(Acc), N};
sample_poly_vector_loop(RemK, Eta, Seed, N, Acc) ->
  PolyBytes = prf(Eta, Seed, N),
  Poly = sample_poly_cbd(Eta, PolyBytes),
  sample_poly_vector_loop(RemK - 1, Eta, Seed, N + 1, [Poly | Acc]).

-spec prf(pos_integer(), <<_:256>>, non_neg_integer()) -> binary().
prf(Eta, Seed, N) ->
  shake256(<<Seed/binary, N:8>>, 64 * Eta * 8).

-spec shake128(binary(), pos_integer()) -> binary().
shake128(Data, BitLen) ->
  ecu_compat:hash_xof(shake128, Data, BitLen).

-spec shake256(binary(), pos_integer()) -> binary().
shake256(Data, BitLen) ->
  ecu_compat:hash_xof(shake256, Data, BitLen).

-spec sample_poly_cbd(pos_integer(), binary()) -> poly().
sample_poly_cbd(2, Bytes) when byte_size(Bytes) =:= 128 ->
  sample_cbd2(Bytes);
sample_poly_cbd(3, Bytes) when byte_size(Bytes) =:= 192 ->
  sample_cbd3(Bytes).

-spec sample_cbd2(binary()) -> poly().
sample_cbd2(<<Byte:8, Rest/binary>>) ->
  B0 = Byte band 1,
  B1 = (Byte bsr 1) band 1,
  B2 = (Byte bsr 2) band 1,
  B3 = (Byte bsr 3) band 1,
  B4 = (Byte bsr 4) band 1,
  B5 = (Byte bsr 5) band 1,
  B6 = (Byte bsr 6) band 1,
  B7 = (Byte bsr 7) band 1,
  C0 = (B0 + B1 - B2 - B3 + ?ML_KEM_Q) rem ?ML_KEM_Q,
  C1 = (B4 + B5 - B6 - B7 + ?ML_KEM_Q) rem ?ML_KEM_Q,
  [C0, C1 | sample_cbd2(Rest)];
sample_cbd2(<<>>) ->
  [].

-spec sample_cbd3(binary()) -> poly().
sample_cbd3(<<B0:8, B1:8, B2:8, Rest/binary>>) ->
  V = B0 bor (B1 bsl 8) bor (B2 bsl 16),
  [
    begin
      Shift = 6 * J,
      X0 = (V bsr Shift) band 1,
      X1 = (V bsr (Shift + 1)) band 1,
      X2 = (V bsr (Shift + 2)) band 1,
      Y0 = (V bsr (Shift + 3)) band 1,
      Y1 = (V bsr (Shift + 4)) band 1,
      Y2 = (V bsr (Shift + 5)) band 1,
      (X0 + X1 + X2 - Y0 - Y1 - Y2 + ?ML_KEM_Q) rem ?ML_KEM_Q
    end
   || J <- [0, 1, 2, 3]
  ] ++ sample_cbd3(Rest);
sample_cbd3(<<>>) ->
  [].

%% ===================================================================
%% Compression & Serialization
%% ===================================================================

-spec compress(pos_integer(), poly()) -> poly().
compress(D, Poly) ->
  Divisor = 1 bsl D,
  [
    (((X bsl D) + 1664) div ?ML_KEM_Q) rem Divisor
   || X <- Poly
  ].

-spec decompress(pos_integer(), poly()) -> poly().
decompress(D, Poly) ->
  Divisor = 1 bsl D,
  Half = 1 bsl (D - 1),
  [
    ((?ML_KEM_Q * Y) + Half) div Divisor
   || Y <- Poly
  ].

-spec byte_encode(pos_integer(), poly()) -> binary().
byte_encode(12, Poly) ->
  byte_encode_12(Poly);
byte_encode(11, Poly) ->
  byte_encode_11(Poly);
byte_encode(10, Poly) ->
  byte_encode_10(Poly);
byte_encode(5, Poly) ->
  byte_encode_5(Poly);
byte_encode(4, Poly) ->
  byte_encode_4(Poly);
byte_encode(1, Poly) ->
  byte_encode_1(Poly).

-spec byte_encode_12(poly()) -> binary().
byte_encode_12([C0, C1 | Rest]) ->
  B0 = C0 band 16#FF,
  B1 = (C0 bsr 8) bor ((C1 band 16#0F) bsl 4),
  B2 = (C1 bsr 4) band 16#FF,
  <<B0:8, B1:8, B2:8, (byte_encode_12(Rest))/binary>>;
byte_encode_12([]) ->
  <<>>.

-spec byte_encode_11(poly()) -> binary().
byte_encode_11([C0, C1, C2, C3, C4, C5, C6, C7 | Rest]) ->
  Val =
    C0 bor
      (C1 bsl 11) bor
      (C2 bsl 22) bor
      (C3 bsl 33) bor
      (C4 bsl 44) bor
      (C5 bsl 55) bor
      (C6 bsl 66) bor
      (C7 bsl 77),
  <<Val:88/little, (byte_encode_11(Rest))/binary>>;
byte_encode_11([]) ->
  <<>>.

-spec byte_encode_10(poly()) -> binary().
byte_encode_10([C0, C1, C2, C3 | Rest]) ->
  B0 = C0 band 16#FF,
  B1 = (C0 bsr 8) bor ((C1 band 16#3F) bsl 2),
  B2 = (C1 bsr 6) bor ((C2 band 16#0F) bsl 4),
  B3 = (C2 bsr 4) bor ((C3 band 16#03) bsl 6),
  B4 = (C3 bsr 2) band 16#FF,
  <<B0:8, B1:8, B2:8, B3:8, B4:8, (byte_encode_10(Rest))/binary>>;
byte_encode_10([]) ->
  <<>>.

-spec byte_encode_5(poly()) -> binary().
byte_encode_5([C0, C1, C2, C3, C4, C5, C6, C7 | Rest]) ->
  Val =
    C0 bor
      (C1 bsl 5) bor
      (C2 bsl 10) bor
      (C3 bsl 15) bor
      (C4 bsl 20) bor
      (C5 bsl 25) bor
      (C6 bsl 30) bor
      (C7 bsl 35),
  <<Val:40/little, (byte_encode_5(Rest))/binary>>;
byte_encode_5([]) ->
  <<>>.

-spec byte_encode_4(poly()) -> binary().
byte_encode_4([C0, C1 | Rest]) ->
  <<(C0 bor (C1 bsl 4)):8, (byte_encode_4(Rest))/binary>>;
byte_encode_4([]) ->
  <<>>.

-spec byte_encode_1(poly()) -> binary().
byte_encode_1([C0, C1, C2, C3, C4, C5, C6, C7 | Rest]) ->
  Val =
    (C0 band 1) bor
      ((C1 band 1) bsl 1) bor
      ((C2 band 1) bsl 2) bor
      ((C3 band 1) bsl 3) bor
      ((C4 band 1) bsl 4) bor
      ((C5 band 1) bsl 5) bor
      ((C6 band 1) bsl 6) bor
      ((C7 band 1) bsl 7),
  <<Val:8, (byte_encode_1(Rest))/binary>>;
byte_encode_1([]) ->
  <<>>.

-spec byte_decode(pos_integer(), binary()) -> poly().
byte_decode(12, Bytes) ->
  byte_decode_12(Bytes);
byte_decode(11, Bytes) ->
  byte_decode_11(Bytes);
byte_decode(10, Bytes) ->
  byte_decode_10(Bytes);
byte_decode(5, Bytes) ->
  byte_decode_5(Bytes);
byte_decode(4, Bytes) ->
  byte_decode_4(Bytes);
byte_decode(1, Bytes) ->
  byte_decode_1(Bytes).

-spec byte_decode_12(binary()) -> poly().
byte_decode_12(<<B0:8, B1:8, B2:8, Rest/binary>>) ->
  C0 = B0 bor ((B1 band 16#0F) bsl 8),
  C1 = (B1 bsr 4) bor (B2 bsl 4),
  [C0, C1 | byte_decode_12(Rest)];
byte_decode_12(<<>>) ->
  [].

-spec byte_decode_11(binary()) -> poly().
byte_decode_11(<<Val:88/little, Rest/binary>>) ->
  [
    (Val bsr Shift) band 16#7FF
   || Shift <- [0, 11, 22, 33, 44, 55, 66, 77]
  ] ++ byte_decode_11(Rest);
byte_decode_11(<<>>) ->
  [].

-spec byte_decode_10(binary()) -> poly().
byte_decode_10(<<B0:8, B1:8, B2:8, B3:8, B4:8, Rest/binary>>) ->
  C0 = B0 bor ((B1 band 16#03) bsl 8),
  C1 = (B1 bsr 2) bor ((B2 band 16#0F) bsl 6),
  C2 = (B2 bsr 4) bor ((B3 band 16#3F) bsl 4),
  C3 = (B3 bsr 6) bor (B4 bsl 2),
  [C0, C1, C2, C3 | byte_decode_10(Rest)];
byte_decode_10(<<>>) ->
  [].

-spec byte_decode_5(binary()) -> poly().
byte_decode_5(<<Val:40/little, Rest/binary>>) ->
  [
    (Val bsr Shift) band 16#1F
   || Shift <- [0, 5, 10, 15, 20, 25, 30, 35]
  ] ++ byte_decode_5(Rest);
byte_decode_5(<<>>) ->
  [].

-spec byte_decode_4(binary()) -> poly().
byte_decode_4(<<B:8, Rest/binary>>) ->
  [B band 16#0F, B bsr 4 | byte_decode_4(Rest)];
byte_decode_4(<<>>) ->
  [].

-spec byte_decode_1(binary()) -> poly().
byte_decode_1(<<Val:8, Rest/binary>>) ->
  [
    (Val bsr Shift) band 1
   || Shift <- [0, 1, 2, 3, 4, 5, 6, 7]
  ] ++ byte_decode_1(Rest);
byte_decode_1(<<>>) ->
  [].

-spec decode_poly_vector(pos_integer(), non_neg_integer(), binary()) -> [poly()].
decode_poly_vector(_D, 0, <<>>) ->
  [];
decode_poly_vector(D, K, Bytes) ->
  PolyBytesLen = (256 * D) div 8,
  <<Chunk:PolyBytesLen/binary, Rest/binary>> = Bytes,
  [byte_decode(D, Chunk) | decode_poly_vector(D, K - 1, Rest)].

%% ===================================================================
%% Helpers & Validation
%% ===================================================================

-spec params(parameter_set()) ->
  {
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer(),
    pos_integer()
  }.
params(ml_kem_512) -> {2, 3, 2, 10, 4, 800, 768, 1632};
params(mlkem512) -> params(ml_kem_512);
params(ml_kem_768) -> {3, 2, 2, 10, 4, 1184, 1088, 2400};
params(mlkem768) -> params(ml_kem_768);
params(ml_kem_1024) -> {4, 2, 2, 11, 5, 1568, 1568, 3168};
params(mlkem1024) -> params(ml_kem_1024);
params(_) -> error(badarg).

-spec parameter_set_from_sk(secret_key()) -> parameter_set().
parameter_set_from_sk(SecretKey) ->
  case byte_size(SecretKey) of
    1632 -> ml_kem_512;
    2400 -> ml_kem_768;
    3168 -> ml_kem_1024;
    _ -> error(badarg)
  end.

-spec validate_public_key(pos_integer(), public_key()) -> ok | error.
validate_public_key(K, PublicKey) ->
  TBytesLen = 384 * K,
  <<TBytes:TBytesLen/binary, _/binary>> = PublicKey,
  PolyList = decode_poly_vector(12, K, TBytes),
  case
    lists:all(
      fun(Poly) -> lists:all(fun(C) -> C < ?ML_KEM_Q end, Poly) end,
      PolyList
    )
  of
    true -> ok;
    false -> error
  end.

-spec subtle_eq(binary(), binary()) -> boolean().
subtle_eq(A, B) when byte_size(A) =:= byte_size(B) ->
  Diff = lists:foldl(
    fun({X, Y}, Acc) -> Acc bor (X bxor Y) end,
    0,
    lists:zip(binary_to_list(A), binary_to_list(B))
  ),
  Diff =:= 0;
subtle_eq(_, _) ->
  false.
