%%%-------------------------------------------------------------------
%%% @doc
%%% RFC 9380: Hashing to Elliptic Curves and Subgroups.
%%%
%%% Implements deterministic encoding and hashing to elliptic curves with
%%% zero external C/NIF dependencies:
%%%   - secp256k1 (Simplified SWU with 3-isogeny, SHA-256)
%%%   - edwards25519 (Elligator 2 with rational map, SHA-512)
%%%   - edwards448 (Elligator 2 with rational map, SHAKE256)
%%%
%%% Supported ciphersuites (RFC 9380 Section 8):
%%%   - `secp256k1_xmd_sha256_sswu_ro' (`secp256k1_XMD:SHA-256_SSWU_RO_')
%%%   - `secp256k1_xmd_sha256_sswu_nu' (`secp256k1_XMD:SHA-256_SSWU_NU_')
%%%   - `edwards25519_xmd_sha512_ell2_ro' (`edwards25519_XMD:SHA-512_ELL2_RO_')
%%%   - `edwards25519_xmd_sha512_ell2_nu' (`edwards25519_XMD:SHA-512_ELL2_NU_')
%%%   - `edwards448_xof_shake256_ell2_ro' (`edwards448_XOF:SHAKE256_ELL2_RO_')
%%%   - `edwards448_xof_shake256_ell2_nu' (`edwards448_XOF:SHAKE256_ELL2_NU_')
%%%
%%% Reference:
%%%   RFC 9380: https://www.rfc-editor.org/rfc/rfc9380.html
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_h2c).

-typing([eqwalizer]).

-export_type([
  suite/0,
  pt_affine/0
]).

-type suite() ::
  secp256k1_xmd_sha256_sswu_ro
  | secp256k1_xmd_sha256_sswu_nu
  | edwards25519_xmd_sha512_ell2_ro
  | edwards25519_xmd_sha512_ell2_nu
  | edwards448_xof_shake256_ell2_ro
  | edwards448_xof_shake256_ell2_nu
  | binary().

-type pt_affine() :: {non_neg_integer(), non_neg_integer()}.

-export([
  hash_to_curve/2,
  hash_to_curve/3,
  encode_to_curve/2,
  encode_to_curve/3,
  hash_to_field/4,
  expand_message_xmd/4,
  expand_message_xof/3,
  map_to_curve/2,
  clear_cofactor/2
]).

-ifdef(TEST).
-compile([export_all, nowarn_export_all]).
-endif.

%% Field primes
-define(P_SECP256K1, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F).
-define(P_ED25519, ((1 bsl 255) - 19)).
-define(P_ED448, ((1 bsl 448) - (1 bsl 224) - 1)).

%% secp256k1 isogenous curve E': y'^2 = x'^3 + A' * x' + B'
-define(SECP_A_PRIME, 16#3F8731ABDD661ADCA08A5558F0F5D272E953D363CB6F0E5D405447C01A444533).
-define(SECP_B_PRIME, 1771).
-define(SECP_Z, (?P_SECP256K1 - 11)).
-define(SECP_C2, 16#31FDF302724013E57AD13FB38F842AFEEC184F00A74789DD286729C8303C4A59).

%% 3-isogeny coefficients for secp256k1 (RFC 9380 Appendix E.1)
-define(ISO_K10, 16#8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA8C7).
-define(ISO_K11, 16#7D3D4C80BC321D5B9F315CEA7FD44C5D595D2FC0BF63B92DFFF1044F17C6581).
-define(ISO_K12, 16#534C328D23F234E6E2A413DECA25CAECE4506144037C40314ECBD0B53D9DD262).
-define(ISO_K13, 16#8E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38E38DAAAAA88C).
-define(ISO_K20, 16#D35771193D94918A9CA34CCBB7B640DD86CD409542F8487D9FE6B745781EB49B).
-define(ISO_K21, 16#EDADC6F64383DC1DF7C4B2D51B54225406D36B641F5E41BBC52A56612A8C6D14).
-define(ISO_K30, 16#4BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684B8E38E23C).
-define(ISO_K31, 16#C75E0C32D5CB7C0FA9D0A54B12A0A6D5647AB046D686DA6FDFFC90FC201D71A3).
-define(ISO_K32, 16#29A6194691F91A73715209EF6512E576722830A201BE2018A765E85A9ECEE931).
-define(ISO_K33, 16#2F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F684BDA12F38E38D84).
-define(ISO_K40, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFF93B).
-define(ISO_K41, 16#7A06534BB8BDB49FD5E9E6632722C2989467C1BFC8E8D978DFB425D2685C2573).
-define(ISO_K42, 16#6484AA716545CA2CF3A70C3FA8FE337E0A3D21162F0D6299A7BF8192BFD2A76F).

%% Curve25519 & Ed25519 constants (RFC 9380 Appendix G.2.1 and G.2.2)
-define(ED25519_J, 486662).
-define(ED25519_C1_M, ((?P_ED25519 + 3) div 8)).
-define(ED25519_C4_M, ((?P_ED25519 - 5) div 8)).
-define(ED25519_C1_E, 16#0F26EDF460A006BBD27B08DC03FC4F7EC5A1D3D14B7D1A82CC6E04AAFF457E06).

%% Curve448 & Ed448 constants (RFC 9380 Appendix G.2.3 and G.2.4)
-define(ED448_J, 156326).
-define(ED448_C1_M, ((?P_ED448 - 3) div 4)).

%%====================================================================
%% API Functions
%%====================================================================

%% @doc Hashes an arbitrary message to an elliptic curve point using the
%% Random Oracle encoding (`hash_to_curve') with the suite's default DST.
-spec hash_to_curve(suite(), binary()) -> pt_affine().
hash_to_curve(Suite, Msg) when is_binary(Msg) ->
  SuiteAtom = normalize_suite(Suite),
  DST = default_dst(SuiteAtom),
  hash_to_curve(SuiteAtom, Msg, DST).

%% @doc Hashes an arbitrary message to an elliptic curve point using the
%% Random Oracle encoding (`hash_to_curve') with an explicit DST.
-spec hash_to_curve(suite(), binary(), binary()) -> pt_affine().
hash_to_curve(Suite, Msg, DST) when is_binary(Msg), is_binary(DST) ->
  SuiteAtom = normalize_suite(Suite),
  case is_ro_suite(SuiteAtom) of
    false ->
      error(badarg);
    true ->
      case byte_size(DST) of
        0 ->
          error(badarg);
        _ ->
          [U0, U1] = hash_to_field(Msg, DST, 2, SuiteAtom),
          Q0 = map_to_curve(SuiteAtom, U0),
          Q1 = map_to_curve(SuiteAtom, U1),
          R = p_add(SuiteAtom, Q0, Q1),
          clear_cofactor(SuiteAtom, R)
      end
  end.

%% @doc Encodes an arbitrary message to an elliptic curve point using the
%% Non-Uniform encoding (`encode_to_curve') with the suite's default DST.
-spec encode_to_curve(suite(), binary()) -> pt_affine().
encode_to_curve(Suite, Msg) when is_binary(Msg) ->
  SuiteAtom = normalize_suite(Suite),
  DST = default_dst(SuiteAtom),
  encode_to_curve(SuiteAtom, Msg, DST).

%% @doc Encodes an arbitrary message to an elliptic curve point using the
%% Non-Uniform encoding (`encode_to_curve') with an explicit DST.
-spec encode_to_curve(suite(), binary(), binary()) -> pt_affine().
encode_to_curve(Suite, Msg, DST) when is_binary(Msg), is_binary(DST) ->
  SuiteAtom = normalize_suite(Suite),
  case is_nu_suite(SuiteAtom) of
    false ->
      error(badarg);
    true ->
      case byte_size(DST) of
        0 ->
          error(badarg);
        _ ->
          [U0] = hash_to_field(Msg, DST, 1, SuiteAtom),
          Q = map_to_curve(SuiteAtom, U0),
          clear_cofactor(SuiteAtom, Q)
      end
  end.

%% @doc Hashes an arbitrary message to finite field elements according to
%% RFC 9380 Section 5.2.
-spec hash_to_field(binary(), binary(), pos_integer(), suite()) -> [non_neg_integer()].
hash_to_field(Msg, DST, Count, Suite) when
  is_binary(Msg), is_binary(DST), is_integer(Count), Count > 0
->
  SuiteAtom = normalize_suite(Suite),
  case byte_size(DST) of
    0 ->
      error(badarg);
    _ ->
      {P, L, ExpandFun} = suite_field_params(SuiteAtom),
      LenInBytes = Count * L,
      UniformBytes = ExpandFun(Msg, DST, LenInBytes),
      unpack_field_elements(UniformBytes, Count, L, P, [])
  end.

%% @doc Expands a message into a pseudo-random byte string using a Merkle-Damgaard
%% or sponge hash function (RFC 9380 Section 5.3.1).
-spec expand_message_xmd(binary(), binary(), pos_integer(), sha256 | sha512) -> binary().
expand_message_xmd(Msg, DST, LenInBytes, Hash) when
  is_binary(Msg),
  is_binary(DST),
  is_integer(LenInBytes),
  LenInBytes > 0,
  LenInBytes =< 65535,
  (Hash =:= sha256 orelse Hash =:= sha512)
->
  case byte_size(DST) of
    0 ->
      error(badarg);
    _ ->
      {BInBytes, SInBytes} =
        case Hash of
          sha256 -> {32, 64};
          sha512 -> {64, 128}
        end,
      Ell = (LenInBytes + BInBytes - 1) div BInBytes,
      if
        Ell > 255 ->
          error(badarg);
        true ->
          ActualDST =
            case byte_size(DST) > 255 of
              true -> crypto:hash(Hash, <<"H2C-OVERSIZE-DST-", DST/binary>>);
              false -> DST
            end,
          DSTLen = byte_size(ActualDST),
          DSTPrime = <<ActualDST/binary, DSTLen:8>>,
          ZPad = binary:copy(<<0>>, SInBytes),
          LIBStr = <<LenInBytes:16/big>>,
          MsgPrime = <<ZPad/binary, Msg/binary, LIBStr/binary, 0:8, DSTPrime/binary>>,
          B0 = crypto:hash(Hash, MsgPrime),
          B1 = crypto:hash(Hash, <<B0/binary, 1:8, DSTPrime/binary>>),
          UniformBytes = expand_xmd_loop(2, Ell, B0, B1, DSTPrime, Hash, [B1]),
          binary:part(UniformBytes, 0, LenInBytes)
      end
  end;
expand_message_xmd(_, _, _, _) ->
  error(badarg).

%% @doc Expands a message into a pseudo-random byte string using SHAKE256
%% extendable-output function (RFC 9380 Section 5.3.2).
-spec expand_message_xof(binary(), binary(), pos_integer()) -> binary().
expand_message_xof(Msg, DST, LenInBytes) when
  is_binary(Msg),
  is_binary(DST),
  is_integer(LenInBytes),
  LenInBytes > 0,
  LenInBytes =< 65535
->
  case byte_size(DST) of
    0 ->
      error(badarg);
    _ ->
      ActualDST =
        case byte_size(DST) > 255 of
          true ->
            %% For edwards448, k = 224, ceil(2 * k / 8) = 56 bytes
            ecu_keccak:shake256(<<"H2C-OVERSIZE-DST-", DST/binary>>, 56 * 8);
          false ->
            DST
        end,
      DSTLen = byte_size(ActualDST),
      DSTPrime = <<ActualDST/binary, DSTLen:8>>,
      MsgPrime = <<Msg/binary, LenInBytes:16/big, DSTPrime/binary>>,
      ecu_keccak:shake256(MsgPrime, LenInBytes * 8)
  end;
expand_message_xof(_, _, _) ->
  error(badarg).

%% @doc Maps a field element to a point on the curve (RFC 9380 Section 6).
-spec map_to_curve(suite(), non_neg_integer()) -> pt_affine().
map_to_curve(Suite, U) when is_integer(U), U >= 0 ->
  SuiteAtom = normalize_suite(Suite),
  case curve_family(SuiteAtom) of
    secp256k1 ->
      map_to_curve_secp256k1(U);
    edwards25519 ->
      map_to_curve_edwards25519(U);
    edwards448 ->
      map_to_curve_edwards448(U)
  end.

%% @doc Clears the curve cofactor on the given point (RFC 9380 Section 7).
-spec clear_cofactor(suite(), pt_affine()) -> pt_affine().
clear_cofactor(Suite, Pt) ->
  SuiteAtom = normalize_suite(Suite),
  case curve_family(SuiteAtom) of
    secp256k1 ->
      case ecu_secp256k1:on_curve(Pt) of
        true -> Pt;
        false -> error(badarg)
      end;
    edwards25519 ->
      case ecu_ed25519:on_curve(Pt) of
        true ->
          P = ecu_ed25519:scalar_mul_noclamp(8, Pt),
          ecu_ed25519:to_affine(P);
        false ->
          error(badarg)
      end;
    edwards448 ->
      case ecu_ed448:on_curve(Pt) of
        true ->
          P = ecu_ed448:scalar_mul_noclamp(4, Pt),
          ecu_ed448:to_affine(P);
        false ->
          error(badarg)
      end
  end.

-spec is_ro_suite(suite()) -> boolean().
is_ro_suite(secp256k1_xmd_sha256_sswu_ro) -> true;
is_ro_suite(edwards25519_xmd_sha512_ell2_ro) -> true;
is_ro_suite(edwards448_xof_shake256_ell2_ro) -> true;
is_ro_suite(_) -> false.

-spec is_nu_suite(suite()) -> boolean().
is_nu_suite(secp256k1_xmd_sha256_sswu_nu) -> true;
is_nu_suite(edwards25519_xmd_sha512_ell2_nu) -> true;
is_nu_suite(edwards448_xof_shake256_ell2_nu) -> true;
is_nu_suite(_) -> false.

%%====================================================================
%% Internal: Suite Normalization and Mapping
%%====================================================================

-spec normalize_suite(suite()) -> suite().
normalize_suite(secp256k1_xmd_sha256_sswu_ro) -> secp256k1_xmd_sha256_sswu_ro;
normalize_suite(secp256k1_xmd_sha256_sswu_nu) -> secp256k1_xmd_sha256_sswu_nu;
normalize_suite(edwards25519_xmd_sha512_ell2_ro) -> edwards25519_xmd_sha512_ell2_ro;
normalize_suite(edwards25519_xmd_sha512_ell2_nu) -> edwards25519_xmd_sha512_ell2_nu;
normalize_suite(edwards448_xof_shake256_ell2_ro) -> edwards448_xof_shake256_ell2_ro;
normalize_suite(edwards448_xof_shake256_ell2_nu) -> edwards448_xof_shake256_ell2_nu;
normalize_suite(<<"secp256k1_XMD:SHA-256_SSWU_RO_">>) -> secp256k1_xmd_sha256_sswu_ro;
normalize_suite(<<"secp256k1_XMD:SHA-256_SSWU_NU_">>) -> secp256k1_xmd_sha256_sswu_nu;
normalize_suite(<<"edwards25519_XMD:SHA-512_ELL2_RO_">>) -> edwards25519_xmd_sha512_ell2_ro;
normalize_suite(<<"edwards25519_XMD:SHA-512_ELL2_NU_">>) -> edwards25519_xmd_sha512_ell2_nu;
normalize_suite(<<"edwards448_XOF:SHAKE256_ELL2_RO_">>) -> edwards448_xof_shake256_ell2_ro;
normalize_suite(<<"edwards448_XOF:SHAKE256_ELL2_NU_">>) -> edwards448_xof_shake256_ell2_nu;
normalize_suite(_) -> error(badarg).

-spec default_dst(suite()) -> binary().
default_dst(secp256k1_xmd_sha256_sswu_ro) -> <<"secp256k1_XMD:SHA-256_SSWU_RO_">>;
default_dst(secp256k1_xmd_sha256_sswu_nu) -> <<"secp256k1_XMD:SHA-256_SSWU_NU_">>;
default_dst(edwards25519_xmd_sha512_ell2_ro) -> <<"edwards25519_XMD:SHA-512_ELL2_RO_">>;
default_dst(edwards25519_xmd_sha512_ell2_nu) -> <<"edwards25519_XMD:SHA-512_ELL2_NU_">>;
default_dst(edwards448_xof_shake256_ell2_ro) -> <<"edwards448_XOF:SHAKE256_ELL2_RO_">>;
default_dst(edwards448_xof_shake256_ell2_nu) -> <<"edwards448_XOF:SHAKE256_ELL2_NU_">>.

-spec curve_family(suite()) -> secp256k1 | edwards25519 | edwards448.
curve_family(secp256k1_xmd_sha256_sswu_ro) -> secp256k1;
curve_family(secp256k1_xmd_sha256_sswu_nu) -> secp256k1;
curve_family(edwards25519_xmd_sha512_ell2_ro) -> edwards25519;
curve_family(edwards25519_xmd_sha512_ell2_nu) -> edwards25519;
curve_family(edwards448_xof_shake256_ell2_ro) -> edwards448;
curve_family(edwards448_xof_shake256_ell2_nu) -> edwards448.

-spec suite_field_params(suite()) ->
  {pos_integer(), pos_integer(), fun((binary(), binary(), pos_integer()) -> binary())}.
suite_field_params(secp256k1_xmd_sha256_sswu_ro) ->
  {?P_SECP256K1, 48, fun(M, D, L) -> expand_message_xmd(M, D, L, sha256) end};
suite_field_params(secp256k1_xmd_sha256_sswu_nu) ->
  {?P_SECP256K1, 48, fun(M, D, L) -> expand_message_xmd(M, D, L, sha256) end};
suite_field_params(edwards25519_xmd_sha512_ell2_ro) ->
  {?P_ED25519, 48, fun(M, D, L) -> expand_message_xmd(M, D, L, sha512) end};
suite_field_params(edwards25519_xmd_sha512_ell2_nu) ->
  {?P_ED25519, 48, fun(M, D, L) -> expand_message_xmd(M, D, L, sha512) end};
suite_field_params(edwards448_xof_shake256_ell2_ro) ->
  {?P_ED448, 84, fun(M, D, L) -> expand_message_xof(M, D, L) end};
suite_field_params(edwards448_xof_shake256_ell2_nu) ->
  {?P_ED448, 84, fun(M, D, L) -> expand_message_xof(M, D, L) end}.

-spec unpack_field_elements(binary(), non_neg_integer(), pos_integer(), pos_integer(), [
  non_neg_integer()
]) ->
  [non_neg_integer()].
unpack_field_elements(_Bin, 0, _L, _P, Acc) ->
  lists:reverse(Acc);
unpack_field_elements(Bin, Count, L, P, Acc) ->
  <<Chunk:L/binary, Rest/binary>> = Bin,
  Val = binary:decode_unsigned(Chunk, big) rem P,
  unpack_field_elements(Rest, Count - 1, L, P, [Val | Acc]).

-spec expand_xmd_loop(
  pos_integer(),
  pos_integer(),
  binary(),
  binary(),
  binary(),
  sha256 | sha512,
  [binary()]
) -> binary().
expand_xmd_loop(I, Ell, _B0, _PrevB, _DSTPrime, _Hash, Acc) when I > Ell ->
  iolist_to_binary(lists:reverse(Acc));
expand_xmd_loop(I, Ell, B0, PrevB, DSTPrime, Hash, Acc) ->
  Bi = crypto:hash(Hash, <<(crypto:exor(B0, PrevB))/binary, I:8, DSTPrime/binary>>),
  expand_xmd_loop(I + 1, Ell, B0, Bi, DSTPrime, Hash, [Bi | Acc]).

%%====================================================================
%% Internal: Point Addition
%%====================================================================

-spec p_add(suite(), pt_affine(), pt_affine()) -> pt_affine().
p_add(Suite, P1, P2) ->
  case curve_family(Suite) of
    secp256k1 ->
      ecu_secp256k1:p_add(P1, P2);
    edwards25519 ->
      R = ecu_ed25519:p_add(P1, P2),
      ecu_ed25519:to_affine(R);
    edwards448 ->
      R = ecu_ed448:p_add(P1, P2),
      ecu_ed448:to_affine(R)
  end.

%%====================================================================
%% Internal: secp256k1 Simplified SWU + 3-Isogeny (RFC 9380 App E.1 / F.2)
%%====================================================================

-spec map_to_curve_secp256k1(non_neg_integer()) -> pt_affine().
map_to_curve_secp256k1(U) ->
  {Xp, Yp} = sswu_secp256k1(U rem ?P_SECP256K1),
  secp256k1_isogeny(Xp, Yp).

-spec sswu_secp256k1(non_neg_integer()) -> pt_affine().
sswu_secp256k1(U) ->
  P = ?P_SECP256K1,
  TV1 = f_mul(?SECP_Z, f_mul(U, U, P), P),
  TV2 = f_add(f_mul(TV1, TV1, P), TV1, P),
  TV3 = f_mul(?SECP_B_PRIME, f_add(TV2, 1, P), P),
  TV4_inner =
    case TV2 of
      0 -> ?SECP_Z;
      _ -> f_sub(0, TV2, P)
    end,
  TV4 = f_mul(?SECP_A_PRIME, TV4_inner, P),
  TV2_1 = f_add(f_mul(TV3, TV3, P), f_mul(?SECP_A_PRIME, f_mul(TV4, TV4, P), P), P),
  TV2_2 = f_mul(TV2_1, TV3, P),
  TV6 = f_mul(f_mul(TV4, TV4, P), TV4, P),
  TV2_3 = f_add(TV2_2, f_mul(?SECP_B_PRIME, TV6, P), P),
  X_cand = f_mul(TV1, TV3, P),
  {IsQR, Y1} = sqrt_ratio_3mod4(TV2_3, TV6, P, ?SECP_C2),
  Y_cand = f_mul(f_mul(TV1, U, P), Y1, P),
  X =
    case IsQR of
      true -> TV3;
      false -> X_cand
    end,
  Y =
    case IsQR of
      true -> Y1;
      false -> Y_cand
    end,
  E1 = (U rem 2 =:= Y rem 2),
  Y_fixed =
    case E1 of
      true -> Y;
      false -> f_sub(0, Y, P)
    end,
  X_final = f_mul(X, f_inv(TV4, P), P),
  {X_final, Y_fixed}.

-spec sqrt_ratio_3mod4(non_neg_integer(), non_neg_integer(), pos_integer(), non_neg_integer()) ->
  {boolean(), non_neg_integer()}.
sqrt_ratio_3mod4(U, V, P, C2) ->
  C1 = (P - 3) div 4,
  TV1 = f_mul(V, V, P),
  TV2 = f_mul(U, V, P),
  TV1_1 = f_mul(TV1, TV2, P),
  Y1 = f_mul(f_pow(TV1_1, C1, P), TV2, P),
  Y2 = f_mul(Y1, C2, P),
  TV3 = f_mul(f_mul(Y1, Y1, P), V, P),
  IsQR = (TV3 =:= U),
  Y =
    case IsQR of
      true -> Y1;
      false -> Y2
    end,
  {IsQR, Y}.

-spec secp256k1_isogeny(non_neg_integer(), non_neg_integer()) -> pt_affine().
secp256k1_isogeny(Xp, Yp) ->
  P = ?P_SECP256K1,
  Xp2 = f_mul(Xp, Xp, P),
  Xp3 = f_mul(Xp2, Xp, P),
  Xnum = f_add(
    f_add(
      f_add(f_mul(?ISO_K13, Xp3, P), f_mul(?ISO_K12, Xp2, P), P),
      f_mul(?ISO_K11, Xp, P),
      P
    ),
    ?ISO_K10,
    P
  ),
  Xden = f_add(f_add(Xp2, f_mul(?ISO_K21, Xp, P), P), ?ISO_K20, P),
  Ynum = f_add(
    f_add(
      f_add(f_mul(?ISO_K33, Xp3, P), f_mul(?ISO_K32, Xp2, P), P),
      f_mul(?ISO_K31, Xp, P),
      P
    ),
    ?ISO_K30,
    P
  ),
  Yden = f_add(
    f_add(
      f_add(Xp3, f_mul(?ISO_K42, Xp2, P), P),
      f_mul(?ISO_K41, Xp, P),
      P
    ),
    ?ISO_K40,
    P
  ),
  case Xden =:= 0 orelse Yden =:= 0 of
    true ->
      {0, 0};
    false ->
      X = f_mul(Xnum, f_inv(Xden, P), P),
      Y = f_mul(f_mul(Yp, Ynum, P), f_inv(Yden, P), P),
      {X, Y}
  end.

%%====================================================================
%% Internal: edwards25519 Elligator 2 + Birational Map (RFC 9380 App G.2.1/2)
%%====================================================================

-spec map_to_curve_edwards25519(non_neg_integer()) -> pt_affine().
map_to_curve_edwards25519(U) ->
  P = ?P_ED25519,
  Unorm = U rem P,
  {XMn, XMd, YMn, YMd} = elligator2_curve25519(Unorm),
  XN = f_mul(f_mul(XMn, YMd, P), ?ED25519_C1_E, P),
  XD = f_mul(XMd, YMn, P),
  YN = f_sub(XMn, XMd, P),
  YD = f_add(XMn, XMd, P),
  case f_mul(XD, YD, P) of
    0 -> {0, 1};
    _ -> {f_mul(XN, f_inv(XD, P), P), f_mul(YN, f_inv(YD, P), P)}
  end.

-spec elligator2_curve25519(non_neg_integer()) ->
  {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
elligator2_curve25519(U) ->
  P = ?P_ED25519,
  C2_M = f_pow(2, ?ED25519_C1_M, P),
  C3_M = f_pow(2, (P - 1) div 4, P),
  TV1 = f_mul(f_mul(U, U, P), 2, P),
  XD = f_add(TV1, 1, P),
  X1N = f_sub(0, ?ED25519_J, P),
  TV2 = f_mul(XD, XD, P),
  GXD = f_mul(TV2, XD, P),
  GX1 = f_mul(f_add(f_mul(f_mul(?ED25519_J, TV1, P), X1N, P), TV2, P), X1N, P),
  TV3 = f_mul(GXD, GXD, P),
  TV2_1 = f_mul(TV3, TV3, P),
  TV3_1 = f_mul(f_mul(TV3, GXD, P), GX1, P),
  TV2_2 = f_mul(TV2_1, TV3_1, P),
  Y11 = f_mul(f_pow(TV2_2, ?ED25519_C4_M, P), TV3_1, P),
  Y12 = f_mul(Y11, C3_M, P),
  TV2_3 = f_mul(f_mul(Y11, Y11, P), GXD, P),
  E1 = (TV2_3 =:= GX1),
  Y1 =
    case E1 of
      true -> Y11;
      false -> Y12
    end,
  X2N = f_mul(X1N, TV1, P),
  Y21 = f_mul(f_mul(Y11, U, P), C2_M, P),
  Y22 = f_mul(Y21, C3_M, P),
  GX2 = f_mul(GX1, TV1, P),
  TV2_4 = f_mul(f_mul(Y21, Y21, P), GXD, P),
  E2 = (TV2_4 =:= GX2),
  Y2 =
    case E2 of
      true -> Y21;
      false -> Y22
    end,
  TV2_5 = f_mul(f_mul(Y1, Y1, P), GXD, P),
  E3 = (TV2_5 =:= GX1),
  XN =
    case E3 of
      true -> X1N;
      false -> X2N
    end,
  Y_cand =
    case E3 of
      true -> Y1;
      false -> Y2
    end,
  E4 = (Y_cand rem 2 =:= 1),
  Y =
    case E3 xor E4 of
      true -> f_sub(0, Y_cand, P);
      false -> Y_cand
    end,
  {XN, XD, Y, 1}.

%%====================================================================
%% Internal: edwards448 Elligator 2 + 4-Isogeny (RFC 9380 App G.2.3/4)
%%====================================================================

-spec map_to_curve_edwards448(non_neg_integer()) -> pt_affine().
map_to_curve_edwards448(U) ->
  P = ?P_ED448,
  Unorm = U rem P,
  {Xn, Xd, Yn, Yd} = elligator2_curve448(Unorm),
  Xn2 = f_mul(Xn, Xn, P),
  Xd2 = f_mul(Xd, Xd, P),
  Xd4 = f_mul(Xd2, Xd2, P),
  Yn2 = f_mul(Yn, Yn, P),
  Yd2 = f_mul(Yd, Yd, P),
  XEn_0 = f_sub(Xn2, Xd2, P),
  TV2_0 = f_sub(XEn_0, Xd2, P),
  XEn = f_mul(f_mul(f_mul(f_mul(XEn_0, Xd2, P), Yd, P), Yn, P), 4, P),
  TV2_1 = f_mul(f_mul(TV2_0, Xn2, P), Yd2, P),
  TV3 = f_mul(4, Yn2, P),
  TV1_0 = f_mul(f_add(TV3, Yd2, P), Xd4, P),
  XEd = f_add(TV1_0, TV2_1, P),
  TV2_2 = f_mul(TV2_1, Xn, P),
  TV4_0 = f_mul(Xn, Xd4, P),
  YEn = f_sub(f_mul(f_sub(TV3, Yd2, P), TV4_0, P), TV2_2, P),
  TV1_1 = f_mul(f_mul(f_mul(f_add(Xn2, Xd2, P), Xd2, P), Xd, P), Yn2, P),
  TV1_2 = f_mul(f_sub(0, 2, P), TV1_1, P),
  YEd_0 = f_add(TV2_2, TV1_2, P),
  YEd = f_add(YEd_0, f_mul(TV4_0, Yd2, P), P),
  case f_mul(XEd, YEd, P) of
    0 -> {0, 1};
    _ -> {f_mul(XEn, f_inv(XEd, P), P), f_mul(YEn, f_inv(YEd, P), P)}
  end.

-spec elligator2_curve448(non_neg_integer()) ->
  {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
elligator2_curve448(U) ->
  P = ?P_ED448,
  TV1_init = f_mul(U, U, P),
  E1 = (TV1_init =:= 1),
  TV1 =
    case E1 of
      true -> 0;
      false -> TV1_init
    end,
  XD = f_sub(1, TV1, P),
  X1N = f_sub(0, ?ED448_J, P),
  TV2 = f_mul(XD, XD, P),
  GXD = f_mul(TV2, XD, P),
  GX1 = f_mul(f_add(f_mul(f_mul(f_sub(0, ?ED448_J, P), TV1, P), X1N, P), TV2, P), X1N, P),
  TV3 = f_mul(GXD, GXD, P),
  TV2_1 = f_mul(GX1, GXD, P),
  TV3_1 = f_mul(TV3, TV2_1, P),
  Y1 = f_mul(f_pow(TV3_1, ?ED448_C1_M, P), TV2_1, P),
  X2N = f_mul(f_sub(0, TV1, P), X1N, P),
  Y2 =
    case E1 of
      true -> 0;
      false -> f_mul(Y1, U, P)
    end,
  TV2_2 = f_mul(f_mul(Y1, Y1, P), GXD, P),
  E2 = (TV2_2 =:= GX1),
  XN =
    case E2 of
      true -> X1N;
      false -> X2N
    end,
  Y_cand =
    case E2 of
      true -> Y1;
      false -> Y2
    end,
  E3 = (Y_cand rem 2 =:= 1),
  Y =
    case E2 xor E3 of
      true -> f_sub(0, Y_cand, P);
      false -> Y_cand
    end,
  {XN, XD, Y, 1}.

%%====================================================================
%% Internal: Finite Field Arithmetic Helpers
%%====================================================================

-spec f_add(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
f_add(A, B, P) -> (A + B) rem P.

-spec f_sub(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
f_sub(A, B, P) -> (A - B + P) rem P.

-spec f_mul(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
f_mul(A, B, P) -> (A * B) rem P.

-spec f_pow(non_neg_integer(), non_neg_integer(), pos_integer()) -> non_neg_integer().
f_pow(Base, Exp, P) ->
  ecu_misc:exp_mod(Base rem P, Exp, P).

-spec f_inv(non_neg_integer(), pos_integer()) -> non_neg_integer().
f_inv(0, _P) -> 0;
f_inv(A, P) -> f_pow(A, P - 2, P).
