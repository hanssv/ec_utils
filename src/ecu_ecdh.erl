%%% File        : ecu_ecdh.erl
%%% Author      : Hans Svensson
%%% Description : Diffie-Hellman Key Exchange (X25519, X448, secp256k1)
%%% Created     : 28 Oct 2026 by Hans Svensson
-module(ecu_ecdh).

-typing([eqwalizer]).

-export([keypair/1,
         keypair_from_seed/2,
         compute_key/3,
         x25519/2,
         x448/2,
         clamp/2,
         ed25519_public_to_x25519/1,
         ed25519_secret_to_x25519/1]).

-include("ecu_secp256k1.hrl").

-define(P25519, 16#7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED).
-define(A24_25519, 121665).

-define(P448, 16#FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF).
-define(A24_448, 39081).

-type curve() :: x25519 | x448 | secp256k1.
-type privkey() :: <<_:256>> | <<_:448>>.
-type pubkey() :: <<_:256>> | <<_:448>> | <<_:520>> | ecu_secp256k1:pt_compressed() | ecu_secp256k1:pt_affine().

-export_type([curve/0, privkey/0, pubkey/0]).

%% @doc Generates a fresh keypair {PublicKey, PrivateKey} for the given curve.
-spec keypair(x25519) -> {<<_:256>>, <<_:256>>};
             (x448) -> {<<_:448>>, <<_:448>>};
             (secp256k1) -> {ecu_secp256k1:pt_compressed(), <<_:256>>}.
keypair(x25519) ->
  Priv = crypto:strong_rand_bytes(32),
  keypair_from_seed(x25519, Priv);
keypair(x448) ->
  Priv = crypto:strong_rand_bytes(56),
  keypair_from_seed(x448, Priv);
keypair(secp256k1) ->
  PrivInt = rnd_secp256k1_scalar(),
  Priv = <<PrivInt:256>>,
  {ecu_ecdsa:private_to_public(secp256k1, Priv), Priv}.

%% @doc Deterministically derives a keypair from a seed.
-spec keypair_from_seed(x25519, binary()) -> {<<_:256>>, <<_:256>>};
                       (x448, binary()) -> {<<_:448>>, <<_:448>>};
                       (secp256k1, binary()) -> {ecu_secp256k1:pt_compressed(), <<_:256>>}.
keypair_from_seed(x25519, Seed = <<_:32/bytes>>) ->
  Clamped = clamp(x25519, Seed),
  Pub = x25519(Clamped, <<9:256/little>>),
  {Pub, Clamped};
keypair_from_seed(x448, Seed = <<_:56/bytes>>) ->
  Clamped = clamp(x448, Seed),
  Pub = x448(Clamped, <<5:448/little>>),
  {Pub, Clamped};
keypair_from_seed(secp256k1, Seed = <<_:32/bytes>>) ->
  <<PrivInt0:256>> = Seed,
  PrivInt = case PrivInt0 rem ?N of
              0 -> 1;
              N -> N
            end,
  Priv = <<PrivInt:256>>,
  {ecu_ecdsa:private_to_public(secp256k1, Priv), Priv};
keypair_from_seed(_, _) ->
  error(badarg).

%% @doc Computes the shared secret using Diffie-Hellman key agreement.
%% For x25519: returns 32-byte shared secret via RFC 7748.
%% For x448: returns 56-byte shared secret via RFC 7748.
%% For secp256k1: returns 32-byte shared secret (the x-coordinate of [d_A] Q_B).
-spec compute_key(curve(), pubkey(), privkey()) -> binary().
compute_key(x25519, PeerPub = <<_:32/bytes>>, MyPriv = <<_:32/bytes>>) ->
  x25519(MyPriv, PeerPub);
compute_key(x448, PeerPub = <<_:56/bytes>>, MyPriv = <<_:56/bytes>>) ->
  x448(MyPriv, PeerPub);
compute_key(secp256k1, PeerPub, <<PrivInt:256>>) when PrivInt >= 1, PrivInt < ?N ->
  Pt = case PeerPub of
         <<_:33/bytes>> ->
           ecu_secp256k1:decompress(PeerPub);
         <<4:8, X:256, Y:256>> ->
           case valid_secp256k1_point({X, Y}) of
             true  -> {X, Y};
             false -> error(badarg)
           end;
         {X, Y} when is_integer(X), is_integer(Y) ->
           case valid_secp256k1_point({X, Y}) of
             true  -> {X, Y};
             false -> error(badarg)
           end;
         _ ->
           error(badarg)
       end,
  case ecu_secp256k1:scalar_mul(PrivInt, Pt) of
    {0, 0} -> error(point_at_infinity);
    {SX, _SY} -> <<SX:256>>
  end;
compute_key(_, _, _) ->
  error(badarg).

%% @doc RFC 7748 Section 5: The X25519 function.
%% Clamps the input scalar and evaluates the Montgomery ladder over GF(2^255 - 19).
-spec x25519(<<_:256>>, <<_:256>>) -> <<_:256>>.
x25519(Scalar = <<_:32/bytes>>, UCoord = <<_:32/bytes>>) ->
  Clamped = clamp(x25519, Scalar),
  <<KInt:256/little>> = Clamped,
  <<U0:31/binary, LastByte:8>> = UCoord,
  <<UInt:256/little>> = <<U0/binary, (LastByte band 127):8>>,
  X1 = UInt rem ?P25519,
  montgomery_ladder(KInt, X1, 254, ?A24_25519, ?P25519, 32);
x25519(_, _) ->
  error(badarg).

%% @doc RFC 7748 Section 5: The X448 function.
%% Clamps the input scalar and evaluates the Montgomery ladder over GF(2^448 - 2^224 - 1).
-spec x448(<<_:448>>, <<_:448>>) -> <<_:448>>.
x448(Scalar = <<_:56/bytes>>, UCoord = <<_:56/bytes>>) ->
  Clamped = clamp(x448, Scalar),
  <<KInt:448/little>> = Clamped,
  <<UInt:448/little>> = UCoord,
  X1 = UInt rem ?P448,
  montgomery_ladder(KInt, X1, 447, ?A24_448, ?P448, 56);
x448(_, _) ->
  error(badarg).

%% @doc RFC 7748 scalar clamping.
-spec clamp(x25519 | x448, binary()) -> binary().
clamp(x25519, <<K0:8, KMid:30/binary, K31:8>>) ->
  <<(K0 band 248):8, KMid/binary, ((K31 band 127) bor 64):8>>;
clamp(x448, <<K0:8, KMid:54/binary, K55:8>>) ->
  <<(K0 band 252):8, KMid/binary, (K55 bor 128):8>>;
clamp(_, _) ->
  error(badarg).

%% @doc Converts an Ed25519 public key (twisted Edwards point y) to an X25519
%% public key (Montgomery point u = (1 + y) / (1 - y) mod p).
%% Matches libsodium `crypto_sign_ed25519_pk_to_curve25519'.
-spec ed25519_public_to_x25519(<<_:256>>) -> <<_:256>>.
ed25519_public_to_x25519(EdPK = <<_:32/bytes>>) ->
  <<YBytes:31/binary, LastByte:8>> = EdPK,
  YLast = LastByte band 127,
  <<Y:256/little>> = <<YBytes/binary, YLast:8>>,
  case Y < ?P25519 of
    false -> error(badarg);
    true ->
      OneMinusY = (?P25519 - Y + 1) rem ?P25519,
      case OneMinusY of
        0 -> error(badarg);
        _ ->
          OnePlusY = (1 + Y) rem ?P25519,
          U = (OnePlusY * f_inv(OneMinusY, ?P25519)) rem ?P25519,
          <<U:256/little>>
      end
  end;
ed25519_public_to_x25519(_) ->
  error(badarg).

%% @doc Converts an Ed25519 secret key (either 32-byte seed or 64-byte secret key)
%% to an X25519 private key by hashing with SHA-512 and clamping the lower 32 bytes.
%% Matches libsodium `crypto_sign_ed25519_sk_to_curve25519'.
-spec ed25519_secret_to_x25519(binary()) -> <<_:256>>.
ed25519_secret_to_x25519(<<Seed:32/bytes, _:32/bytes>>) ->
  ed25519_secret_to_x25519(Seed);
ed25519_secret_to_x25519(Seed = <<_:32/bytes>>) ->
  <<H0:32/binary, _/binary>> = crypto:hash(sha512, Seed),
  clamp(x25519, H0);
ed25519_secret_to_x25519(_) ->
  error(badarg).

%% --- internal helpers

-spec montgomery_ladder(non_neg_integer(), non_neg_integer(), non_neg_integer(),
                        non_neg_integer(), pos_integer(), pos_integer()) -> binary().
montgomery_ladder(KInt, X1, TopBit, A24, P, ByteLen) ->
  {X2Fin, Z2Fin, X3Fin, Z3Fin, LastSwap} =
    ladder_loop(TopBit, KInt, X1, 1, 0, X1, 1, 0, A24, P),
  {X2Res, _} = cswap(LastSwap, X2Fin, X3Fin),
  {Z2Res, _} = cswap(LastSwap, Z2Fin, Z3Fin),
  InvZ = f_inv(Z2Res, P),
  OutInt = (X2Res * InvZ) rem P,
  <<OutInt:(ByteLen * 8)/little>>.

-spec ladder_loop(integer(), non_neg_integer(), non_neg_integer(),
                  non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(),
                  0 | 1, non_neg_integer(), pos_integer()) ->
    {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), 0 | 1}.
ladder_loop(T, _KInt, _X1, X2, Z2, X3, Z3, Swap, _A24, _P) when T < 0 ->
  {X2, Z2, X3, Z3, Swap};
ladder_loop(T, KInt, X1, X2, Z2, X3, Z3, Swap, A24, P) ->
  Kt = (KInt bsr T) band 1,
  NewSwap = Swap bxor Kt,
  {X2S, X3S} = cswap(NewSwap, X2, X3),
  {Z2S, Z3S} = cswap(NewSwap, Z2, Z3),

  A = (X2S + Z2S) rem P,
  AA = (A * A) rem P,
  B = (X2S - Z2S + P) rem P,
  BB = (B * B) rem P,
  E = (AA - BB + P) rem P,
  C = (X3S + Z3S) rem P,
  D = (X3S - Z3S + P) rem P,
  DA = (D * A) rem P,
  CB = (C * B) rem P,
  DAPlusCB = (DA + CB) rem P,
  X3Next = (DAPlusCB * DAPlusCB) rem P,
  DAMinusCB = (DA - CB + P) rem P,
  Z3Next = (X1 * ((DAMinusCB * DAMinusCB) rem P)) rem P,
  X2Next = (AA * BB) rem P,
  Z2Next = (E * (AA + A24 * E)) rem P,

  ladder_loop(T - 1, KInt, X1, X2Next, Z2Next, X3Next, Z3Next, Kt, A24, P).

-compile({inline, [cswap/3]}).
-spec cswap(0 | 1, non_neg_integer(), non_neg_integer()) ->
    {non_neg_integer(), non_neg_integer()}.
cswap(1, A, B) -> {B, A};
cswap(0, A, B) -> {A, B}.

-spec f_inv(non_neg_integer(), pos_integer()) -> non_neg_integer().
f_inv(0, _P) ->
  0;
f_inv(A, P) ->
  ecu_misc:exp_mod(A, P - 2, P).

-spec valid_secp256k1_point(term()) -> boolean().
valid_secp256k1_point({X, Y}) when is_integer(X), is_integer(Y) ->
  X >= 0 andalso X < ?P
  andalso Y >= 0 andalso Y < ?P
  andalso ecu_secp256k1:on_curve({X, Y});
valid_secp256k1_point(_) ->
  false.

-spec rnd_secp256k1_scalar() -> pos_integer().
rnd_secp256k1_scalar() ->
  <<K:256>> = crypto:strong_rand_bytes(32),
  case K == 0 orelse K >= ?N of
    true  -> rnd_secp256k1_scalar();
    false -> K
  end.
