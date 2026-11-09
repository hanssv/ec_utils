%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang SHA-2 hash functions (FIPS 180-4 / RFC 6234).
%%%
%%% Implements:
%%%   - SHA-256 (32-byte digest)
%%%   - SHA-224 (28-byte digest)
%%%   - SHA-512 (64-byte digest)
%%%   - SHA-384 (48-byte digest)
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_sha2).

-typing([eqwalizer]).

-compile(
  {inline, [
    rotr32/2,
    rotr64/2,
    k_constants_256/0,
    k_constants_512/0
  ]}
).

-export([
  sha256/1,
  sha224/1,
  sha512/1,
  sha384/1,
  hash/2,
  init_state_256/0,
  init_state_512/0,
  compress_block_256/2,
  compress_block_512/2,
  compress_32b_msg_256/9,
  compress_64b_msg_512/9
]).

-export_type([
  state256/0,
  state512/0
]).

-define(MASK32, 16#ffffffff).
-define(MASK64, 16#ffffffffffffffff).

-type state256() :: {
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer()
}.

-type state512() :: {
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer()
}.

-spec hash(sha256 | sha224 | sha512 | sha384, binary() | iolist()) -> binary().
hash(sha256, Data) -> sha256(Data);
hash(sha224, Data) -> sha224(Data);
hash(sha512, Data) -> sha512(Data);
hash(sha384, Data) -> sha384(Data).

-spec sha256(binary() | iolist()) -> binary().
sha256(Data) ->
  Bin = to_binary(Data),
  Padded = pad_sha256(Bin),
  process_blocks_256(Padded, init_state_256()).

-spec sha224(binary() | iolist()) -> binary().
sha224(Data) ->
  Bin = to_binary(Data),
  Padded = pad_sha256(Bin),
  H0 = 16#c1059ed8,
  H1 = 16#367cd507,
  H2 = 16#3070dd17,
  H3 = 16#f70e5939,
  H4 = 16#ffc00b31,
  H5 = 16#68581511,
  H6 = 16#64f98fa7,
  H7 = 16#befa4fa4,
  <<Res:28/binary, _/binary>> = process_blocks_256(Padded, {H0, H1, H2, H3, H4, H5, H6, H7}),
  Res.

-spec sha512(binary() | iolist()) -> binary().
sha512(Data) ->
  Bin = to_binary(Data),
  Padded = pad_sha512(Bin),
  process_blocks_512(Padded, init_state_512()).

-spec sha384(binary() | iolist()) -> binary().
sha384(Data) ->
  Bin = to_binary(Data),
  Padded = pad_sha512(Bin),
  H0 = 16#cbbb9d5dc1059ed8,
  H1 = 16#629a292a367cd507,
  H2 = 16#9159015a3070dd17,
  H3 = 16#152fecd8f70e5939,
  H4 = 16#67332667ffc00b31,
  H5 = 16#8eb44a8768581511,
  H6 = 16#db0c2e0d64f98fa7,
  H7 = 16#47b5481dbefa4fa4,
  <<Res:48/binary, _/binary>> = process_blocks_512(Padded, {H0, H1, H2, H3, H4, H5, H6, H7}),
  Res.

-spec to_binary(binary() | iolist()) -> binary().
to_binary(B) when is_binary(B) -> B;
to_binary(L) -> iolist_to_binary(L).

%%%===================================================================
%%% SHA-256 Block Processing & Round Functions
%%%===================================================================

-spec pad_sha256(binary()) -> binary().
pad_sha256(Data) ->
  BitLen = byte_size(Data) * 8,
  PadLen = (56 - (byte_size(Data) + 1) rem 64 + 64) rem 64,
  <<Data/binary, 16#80, 0:(PadLen * 8), BitLen:64/big>>.

-spec process_blocks_256(binary(), state256()) -> binary().
process_blocks_256(<<>>, {H0, H1, H2, H3, H4, H5, H6, H7}) ->
  <<H0:32/big, H1:32/big, H2:32/big, H3:32/big, H4:32/big, H5:32/big, H6:32/big, H7:32/big>>;
process_blocks_256(<<Block:64/binary, Rest/binary>>, State) ->
  NewState = compress_block_256(Block, State),
  process_blocks_256(Rest, NewState).

-spec compress_block_256(binary(), state256()) -> state256().
compress_block_256(
  <<W0:32, W1:32, W2:32, W3:32, W4:32, W5:32, W6:32, W7:32, W8:32, W9:32, W10:32, W11:32, W12:32, W13:32,
    W14:32, W15:32>>,
  {H0, H1, H2, H3, H4, H5, H6, H7}
) ->
  {A, B, C, D, E, F, G, H} =
    rounds_0_to_15_256(
      16,
      W0,
      W1,
      W2,
      W3,
      W4,
      W5,
      W6,
      W7,
      W8,
      W9,
      W10,
      W11,
      W12,
      W13,
      W14,
      W15,
      H0,
      H1,
      H2,
      H3,
      H4,
      H5,
      H6,
      H7,
      k_constants_256()
    ),
  {
    (H0 + A) band ?MASK32,
    (H1 + B) band ?MASK32,
    (H2 + C) band ?MASK32,
    (H3 + D) band ?MASK32,
    (H4 + E) band ?MASK32,
    (H5 + F) band ?MASK32,
    (H6 + G) band ?MASK32,
    (H7 + H) band ?MASK32
  }.

-spec init_state_256() -> state256().
init_state_256() ->
  {
    16#6a09e667,
    16#bb67ae85,
    16#3c6ef372,
    16#a54ff53a,
    16#510e527f,
    16#9b05688c,
    16#1f83d9ab,
    16#5be0cd19
  }.

-spec compress_32b_msg_256(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  state256()
) -> state256().
compress_32b_msg_256(U0, U1, U2, U3, U4, U5, U6, U7, {H0, H1, H2, H3, H4, H5, H6, H7}) ->
  {A, B, C, D, E, F, G, H} =
    rounds_0_to_15_256(
      16,
      U0,
      U1,
      U2,
      U3,
      U4,
      U5,
      U6,
      U7,
      16#80000000,
      0,
      0,
      0,
      0,
      0,
      0,
      768,
      H0,
      H1,
      H2,
      H3,
      H4,
      H5,
      H6,
      H7,
      k_constants_256()
    ),
  {
    (H0 + A) band ?MASK32,
    (H1 + B) band ?MASK32,
    (H2 + C) band ?MASK32,
    (H3 + D) band ?MASK32,
    (H4 + E) band ?MASK32,
    (H5 + F) band ?MASK32,
    (H6 + G) band ?MASK32,
    (H7 + H) band ?MASK32
  }.

-spec rounds_0_to_15_256(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  [non_neg_integer()]
) -> state256().
rounds_0_to_15_256(
  0,
  W0,
  W1,
  W2,
  W3,
  W4,
  W5,
  W6,
  W7,
  W8,
  W9,
  W10,
  W11,
  W12,
  W13,
  W14,
  W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  Ks
) ->
  rounds_16_to_63_256(
    W0,
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    W7,
    W8,
    W9,
    W10,
    W11,
    W12,
    W13,
    W14,
    W15,
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    Ks
  );
rounds_0_to_15_256(
  N,
  W0,
  W1,
  W2,
  W3,
  W4,
  W5,
  W6,
  W7,
  W8,
  W9,
  W10,
  W11,
  W12,
  W13,
  W14,
  W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  [K | Ks]
) ->
  S1 = rotr32(E, 6) bxor rotr32(E, 11) bxor rotr32(E, 25),
  Ch = G bxor (E band (F bxor G)),
  Temp1 = (H + S1 + Ch + K + W0) band ?MASK32,
  S0 = rotr32(A, 2) bxor rotr32(A, 13) bxor rotr32(A, 22),
  Maj = (A band B) bxor ((A bxor B) band C),
  Temp2 = (S0 + Maj) band ?MASK32,
  NewA = (Temp1 + Temp2) band ?MASK32,
  NewE = (D + Temp1) band ?MASK32,
  rounds_0_to_15_256(
    N - 1,
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    W7,
    W8,
    W9,
    W10,
    W11,
    W12,
    W13,
    W14,
    W15,
    W0,
    NewA,
    A,
    B,
    C,
    NewE,
    E,
    F,
    G,
    Ks
  );
rounds_0_to_15_256(
  _N,
  _W0,
  _W1,
  _W2,
  _W3,
  _W4,
  _W5,
  _W6,
  _W7,
  _W8,
  _W9,
  _W10,
  _W11,
  _W12,
  _W13,
  _W14,
  _W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  []
) ->
  {A, B, C, D, E, F, G, H}.

-spec rounds_16_to_63_256(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  [non_neg_integer()]
) -> state256().
rounds_16_to_63_256(
  _W0,
  _W1,
  _W2,
  _W3,
  _W4,
  _W5,
  _W6,
  _W7,
  _W8,
  _W9,
  _W10,
  _W11,
  _W12,
  _W13,
  _W14,
  _W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  []
) ->
  {A, B, C, D, E, F, G, H};
rounds_16_to_63_256(
  W0,
  W1,
  W2,
  W3,
  W4,
  W5,
  W6,
  W7,
  W8,
  W9,
  W10,
  W11,
  W12,
  W13,
  W14,
  W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  [K | Ks]
) ->
  S0 = rotr32(W1, 7) bxor rotr32(W1, 18) bxor (W1 bsr 3),
  S1 = rotr32(W14, 17) bxor rotr32(W14, 19) bxor (W14 bsr 10),
  Wi = (W0 + S0 + W9 + S1) band ?MASK32,
  S1_round = rotr32(E, 6) bxor rotr32(E, 11) bxor rotr32(E, 25),
  Ch = G bxor (E band (F bxor G)),
  Temp1 = (H + S1_round + Ch + K + Wi) band ?MASK32,
  S0_round = rotr32(A, 2) bxor rotr32(A, 13) bxor rotr32(A, 22),
  Maj = (A band B) bxor ((A bxor B) band C),
  Temp2 = (S0_round + Maj) band ?MASK32,
  NewA = (Temp1 + Temp2) band ?MASK32,
  NewE = (D + Temp1) band ?MASK32,
  rounds_16_to_63_256(
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    W7,
    W8,
    W9,
    W10,
    W11,
    W12,
    W13,
    W14,
    W15,
    Wi,
    NewA,
    A,
    B,
    C,
    NewE,
    E,
    F,
    G,
    Ks
  ).

-spec rotr32(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
rotr32(X, N) ->
  (X bsr N) bor ((X band ((1 bsl N) - 1)) bsl (32 - N)).

-spec k_constants_256() -> [non_neg_integer()].
k_constants_256() ->
  [
    16#428a2f98,
    16#71374491,
    16#b5c0fbcf,
    16#e9b5dba5,
    16#3956c25b,
    16#59f111f1,
    16#923f82a4,
    16#ab1c5ed5,
    16#d807aa98,
    16#12835b01,
    16#243185be,
    16#550c7dc3,
    16#72be5d74,
    16#80deb1fe,
    16#9bdc06a7,
    16#c19bf174,
    16#e49b69c1,
    16#efbe4786,
    16#0fc19dc6,
    16#240ca1cc,
    16#2de92c6f,
    16#4a7484aa,
    16#5cb0a9dc,
    16#76f988da,
    16#983e5152,
    16#a831c66d,
    16#b00327c8,
    16#bf597fc7,
    16#c6e00bf3,
    16#d5a79147,
    16#06ca6351,
    16#14292967,
    16#27b70a85,
    16#2e1b2138,
    16#4d2c6dfc,
    16#53380d13,
    16#650a7354,
    16#766a0abb,
    16#81c2c92e,
    16#92722c85,
    16#a2bfe8a1,
    16#a81a664b,
    16#c24b8b70,
    16#c76c51a3,
    16#d192e819,
    16#d6990624,
    16#f40e3585,
    16#106aa070,
    16#19a4c116,
    16#1e376c08,
    16#2748774c,
    16#34b0bcb5,
    16#391c0cb3,
    16#4ed8aa4a,
    16#5b9cca4f,
    16#682e6ff3,
    16#748f82ee,
    16#78a5636f,
    16#84c87814,
    16#8cc70208,
    16#90befffa,
    16#a4506ceb,
    16#bef9a3f7,
    16#c67178f2
  ].

%%%===================================================================
%%% SHA-512 Block Processing & Round Functions
%%%===================================================================

-spec pad_sha512(binary()) -> binary().
pad_sha512(Data) ->
  BitLen = byte_size(Data) * 8,
  PadLen = (112 - (byte_size(Data) + 1) rem 128 + 128) rem 128,
  <<Data/binary, 16#80, 0:(PadLen * 8), BitLen:128/big>>.

-spec process_blocks_512(binary(), state512()) -> binary().
process_blocks_512(<<>>, {H0, H1, H2, H3, H4, H5, H6, H7}) ->
  <<H0:64/big, H1:64/big, H2:64/big, H3:64/big, H4:64/big, H5:64/big, H6:64/big, H7:64/big>>;
process_blocks_512(<<Block:128/binary, Rest/binary>>, State) ->
  NewState = compress_block_512(Block, State),
  process_blocks_512(Rest, NewState).

-spec compress_block_512(binary(), state512()) -> state512().
compress_block_512(
  <<W0:64, W1:64, W2:64, W3:64, W4:64, W5:64, W6:64, W7:64, W8:64, W9:64, W10:64, W11:64, W12:64, W13:64,
    W14:64, W15:64>>,
  {H0, H1, H2, H3, H4, H5, H6, H7}
) ->
  {A, B, C, D, E, F, G, H} =
    rounds_0_to_15_512(
      16,
      W0,
      W1,
      W2,
      W3,
      W4,
      W5,
      W6,
      W7,
      W8,
      W9,
      W10,
      W11,
      W12,
      W13,
      W14,
      W15,
      H0,
      H1,
      H2,
      H3,
      H4,
      H5,
      H6,
      H7,
      k_constants_512()
    ),
  {
    (H0 + A) band ?MASK64,
    (H1 + B) band ?MASK64,
    (H2 + C) band ?MASK64,
    (H3 + D) band ?MASK64,
    (H4 + E) band ?MASK64,
    (H5 + F) band ?MASK64,
    (H6 + G) band ?MASK64,
    (H7 + H) band ?MASK64
  }.

-spec init_state_512() -> state512().
init_state_512() ->
  {
    16#6a09e667f3bcc908,
    16#bb67ae8584caa73b,
    16#3c6ef372fe94f82b,
    16#a54ff53a5f1d36f1,
    16#510e527fade682d1,
    16#9b05688c2b3e6c1f,
    16#1f83d9abfb41bd6b,
    16#5be0cd19137e2179
  }.

-spec compress_64b_msg_512(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  state512()
) -> state512().
compress_64b_msg_512(U0, U1, U2, U3, U4, U5, U6, U7, {H0, H1, H2, H3, H4, H5, H6, H7}) ->
  {A, B, C, D, E, F, G, H} =
    rounds_0_to_15_512(
      16,
      U0,
      U1,
      U2,
      U3,
      U4,
      U5,
      U6,
      U7,
      16#8000000000000000,
      0,
      0,
      0,
      0,
      0,
      0,
      1536,
      H0,
      H1,
      H2,
      H3,
      H4,
      H5,
      H6,
      H7,
      k_constants_512()
    ),
  {
    (H0 + A) band ?MASK64,
    (H1 + B) band ?MASK64,
    (H2 + C) band ?MASK64,
    (H3 + D) band ?MASK64,
    (H4 + E) band ?MASK64,
    (H5 + F) band ?MASK64,
    (H6 + G) band ?MASK64,
    (H7 + H) band ?MASK64
  }.

-spec rounds_0_to_15_512(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  [non_neg_integer()]
) -> state512().
rounds_0_to_15_512(
  0,
  W0,
  W1,
  W2,
  W3,
  W4,
  W5,
  W6,
  W7,
  W8,
  W9,
  W10,
  W11,
  W12,
  W13,
  W14,
  W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  Ks
) ->
  rounds_16_to_79_512(
    W0,
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    W7,
    W8,
    W9,
    W10,
    W11,
    W12,
    W13,
    W14,
    W15,
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    Ks
  );
rounds_0_to_15_512(
  N,
  W0,
  W1,
  W2,
  W3,
  W4,
  W5,
  W6,
  W7,
  W8,
  W9,
  W10,
  W11,
  W12,
  W13,
  W14,
  W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  [K | Ks]
) ->
  S1 = rotr64(E, 14) bxor rotr64(E, 18) bxor rotr64(E, 41),
  Ch = G bxor (E band (F bxor G)),
  Temp1 = (H + S1 + Ch + K + W0) band ?MASK64,
  S0 = rotr64(A, 28) bxor rotr64(A, 34) bxor rotr64(A, 39),
  Maj = (A band B) bxor ((A bxor B) band C),
  Temp2 = (S0 + Maj) band ?MASK64,
  NewA = (Temp1 + Temp2) band ?MASK64,
  NewE = (D + Temp1) band ?MASK64,
  rounds_0_to_15_512(
    N - 1,
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    W7,
    W8,
    W9,
    W10,
    W11,
    W12,
    W13,
    W14,
    W15,
    W0,
    NewA,
    A,
    B,
    C,
    NewE,
    E,
    F,
    G,
    Ks
  );
rounds_0_to_15_512(
  _N,
  _W0,
  _W1,
  _W2,
  _W3,
  _W4,
  _W5,
  _W6,
  _W7,
  _W8,
  _W9,
  _W10,
  _W11,
  _W12,
  _W13,
  _W14,
  _W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  []
) ->
  {A, B, C, D, E, F, G, H}.

-spec rounds_16_to_79_512(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  [non_neg_integer()]
) -> state512().
rounds_16_to_79_512(
  _W0,
  _W1,
  _W2,
  _W3,
  _W4,
  _W5,
  _W6,
  _W7,
  _W8,
  _W9,
  _W10,
  _W11,
  _W12,
  _W13,
  _W14,
  _W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  []
) ->
  {A, B, C, D, E, F, G, H};
rounds_16_to_79_512(
  W0,
  W1,
  W2,
  W3,
  W4,
  W5,
  W6,
  W7,
  W8,
  W9,
  W10,
  W11,
  W12,
  W13,
  W14,
  W15,
  A,
  B,
  C,
  D,
  E,
  F,
  G,
  H,
  [K | Ks]
) ->
  S0 = rotr64(W1, 1) bxor rotr64(W1, 8) bxor (W1 bsr 7),
  S1 = rotr64(W14, 19) bxor rotr64(W14, 61) bxor (W14 bsr 6),
  Wi = (W0 + S0 + W9 + S1) band ?MASK64,
  S1_round = rotr64(E, 14) bxor rotr64(E, 18) bxor rotr64(E, 41),
  Ch = G bxor (E band (F bxor G)),
  Temp1 = (H + S1_round + Ch + K + Wi) band ?MASK64,
  S0_round = rotr64(A, 28) bxor rotr64(A, 34) bxor rotr64(A, 39),
  Maj = (A band B) bxor ((A bxor B) band C),
  Temp2 = (S0_round + Maj) band ?MASK64,
  NewA = (Temp1 + Temp2) band ?MASK64,
  NewE = (D + Temp1) band ?MASK64,
  rounds_16_to_79_512(
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    W7,
    W8,
    W9,
    W10,
    W11,
    W12,
    W13,
    W14,
    W15,
    Wi,
    NewA,
    A,
    B,
    C,
    NewE,
    E,
    F,
    G,
    Ks
  ).

-spec rotr64(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
rotr64(X, N) ->
  (X bsr N) bor ((X band ((1 bsl N) - 1)) bsl (64 - N)).

-spec k_constants_512() -> [non_neg_integer()].
k_constants_512() ->
  [
    16#428a2f98d728ae22,
    16#7137449123ef65cd,
    16#b5c0fbcfec4d3b2f,
    16#e9b5dba58189dbbc,
    16#3956c25bf348b538,
    16#59f111f1b605d019,
    16#923f82a4af194f9b,
    16#ab1c5ed5da6d8118,
    16#d807aa98a3030242,
    16#12835b0145706fbe,
    16#243185be4ee4b28c,
    16#550c7dc3d5ffb4e2,
    16#72be5d74f27b896f,
    16#80deb1fe3b1696b1,
    16#9bdc06a725c71235,
    16#c19bf174cf692694,
    16#e49b69c19ef14ad2,
    16#efbe4786384f25e3,
    16#0fc19dc68b8cd5b5,
    16#240ca1cc77ac9c65,
    16#2de92c6f592b0275,
    16#4a7484aa6ea6e483,
    16#5cb0a9dcbd41fbd4,
    16#76f988da831153b5,
    16#983e5152ee66dfab,
    16#a831c66d2db43210,
    16#b00327c898fb213f,
    16#bf597fc7beef0ee4,
    16#c6e00bf33da88fc2,
    16#d5a79147930aa725,
    16#06ca6351e003826f,
    16#142929670a0e6e70,
    16#27b70a8546d22ffc,
    16#2e1b21385c26c926,
    16#4d2c6dfc5ac42aed,
    16#53380d139d95b3df,
    16#650a73548baf63de,
    16#766a0abb3c77b2a8,
    16#81c2c92e47edaee6,
    16#92722c851482353b,
    16#a2bfe8a14cf10364,
    16#a81a664bbc423001,
    16#c24b8b70d0f89791,
    16#c76c51a30654be30,
    16#d192e819d6ef5218,
    16#d69906245565a910,
    16#f40e35855771202a,
    16#106aa07032bbd1b8,
    16#19a4c116b8d2d0c8,
    16#1e376c085141ab53,
    16#2748774cdf8eeb99,
    16#34b0bcb5e19b48a8,
    16#391c0cb3c5c95a63,
    16#4ed8aa4ae3418acb,
    16#5b9cca4f7763e373,
    16#682e6ff3d6b2b8a3,
    16#748f82ee5defb2fc,
    16#78a5636f43172f60,
    16#84c87814a1f0ab72,
    16#8cc702081a6439ec,
    16#90befffa23631e28,
    16#a4506cebde82bde9,
    16#bef9a3f7b2c67915,
    16#c67178f2e372532b,
    16#ca273eceea26619c,
    16#d186b8c721c0c207,
    16#eada7dd6cde0eb1e,
    16#f57d4f7fee6ed178,
    16#06f067aa72176fba,
    16#0a637dc5a2c898a6,
    16#113f9804bef90dae,
    16#1b710b35131c471b,
    16#28db77f523047d84,
    16#32caab7b40c72493,
    16#3c9ebe0a15c9bebc,
    16#431d67c49c100d4c,
    16#4cc5d4becb3e42b6,
    16#597f299cfc657e2a,
    16#5fcb6fab3ad6faec,
    16#6c44198c4a475817
  ].
