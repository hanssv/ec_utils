%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang Password-Based Key Derivation Function 2 (PBKDF2, RFC 2898 / PKCS #5).
%%%
%%% Implements PBKDF2 with HMAC-SHA512 (used in BIP-39 seed generation)
%%% and other SHA-2/SHA-3 hash algorithms without external dependencies.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_pbkdf2).

-typing([eqwalizer]).

-export([
  pbkdf2_hmac/5
]).

-type hash_type() :: ecu_hmac:hash_type().

-spec pbkdf2_hmac(
  hash_type(),
  binary() | iolist(),
  binary() | iolist(),
  pos_integer(),
  non_neg_integer()
) -> binary().
pbkdf2_hmac(_Digest, _Password, _Salt, _Iterations, 0) ->
  <<>>;
pbkdf2_hmac(sha512, Password, Salt, Iterations, Length) when
  is_integer(Iterations), Iterations > 0, is_integer(Length), Length > 0
->
  pbkdf2_sha512(to_binary(Password), to_binary(Salt), Iterations, Length);
pbkdf2_hmac(sha256, Password, Salt, Iterations, Length) when
  is_integer(Iterations), Iterations > 0, is_integer(Length), Length > 0
->
  pbkdf2_sha256(to_binary(Password), to_binary(Salt), Iterations, Length);
pbkdf2_hmac(Digest, Password, Salt, Iterations, Length) when
  is_integer(Iterations), Iterations > 0, is_integer(Length), Length > 0
->
  PassBin = to_binary(Password),
  SaltBin = to_binary(Salt),
  HLen = hash_len(Digest),
  TotalBlocks = (Length + HLen - 1) div HLen,
  Derived = pbkdf2_blocks(1, TotalBlocks, Digest, PassBin, SaltBin, Iterations, <<>>),
  binary:part(Derived, 0, Length).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec pbkdf2_sha512(binary(), binary(), pos_integer(), pos_integer()) -> binary().
pbkdf2_sha512(Password, Salt, Iterations, Length) ->
  KeyNorm =
    if
      byte_size(Password) > 128 ->
        ecu_sha2:sha512(Password);
      true ->
        Password
    end,
  PadZeros = 128 - byte_size(KeyNorm),
  <<K0:64, K1:64, K2:64, K3:64, K4:64, K5:64, K6:64, K7:64, K8:64, K9:64, K10:64, K11:64, K12:64, K13:64,
    K14:64,
    K15:64>> =
    <<KeyNorm/binary, 0:(PadZeros * 8)>>,
  IpadW = 16#3636363636363636,
  OpadW = 16#5c5c5c5c5c5c5c5c,
  Ki = <<
    (K0 bxor IpadW):64,
    (K1 bxor IpadW):64,
    (K2 bxor IpadW):64,
    (K3 bxor IpadW):64,
    (K4 bxor IpadW):64,
    (K5 bxor IpadW):64,
    (K6 bxor IpadW):64,
    (K7 bxor IpadW):64,
    (K8 bxor IpadW):64,
    (K9 bxor IpadW):64,
    (K10 bxor IpadW):64,
    (K11 bxor IpadW):64,
    (K12 bxor IpadW):64,
    (K13 bxor IpadW):64,
    (K14 bxor IpadW):64,
    (K15 bxor IpadW):64
  >>,
  Ko = <<
    (K0 bxor OpadW):64,
    (K1 bxor OpadW):64,
    (K2 bxor OpadW):64,
    (K3 bxor OpadW):64,
    (K4 bxor OpadW):64,
    (K5 bxor OpadW):64,
    (K6 bxor OpadW):64,
    (K7 bxor OpadW):64,
    (K8 bxor OpadW):64,
    (K9 bxor OpadW):64,
    (K10 bxor OpadW):64,
    (K11 bxor OpadW):64,
    (K12 bxor OpadW):64,
    (K13 bxor OpadW):64,
    (K14 bxor OpadW):64,
    (K15 bxor OpadW):64
  >>,
  InitState = ecu_sha2:init_state_512_split(),
  IState = ecu_sha2:compress_block_512_split(Ki, InitState),
  OState = ecu_sha2:compress_block_512_split(Ko, InitState),
  TotalBlocks = (Length + 63) div 64,
  Derived = pbkdf2_blocks_512(1, TotalBlocks, Password, Salt, Iterations, IState, OState, <<>>),
  binary:part(Derived, 0, Length).

-spec pbkdf2_blocks_512(
  pos_integer(),
  non_neg_integer(),
  binary(),
  binary(),
  pos_integer(),
  ecu_sha2:state512_split(),
  ecu_sha2:state512_split(),
  binary()
) -> binary().
pbkdf2_blocks_512(BlockIndex, TotalBlocks, _Password, _Salt, _Iterations, _IState, _OState, Acc) when
  BlockIndex > TotalBlocks
->
  Acc;
pbkdf2_blocks_512(BlockIndex, TotalBlocks, Password, Salt, Iterations, IState, OState, Acc) ->
  U1 = ecu_hmac:hmac(sha512, Password, <<Salt/binary, BlockIndex:32/big>>),
  <<U0_h:32, U0_l:32, U1_h:32, U1_l:32, U2_h:32, U2_l:32, U3_h:32, U3_l:32, U4_h:32, U4_l:32, U5_h:32,
    U5_l:32, U6_h:32, U6_l:32, U7_h:32, U7_l:32>> = U1,
  U = {
    U0_h,
    U0_l,
    U1_h,
    U1_l,
    U2_h,
    U2_l,
    U3_h,
    U3_l,
    U4_h,
    U4_l,
    U5_h,
    U5_l,
    U6_h,
    U6_l,
    U7_h,
    U7_l
  },
  Block = ecu_sha2:pbkdf2_loop_512(2, Iterations, IState, OState, U, U),
  pbkdf2_blocks_512(
    BlockIndex + 1,
    TotalBlocks,
    Password,
    Salt,
    Iterations,
    IState,
    OState,
    <<Acc/binary, Block/binary>>
  ).

-spec pbkdf2_sha256(binary(), binary(), pos_integer(), pos_integer()) -> binary().
pbkdf2_sha256(Password, Salt, Iterations, Length) ->
  KeyNorm =
    if
      byte_size(Password) > 64 ->
        ecu_sha2:sha256(Password);
      true ->
        Password
    end,
  PadZeros = 64 - byte_size(KeyNorm),
  <<K0:32, K1:32, K2:32, K3:32, K4:32, K5:32, K6:32, K7:32, K8:32, K9:32, K10:32, K11:32, K12:32, K13:32,
    K14:32,
    K15:32>> =
    <<KeyNorm/binary, 0:(PadZeros * 8)>>,
  IpadW = 16#36363636,
  OpadW = 16#5c5c5c5c,
  Ki = <<
    (K0 bxor IpadW):32,
    (K1 bxor IpadW):32,
    (K2 bxor IpadW):32,
    (K3 bxor IpadW):32,
    (K4 bxor IpadW):32,
    (K5 bxor IpadW):32,
    (K6 bxor IpadW):32,
    (K7 bxor IpadW):32,
    (K8 bxor IpadW):32,
    (K9 bxor IpadW):32,
    (K10 bxor IpadW):32,
    (K11 bxor IpadW):32,
    (K12 bxor IpadW):32,
    (K13 bxor IpadW):32,
    (K14 bxor IpadW):32,
    (K15 bxor IpadW):32
  >>,
  Ko = <<
    (K0 bxor OpadW):32,
    (K1 bxor OpadW):32,
    (K2 bxor OpadW):32,
    (K3 bxor OpadW):32,
    (K4 bxor OpadW):32,
    (K5 bxor OpadW):32,
    (K6 bxor OpadW):32,
    (K7 bxor OpadW):32,
    (K8 bxor OpadW):32,
    (K9 bxor OpadW):32,
    (K10 bxor OpadW):32,
    (K11 bxor OpadW):32,
    (K12 bxor OpadW):32,
    (K13 bxor OpadW):32,
    (K14 bxor OpadW):32,
    (K15 bxor OpadW):32
  >>,
  InitState = ecu_sha2:init_state_256(),
  IState = ecu_sha2:compress_block_256(Ki, InitState),
  OState = ecu_sha2:compress_block_256(Ko, InitState),
  TotalBlocks = (Length + 31) div 32,
  Derived = pbkdf2_blocks_256(1, TotalBlocks, Password, Salt, Iterations, IState, OState, <<>>),
  binary:part(Derived, 0, Length).

-spec pbkdf2_blocks_256(
  pos_integer(),
  non_neg_integer(),
  binary(),
  binary(),
  pos_integer(),
  ecu_sha2:state256(),
  ecu_sha2:state256(),
  binary()
) -> binary().
pbkdf2_blocks_256(BlockIndex, TotalBlocks, _Password, _Salt, _Iterations, _IState, _OState, Acc) when
  BlockIndex > TotalBlocks
->
  Acc;
pbkdf2_blocks_256(BlockIndex, TotalBlocks, Password, Salt, Iterations, IState, OState, Acc) ->
  U1 = ecu_hmac:hmac(sha256, Password, <<Salt/binary, BlockIndex:32/big>>),
  <<U0:32, U1_1:32, U2:32, U3:32, U4:32, U5:32, U6:32, U7:32>> = U1,
  Block =
    pbkdf2_loop_256(
      2,
      Iterations,
      IState,
      OState,
      U0,
      U1_1,
      U2,
      U3,
      U4,
      U5,
      U6,
      U7,
      U0,
      U1_1,
      U2,
      U3,
      U4,
      U5,
      U6,
      U7
    ),
  pbkdf2_blocks_256(
    BlockIndex + 1,
    TotalBlocks,
    Password,
    Salt,
    Iterations,
    IState,
    OState,
    <<Acc/binary, Block/binary>>
  ).

-spec pbkdf2_loop_256(
  pos_integer(),
  pos_integer(),
  ecu_sha2:state256(),
  ecu_sha2:state256(),
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
  non_neg_integer()
) -> binary().
pbkdf2_loop_256(
  Iter,
  Iterations,
  _IState,
  _OState,
  _U0,
  _U1,
  _U2,
  _U3,
  _U4,
  _U5,
  _U6,
  _U7,
  Acc0,
  Acc1,
  Acc2,
  Acc3,
  Acc4,
  Acc5,
  Acc6,
  Acc7
) when Iter > Iterations ->
  <<Acc0:32/big, Acc1:32/big, Acc2:32/big, Acc3:32/big, Acc4:32/big, Acc5:32/big, Acc6:32/big,
    Acc7:32/big>>;
pbkdf2_loop_256(
  Iter,
  Iterations,
  IState,
  OState,
  U0,
  U1,
  U2,
  U3,
  U4,
  U5,
  U6,
  U7,
  Acc0,
  Acc1,
  Acc2,
  Acc3,
  Acc4,
  Acc5,
  Acc6,
  Acc7
) ->
  {IH0, IH1, IH2, IH3, IH4, IH5, IH6, IH7} =
    ecu_sha2:compress_32b_msg_256(U0, U1, U2, U3, U4, U5, U6, U7, IState),
  {NewU0, NewU1, NewU2, NewU3, NewU4, NewU5, NewU6, NewU7} =
    ecu_sha2:compress_32b_msg_256(IH0, IH1, IH2, IH3, IH4, IH5, IH6, IH7, OState),
  pbkdf2_loop_256(
    Iter + 1,
    Iterations,
    IState,
    OState,
    NewU0,
    NewU1,
    NewU2,
    NewU3,
    NewU4,
    NewU5,
    NewU6,
    NewU7,
    Acc0 bxor NewU0,
    Acc1 bxor NewU1,
    Acc2 bxor NewU2,
    Acc3 bxor NewU3,
    Acc4 bxor NewU4,
    Acc5 bxor NewU5,
    Acc6 bxor NewU6,
    Acc7 bxor NewU7
  ).

-spec pbkdf2_blocks(
  pos_integer(),
  non_neg_integer(),
  hash_type(),
  binary(),
  binary(),
  pos_integer(),
  binary()
) -> binary().
pbkdf2_blocks(BlockIndex, TotalBlocks, _Digest, _Password, _Salt, _Iterations, Acc) when
  BlockIndex > TotalBlocks
->
  Acc;
pbkdf2_blocks(BlockIndex, TotalBlocks, Digest, Password, Salt, Iterations, Acc) ->
  U1 = ecu_hmac:hmac(Digest, Password, <<Salt/binary, BlockIndex:32/big>>),
  Block = pbkdf2_f(2, Iterations, Digest, Password, U1, U1),
  pbkdf2_blocks(
    BlockIndex + 1,
    TotalBlocks,
    Digest,
    Password,
    Salt,
    Iterations,
    <<Acc/binary, Block/binary>>
  ).

-spec pbkdf2_f(
  pos_integer(),
  pos_integer(),
  hash_type(),
  binary(),
  binary(),
  binary()
) -> binary().
pbkdf2_f(Iter, Iterations, _Digest, _Password, _PrevU, Acc) when Iter > Iterations ->
  Acc;
pbkdf2_f(Iter, Iterations, Digest, Password, PrevU, Acc) ->
  U = ecu_hmac:hmac(Digest, Password, PrevU),
  NewAcc = ecu_entropy:exor(Acc, U),
  pbkdf2_f(Iter + 1, Iterations, Digest, Password, U, NewAcc).

-spec to_binary(binary() | iolist()) -> binary().
to_binary(Bin) when is_binary(Bin) -> Bin;
to_binary(List) when is_list(List) -> iolist_to_binary(List).

-spec hash_len(hash_type()) -> pos_integer().
hash_len(sha224) -> 28;
hash_len(sha256) -> 32;
hash_len(sha384) -> 48;
hash_len(sha512) -> 64;
hash_len(ripemd160) -> 20;
hash_len(sha3_224) -> 28;
hash_len(sha3_256) -> 32;
hash_len(sha3_384) -> 48;
hash_len(sha3_512) -> 64.
