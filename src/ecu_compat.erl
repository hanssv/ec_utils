%%%-------------------------------------------------------------------
%%% @doc
%%% Unified cryptographic gateway for ec_utils.
%%%
%%% Transparently dispatches cryptographic operations to OTP `crypto'
%%% when available (Mode 1), or pure-Erlang implementations (Mode 2).
%%%
%%% When compiled with `-DNO_CRYPTO', all calls to OTP `crypto' are
%%% stripped at compile time, leaving a zero-dependency pure BEAM module.
%%%
%%% Runtime mode can be queried or configured via:
%%%   - `ecu_compat:mode/0'
%%%   - `ecu_compat:set_mode/1' (default | pure | otp)
%%%   - Application env `{ec_utils, crypto_mode, Mode}'
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_compat).

-typing([eqwalizer]).

-include("ecu_compat.hrl").

-export([
  strong_rand_bytes/1,
  exor/2,
  hash/2,
  hash_xof/3,
  mac/4,
  hkdf/5,
  pbkdf2_hmac/5,
  mod_pow/3,
  is_crypto_available/0,
  mode/0,
  set_mode/1
]).

-type mode() :: default | pure | otp.
-type hash_algorithm() ::
  sha224
  | sha256
  | sha384
  | sha512
  | ripemd160
  | sha3_224
  | sha3_256
  | sha3_384
  | sha3_512
  | keccak256.

-type hmac_algorithm() :: ecu_hmac:hash_type().
-type xof_algorithm() :: shake128 | shake256.

-export_type([mode/0, hash_algorithm/0, hmac_algorithm/0, xof_algorithm/0]).

-define(MODE_KEY, {?MODULE, crypto_mode}).
-define(AVAIL_KEY, {?MODULE, crypto_available}).

%%%===================================================================
%%% Mode Configuration
%%%===================================================================

-spec mode() -> mode().
-ifdef(ECU_NO_CRYPTO).
mode() -> pure.
-else.
mode() ->
  case persistent_term:get(?MODE_KEY, undefined) of
    undefined ->
      Mode = application:get_env(ec_utils, crypto_mode, default),
      persistent_term:put(?MODE_KEY, Mode),
      Mode;
    Mode ->
      Mode
  end.
-endif.

-spec set_mode(mode()) -> ok.
-ifdef(ECU_NO_CRYPTO).
set_mode(pure) -> ok;
set_mode(_) -> erlang:error(no_crypto_compiled).
-else.
set_mode(Mode) when Mode =:= default; Mode =:= pure; Mode =:= otp ->
  persistent_term:put(?MODE_KEY, Mode),
  ok.
-endif.

-spec is_crypto_available() -> boolean().
-ifdef(ECU_NO_CRYPTO).
is_crypto_available() -> false.
-else.
is_crypto_available() ->
  case mode() of
    pure ->
      false;
    otp ->
      true;
    default ->
      case persistent_term:get(?AVAIL_KEY, undefined) of
        undefined ->
          Avail =
            case code:ensure_loaded(crypto) of
              {module, crypto} -> true;
              _ -> false
            end,
          persistent_term:put(?AVAIL_KEY, Avail),
          Avail;
        Avail ->
          Avail
      end
  end.
-endif.

%%%===================================================================
%%% Cryptographic Primitives
%%%===================================================================

-spec strong_rand_bytes(non_neg_integer()) -> binary().
-ifdef(ECU_NO_CRYPTO).
strong_rand_bytes(N) ->
  ecu_entropy:strong_rand_bytes(N).
-else.
strong_rand_bytes(N) ->
  case is_crypto_available() of
    true ->
      crypto:strong_rand_bytes(N);
    false ->
      ecu_entropy:strong_rand_bytes(N)
  end.
-endif.

-spec exor(binary() | iolist(), binary() | iolist()) -> binary().
-ifdef(ECU_NO_CRYPTO).
exor(A, B) ->
  ecu_entropy:exor(A, B).
-else.
exor(A, B) ->
  case is_crypto_available() of
    true ->
      crypto:exor(A, B);
    false ->
      ecu_entropy:exor(A, B)
  end.
-endif.

-spec hash(hash_algorithm(), binary() | iolist()) -> binary().
-ifdef(ECU_NO_CRYPTO).
hash(Alg, Data) ->
  pure_hash(Alg, Data).
-else.
hash(Alg, Data) ->
  case is_crypto_available() of
    true when Alg =/= keccak256 ->
      crypto:hash(Alg, Data);
    _ ->
      pure_hash(Alg, Data)
  end.
-endif.

-spec hash_xof(xof_algorithm(), binary() | iolist(), pos_integer()) -> binary().
-ifdef(ECU_NO_CRYPTO).
hash_xof(Alg, Data, BitLen) ->
  pure_hash_xof(Alg, Data, BitLen).
-else.
hash_xof(Alg, Data, BitLen) ->
  case is_crypto_available() of
    true ->
      crypto:hash_xof(Alg, Data, BitLen);
    false ->
      pure_hash_xof(Alg, Data, BitLen)
  end.
-endif.

-spec mac(hmac, hmac_algorithm(), binary() | iolist(), binary() | iolist()) -> binary().
-ifdef(ECU_NO_CRYPTO).
mac(hmac, Alg, Key, Data) ->
  ecu_hmac:hmac(Alg, Key, Data).
-else.
mac(hmac, ripemd160, Key, Data) ->
  ecu_hmac:hmac(ripemd160, Key, Data);
mac(hmac, Alg, Key, Data) ->
  case is_crypto_available() of
    true ->
      crypto:mac(hmac, Alg, Key, Data);
    false ->
      ecu_hmac:hmac(Alg, Key, Data)
  end.
-endif.

-spec hkdf(
  hmac_algorithm(),
  binary() | iolist(),
  binary() | iolist(),
  binary() | iolist(),
  non_neg_integer()
) -> binary().
hkdf(Alg, IKM, Salt, Info, Length) ->
  ecu_hkdf:hkdf(Alg, IKM, Salt, Info, Length).

-spec pbkdf2_hmac(
  hmac_algorithm(),
  binary() | iolist(),
  binary() | iolist(),
  pos_integer(),
  non_neg_integer()
) -> binary().
-ifdef(ECU_NO_CRYPTO).
pbkdf2_hmac(Digest, Password, Salt, Iterations, Length) ->
  ecu_pbkdf2:pbkdf2_hmac(Digest, Password, Salt, Iterations, Length).
-else.
pbkdf2_hmac(Digest, Password, Salt, Iterations, Length) ->
  case is_crypto_available() of
    true when
      Digest =:= sha224;
      Digest =:= sha256;
      Digest =:= sha384;
      Digest =:= sha512
    ->
      PassBin = to_binary(Password),
      SaltBin = to_binary(Salt),
      crypto:pbkdf2_hmac(Digest, PassBin, SaltBin, Iterations, Length);
    _ ->
      ecu_pbkdf2:pbkdf2_hmac(Digest, Password, Salt, Iterations, Length)
  end.
-endif.

-spec mod_pow(
  integer() | binary(),
  non_neg_integer() | binary(),
  pos_integer() | binary()
) -> binary() | error.
-ifdef(ECU_NO_CRYPTO).
mod_pow(A, B, P) ->
  pure_mod_pow(A, B, P).
-else.
mod_pow(A, B, P) ->
  case is_crypto_available() of
    true ->
      crypto:mod_pow(A, B, P);
    false ->
      pure_mod_pow(A, B, P)
  end.
-endif.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec pure_hash(hash_algorithm(), binary() | iolist()) -> binary().
pure_hash(sha224, Data) -> ecu_sha2:sha224(Data);
pure_hash(sha256, Data) -> ecu_sha2:sha256(Data);
pure_hash(sha384, Data) -> ecu_sha2:sha384(Data);
pure_hash(sha512, Data) -> ecu_sha2:sha512(Data);
pure_hash(ripemd160, Data) -> ecu_ripemd160:ripemd160(Data);
pure_hash(sha3_224, Data) -> ecu_keccak:sha3_224(Data);
pure_hash(sha3_256, Data) -> ecu_keccak:sha3_256(Data);
pure_hash(sha3_384, Data) -> ecu_keccak:sha3_384(Data);
pure_hash(sha3_512, Data) -> ecu_keccak:sha3_512(Data);
pure_hash(keccak256, Data) -> ecu_keccak:keccak256(Data).

-spec pure_hash_xof(xof_algorithm(), binary() | iolist(), pos_integer()) -> binary().
pure_hash_xof(shake128, Data, BitLen) ->
  ecu_keccak:shake128(Data, BitLen);
pure_hash_xof(shake256, Data, BitLen) ->
  ecu_keccak:shake256(Data, BitLen).

-spec pure_mod_pow(
  integer() | binary(),
  non_neg_integer() | binary(),
  pos_integer() | binary()
) -> binary() | error.
pure_mod_pow(A0, B0, P0) ->
  A = to_integer(A0),
  B = to_integer(B0),
  P = to_integer(P0),
  if
    P =< 0; B < 0 ->
      error;
    B =:= 0 ->
      binary:encode_unsigned(1 rem P);
    true ->
      Res = pure_mod_pow_loop(A rem P, B, P, 1),
      binary:encode_unsigned(Res)
  end.

-spec pure_mod_pow_loop(
  non_neg_integer(),
  non_neg_integer(),
  pos_integer(),
  non_neg_integer()
) -> non_neg_integer().
pure_mod_pow_loop(_Base, 0, _Mod, Acc) ->
  Acc;
pure_mod_pow_loop(Base, Exp, Mod, Acc) ->
  NewAcc =
    case Exp band 1 of
      1 -> (Acc * Base) rem Mod;
      0 -> Acc
    end,
  NewBase = (Base * Base) rem Mod,
  pure_mod_pow_loop(NewBase, Exp bsr 1, Mod, NewAcc).

-spec to_integer(integer() | binary()) -> integer().
to_integer(I) when is_integer(I) -> I;
to_integer(B) when is_binary(B) -> binary:decode_unsigned(B).

-ifndef(ECU_NO_CRYPTO).
-spec to_binary(binary() | iolist()) -> binary().
to_binary(Bin) when is_binary(Bin) -> Bin;
to_binary(List) when is_list(List) -> iolist_to_binary(List).
-endif.
