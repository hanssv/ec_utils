%%%-------------------------------------------------------------------
%%% @doc
%%% Header definitions for ec_utils cryptographic backend selection.
%%%
%%% When compiled with `-DNO_CRYPTO', all references to OTP `crypto'
%%% are eliminated at compile time for pure-Erlang/Nerves/Wasm targets.
%%% @end
%%%-------------------------------------------------------------------

-ifndef(ECU_COMPAT_HRL).
-define(ECU_COMPAT_HRL, true).

-ifdef(NO_CRYPTO).
-define(ECU_NO_CRYPTO, true).
-endif.

-endif.
