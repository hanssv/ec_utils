%%%-------------------------------------------------------------------
%%% @doc
%%% Curve and field parameters for BN254 (alt_bn128).
%%%
%%% References:
%%%   - EIP-196: Precompiled contracts for addition and scalar multiplication
%%%     on the elliptic curve alt_bn128
%%%     https://eips.ethereum.org/EIPS/eip-196
%%%   - EIP-197: Precompiled contracts for optimal ate pairing check
%%%     on the elliptic curve alt_bn128
%%%     https://eips.ethereum.org/EIPS/eip-197
%%% @end
%%%-------------------------------------------------------------------

-ifndef(ECU_BN254_HRL).
-define(ECU_BN254_HRL, true).

%% Base field modulus p (254 bits, p = 3 mod 4)
-define(BN254_P,
  16#30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
).

%% Subgroup order r (254 bits prime)
-define(BN254_R,
  16#30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
).

%% BN parameter x (positive: x = 4965661362426348881 = 0x44e992b44a6909f1)
-define(BN254_X, 16#44e992b44a6909f1).

%% Curve coefficient b for G1: y^2 = x^3 + 3
-define(BN254_B, 3).

%% G1 Generator (affine)
-define(BN254_G1_X, 1).
-define(BN254_G1_Y, 2).

%% G2 Twist curve coefficient b' = 3 / (9 + u) = (27 - 3u) / 82 over Fp2
%% b' = {b0, b1} = b0 + b1*u
%% 82^(-1) mod p = 16#2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5
%% 27 * 82^(-1) mod p:
-define(BN254_TWIST_B0,
  16#2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5
).
%% -3 * 82^(-1) mod p:
-define(BN254_TWIST_B1,
  16#9713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2
).

%% G2 Generator (affine, over Fp2: {c0, c1} where element is c0 + c1*u)
-define(BN254_G2_X0,
  16#1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
).
-define(BN254_G2_X1,
  16#198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
).
-define(BN254_G2_Y0,
  16#12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
).
-define(BN254_G2_Y1,
  16#090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
).

-endif.
