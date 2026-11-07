%%%-------------------------------------------------------------------
%%% @doc
%%% Curve and field parameters for BLS12-381.
%%%
%%% References:
%%%   - RFC 9380: https://www.rfc-editor.org/rfc/rfc9380.html
%%%   - draft-irtf-cfrg-pairing-friendly-curves:
%%%     https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves
%%%   - Zcash BLS12-381 specification:
%%%     https://github.com/zkcrypto/bls12_381
%%% @end
%%%-------------------------------------------------------------------

-ifndef(ECU_BLS12_381_HRL).
-define(ECU_BLS12_381_HRL, true).

%% Base field modulus p (381 bits, p = 3 mod 4)
-define(BLS12_381_P,
  16#1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
).

%% Subgroup order r (255 bits prime)
-define(BLS12_381_R,
  16#73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
).

%% BLS parameter x (negative: x = -0xd201000000010000)
-define(BLS12_381_X, -16#d201000000010000).
-define(BLS12_381_ABS_X, 16#d201000000010000).

%% Curve coefficient b for G1: y^2 = x^3 + 4
-define(BLS12_381_B, 4).

%% G1 Generator (affine)
-define(BLS12_381_G1_X,
  16#17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
).
-define(BLS12_381_G1_Y,
  16#08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1
).

%% G2 Generator (affine, over Fp2: {c0, c1} where element is c0 + c1*u)
-define(BLS12_381_G2_X0,
  16#024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
).
-define(BLS12_381_G2_X1,
  16#13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
).
-define(BLS12_381_G2_Y0,
  16#0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
).
-define(BLS12_381_G2_Y1,
  16#0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be
).

-endif.
