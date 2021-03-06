%%% File        : secp256k1_tests.erl
%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 22 Dec 2021 by Hans Svensson
-module(secp256k1_tests).

-compile([export_all, nowarn_export_all]).

-include_lib("eunit/include/eunit.hrl").

on_curve_test() ->
  %% https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/
  KnownPts =
    [{16#79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      16#483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8},
     {16#C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
      16#1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A},
     {16#F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
      16#388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672},
     {16#E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13,
      16#51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922},
     {16#2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4,
      16#D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6}],

  [ ?assert(ecu_secp256k1:on_curve(Pt)) || Pt <- KnownPts ],

  ?assert(not ecu_secp256k1:on_curve({42, 723})).

scalar_mul_test() ->
  %% https://chuckbatson.wordpress.com/2014/11/26/secp256k1-test-vectors/
  KnownPts =
    [{1,
      16#79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      16#483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8},
     {2,
      16#C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
      16#1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A},
     {3,
      16#F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
      16#388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672},
     {4,
      16#E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13,
      16#51ED993EA0D455B75642E2098EA51448D967AE33BFBDFE40CFE97BDC47739922},
     {5,
      16#2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4,
      16#D8AC222636E5E3D6D4DBA9DDA6C9C426F788271BAB0D6840DCA87D3AA6AC62D6},
     {20,
      16#4CE119C96E2FA357200B559B2F7DD5A5F02D5290AFF74B03F3E471B273211C97,
      16#12BA26DCB10EC1625DA61FA10A844C676162948271D96967450288EE9233DC3A},
     {112233445566778899,
      16#A90CC3D3F3E146DAADFC74CA1372207CB4B725AE708CEF713A98EDD73D99EF29,
      16#5A79D6B289610C68BC3B47F3D72F9788A26A06868B4D8E433E1E2AD76FB7DC76},
     {112233445566778899112233445566778899,
      16#E5A2636BCFD412EBF36EC45B19BFB68A1BC5F8632E678132B885F7DF99C5E9B3,
      16#736C1CE161AE27B405CAFD2A7520370153C2C861AC51D6C1D5985D9606B45F39}
    ],

  [ begin
      {X, Y} = ecu_secp256k1:scalar_mul_base(K),
      ?assertEqual({x, K, Ex}, {x, K, X}),
      ?assertEqual({y, K, Ey}, {y, K, Y})
    end || {K, Ex, Ey} <- KnownPts ].

compression_test() ->
  Test = fun(P) ->
             CP = ecu_secp256k1:compress(P),
             DP = ecu_secp256k1:decompress(CP),
%%              ?debugFmt("\nP : ~200p\nCP: ~200p\nDP: ~200p", [P, CP, DP]),
             ?assertEqual(P, DP)
         end,
  [ Test(ecu_secp256k1:scalar_mul_base(K)) || K <- lists:seq(10, 100) ].


