%%% Author      : Hans Svensson
%%% Description :
%%% Created     : 14 Jan 2022 by Hans Svensson
-module(ed25519_eqc).

-compile([export_all, nowarn_export_all]).

-include_lib("eqc/include/eqc.hrl").

%% Let's use enacl/libsodium as the oracle
-define(N, 16#1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED).

gen_large_n() ->
  ?LET(<<X:512>>, binary(64), 1 + (X rem (?N - 1))).

gen_scalar() ->
  ?LET(N, gen_large_n(), <<N:256/little>>).

gen_point() ->
  ?LET(S, gen_scalar(), enacl:crypto_ed25519_scalarmult_base_noclamp(S)).

prop_compress() ->
  ?FORALL(S, gen_scalar(),
    begin
      CompP = enacl:crypto_ed25519_scalarmult_base_noclamp(S),
      DecP  = ecu_ed25519:scalar_mul_base_noclamp(S),
      equals(CompP, ecu_ed25519:compress(DecP))
    end).

prop_decompress() ->
  ?FORALL(S, gen_scalar(),
    begin
      CompP = enacl:crypto_ed25519_scalarmult_base_noclamp(S),
      DecP  = ecu_ed25519:scalar_mul_base_noclamp(S),
      equal_pts(DecP, ecu_ed25519:decompress(CompP))
    end).

prop_compress_decompress() ->
  ?FORALL(P, gen_point(),
    equals(P, ecu_ed25519:compress(ecu_ed25519:decompress(P)))
  ).

prop_compress_decompress2() ->
  ?FORALL(S, gen_scalar(),
    begin
      P = ecu_ed25519:scalar_mul_base(S),
      equal_pts(P, ecu_ed25519:decompress(ecu_ed25519:compress(P)))
    end
  ).

%% prop_valid_point() ->
%%   ?FORALL(B, noshrink(binary(32)),
%%   begin
%%     Expected  = enacl:crypto_ed25519_is_valid_point(B),
%%     {X1, X2} =
%%     try
%%       DP = ecu_ed25519:decompress(B),
%%       {DP, ecu_ed25519:scalar_mul(ecu_ed25519:n(), DP)}
%%     catch _:_ -> {novalue, novalue} end,
%%     TestValue = try ecu_ed25519:on_curve(ecu_ed25519:decompress(B)) catch _:_ -> false end,
%%     if Expected /= TestValue -> eqc:format("Expected: ~p Got: ~p - for \"point\" ~250p\nDP: ~200p\nX2: ~200p\n", [Expected, TestValue, B, X1, X2]);
%%        true -> ok end,
%%     ?WHENFAIL(eqc:format("Expected: ~p Got: ~p - for \"point\" ~250p\nDP: ~200p\nX2: ~200p\n", [Expected, TestValue, B, X1, X2]),
%%               true orelse Expected == TestValue)
%%   end).

prop_generate_valid_point() ->
  ?FORALL(P, gen_point(),  ecu_ed25519:on_curve(ecu_ed25519:decompress(P))).

prop_scalar_mul_base() ->
  ?FORALL(S, gen_scalar(),
  begin
    E = enacl:crypto_ed25519_scalarmult_base(S),
    P = ecu_ed25519:scalar_mul_base(S),
    equals(E, ecu_ed25519:compress(P))
  end).

prop_scalar_mul_base_noclamp() ->
  ?FORALL(S, gen_scalar(),
  begin
    E = enacl:crypto_ed25519_scalarmult_base_noclamp(S),
    P = ecu_ed25519:scalar_mul_base_noclamp(S),
    equals(E, ecu_ed25519:compress(P))
  end).

prop_scalar_mul() ->
  ?FORALL({S, P0}, {gen_scalar(), gen_point()},
  begin
    E = enacl:crypto_ed25519_scalarmult(S, P0),
    P = ecu_ed25519:scalar_mul(S, P0),
    equals(E, ecu_ed25519:compress(P))
  end).

prop_scalar_mul_noclamp() ->
  ?FORALL({S, P0}, {gen_scalar(), gen_point()},
  begin
    E = enacl:crypto_ed25519_scalarmult_noclamp(S, P0),
    P = ecu_ed25519:scalar_mul_noclamp(S, ecu_ed25519:decompress(P0)),
    equals(E, ecu_ed25519:compress(P))
  end).

prop_arithmetics1() ->
  ?FORALL({P1, P2, P3}, {gen_point(), gen_point(), gen_point()},
  begin
    Res1 = ecu_ed25519:p_add(P1, ecu_ed25519:p_add(P2, P3)),
    Res2 = ecu_ed25519:p_add(ecu_ed25519:p_add(P1, P2), P3),
    equal_pts(Res1, Res2)
  end).

prop_arithmetics2() ->
  ?FORALL({P1, P2}, {gen_point(), gen_point()},
  begin
    Res1 = ecu_ed25519:p_sub(ecu_ed25519:p_add(P1, P2), P2),
    equal_pts(P1, Res1)
  end).

prop_dbl() ->
  ?FORALL(P, gen_point(),
  begin
    A = ecu_ed25519:p_add(P, P),
    B = ecu_ed25519:p_dbl(P),
    ?WHENFAIL(eqc:format("~p\n  /=\n~p\n", [ecu_ed25519:to_affine(A), ecu_ed25519:to_affine(B)]),
              ecu_ed25519:pt_eq(A, B))
  end).

equal_pts(P1, P2) ->
  ?WHENFAIL(eqc:format("~p\n  /=\n~p\n", [ecu_ed25519:to_affine(P1), ecu_ed25519:to_affine(P2)]),
            ecu_ed25519:pt_eq(P1, P2)).
