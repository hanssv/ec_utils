%%%-------------------------------------------------------------------
%%% @doc
%%% Pure-Erlang RIPEMD-160 hash function (RFC 2857 / ISO/IEC 10118-3).
%%%
%%% Implements the 160-bit cryptographic hash function developed by
%%% Dobbertin, Bosselaers, and Preneel (1996), producing a 20-byte digest.
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_ripemd160).

-typing([eqwalizer]).

-export([
  ripemd160/1,
  hash/1
]).

-define(MASK32, 16#ffffffff).

-spec hash(binary() | iolist()) -> binary().
hash(Data) ->
  ripemd160(Data).

-spec ripemd160(binary() | iolist()) -> binary().
ripemd160(Data) ->
  Bin = to_binary(Data),
  BitLen = byte_size(Bin) * 8,
  PadZeros =
    case (byte_size(Bin) + 1) rem 64 of
      Mod when Mod =< 56 -> 56 - Mod;
      Mod -> 56 + 64 - Mod
    end,
  Padded = <<Bin/binary, 16#80, 0:(PadZeros * 8), BitLen:64/little>>,
  process_blocks(Padded, 16#67452301, 16#efcdab89, 16#98badcfe, 16#10325476, 16#c3d2e1f0).

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec to_binary(binary() | iolist()) -> binary().
to_binary(Bin) when is_binary(Bin) -> Bin;
to_binary(List) when is_list(List) -> iolist_to_binary(List).

-spec process_blocks(
  binary(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer()
) -> binary().
process_blocks(<<>>, H0, H1, H2, H3, H4) ->
  <<H0:32/little, H1:32/little, H2:32/little, H3:32/little, H4:32/little>>;
process_blocks(
  <<X0:32/little, X1:32/little, X2:32/little, X3:32/little, X4:32/little, X5:32/little, X6:32/little,
    X7:32/little, X8:32/little, X9:32/little, X10:32/little, X11:32/little, X12:32/little, X13:32/little,
    X14:32/little, X15:32/little, Rest/binary>>,
  H0,
  H1,
  H2,
  H3,
  H4
) ->
  X = {X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15},
  {Aa, Bb, Cc, Dd, Ee} = round_left(H0, H1, H2, H3, H4, X),
  {A, B, C, D, E} = round_right(H0, H1, H2, H3, H4, X),
  T = (H1 + Cc + D) band ?MASK32,
  NewH1 = (H2 + Dd + E) band ?MASK32,
  NewH2 = (H3 + Ee + A) band ?MASK32,
  NewH3 = (H4 + Aa + B) band ?MASK32,
  NewH4 = (H0 + Bb + C) band ?MASK32,
  NewH0 = T,
  process_blocks(Rest, NewH0, NewH1, NewH2, NewH3, NewH4).

-spec round_left(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  {
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
  }
) ->
  {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
round_left(A0, B0, C0, D0, E0, {X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15}) ->
  A_L_1 = ((rol(11, (A0 + f0(B0, C0, D0) + X0 + 0) band 16#ffffffff) + E0) band 16#ffffffff),
  C_L_1 = rol(10, C0),
  E_L_2 =
    ((rol(14, (E0 + f0(A_L_1, B0, C_L_1) + X1 + 0) band 16#ffffffff) + D0) band 16#ffffffff),
  B_L_2 = rol(10, B0),
  D_L_3 =
    ((rol(15, (D0 + f0(E_L_2, A_L_1, B_L_2) + X2 + 0) band 16#ffffffff) + C_L_1) band
      16#ffffffff),
  A_L_3 = rol(10, A_L_1),
  C_L_4 =
    ((rol(12, (C_L_1 + f0(D_L_3, E_L_2, A_L_3) + X3 + 0) band 16#ffffffff) + B_L_2) band
      16#ffffffff),
  E_L_4 = rol(10, E_L_2),
  B_L_5 =
    ((rol(5, (B_L_2 + f0(C_L_4, D_L_3, E_L_4) + X4 + 0) band 16#ffffffff) + A_L_3) band
      16#ffffffff),
  D_L_5 = rol(10, D_L_3),
  A_L_6 =
    ((rol(8, (A_L_3 + f0(B_L_5, C_L_4, D_L_5) + X5 + 0) band 16#ffffffff) + E_L_4) band
      16#ffffffff),
  C_L_6 = rol(10, C_L_4),
  E_L_7 =
    ((rol(7, (E_L_4 + f0(A_L_6, B_L_5, C_L_6) + X6 + 0) band 16#ffffffff) + D_L_5) band
      16#ffffffff),
  B_L_7 = rol(10, B_L_5),
  D_L_8 =
    ((rol(9, (D_L_5 + f0(E_L_7, A_L_6, B_L_7) + X7 + 0) band 16#ffffffff) + C_L_6) band
      16#ffffffff),
  A_L_8 = rol(10, A_L_6),
  C_L_9 =
    ((rol(11, (C_L_6 + f0(D_L_8, E_L_7, A_L_8) + X8 + 0) band 16#ffffffff) + B_L_7) band
      16#ffffffff),
  E_L_9 = rol(10, E_L_7),
  B_L_10 =
    ((rol(13, (B_L_7 + f0(C_L_9, D_L_8, E_L_9) + X9 + 0) band 16#ffffffff) + A_L_8) band
      16#ffffffff),
  D_L_10 = rol(10, D_L_8),
  A_L_11 =
    ((rol(14, (A_L_8 + f0(B_L_10, C_L_9, D_L_10) + X10 + 0) band 16#ffffffff) + E_L_9) band
      16#ffffffff),
  C_L_11 = rol(10, C_L_9),
  E_L_12 =
    ((rol(15, (E_L_9 + f0(A_L_11, B_L_10, C_L_11) + X11 + 0) band 16#ffffffff) + D_L_10) band
      16#ffffffff),
  B_L_12 = rol(10, B_L_10),
  D_L_13 =
    ((rol(6, (D_L_10 + f0(E_L_12, A_L_11, B_L_12) + X12 + 0) band 16#ffffffff) + C_L_11) band
      16#ffffffff),
  A_L_13 = rol(10, A_L_11),
  C_L_14 =
    ((rol(7, (C_L_11 + f0(D_L_13, E_L_12, A_L_13) + X13 + 0) band 16#ffffffff) + B_L_12) band
      16#ffffffff),
  E_L_14 = rol(10, E_L_12),
  B_L_15 =
    ((rol(9, (B_L_12 + f0(C_L_14, D_L_13, E_L_14) + X14 + 0) band 16#ffffffff) + A_L_13) band
      16#ffffffff),
  D_L_15 = rol(10, D_L_13),
  A_L_16 =
    ((rol(8, (A_L_13 + f0(B_L_15, C_L_14, D_L_15) + X15 + 0) band 16#ffffffff) + E_L_14) band
      16#ffffffff),
  C_L_16 = rol(10, C_L_14),
  E_L_17 =
    ((rol(7, (E_L_14 + f1(A_L_16, B_L_15, C_L_16) + X7 + 16#5a827999) band 16#ffffffff) +
      D_L_15) band 16#ffffffff),
  B_L_17 = rol(10, B_L_15),
  D_L_18 =
    ((rol(6, (D_L_15 + f1(E_L_17, A_L_16, B_L_17) + X4 + 16#5a827999) band 16#ffffffff) +
      C_L_16) band 16#ffffffff),
  A_L_18 = rol(10, A_L_16),
  C_L_19 =
    ((rol(8, (C_L_16 + f1(D_L_18, E_L_17, A_L_18) + X13 + 16#5a827999) band 16#ffffffff) +
      B_L_17) band 16#ffffffff),
  E_L_19 = rol(10, E_L_17),
  B_L_20 =
    ((rol(13, (B_L_17 + f1(C_L_19, D_L_18, E_L_19) + X1 + 16#5a827999) band 16#ffffffff) +
      A_L_18) band 16#ffffffff),
  D_L_20 = rol(10, D_L_18),
  A_L_21 =
    ((rol(11, (A_L_18 + f1(B_L_20, C_L_19, D_L_20) + X10 + 16#5a827999) band 16#ffffffff) +
      E_L_19) band 16#ffffffff),
  C_L_21 = rol(10, C_L_19),
  E_L_22 =
    ((rol(9, (E_L_19 + f1(A_L_21, B_L_20, C_L_21) + X6 + 16#5a827999) band 16#ffffffff) +
      D_L_20) band 16#ffffffff),
  B_L_22 = rol(10, B_L_20),
  D_L_23 =
    ((rol(7, (D_L_20 + f1(E_L_22, A_L_21, B_L_22) + X15 + 16#5a827999) band 16#ffffffff) +
      C_L_21) band 16#ffffffff),
  A_L_23 = rol(10, A_L_21),
  C_L_24 =
    ((rol(15, (C_L_21 + f1(D_L_23, E_L_22, A_L_23) + X3 + 16#5a827999) band 16#ffffffff) +
      B_L_22) band 16#ffffffff),
  E_L_24 = rol(10, E_L_22),
  B_L_25 =
    ((rol(7, (B_L_22 + f1(C_L_24, D_L_23, E_L_24) + X12 + 16#5a827999) band 16#ffffffff) +
      A_L_23) band 16#ffffffff),
  D_L_25 = rol(10, D_L_23),
  A_L_26 =
    ((rol(12, (A_L_23 + f1(B_L_25, C_L_24, D_L_25) + X0 + 16#5a827999) band 16#ffffffff) +
      E_L_24) band 16#ffffffff),
  C_L_26 = rol(10, C_L_24),
  E_L_27 =
    ((rol(15, (E_L_24 + f1(A_L_26, B_L_25, C_L_26) + X9 + 16#5a827999) band 16#ffffffff) +
      D_L_25) band 16#ffffffff),
  B_L_27 = rol(10, B_L_25),
  D_L_28 =
    ((rol(9, (D_L_25 + f1(E_L_27, A_L_26, B_L_27) + X5 + 16#5a827999) band 16#ffffffff) +
      C_L_26) band 16#ffffffff),
  A_L_28 = rol(10, A_L_26),
  C_L_29 =
    ((rol(11, (C_L_26 + f1(D_L_28, E_L_27, A_L_28) + X2 + 16#5a827999) band 16#ffffffff) +
      B_L_27) band 16#ffffffff),
  E_L_29 = rol(10, E_L_27),
  B_L_30 =
    ((rol(7, (B_L_27 + f1(C_L_29, D_L_28, E_L_29) + X14 + 16#5a827999) band 16#ffffffff) +
      A_L_28) band 16#ffffffff),
  D_L_30 = rol(10, D_L_28),
  A_L_31 =
    ((rol(13, (A_L_28 + f1(B_L_30, C_L_29, D_L_30) + X11 + 16#5a827999) band 16#ffffffff) +
      E_L_29) band 16#ffffffff),
  C_L_31 = rol(10, C_L_29),
  E_L_32 =
    ((rol(12, (E_L_29 + f1(A_L_31, B_L_30, C_L_31) + X8 + 16#5a827999) band 16#ffffffff) +
      D_L_30) band 16#ffffffff),
  B_L_32 = rol(10, B_L_30),
  D_L_33 =
    ((rol(11, (D_L_30 + f2(E_L_32, A_L_31, B_L_32) + X3 + 16#6ed9eba1) band 16#ffffffff) +
      C_L_31) band 16#ffffffff),
  A_L_33 = rol(10, A_L_31),
  C_L_34 =
    ((rol(13, (C_L_31 + f2(D_L_33, E_L_32, A_L_33) + X10 + 16#6ed9eba1) band 16#ffffffff) +
      B_L_32) band 16#ffffffff),
  E_L_34 = rol(10, E_L_32),
  B_L_35 =
    ((rol(6, (B_L_32 + f2(C_L_34, D_L_33, E_L_34) + X14 + 16#6ed9eba1) band 16#ffffffff) +
      A_L_33) band 16#ffffffff),
  D_L_35 = rol(10, D_L_33),
  A_L_36 =
    ((rol(7, (A_L_33 + f2(B_L_35, C_L_34, D_L_35) + X4 + 16#6ed9eba1) band 16#ffffffff) +
      E_L_34) band 16#ffffffff),
  C_L_36 = rol(10, C_L_34),
  E_L_37 =
    ((rol(14, (E_L_34 + f2(A_L_36, B_L_35, C_L_36) + X9 + 16#6ed9eba1) band 16#ffffffff) +
      D_L_35) band 16#ffffffff),
  B_L_37 = rol(10, B_L_35),
  D_L_38 =
    ((rol(9, (D_L_35 + f2(E_L_37, A_L_36, B_L_37) + X15 + 16#6ed9eba1) band 16#ffffffff) +
      C_L_36) band 16#ffffffff),
  A_L_38 = rol(10, A_L_36),
  C_L_39 =
    ((rol(13, (C_L_36 + f2(D_L_38, E_L_37, A_L_38) + X8 + 16#6ed9eba1) band 16#ffffffff) +
      B_L_37) band 16#ffffffff),
  E_L_39 = rol(10, E_L_37),
  B_L_40 =
    ((rol(15, (B_L_37 + f2(C_L_39, D_L_38, E_L_39) + X1 + 16#6ed9eba1) band 16#ffffffff) +
      A_L_38) band 16#ffffffff),
  D_L_40 = rol(10, D_L_38),
  A_L_41 =
    ((rol(14, (A_L_38 + f2(B_L_40, C_L_39, D_L_40) + X2 + 16#6ed9eba1) band 16#ffffffff) +
      E_L_39) band 16#ffffffff),
  C_L_41 = rol(10, C_L_39),
  E_L_42 =
    ((rol(8, (E_L_39 + f2(A_L_41, B_L_40, C_L_41) + X7 + 16#6ed9eba1) band 16#ffffffff) +
      D_L_40) band 16#ffffffff),
  B_L_42 = rol(10, B_L_40),
  D_L_43 =
    ((rol(13, (D_L_40 + f2(E_L_42, A_L_41, B_L_42) + X0 + 16#6ed9eba1) band 16#ffffffff) +
      C_L_41) band 16#ffffffff),
  A_L_43 = rol(10, A_L_41),
  C_L_44 =
    ((rol(6, (C_L_41 + f2(D_L_43, E_L_42, A_L_43) + X6 + 16#6ed9eba1) band 16#ffffffff) +
      B_L_42) band 16#ffffffff),
  E_L_44 = rol(10, E_L_42),
  B_L_45 =
    ((rol(5, (B_L_42 + f2(C_L_44, D_L_43, E_L_44) + X13 + 16#6ed9eba1) band 16#ffffffff) +
      A_L_43) band 16#ffffffff),
  D_L_45 = rol(10, D_L_43),
  A_L_46 =
    ((rol(12, (A_L_43 + f2(B_L_45, C_L_44, D_L_45) + X11 + 16#6ed9eba1) band 16#ffffffff) +
      E_L_44) band 16#ffffffff),
  C_L_46 = rol(10, C_L_44),
  E_L_47 =
    ((rol(7, (E_L_44 + f2(A_L_46, B_L_45, C_L_46) + X5 + 16#6ed9eba1) band 16#ffffffff) +
      D_L_45) band 16#ffffffff),
  B_L_47 = rol(10, B_L_45),
  D_L_48 =
    ((rol(5, (D_L_45 + f2(E_L_47, A_L_46, B_L_47) + X12 + 16#6ed9eba1) band 16#ffffffff) +
      C_L_46) band 16#ffffffff),
  A_L_48 = rol(10, A_L_46),
  C_L_49 =
    ((rol(11, (C_L_46 + f3(D_L_48, E_L_47, A_L_48) + X1 + 16#8f1bbcdc) band 16#ffffffff) +
      B_L_47) band 16#ffffffff),
  E_L_49 = rol(10, E_L_47),
  B_L_50 =
    ((rol(12, (B_L_47 + f3(C_L_49, D_L_48, E_L_49) + X9 + 16#8f1bbcdc) band 16#ffffffff) +
      A_L_48) band 16#ffffffff),
  D_L_50 = rol(10, D_L_48),
  A_L_51 =
    ((rol(14, (A_L_48 + f3(B_L_50, C_L_49, D_L_50) + X11 + 16#8f1bbcdc) band 16#ffffffff) +
      E_L_49) band 16#ffffffff),
  C_L_51 = rol(10, C_L_49),
  E_L_52 =
    ((rol(15, (E_L_49 + f3(A_L_51, B_L_50, C_L_51) + X10 + 16#8f1bbcdc) band 16#ffffffff) +
      D_L_50) band 16#ffffffff),
  B_L_52 = rol(10, B_L_50),
  D_L_53 =
    ((rol(14, (D_L_50 + f3(E_L_52, A_L_51, B_L_52) + X0 + 16#8f1bbcdc) band 16#ffffffff) +
      C_L_51) band 16#ffffffff),
  A_L_53 = rol(10, A_L_51),
  C_L_54 =
    ((rol(15, (C_L_51 + f3(D_L_53, E_L_52, A_L_53) + X8 + 16#8f1bbcdc) band 16#ffffffff) +
      B_L_52) band 16#ffffffff),
  E_L_54 = rol(10, E_L_52),
  B_L_55 =
    ((rol(9, (B_L_52 + f3(C_L_54, D_L_53, E_L_54) + X12 + 16#8f1bbcdc) band 16#ffffffff) +
      A_L_53) band 16#ffffffff),
  D_L_55 = rol(10, D_L_53),
  A_L_56 =
    ((rol(8, (A_L_53 + f3(B_L_55, C_L_54, D_L_55) + X4 + 16#8f1bbcdc) band 16#ffffffff) +
      E_L_54) band 16#ffffffff),
  C_L_56 = rol(10, C_L_54),
  E_L_57 =
    ((rol(9, (E_L_54 + f3(A_L_56, B_L_55, C_L_56) + X13 + 16#8f1bbcdc) band 16#ffffffff) +
      D_L_55) band 16#ffffffff),
  B_L_57 = rol(10, B_L_55),
  D_L_58 =
    ((rol(14, (D_L_55 + f3(E_L_57, A_L_56, B_L_57) + X3 + 16#8f1bbcdc) band 16#ffffffff) +
      C_L_56) band 16#ffffffff),
  A_L_58 = rol(10, A_L_56),
  C_L_59 =
    ((rol(5, (C_L_56 + f3(D_L_58, E_L_57, A_L_58) + X7 + 16#8f1bbcdc) band 16#ffffffff) +
      B_L_57) band 16#ffffffff),
  E_L_59 = rol(10, E_L_57),
  B_L_60 =
    ((rol(6, (B_L_57 + f3(C_L_59, D_L_58, E_L_59) + X15 + 16#8f1bbcdc) band 16#ffffffff) +
      A_L_58) band 16#ffffffff),
  D_L_60 = rol(10, D_L_58),
  A_L_61 =
    ((rol(8, (A_L_58 + f3(B_L_60, C_L_59, D_L_60) + X14 + 16#8f1bbcdc) band 16#ffffffff) +
      E_L_59) band 16#ffffffff),
  C_L_61 = rol(10, C_L_59),
  E_L_62 =
    ((rol(6, (E_L_59 + f3(A_L_61, B_L_60, C_L_61) + X5 + 16#8f1bbcdc) band 16#ffffffff) +
      D_L_60) band 16#ffffffff),
  B_L_62 = rol(10, B_L_60),
  D_L_63 =
    ((rol(5, (D_L_60 + f3(E_L_62, A_L_61, B_L_62) + X6 + 16#8f1bbcdc) band 16#ffffffff) +
      C_L_61) band 16#ffffffff),
  A_L_63 = rol(10, A_L_61),
  C_L_64 =
    ((rol(12, (C_L_61 + f3(D_L_63, E_L_62, A_L_63) + X2 + 16#8f1bbcdc) band 16#ffffffff) +
      B_L_62) band 16#ffffffff),
  E_L_64 = rol(10, E_L_62),
  B_L_65 =
    ((rol(9, (B_L_62 + f4(C_L_64, D_L_63, E_L_64) + X4 + 16#a953fd4e) band 16#ffffffff) +
      A_L_63) band 16#ffffffff),
  D_L_65 = rol(10, D_L_63),
  A_L_66 =
    ((rol(15, (A_L_63 + f4(B_L_65, C_L_64, D_L_65) + X0 + 16#a953fd4e) band 16#ffffffff) +
      E_L_64) band 16#ffffffff),
  C_L_66 = rol(10, C_L_64),
  E_L_67 =
    ((rol(5, (E_L_64 + f4(A_L_66, B_L_65, C_L_66) + X5 + 16#a953fd4e) band 16#ffffffff) +
      D_L_65) band 16#ffffffff),
  B_L_67 = rol(10, B_L_65),
  D_L_68 =
    ((rol(11, (D_L_65 + f4(E_L_67, A_L_66, B_L_67) + X9 + 16#a953fd4e) band 16#ffffffff) +
      C_L_66) band 16#ffffffff),
  A_L_68 = rol(10, A_L_66),
  C_L_69 =
    ((rol(6, (C_L_66 + f4(D_L_68, E_L_67, A_L_68) + X7 + 16#a953fd4e) band 16#ffffffff) +
      B_L_67) band 16#ffffffff),
  E_L_69 = rol(10, E_L_67),
  B_L_70 =
    ((rol(8, (B_L_67 + f4(C_L_69, D_L_68, E_L_69) + X12 + 16#a953fd4e) band 16#ffffffff) +
      A_L_68) band 16#ffffffff),
  D_L_70 = rol(10, D_L_68),
  A_L_71 =
    ((rol(13, (A_L_68 + f4(B_L_70, C_L_69, D_L_70) + X2 + 16#a953fd4e) band 16#ffffffff) +
      E_L_69) band 16#ffffffff),
  C_L_71 = rol(10, C_L_69),
  E_L_72 =
    ((rol(12, (E_L_69 + f4(A_L_71, B_L_70, C_L_71) + X10 + 16#a953fd4e) band 16#ffffffff) +
      D_L_70) band 16#ffffffff),
  B_L_72 = rol(10, B_L_70),
  D_L_73 =
    ((rol(5, (D_L_70 + f4(E_L_72, A_L_71, B_L_72) + X14 + 16#a953fd4e) band 16#ffffffff) +
      C_L_71) band 16#ffffffff),
  A_L_73 = rol(10, A_L_71),
  C_L_74 =
    ((rol(12, (C_L_71 + f4(D_L_73, E_L_72, A_L_73) + X1 + 16#a953fd4e) band 16#ffffffff) +
      B_L_72) band 16#ffffffff),
  E_L_74 = rol(10, E_L_72),
  B_L_75 =
    ((rol(13, (B_L_72 + f4(C_L_74, D_L_73, E_L_74) + X3 + 16#a953fd4e) band 16#ffffffff) +
      A_L_73) band 16#ffffffff),
  D_L_75 = rol(10, D_L_73),
  A_L_76 =
    ((rol(14, (A_L_73 + f4(B_L_75, C_L_74, D_L_75) + X8 + 16#a953fd4e) band 16#ffffffff) +
      E_L_74) band 16#ffffffff),
  C_L_76 = rol(10, C_L_74),
  E_L_77 =
    ((rol(11, (E_L_74 + f4(A_L_76, B_L_75, C_L_76) + X11 + 16#a953fd4e) band 16#ffffffff) +
      D_L_75) band 16#ffffffff),
  B_L_77 = rol(10, B_L_75),
  D_L_78 =
    ((rol(8, (D_L_75 + f4(E_L_77, A_L_76, B_L_77) + X6 + 16#a953fd4e) band 16#ffffffff) +
      C_L_76) band 16#ffffffff),
  A_L_78 = rol(10, A_L_76),
  C_L_79 =
    ((rol(5, (C_L_76 + f4(D_L_78, E_L_77, A_L_78) + X15 + 16#a953fd4e) band 16#ffffffff) +
      B_L_77) band 16#ffffffff),
  E_L_79 = rol(10, E_L_77),
  B_L_80 =
    ((rol(6, (B_L_77 + f4(C_L_79, D_L_78, E_L_79) + X13 + 16#a953fd4e) band 16#ffffffff) +
      A_L_78) band 16#ffffffff),
  D_L_80 = rol(10, D_L_78),
  {A_L_78, B_L_80, C_L_79, D_L_80, E_L_79}.

-spec round_right(
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  non_neg_integer(),
  {
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
  }
) ->
  {non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer(), non_neg_integer()}.
round_right(A0, B0, C0, D0, E0, {X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15}) ->
  A_R_1 =
    ((rol(8, (A0 + f4(B0, C0, D0) + X5 + 16#50a28be6) band 16#ffffffff) + E0) band
      16#ffffffff),
  C_R_1 = rol(10, C0),
  E_R_2 =
    ((rol(9, (E0 + f4(A_R_1, B0, C_R_1) + X14 + 16#50a28be6) band 16#ffffffff) + D0) band
      16#ffffffff),
  B_R_2 = rol(10, B0),
  D_R_3 =
    ((rol(9, (D0 + f4(E_R_2, A_R_1, B_R_2) + X7 + 16#50a28be6) band 16#ffffffff) + C_R_1) band
      16#ffffffff),
  A_R_3 = rol(10, A_R_1),
  C_R_4 =
    ((rol(11, (C_R_1 + f4(D_R_3, E_R_2, A_R_3) + X0 + 16#50a28be6) band 16#ffffffff) + B_R_2) band
      16#ffffffff),
  E_R_4 = rol(10, E_R_2),
  B_R_5 =
    ((rol(13, (B_R_2 + f4(C_R_4, D_R_3, E_R_4) + X9 + 16#50a28be6) band 16#ffffffff) + A_R_3) band
      16#ffffffff),
  D_R_5 = rol(10, D_R_3),
  A_R_6 =
    ((rol(15, (A_R_3 + f4(B_R_5, C_R_4, D_R_5) + X2 + 16#50a28be6) band 16#ffffffff) + E_R_4) band
      16#ffffffff),
  C_R_6 = rol(10, C_R_4),
  E_R_7 =
    ((rol(15, (E_R_4 + f4(A_R_6, B_R_5, C_R_6) + X11 + 16#50a28be6) band 16#ffffffff) + D_R_5) band
      16#ffffffff),
  B_R_7 = rol(10, B_R_5),
  D_R_8 =
    ((rol(5, (D_R_5 + f4(E_R_7, A_R_6, B_R_7) + X4 + 16#50a28be6) band 16#ffffffff) + C_R_6) band
      16#ffffffff),
  A_R_8 = rol(10, A_R_6),
  C_R_9 =
    ((rol(7, (C_R_6 + f4(D_R_8, E_R_7, A_R_8) + X13 + 16#50a28be6) band 16#ffffffff) + B_R_7) band
      16#ffffffff),
  E_R_9 = rol(10, E_R_7),
  B_R_10 =
    ((rol(7, (B_R_7 + f4(C_R_9, D_R_8, E_R_9) + X6 + 16#50a28be6) band 16#ffffffff) + A_R_8) band
      16#ffffffff),
  D_R_10 = rol(10, D_R_8),
  A_R_11 =
    ((rol(8, (A_R_8 + f4(B_R_10, C_R_9, D_R_10) + X15 + 16#50a28be6) band 16#ffffffff) +
      E_R_9) band 16#ffffffff),
  C_R_11 = rol(10, C_R_9),
  E_R_12 =
    ((rol(11, (E_R_9 + f4(A_R_11, B_R_10, C_R_11) + X8 + 16#50a28be6) band 16#ffffffff) +
      D_R_10) band 16#ffffffff),
  B_R_12 = rol(10, B_R_10),
  D_R_13 =
    ((rol(14, (D_R_10 + f4(E_R_12, A_R_11, B_R_12) + X1 + 16#50a28be6) band 16#ffffffff) +
      C_R_11) band 16#ffffffff),
  A_R_13 = rol(10, A_R_11),
  C_R_14 =
    ((rol(14, (C_R_11 + f4(D_R_13, E_R_12, A_R_13) + X10 + 16#50a28be6) band 16#ffffffff) +
      B_R_12) band 16#ffffffff),
  E_R_14 = rol(10, E_R_12),
  B_R_15 =
    ((rol(12, (B_R_12 + f4(C_R_14, D_R_13, E_R_14) + X3 + 16#50a28be6) band 16#ffffffff) +
      A_R_13) band 16#ffffffff),
  D_R_15 = rol(10, D_R_13),
  A_R_16 =
    ((rol(6, (A_R_13 + f4(B_R_15, C_R_14, D_R_15) + X12 + 16#50a28be6) band 16#ffffffff) +
      E_R_14) band 16#ffffffff),
  C_R_16 = rol(10, C_R_14),
  E_R_17 =
    ((rol(9, (E_R_14 + f3(A_R_16, B_R_15, C_R_16) + X6 + 16#5c4dd124) band 16#ffffffff) +
      D_R_15) band 16#ffffffff),
  B_R_17 = rol(10, B_R_15),
  D_R_18 =
    ((rol(13, (D_R_15 + f3(E_R_17, A_R_16, B_R_17) + X11 + 16#5c4dd124) band 16#ffffffff) +
      C_R_16) band 16#ffffffff),
  A_R_18 = rol(10, A_R_16),
  C_R_19 =
    ((rol(15, (C_R_16 + f3(D_R_18, E_R_17, A_R_18) + X3 + 16#5c4dd124) band 16#ffffffff) +
      B_R_17) band 16#ffffffff),
  E_R_19 = rol(10, E_R_17),
  B_R_20 =
    ((rol(7, (B_R_17 + f3(C_R_19, D_R_18, E_R_19) + X7 + 16#5c4dd124) band 16#ffffffff) +
      A_R_18) band 16#ffffffff),
  D_R_20 = rol(10, D_R_18),
  A_R_21 =
    ((rol(12, (A_R_18 + f3(B_R_20, C_R_19, D_R_20) + X0 + 16#5c4dd124) band 16#ffffffff) +
      E_R_19) band 16#ffffffff),
  C_R_21 = rol(10, C_R_19),
  E_R_22 =
    ((rol(8, (E_R_19 + f3(A_R_21, B_R_20, C_R_21) + X13 + 16#5c4dd124) band 16#ffffffff) +
      D_R_20) band 16#ffffffff),
  B_R_22 = rol(10, B_R_20),
  D_R_23 =
    ((rol(9, (D_R_20 + f3(E_R_22, A_R_21, B_R_22) + X5 + 16#5c4dd124) band 16#ffffffff) +
      C_R_21) band 16#ffffffff),
  A_R_23 = rol(10, A_R_21),
  C_R_24 =
    ((rol(11, (C_R_21 + f3(D_R_23, E_R_22, A_R_23) + X10 + 16#5c4dd124) band 16#ffffffff) +
      B_R_22) band 16#ffffffff),
  E_R_24 = rol(10, E_R_22),
  B_R_25 =
    ((rol(7, (B_R_22 + f3(C_R_24, D_R_23, E_R_24) + X14 + 16#5c4dd124) band 16#ffffffff) +
      A_R_23) band 16#ffffffff),
  D_R_25 = rol(10, D_R_23),
  A_R_26 =
    ((rol(7, (A_R_23 + f3(B_R_25, C_R_24, D_R_25) + X15 + 16#5c4dd124) band 16#ffffffff) +
      E_R_24) band 16#ffffffff),
  C_R_26 = rol(10, C_R_24),
  E_R_27 =
    ((rol(12, (E_R_24 + f3(A_R_26, B_R_25, C_R_26) + X8 + 16#5c4dd124) band 16#ffffffff) +
      D_R_25) band 16#ffffffff),
  B_R_27 = rol(10, B_R_25),
  D_R_28 =
    ((rol(7, (D_R_25 + f3(E_R_27, A_R_26, B_R_27) + X12 + 16#5c4dd124) band 16#ffffffff) +
      C_R_26) band 16#ffffffff),
  A_R_28 = rol(10, A_R_26),
  C_R_29 =
    ((rol(6, (C_R_26 + f3(D_R_28, E_R_27, A_R_28) + X4 + 16#5c4dd124) band 16#ffffffff) +
      B_R_27) band 16#ffffffff),
  E_R_29 = rol(10, E_R_27),
  B_R_30 =
    ((rol(15, (B_R_27 + f3(C_R_29, D_R_28, E_R_29) + X9 + 16#5c4dd124) band 16#ffffffff) +
      A_R_28) band 16#ffffffff),
  D_R_30 = rol(10, D_R_28),
  A_R_31 =
    ((rol(13, (A_R_28 + f3(B_R_30, C_R_29, D_R_30) + X1 + 16#5c4dd124) band 16#ffffffff) +
      E_R_29) band 16#ffffffff),
  C_R_31 = rol(10, C_R_29),
  E_R_32 =
    ((rol(11, (E_R_29 + f3(A_R_31, B_R_30, C_R_31) + X2 + 16#5c4dd124) band 16#ffffffff) +
      D_R_30) band 16#ffffffff),
  B_R_32 = rol(10, B_R_30),
  D_R_33 =
    ((rol(9, (D_R_30 + f2(E_R_32, A_R_31, B_R_32) + X15 + 16#6d703ef3) band 16#ffffffff) +
      C_R_31) band 16#ffffffff),
  A_R_33 = rol(10, A_R_31),
  C_R_34 =
    ((rol(7, (C_R_31 + f2(D_R_33, E_R_32, A_R_33) + X5 + 16#6d703ef3) band 16#ffffffff) +
      B_R_32) band 16#ffffffff),
  E_R_34 = rol(10, E_R_32),
  B_R_35 =
    ((rol(15, (B_R_32 + f2(C_R_34, D_R_33, E_R_34) + X1 + 16#6d703ef3) band 16#ffffffff) +
      A_R_33) band 16#ffffffff),
  D_R_35 = rol(10, D_R_33),
  A_R_36 =
    ((rol(11, (A_R_33 + f2(B_R_35, C_R_34, D_R_35) + X3 + 16#6d703ef3) band 16#ffffffff) +
      E_R_34) band 16#ffffffff),
  C_R_36 = rol(10, C_R_34),
  E_R_37 =
    ((rol(8, (E_R_34 + f2(A_R_36, B_R_35, C_R_36) + X7 + 16#6d703ef3) band 16#ffffffff) +
      D_R_35) band 16#ffffffff),
  B_R_37 = rol(10, B_R_35),
  D_R_38 =
    ((rol(6, (D_R_35 + f2(E_R_37, A_R_36, B_R_37) + X14 + 16#6d703ef3) band 16#ffffffff) +
      C_R_36) band 16#ffffffff),
  A_R_38 = rol(10, A_R_36),
  C_R_39 =
    ((rol(6, (C_R_36 + f2(D_R_38, E_R_37, A_R_38) + X6 + 16#6d703ef3) band 16#ffffffff) +
      B_R_37) band 16#ffffffff),
  E_R_39 = rol(10, E_R_37),
  B_R_40 =
    ((rol(14, (B_R_37 + f2(C_R_39, D_R_38, E_R_39) + X9 + 16#6d703ef3) band 16#ffffffff) +
      A_R_38) band 16#ffffffff),
  D_R_40 = rol(10, D_R_38),
  A_R_41 =
    ((rol(12, (A_R_38 + f2(B_R_40, C_R_39, D_R_40) + X11 + 16#6d703ef3) band 16#ffffffff) +
      E_R_39) band 16#ffffffff),
  C_R_41 = rol(10, C_R_39),
  E_R_42 =
    ((rol(13, (E_R_39 + f2(A_R_41, B_R_40, C_R_41) + X8 + 16#6d703ef3) band 16#ffffffff) +
      D_R_40) band 16#ffffffff),
  B_R_42 = rol(10, B_R_40),
  D_R_43 =
    ((rol(5, (D_R_40 + f2(E_R_42, A_R_41, B_R_42) + X12 + 16#6d703ef3) band 16#ffffffff) +
      C_R_41) band 16#ffffffff),
  A_R_43 = rol(10, A_R_41),
  C_R_44 =
    ((rol(14, (C_R_41 + f2(D_R_43, E_R_42, A_R_43) + X2 + 16#6d703ef3) band 16#ffffffff) +
      B_R_42) band 16#ffffffff),
  E_R_44 = rol(10, E_R_42),
  B_R_45 =
    ((rol(13, (B_R_42 + f2(C_R_44, D_R_43, E_R_44) + X10 + 16#6d703ef3) band 16#ffffffff) +
      A_R_43) band 16#ffffffff),
  D_R_45 = rol(10, D_R_43),
  A_R_46 =
    ((rol(13, (A_R_43 + f2(B_R_45, C_R_44, D_R_45) + X0 + 16#6d703ef3) band 16#ffffffff) +
      E_R_44) band 16#ffffffff),
  C_R_46 = rol(10, C_R_44),
  E_R_47 =
    ((rol(7, (E_R_44 + f2(A_R_46, B_R_45, C_R_46) + X4 + 16#6d703ef3) band 16#ffffffff) +
      D_R_45) band 16#ffffffff),
  B_R_47 = rol(10, B_R_45),
  D_R_48 =
    ((rol(5, (D_R_45 + f2(E_R_47, A_R_46, B_R_47) + X13 + 16#6d703ef3) band 16#ffffffff) +
      C_R_46) band 16#ffffffff),
  A_R_48 = rol(10, A_R_46),
  C_R_49 =
    ((rol(15, (C_R_46 + f1(D_R_48, E_R_47, A_R_48) + X8 + 16#7a6d76e9) band 16#ffffffff) +
      B_R_47) band 16#ffffffff),
  E_R_49 = rol(10, E_R_47),
  B_R_50 =
    ((rol(5, (B_R_47 + f1(C_R_49, D_R_48, E_R_49) + X6 + 16#7a6d76e9) band 16#ffffffff) +
      A_R_48) band 16#ffffffff),
  D_R_50 = rol(10, D_R_48),
  A_R_51 =
    ((rol(8, (A_R_48 + f1(B_R_50, C_R_49, D_R_50) + X4 + 16#7a6d76e9) band 16#ffffffff) +
      E_R_49) band 16#ffffffff),
  C_R_51 = rol(10, C_R_49),
  E_R_52 =
    ((rol(11, (E_R_49 + f1(A_R_51, B_R_50, C_R_51) + X1 + 16#7a6d76e9) band 16#ffffffff) +
      D_R_50) band 16#ffffffff),
  B_R_52 = rol(10, B_R_50),
  D_R_53 =
    ((rol(14, (D_R_50 + f1(E_R_52, A_R_51, B_R_52) + X3 + 16#7a6d76e9) band 16#ffffffff) +
      C_R_51) band 16#ffffffff),
  A_R_53 = rol(10, A_R_51),
  C_R_54 =
    ((rol(14, (C_R_51 + f1(D_R_53, E_R_52, A_R_53) + X11 + 16#7a6d76e9) band 16#ffffffff) +
      B_R_52) band 16#ffffffff),
  E_R_54 = rol(10, E_R_52),
  B_R_55 =
    ((rol(6, (B_R_52 + f1(C_R_54, D_R_53, E_R_54) + X15 + 16#7a6d76e9) band 16#ffffffff) +
      A_R_53) band 16#ffffffff),
  D_R_55 = rol(10, D_R_53),
  A_R_56 =
    ((rol(14, (A_R_53 + f1(B_R_55, C_R_54, D_R_55) + X0 + 16#7a6d76e9) band 16#ffffffff) +
      E_R_54) band 16#ffffffff),
  C_R_56 = rol(10, C_R_54),
  E_R_57 =
    ((rol(6, (E_R_54 + f1(A_R_56, B_R_55, C_R_56) + X5 + 16#7a6d76e9) band 16#ffffffff) +
      D_R_55) band 16#ffffffff),
  B_R_57 = rol(10, B_R_55),
  D_R_58 =
    ((rol(9, (D_R_55 + f1(E_R_57, A_R_56, B_R_57) + X12 + 16#7a6d76e9) band 16#ffffffff) +
      C_R_56) band 16#ffffffff),
  A_R_58 = rol(10, A_R_56),
  C_R_59 =
    ((rol(12, (C_R_56 + f1(D_R_58, E_R_57, A_R_58) + X2 + 16#7a6d76e9) band 16#ffffffff) +
      B_R_57) band 16#ffffffff),
  E_R_59 = rol(10, E_R_57),
  B_R_60 =
    ((rol(9, (B_R_57 + f1(C_R_59, D_R_58, E_R_59) + X13 + 16#7a6d76e9) band 16#ffffffff) +
      A_R_58) band 16#ffffffff),
  D_R_60 = rol(10, D_R_58),
  A_R_61 =
    ((rol(12, (A_R_58 + f1(B_R_60, C_R_59, D_R_60) + X9 + 16#7a6d76e9) band 16#ffffffff) +
      E_R_59) band 16#ffffffff),
  C_R_61 = rol(10, C_R_59),
  E_R_62 =
    ((rol(5, (E_R_59 + f1(A_R_61, B_R_60, C_R_61) + X7 + 16#7a6d76e9) band 16#ffffffff) +
      D_R_60) band 16#ffffffff),
  B_R_62 = rol(10, B_R_60),
  D_R_63 =
    ((rol(15, (D_R_60 + f1(E_R_62, A_R_61, B_R_62) + X10 + 16#7a6d76e9) band 16#ffffffff) +
      C_R_61) band 16#ffffffff),
  A_R_63 = rol(10, A_R_61),
  C_R_64 =
    ((rol(8, (C_R_61 + f1(D_R_63, E_R_62, A_R_63) + X14 + 16#7a6d76e9) band 16#ffffffff) +
      B_R_62) band 16#ffffffff),
  E_R_64 = rol(10, E_R_62),
  B_R_65 =
    ((rol(8, (B_R_62 + f0(C_R_64, D_R_63, E_R_64) + X12 + 0) band 16#ffffffff) + A_R_63) band
      16#ffffffff),
  D_R_65 = rol(10, D_R_63),
  A_R_66 =
    ((rol(5, (A_R_63 + f0(B_R_65, C_R_64, D_R_65) + X15 + 0) band 16#ffffffff) + E_R_64) band
      16#ffffffff),
  C_R_66 = rol(10, C_R_64),
  E_R_67 =
    ((rol(12, (E_R_64 + f0(A_R_66, B_R_65, C_R_66) + X10 + 0) band 16#ffffffff) + D_R_65) band
      16#ffffffff),
  B_R_67 = rol(10, B_R_65),
  D_R_68 =
    ((rol(9, (D_R_65 + f0(E_R_67, A_R_66, B_R_67) + X4 + 0) band 16#ffffffff) + C_R_66) band
      16#ffffffff),
  A_R_68 = rol(10, A_R_66),
  C_R_69 =
    ((rol(12, (C_R_66 + f0(D_R_68, E_R_67, A_R_68) + X1 + 0) band 16#ffffffff) + B_R_67) band
      16#ffffffff),
  E_R_69 = rol(10, E_R_67),
  B_R_70 =
    ((rol(5, (B_R_67 + f0(C_R_69, D_R_68, E_R_69) + X5 + 0) band 16#ffffffff) + A_R_68) band
      16#ffffffff),
  D_R_70 = rol(10, D_R_68),
  A_R_71 =
    ((rol(14, (A_R_68 + f0(B_R_70, C_R_69, D_R_70) + X8 + 0) band 16#ffffffff) + E_R_69) band
      16#ffffffff),
  C_R_71 = rol(10, C_R_69),
  E_R_72 =
    ((rol(6, (E_R_69 + f0(A_R_71, B_R_70, C_R_71) + X7 + 0) band 16#ffffffff) + D_R_70) band
      16#ffffffff),
  B_R_72 = rol(10, B_R_70),
  D_R_73 =
    ((rol(8, (D_R_70 + f0(E_R_72, A_R_71, B_R_72) + X6 + 0) band 16#ffffffff) + C_R_71) band
      16#ffffffff),
  A_R_73 = rol(10, A_R_71),
  C_R_74 =
    ((rol(13, (C_R_71 + f0(D_R_73, E_R_72, A_R_73) + X2 + 0) band 16#ffffffff) + B_R_72) band
      16#ffffffff),
  E_R_74 = rol(10, E_R_72),
  B_R_75 =
    ((rol(6, (B_R_72 + f0(C_R_74, D_R_73, E_R_74) + X13 + 0) band 16#ffffffff) + A_R_73) band
      16#ffffffff),
  D_R_75 = rol(10, D_R_73),
  A_R_76 =
    ((rol(5, (A_R_73 + f0(B_R_75, C_R_74, D_R_75) + X14 + 0) band 16#ffffffff) + E_R_74) band
      16#ffffffff),
  C_R_76 = rol(10, C_R_74),
  E_R_77 =
    ((rol(15, (E_R_74 + f0(A_R_76, B_R_75, C_R_76) + X0 + 0) band 16#ffffffff) + D_R_75) band
      16#ffffffff),
  B_R_77 = rol(10, B_R_75),
  D_R_78 =
    ((rol(13, (D_R_75 + f0(E_R_77, A_R_76, B_R_77) + X3 + 0) band 16#ffffffff) + C_R_76) band
      16#ffffffff),
  A_R_78 = rol(10, A_R_76),
  C_R_79 =
    ((rol(11, (C_R_76 + f0(D_R_78, E_R_77, A_R_78) + X9 + 0) band 16#ffffffff) + B_R_77) band
      16#ffffffff),
  E_R_79 = rol(10, E_R_77),
  B_R_80 =
    ((rol(11, (B_R_77 + f0(C_R_79, D_R_78, E_R_79) + X11 + 0) band 16#ffffffff) + A_R_78) band
      16#ffffffff),
  D_R_80 = rol(10, D_R_78),
  {A_R_78, B_R_80, C_R_79, D_R_80, E_R_79}.

-compile({inline, [rol/2, f0/3, f1/3, f2/3, f3/3, f4/3]}).

-spec rol(non_neg_integer(), non_neg_integer()) -> non_neg_integer().
rol(S, X) ->
  ((X bsl S) bor (X bsr (32 - S))) band ?MASK32.

-spec f0(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
f0(X, Y, Z) -> X bxor Y bxor Z.

-spec f1(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
f1(X, Y, Z) -> (X band Y) bor ((bnot X band ?MASK32) band Z).

-spec f2(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
f2(X, Y, Z) -> (X bor (bnot Y band ?MASK32)) bxor Z.

-spec f3(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
f3(X, Y, Z) -> (X band Z) bor (Y band (bnot Z band ?MASK32)).

-spec f4(non_neg_integer(), non_neg_integer(), non_neg_integer()) -> non_neg_integer().
f4(X, Y, Z) -> X bxor (Y bor (bnot Z band ?MASK32)).
