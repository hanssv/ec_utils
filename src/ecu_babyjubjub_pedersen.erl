%%%-------------------------------------------------------------------
%%% @doc
%%% Circomlib-compatible Pedersen Hash and Commitments over BabyJubjub.
%%%
%%% Implements the 4-bit window Pedersen hash function matching
%%% Circomlib's `pedersen.circom` template over the BabyJubjub elliptic curve.
%%%
%%% Algorithm:
%%% 1. Input bits are extracted in little-endian order per byte (b_0 .. b_7).
%%% 2. The bit sequence is partitioned into segments of at most 200 bits
%%%    (up to 10 segments = 2000 bits max, matching the 10 predefined base points).
%%% 3. Each segment is subdivided into 4-bit windows {b0, b1, b2, b3}:
%%%      magnitude = 1 + b0 + 2*b1 + 4*b2  (in 1..8)
%%%      sign = if b3 == 1 then -1 else +1
%%%      window_val = sign * magnitude
%%%      window_weight = 16^w = (1 bsl (4*w))
%%% 4. Each segment produces a scalar: K_s = sum_w (window_val_w * 16^w).
%%%    Segment point S_s = K_s * BASE[s] on BabyJubjub.
%%% 5. Total hash point H = S_0 + S_1 + ... + S_{nSegments-1} on BabyJubjub.
%%%
%%% Reference:
%%% - iden3/circomlib circuits/pedersen.circom
%%% - iden3/circomlibjs src/pedersenHash.js
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_babyjubjub_pedersen).

-typing([eqwalizer]).

-export([
  base/1,
  bases/0,
  hash/1,
  hash/2,
  hash_compressed/1,
  commit/2,
  commit/3
]).

-export_type([
  point/0,
  output_format/0
]).

-type point() :: {non_neg_integer(), non_neg_integer()}.
-type output_format() :: affine | compressed | x_only.

-define(MAX_BITS, 2000).
-define(SEGMENT_BITS, 200).

%%%-------------------------------------------------------------------
%%% Predefined Base Points (from Circomlib's pedersen.circom)
%%%-------------------------------------------------------------------

-define(BASE_0,
  {10457101036533406547632367118273992217979173478358440826365724437999023779287,
    19824078218392094440610104313265183977899662750282163392862422243483260492317}
).
-define(BASE_1,
  {2671756056509184035029146175565761955751135805354291559563293617232983272177,
    2663205510731142763556352975002641716101654201788071096152948830924149045094}
).
-define(BASE_2,
  {5802099305472655231388284418920769829666717045250560929368476121199858275951,
    5980429700218124965372158798884772646841287887664001482443826541541529227896}
).
-define(BASE_3,
  {7107336197374528537877327281242680114152313102022415488494307685842428166594,
    2857869773864086953506483169737724679646433914307247183624878062391496185654}
).
-define(BASE_4,
  {20265828622013100949498132415626198973119240347465898028410217039057588424236,
    1160461593266035632937973507065134938065359936056410650153315956301179689506}
).
-define(BASE_5,
  {1487999857809287756929114517587739322941449154962237464737694709326309567994,
    14017256862867289575056460215526364897734808720610101650676790868051368668003}
).
-define(BASE_6,
  {14618644331049802168996997831720384953259095788558646464435263343433563860015,
    13115243279999696210147231297848654998887864576952244320558158620692603342236}
).
-define(BASE_7,
  {6814338563135591367010655964669793483652536871717891893032616415581401894627,
    13660303521961041205824633772157003587453809761793065294055279768121314853695}
).
-define(BASE_8,
  {3571615583211663069428808372184817973703476260057504149923239576077102575715,
    11981351099832644138306422070127357074117642951423551606012551622164230222506}
).
-define(BASE_9,
  {18597552580465440374022635246985743886550544261632147935254624835147509493269,
    6753322320275422086923032033899357299485124665258735666995435957890214041481}
).

%%%-------------------------------------------------------------------
%%% API: Base Points
%%%-------------------------------------------------------------------

%% @doc Return the list of all 10 canonical base points defined in pedersen.circom.
-spec bases() -> [point()].
bases() ->
  [
    ?BASE_0,
    ?BASE_1,
    ?BASE_2,
    ?BASE_3,
    ?BASE_4,
    ?BASE_5,
    ?BASE_6,
    ?BASE_7,
    ?BASE_8,
    ?BASE_9
  ].

%% @doc Return the canonical base point at the given 0-based index (0..9).
-spec base(0..9) -> point().
base(0) -> ?BASE_0;
base(1) -> ?BASE_1;
base(2) -> ?BASE_2;
base(3) -> ?BASE_3;
base(4) -> ?BASE_4;
base(5) -> ?BASE_5;
base(6) -> ?BASE_6;
base(7) -> ?BASE_7;
base(8) -> ?BASE_8;
base(9) -> ?BASE_9;
base(_) -> error(badarg).

%%%-------------------------------------------------------------------
%%% API: Pedersen Hash
%%%-------------------------------------------------------------------

%% @doc Compute the Circomlib-compatible Pedersen hash of binary or bitstring data.
%% Returns the affine point {X, Y} on the BabyJubjub curve.
-spec hash(bitstring()) -> point().
hash(Data) ->
  hash_internal(Data).

%% @doc Compute Pedersen hash with specified output format:
%% - `affine': returns {X, Y} on BabyJubjub
%% - `compressed': returns 32-byte compressed point (ZIP 216 / BabyJubjub format)
%% - `x_only': returns the non-negative integer X coordinate (matching Circom `out[0]')
-spec hash
  (bitstring(), affine) -> point();
  (bitstring(), compressed) -> <<_:256>>;
  (bitstring(), x_only) -> non_neg_integer().
hash(Data, affine) ->
  hash_internal(Data);
hash(Data, compressed) ->
  ecu_babyjubjub:compress(hash_internal(Data));
hash(Data, x_only) ->
  {X, _Y} = hash_internal(Data),
  X;
hash(_, _) ->
  error(badarg).

%% @doc Compute the Pedersen hash returning a 32-byte compressed point.
-spec hash_compressed(bitstring()) -> <<_:256>>.
hash_compressed(Data) ->
  ecu_babyjubjub:compress(hash_internal(Data)).

%%%-------------------------------------------------------------------
%%% API: Pedersen Commitments
%%%-------------------------------------------------------------------

%% @doc Compute a Pedersen commitment C = hash(Message) + Blinding * base(9).
%% base(9) is used as the default blinding generator point.
-spec commit(bitstring(), integer() | binary()) -> point().
commit(Message, Blinding) ->
  commit(Message, Blinding, base(9)).

%% @doc Compute a Pedersen commitment with an explicit blinding generator point.
-spec commit(bitstring(), integer() | binary(), point()) -> point().
commit(Message, BlindingBin, BlindingBase) when is_binary(BlindingBin), byte_size(BlindingBin) =:= 32 ->
  BlindingInt = binary:decode_unsigned(BlindingBin, little),
  commit(Message, BlindingInt, BlindingBase);
commit(Message, BlindingInt, BlindingBase) when is_integer(BlindingInt) ->
  case ecu_babyjubjub:is_on_curve(BlindingBase) of
    true ->
      MsgPoint = hash_internal(Message),
      BlindingPoint =
        if
          BlindingInt >= 0 ->
            ecu_babyjubjub:mul(BlindingBase, BlindingInt);
          true ->
            ecu_babyjubjub:neg(ecu_babyjubjub:mul(BlindingBase, -BlindingInt))
        end,
      ecu_babyjubjub:add(MsgPoint, BlindingPoint);
    false ->
      error(badarg)
  end;
commit(_, _, _) ->
  error(badarg).

%%%-------------------------------------------------------------------
%%% Internal Helpers: Bit Extraction & Window Processing
%%%-------------------------------------------------------------------

-spec hash_internal(bitstring()) -> point().
hash_internal(<<>>) ->
  ecu_babyjubjub:identity();
hash_internal(Data) when is_bitstring(Data) ->
  Bits = bits_from_bitstring(Data),
  NumBits = length(Bits),
  if
    NumBits > ?MAX_BITS ->
      error(input_too_large);
    true ->
      Segments = partition_segments(Bits, []),
      SegPoints = compute_segment_points(Segments, 0, []),
      lists:foldl(
        fun(Pt, Acc) -> ecu_babyjubjub:add(Acc, Pt) end,
        ecu_babyjubjub:identity(),
        SegPoints
      )
  end;
hash_internal(_) ->
  error(badarg).

-spec bits_from_bitstring(bitstring()) -> [0 | 1].
bits_from_bitstring(<<>>) ->
  [];
bits_from_bitstring(<<B:8, Rest/binary>>) ->
  [
    (B bsr 0) band 1,
    (B bsr 1) band 1,
    (B bsr 2) band 1,
    (B bsr 3) band 1,
    (B bsr 4) band 1,
    (B bsr 5) band 1,
    (B bsr 6) band 1,
    (B bsr 7) band 1
    | bits_from_bitstring(Rest)
  ];
bits_from_bitstring(<<B:1, Rest/bitstring>>) ->
  [B | bits_from_bitstring(Rest)].

-spec partition_segments([0 | 1], [[0 | 1]]) -> [[0 | 1]].
partition_segments([], Acc) ->
  lists:reverse(Acc);
partition_segments(Bits, Acc) ->
  {Seg, Rest} =
    if
      length(Bits) =< ?SEGMENT_BITS ->
        {Bits, []};
      true ->
        lists:split(?SEGMENT_BITS, Bits)
    end,
  partition_segments(Rest, [Seg | Acc]).

-spec compute_segment_points([[0 | 1]], non_neg_integer(), [point()]) -> [point()].
compute_segment_points([], _Idx, Acc) ->
  lists:reverse(Acc);
compute_segment_points([SegBits | RestSegs], Idx, Acc) ->
  BasePt = base(Idx),
  Windows = chunk_windows(SegBits, []),
  {Scalar, _} =
    lists:foldl(
      fun({B0, B1, B2, B3}, {CurrentScalar, Shift}) ->
        Mag = 1 + B0 + 2 * B1 + 4 * B2,
        Val =
          if
            B3 =:= 1 -> -Mag;
            true -> Mag
          end,
        {CurrentScalar + (Val bsl Shift), Shift + 4}
      end,
      {0, 0},
      Windows
    ),
  SegPt =
    if
      Scalar =:= 0 ->
        ecu_babyjubjub:identity();
      Scalar > 0 ->
        ecu_babyjubjub:mul(BasePt, Scalar);
      true ->
        ecu_babyjubjub:neg(ecu_babyjubjub:mul(BasePt, -Scalar))
    end,
  compute_segment_points(RestSegs, Idx + 1, [SegPt | Acc]).

-spec chunk_windows([0 | 1], [{0 | 1, 0 | 1, 0 | 1, 0 | 1}]) ->
  [{0 | 1, 0 | 1, 0 | 1, 0 | 1}].
chunk_windows([], Acc) ->
  lists:reverse(Acc);
chunk_windows([B0, B1, B2, B3 | Rest], Acc) ->
  chunk_windows(Rest, [{B0, B1, B2, B3} | Acc]);
chunk_windows([B0, B1, B2], Acc) ->
  lists:reverse([{B0, B1, B2, 0} | Acc]);
chunk_windows([B0, B1], Acc) ->
  lists:reverse([{B0, B1, 0, 0} | Acc]);
chunk_windows([B0], Acc) ->
  lists:reverse([{B0, 0, 0, 0} | Acc]).
