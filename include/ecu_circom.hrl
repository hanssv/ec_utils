%%%-------------------------------------------------------------------
%%% @doc
%%% Record and macro definitions for Circom R1CS and WTNS parsing/validation.
%%% @end
%%%-------------------------------------------------------------------
-ifndef(ECU_CIRCOM_HRL).
-define(ECU_CIRCOM_HRL, true).

-define(R1CS_MAGIC, <<"r1cs">>).
-define(R1CS_VERSION, 1).

-define(WTNS_MAGIC, <<"wtns">>).
-define(WTNS_VERSION, 2).

%% R1CS Section types
-define(R1CS_SEC_HEADER, 1).
-define(R1CS_SEC_CONSTRAINTS, 2).
-define(R1CS_SEC_WIRE_MAP, 3).

%% WTNS Section types
-define(WTNS_SEC_HEADER, 1).
-define(WTNS_SEC_WITNESS, 2).

-record(r1cs_header, {
  field_size = 32 :: non_neg_integer(),
  prime :: integer(),
  n_wires = 0 :: non_neg_integer(),
  n_pub_out = 0 :: non_neg_integer(),
  n_pub_in = 0 :: non_neg_integer(),
  n_prvt_in = 0 :: non_neg_integer(),
  n_labels = 0 :: non_neg_integer(),
  n_constraints = 0 :: non_neg_integer()
}).

-type term_entry() :: {WireId :: non_neg_integer(), Factor :: integer()}.
-type linear_combination() :: [term_entry()].
-type r1cs_constraint() :: {
  A :: linear_combination(),
  B :: linear_combination(),
  C :: linear_combination()
}.

-record(r1cs, {
  header :: #r1cs_header{},
  constraints = [] :: [r1cs_constraint()],
  wire_map = [] :: [non_neg_integer()],
  custom_sections = [] :: [{non_neg_integer(), binary()}]
}).

-record(wtns_header, {
  field_size = 32 :: non_neg_integer(),
  prime :: integer(),
  witness_len = 0 :: non_neg_integer()
}).

-record(wtns, {
  header :: #wtns_header{},
  witness = [] :: [integer()]
}).

-type r1cs_header_rec() :: #r1cs_header{}.
-type r1cs_rec() :: #r1cs{}.
-type wtns_header_rec() :: #wtns_header{}.
-type wtns_rec() :: #wtns{}.

-endif.
