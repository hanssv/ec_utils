%%%-------------------------------------------------------------------
%%% @doc
%%% Parameters and constants for SLH-DSA (NIST FIPS 205).
%%%
%%% Stateless Hash-Based Digital Signature Standard (SLH-DSA), derived
%%% from SPHINCS+, standardized in NIST FIPS 205 (August 2024).
%%%
%%% Reference:
%%%   NIST FIPS 205: Stateless Hash-Based Digital Signature Standard
%%%   https://doi.org/10.6028/NIST.FIPS.205
%%% @end
%%%-------------------------------------------------------------------

%% ADRS Address Types (FIPS 205 Section 4.2)
-define(SLH_ADRS_WOTS_HASH, 0).
-define(SLH_ADRS_WOTS_PK, 1).
-define(SLH_ADRS_TREE, 2).
-define(SLH_ADRS_FORS_TREE, 3).
-define(SLH_ADRS_FORS_ROOTS, 4).
-define(SLH_ADRS_WOTS_PRF, 5).
-define(SLH_ADRS_FORS_PRF, 6).

%% Parameter sets
-type slh_param_set() ::
  slh_dsa_sha2_128s
  | slh_dsa_sha2_128f
  | slh_dsa_sha2_192s
  | slh_dsa_sha2_192f
  | slh_dsa_sha2_256s
  | slh_dsa_sha2_256f
  | slh_dsa_shake_128s
  | slh_dsa_shake_128f
  | slh_dsa_shake_192s
  | slh_dsa_shake_192f
  | slh_dsa_shake_256s
  | slh_dsa_shake_256f.

%% Parameter record
-record(slh_params, {
  name :: slh_param_set(),
  hash :: shake | sha2,
  n :: 16 | 24 | 32,
  h :: pos_integer(),
  d :: pos_integer(),
  hp :: pos_integer(),
  a :: pos_integer(),
  k :: pos_integer(),
  w = 16 :: 16,
  len1 :: pos_integer(),
  len2 = 3 :: 3,
  len :: pos_integer(),
  pk_bytes :: pos_integer(),
  sk_bytes :: pos_integer(),
  sig_bytes :: pos_integer(),
  m :: pos_integer(),
  m_md :: pos_integer(),
  m_tree :: pos_integer(),
  m_leaf :: pos_integer()
}).
