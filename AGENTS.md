# Agent Instructions for `ec_utils`

This guide provides operational rules, guidelines, and commands for AI coding assistants working in the `ec_utils` repository.

---

## 1. Project Overview & Philosophy
`ec_utils` is a pure-Erlang cryptographic library implementing elliptic curve arithmetic, signatures (ECDSA, Ed25519, Ed448, BIP-340 Schnorr), threshold signatures (FROST RFC 9591), and multi-signatures (MuSig2 BIP-327).

- **Production code (`src/`) must have ZERO external C/NIF or third-party dependencies**. It must run completely self-contained on the BEAM.
- Reference NIFs in `crates/` and `test/` exist purely as test oracles for differential fuzzing and cross-verification.

---

## 2. Code Style & Conventions
Detailed style rules are defined in [`STYLE.md`](STYLE.md). Key points:

- **Erlang Formatter**:
  - Always run `make fmt` to format code before finishing.
  - Verify with `make fmt-check`.
  - Indentation is strictly **2 spaces**; line width is **105 characters** (configured via our custom `erlfmt` fork).
- **Module Headers**:
  - Use standard EDoc `@doc` blocks with specification / RFC links.
  - **Never add `Author:` or `Created:` lines**; git tracks authorship.
- **Code Organization**:
  - `src/`: Explicit exports only, `-typing([eqwalizer])`, strict `-spec`s. Never use `export_all` outside `-ifdef(TEST)`.
  - `test/`: EUnit auto-discovers `*_test/0` and `*_test_/0`; no `export_all`.
  - `eqc/`: QuickCheck properties `prop_*` and generators `gen_*`; `-compile([export_all, nowarn_export_all])` is standard.
- **Scripts**:
  - Shell / bash scripts must use **2-space indentation**.
- **Rust NIFs (`crates/`)**:
  - If any Rust code is modified, run `cargo fmt` in that crate.

---

## 3. Communication & Workflow Rules
- **Discussion vs. Implementation**:
  When the user asks for an opinion or discusses an idea, **stop immediately after answering**. Do not proceed to implementation until the user explicitly instructs you to do so.
- **Plans & Confirmation**:
  Always wait for explicit user confirmation after proposing a plan, especially when previous actions were corrected or clarified. Do not assume approval.
- **PR Creation & CI Follow-up**:
  When creating a pull request, always actively monitor and follow up on CI results (`gh pr checks`) until all jobs pass cleanly. Never consider the PR task complete while checks are pending or failing.
- **Documentation Completeness**:
  Whenever adding or modifying a feature, curve, algorithm, or protocol, always update `README.md` (and any related documentation) as an integral part of the task before proposing completion or creating a PR. This includes Quick Start usage examples, API reference summaries, curve parameter documentation, and updating top-level capability listings. Never consider a feature complete with undocumented functionality.
- **Git Commit Messages**:
  - Subject line: strictly **≤ 50 characters** (hard ceiling 72 characters).
  - Format: Imperative mood (e.g. `Add ...`, `Fix ...`, `Document ...`), capitalized, no trailing period.
  - Body: Wrap explanatory body text at **72 characters**, separated from subject by a blank line.
- **Direct Responses**:
  Never use terminal `echo` commands to announce task completion; provide direct, concise markdown responses instead.
- **Benchmark Reporting & Requirements for New Features**:
  - Every new feature, curve, or protocol must include benchmarks in `bench/ecu_bench_suites.erl`.
  - Always use **non-random, deterministic inputs** in benchmark suites to avoid timing fluctuations.
  - When reference NIFs exist, include comparative benchmarks and present results in the standard format:
    `| Operation | Pure Erlang | Reference (Rust NIF) | vs Reference |`
    with execution times in `µs` (or `ms`) and the explicit speed ratio factor (e.g. `1.93×`). Never dump raw Ops/sec without this comparative table.
  - **CI Baseline Compatibility**: CI benchmark jobs copy `bench/` to check out and test against base branches (e.g. `master`). Benchmarks for newly introduced modules in `bench/ecu_bench_suites.erl` MUST be guarded with `case code:ensure_loaded(NewModule) of {module, NewModule} -> ...; _ -> [] end` so older branches without the module do not crash with `undefined function`.
- **Tooling & Command Transparency**:
  NEVER use ad-hoc Python (`python3 -c '...'`, scripts) or arbitrary host runtime one-liners to read files, parse logs, or inspect transcripts. Use dedicated file-reading tools (`read_file`), standard transparent CLI tools (`jq`, `grep`, `sed`), committed named scripts, or Erlang project tools (`rebar3`, `escript`).

---

## 4. Verification Commands

Before proposing completion, run the full verification pipeline:

```bash
make fmt-check         # Verify formatting
rebar3 compile         # Verify compilation (0 warnings)
rebar3 eunit           # EUnit test suite + NIF cross-checks
make eqc               # QuickCheck properties
rebar3 dialyzer        # Dialyzer type analysis
mise run eqwalize      # EqWAlizer type checking
```

---

## 5. Security Scans & Lessons Learned

Periodic, focused security reviews should be run after adding new cryptographic modules or protocols. Scans should focus on concrete cryptographic risks, protocol deviations, and BEAM edge cases rather than stylistic nits. Scratch notes should remain temporary and not be committed to git.

### Common Pitfalls & Invariants

1. **Strict Domain & Range Validation**:
   - *Private scalars*: Explicitly check $0 < s < n$. Never silently modulo-reduce out-of-range scalars on deserialization.
   - *Public keys*: Decompress and verify points lie on the curve and in the prime-order subgroup; reject identity and small-order points unless explicitly permitted by the RFC.
   - *Contributory ECDH*: Detect and reject all-zero shared secrets in X25519 and X448.
   - *Protocol metadata*: Enforce boundary constraints (e.g., BIP-32 depth-0 parent fingerprint and child index must be zero).

2. **Encoding & Unicode Handling on BEAM**:
   - *Fail closed*: Never silently coerce invalid or incomplete UTF-8/Unicode data into empty binaries (`<<>>`). Raise or return explicit error tuples.
   - *Charlists*: Do not use `io_lib:printable_list/1` for Unicode validation; use `io_lib:printable_unicode_list/1`.
   - *DoS & Resource Limits*: Bound input lengths for bignum decoders (e.g., Base58) to prevent quadratic BEAM bignum multiplication and `system_limit` crashes.

3. **Multi-Party State & Nonce Hygiene**:
   - Embed and verify signer public keys inside secret nonce structures to prevent signer mismatch in multi-party protocols (BIP-327).
   - Accurately handle protocol-specified point-at-infinity representations (e.g., BIP-327 33 zero bytes) across nonce aggregation and partial signing.

