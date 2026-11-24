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
- **The Git Barrier (Strict Commit Gating)**:
  NEVER execute `git add`, `git commit`, `git push`, or `gh pr create` in the same turn or thought sequence as running tests, benchmarks, or edits. The verification phase MUST end strictly with presenting the summary report, benchmark table, and proposed commit message, then stopping completely. Committing is a separate, gated phase: you may ONLY stage and commit when the immediately preceding user prompt explicitly commands committing (e.g. "commit", "stage and commit", "proceed with commit"). If a user message contains mixed feedback, questions, or frustration, address them in text first—never attempt to run git commands in that turn.
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

Before proposing completion, run the full verification pipeline **and** verify that all new or modified tests and QuickCheck (`eqc/`) properties comply with the validation invariants in [Section 5 (*Security Scans & Lessons Learned*)](#5-security-scans--lessons-learned):

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

> **Mandatory Reference During Validation**: Whenever writing, reviewing, or running EUnit tests and QuickCheck (`eqc/`) properties, explicitly check against the discipline and invariants below.

### Validation & QuickCheck Discipline

1. **"A Property Is Not a Property Until It Has Failed at Least Once"**:
   - Never rely solely on "happy-path" generators (e.g., generating all curve points as `k * G` in the prime-order subgroup or all polynomial coefficients as small non-negative integers). A predicate like `is_in_subgroup/1` that mistakenly returns `true` for 100% of inputs will pass every positive test.
   - Verify that every new or updated QuickCheck property actually fails when a bug is planted in the implementation (or when a guard under test is inverted/commented out).
   - Include **adversarial and negative generators** in both `eqc/` and `test/`:
     - Points on the curve (or twist) *outside* the prime-order subgroup (explicit small-order/cofactor-torsion points and random curve points without cofactor clearing).
     - Off-curve coordinate tuples and non-canonical binary encodings.
     - Identity / infinity points (`infinity`, `{0, 1}`) injected into public keys, signatures, commitments, blinding bases, and proofs.
     - Boundary, unreduced, and negative scalars (`0`, `1`, `2^254`, `ORDER - 1`, `ORDER`, negative integers).
     - Truncated, oversized, or malformed binary payloads and mismatched metadata headers.

2. **Independent Oracles & External Ground-Truth Test Vectors**:
   - The purpose of a reference NIF in `crates/` is to avoid making the same mistake twice. Reference NIFs must wrap **authoritative upstream crates directly** (e.g., `blst`, `ark-*`, `jubjub`, `redjubjub`, `c-kzg`)—never hand-translate our own Erlang algorithm into Rust.
   - Where no single upstream Rust function exists (e.g., Circomlib circuit gadgets such as Pedersen or EdDSA-Poseidon), validation **must** be anchored by external test vectors generated directly by the upstream reference tool (`circomlib` / `snarkjs`) and verified line-by-line against the upstream circuit/specification.

3. **Line-by-Line Inspection Over Checklist Grepping**:
   - In security reviews, never mark a module or check "Verified Clean" merely because a guard function (e.g., `g1_is_in_subgroup/1` or `check_constraints/2`) is called. Always trace into the callee's body and verify its behavior on adversarial inputs.

### Common Pitfalls & Invariants

1. **Strict Domain & Range Validation**:
   - *Private scalars*: Explicitly check $0 < s < n$. Never silently modulo-reduce out-of-range scalars on deserialization.
   - *Public keys*: Decompress and verify points lie on the curve and in the prime-order subgroup; reject identity and small-order points unless explicitly permitted by the RFC.
   - *Contributory ECDH*: Detect and reject all-zero shared secrets in X25519 and X448.
   - *Protocol metadata*: Enforce boundary constraints (e.g., BIP-32 depth-0 parent fingerprint and child index must be zero; PLONK domain `power` bounded to prevent $2^{\text{power}}$ memory exhaustion).

2. **Separation of Raw Arithmetic vs. Validated Boundary Parsing**:
   - *No premature scalar reduction in subgroup checks*: Low-level `scalar_mul(P, K)` functions must never silently reduce `K rem Order` if `scalar_mul(P, Order)` is used to test subgroup membership (`Order rem Order == 0` turns the subgroup check into a no-op returning `infinity` in $O(1)$). Keep raw unreduced scalar multiplication distinct from prime-subgroup scalar multiplication.
   - *No coordinate shortcutting in projective-to-affine conversion*: On twisted Edwards curves, $X = 0$ includes the order-2 point $(0, -1)$ and $Y = 0$ includes order-4 points $(\pm 1/\sqrt{a}, 0)$. `to_affine/1` must compute $(X Z^{-1}, Y Z^{-1})$ faithfully and only map $Z = 0$ to identity.
   - *No silent fallback coercions in parsers*: Never chain `try binary_to_integer(Bin) catch _:_ -> binary:decode_unsigned(Bin) end` or silently reinterpret ASCII decimal strings as raw big-endian bytes. Fail closed on malformed or ambiguous input formats.

3. **Vacuous-Truth Guards in Verifiers**:
   - Cryptographic verification equations often have degenerate trivial solutions when inputs collapse to zero or identity:
     - *R1CS witnesses*: Homogeneous check $(A \cdot w)(B \cdot w) \equiv (C \cdot w) \pmod p$ is trivially satisfied by $w = \vec{0}$ unless Wire 0 ($w_0 = 1$) is explicitly enforced and the witness prime is matched against the circuit's R1CS prime ($p > 1$).
     - *Pairing equations*: Final exponentiation raises elements to $(p^k - 1) / r$, mapping all cofactor-torsion pairing results to $1 \in \mathbb{F}_{p^k}$. Any pairing-based verifier (BLS signatures, KZG, Groth16, PLONK) will accept torsion-forged or torsion-malleated inputs unless every $G_1$ and $G_2$ input is strictly subgroup-checked.

4. **Encoding & Unicode Handling on BEAM**:
   - *Fail closed*: Never silently coerce invalid or incomplete UTF-8/Unicode data into empty binaries (`<<>>`). Raise or return explicit error tuples.
   - *Charlists*: Do not use `io_lib:printable_list/1` for Unicode validation; use `io_lib:printable_unicode_list/1`.
   - *DoS & Resource Limits*: Bound input lengths for bignum decoders and bitstring-to-list expansions before allocating lists or running bignum arithmetic to prevent `system_limit` and OOM crashes.

5. **Multi-Party State & Nonce Hygiene**:
   - Embed and verify signer public keys inside secret nonce structures to prevent signer mismatch in multi-party protocols (BIP-327).
   - Accurately handle protocol-specified point-at-infinity representations (e.g., BIP-327 33 zero bytes) across nonce aggregation and partial signing.

