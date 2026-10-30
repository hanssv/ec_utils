# ec_utils Code Style & Formatting Guidelines

This document outlines the coding standards, header conventions, and formatting rules for the `ec_utils` codebase. All contributors (human and AI) should adhere to these conventions.

---

## 1. Automated Formatting (`erlfmt`)

We use `erlfmt` (Hans Svensson / Quviq custom fork) to enforce a consistent, automated code style across the entire repository.

### Configuration
- **Indentation**: **2 spaces** (strictly non-negotiable; default in our fork).
- **Line Width**: **105 characters** (default in our fork).

### Make Targets
- **Format all files**:
  ```bash
  make fmt
  ```
  Runs `erlfmt -w {src,include,test,eqc}/*.{erl,hrl,app.src} rebar.config`.

- **Check formatting (CI & pre-commit)**:
  ```bash
  make fmt-check
  ```
  Runs `erlfmt -c {src,include,test,eqc}/*.{erl,hrl,app.src} rebar.config`.

---

## 2. File Header & Docblock Conventions

Every source, test, and header file must start with a standardized EDoc `@doc` header.

### Standard Template
```erlang
%%%-------------------------------------------------------------------
%%% @doc
%%% <Concise 1-2 sentence description of module purpose>
%%%
%%% Reference:
%%%   <RFC, BIP, or academic specification link(s)>
%%% @end
%%%-------------------------------------------------------------------
-module(ecu_example).
```

### Prohibited Header Fields
- **No `Author:` tags**: Authorship is accurately tracked by Git history and commit metadata.
- **No `Created:` tags**: Creation dates are tracked by Git history.
- **No editor mode lines** (e.g., `%%% -*- erlang -*-` or `%%% % @format`).

---

## 3. Code Organization by Directory

### `src/` (Production Core)
- **Zero external runtime dependencies**: The production core must remain self-contained.
- **EqWAlizer typing**: Include `-typing([eqwalizer]).` directly beneath `-module(...)`.
- **Ordering**:
  1. `@doc` block header
  2. `-module(...)`
  3. `-typing([eqwalizer])`
  4. Includes (`-include(...)`)
  5. Types (`-type`, `-export_type`)
  6. Macros (`-define(...)`)
  7. Grouped `-export([...])` with section comments
  8. `-on_load(...)` (if applicable)
  9. `-ifdef(TEST). -compile([export_all, nowarn_export_all]). -endif.`
  10. Function definitions, preceded by explicit `-spec` signatures.
- **Export Policy**: Strict explicit exports only. Never use `export_all` outside of `-ifdef(TEST)`.

### `test/` (EUnit Tests & Reference NIF Wrappers)
- Include `-include_lib("eunit/include/eunit.hrl").`
- **Naming**: Tests should be named `*_test/0` or `*_test_/0`.
- **Export Policy**: Do not use `export_all` in test suites; EUnit auto-discovers test functions. Explicit exports only for shared NIF wrappers or generator fixtures.

### `eqc/` (QuickCheck Properties)
- Include `-include_lib("eqc/include/eqc.hrl").`
- Include `-compile([export_all, nowarn_export_all]).`
- **Naming**:
  - Properties: `prop_*`
  - Generators: `gen_*`
- **Export Policy**: `export_all` is standard in `eqc/` to facilitate running individual generators and sub-properties interactively in the Erlang REPL.

---

## 4. Shell & Script Formatting
- All shell and bash scripts in this repository must use **2-space indentation** (no tabs, no 4 spaces).

---

## 5. Verification Checklist

Before committing any changes, ensure all verification steps pass:

```bash
make fmt-check         # Verify formatting
rebar3 compile         # Verify clean compilation (no warnings)
rebar3 eunit           # Run unit tests & reference NIF cross-checks
make eqc               # Run QuickCheck property test suite
rebar3 dialyzer        # Dialyzer type checking
mise run eqwalize      # EqWAlizer type checking
```
