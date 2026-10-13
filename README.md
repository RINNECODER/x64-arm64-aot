# x64-arm64-aot

An ahead-of-time (static) recompiler that turns x86-64 machine code into native ARM64. It targets
PlayStation 5 executables (FreeBSD-style x86-64 ELF), so they run on Apple silicon without Rosetta 2.

It is the compiler half of the native ARM64 track of
[RINNECODER/AnyPS5](https://github.com/RINNECODER/AnyPS5), a PS5 compatibility runtime for macOS.
Today that runtime runs games under Rosetta 2; this compiler is the path to running them natively.

## How it works

```
x86-64 ELF ──► Capstone decode ──► control-flow recovery ──► per-instruction LLVM IR lowering
                                                                     │
                       native ARM64 object ◄── clang -O2 (AArch64) ◄─┘
```

- **Decode and recover:** Capstone decodes each function. Recovery finds function starts, jump tables and
  call targets, so the whole executable is translated ahead of time instead of at run time.
- **Lower to LLVM IR:** each x86-64 instruction lowers to LLVM IR over an explicit register file, the
  "uniform ABI". Flags, partial-register writes and memory ordering keep x86 semantics.
- **Optimize and emit:** clang/LLVM optimizes the IR and emits a native AArch64 object. The runtime
  in `core/libs/native` links it and dispatches between translated functions.
- **Instruction coverage:** integer and SSE, AVX/AVX2, FMA, BMI1/BMI2, x87, `lock`-prefixed atomics
  (mapped to ARM64 atomics with the x86 memory ordering), and system instructions.
- **Differential testing:** `difftest/` runs each function both natively compiled and as the original
  x86-64 code under Rosetta 2, on the same inputs, and compares the registers and memory afterwards.

## Status (experimental)

- 99.9% of the instruction mnemonics used by a large commercial PS5 title lower to IR.
- About 94% of that title's functions compile end to end.
- Differential tests: 280 of 280 sampled functions match Rosetta 2 bit for bit.
- Compile time is about 55 ms per function. A port of the hot paths to C++ is planned.
- A title's entry point and initialisers run natively. Full game boot is in progress, blocked on runtime
  heap setup.
- Performance against Rosetta 2 is **not benchmarked yet**. Removing per-run translation is the goal,
  not a measured result.

## Run the tests

Requirements: an Apple silicon Mac with the Xcode command-line tools (clang), and Python 3.13.

```sh
python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt
PYTHONPATH=core/aot:. .venv/bin/python -m pytest -n 4 core/aot/tests   # 612 tests
```

## Updates

This repository mirrors the compiler from the `native/arm64` branch of RINNECODER/AnyPS5. Each sync runs
the full test suite and a privacy check before it is published.

## Credits and license

- **Original compiler:** the compiler core (decoder, IR lowering framework, runtime and examples) and its
  newer guest pipeline (module TLS, bundles, checked atomics, C++ exceptions) come from upstream
  [boykopovar/AnyPS5](https://github.com/boykopovar/AnyPS5): Daniele Giovane's AOT compiler
  ([#1835](https://github.com/boykopovar/AnyPS5/pull/1835), [#3891](https://github.com/boykopovar/AnyPS5/pull/3891))
  and its follow-ups (#4718, #4760, #4813, #5021). See `core/aot/VENDORED.md`. Upstream changes are
  merged in regularly.
- **Added in this repository** (built with AI coding agents that I directed and reviewed):
  - instruction coverage: AVX/AVX2 extensions, FMA, BMI1/2, x87, atomics and system instructions;
  - the uniform register-file ABI;
  - the differential testing harness;
  - the related tests.
- **License:** GPL-2.0, inherited from AnyPS5. See `LICENSE`.
- **Scope:** this repository contains no game code or game-derived data.
