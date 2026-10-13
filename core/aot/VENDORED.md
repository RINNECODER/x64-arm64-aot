# Vendored AOT compiler

Source: `boykopovar/AnyPS5` pull request branches, fetched read-only.

| | |
|---|---|
| Base commit | `d4354e41c2cc2b046a117e2773d6a8ae318a71e` |
| PR | [#1835](https://github.com/boykopovar/AnyPS5/pull/1835) (AOT x86-64 → ARM64 compiler), [#3891](https://github.com/boykopovar/AnyPS5/pull/3891) (native ARM64 graphics) |
| Author | Daniele Giovane |
| Fetched | `git fetch --no-tags https://github.com/boykopovar/AnyPS5.git pull/3891/head:refs/remotes/aot/3891 pull/1835/head:refs/remotes/aot/1835` |
| Vendored with | `git checkout aot/3891 -- core/aot core/libs/native core/libs/prx/libc/include/NativeAotImage.hpp` |

Vendored paths:

- `core/aot/` — the offline compiler (Python): Capstone decode, per-instruction LLVM IR
  lowering, `clang` → ARM64 object, contracts, tests, `examples/hello_notify.py`,
  `examples/gpu_cube/`.
- `core/libs/native/` — the native runtime consumer (`NativeAotImage`, `NativeAotPointer`,
  `NativeAotReadonly`, `NativeAotTime`, `NativeAotMain`, the gpu_cube launchers/reference).
  `CMakeLists.txt` is rewritten for this fork's Metal backend (see below).
- `core/libs/prx/libc/include/NativeAotImage.hpp` — the runtime registration header the
  above includes; it is part of the AOT runtime and is absent from this fork's tree.
- AOT test and runtime sources the vendored CMake references and this fork lacks:
  `core/libs/tests/{NativeAotGraphicsLayouts,NativeAotImage,NativeAotReadonly,NativeAotRuntime,
  NativeDirectMemoryAliases,AtomicSharedPointer,HostCounter,GuestTlsMacOs}.cpp`,
  `core/libs/prx/libkernel/Pthread/{include/GuestTlsMacOs.hpp,src/GuestTlsMacOs.cpp}`.
- `core/libs/prx/libkernel/Pthread/src/MainThreadMacOs.cpp` — upstream's native arm64 guest
  start (`Aps5StartGuest` on a guest thread with the main thread in its run loop). The
  fork's `libkernel/Darwin/GuestRuntime.cpp` is `#if __APPLE__ && __x86_64__` only.

Not vendored: the upstream Vulkan graphics closure. This fork's `core/libs/native/CMakeLists.txt`
is replaced with a Metal version (`cmake/NativeAotGraphics.cmake`); it builds one static
`anyps5_native_graphics` from the component sources plus the Metal `libSceAgcDriver` and
`libSceVideoOut` source lists from `cmake/RosettaGraphics.cmake`, so the gpu_cube fixture needs
no Vulkan loader or MoltenVK.

## Local deviations from the upstream ref

1. **`core/aot/examples/gpu_cube/contracts.json` requalified (4 provider hashes).**
   The contract binds provider source excerpts to whole-file SHA-256 values. Three
   providers differ from the upstream branch only by *unrelated* additions:
   - `core/libs/prx/libc/src/Process.cpp` — adds `LibcBeginHostExit_nid_postfix`
   - `core/libs/prx/libc/src/RuntimeSupport.cpp` — drops `strtoimax`/`strtoumax`, adds
     `__divti3`/`__umodti3`
   - `core/libs/prx/libkernel/System/src/Notification.cpp` — adds a `File`-based stderr
     path in `sceKernelDebugOutText`
   The contracted excerpts (`atexit`/`exit`, `__cxa_atexit`,
   `sceKernelSendNotificationRequest`) are unchanged and still present. Only the
   whole-file hashes were updated. **This is a local requalification and must be reviewed
   before any acceptance claim**; the upstream-qualified hashes are the aot/3891 blobs.
2. **Three AOT submodules cloned by hand** at the aot/3891 pins, because the sandbox
   cannot write `.git/config` and therefore `git submodule update --init` fails with
   `could not write config file .../.git/config: Operation not permitted`:
   - `3rdparty/capstone` `accf4df62f1fba6f92cae692985d27063552601c`
   - `3rdparty/pyelftools` `d4ea35fc3c34eb0e4d3f8cfafb31552f5b5c37d6`
   - `3rdparty/ps5link-sdk` `ea771e535378740b6a058b8e5419eb8a0e0e0ec8`
   `.gitmodules` gained the matching entries; the other third-party submodules remain
   empty and are untouched.
3. **`core/libs/prx/libkernel/Time/Time.cpp` arm64 patch.** The fork's file includes
   `<x86intrin.h>` and calls `__rdtsc()` unconditionally (Rosetta path). Guarded the include
   and added `HostTsc()` (`mach_absolute_time()` off x86) so the file compiles for arm64;
   `sceKernelReadTsc`/`sceKernelGetTscFrequency` keep `__rdtsc` on x86_64.
4. **`core/libs/native/CMakeLists.txt` rewritten for the Metal backend** (see above).
   `SignalSets.cpp` is excluded (fork-only x86_64 inline asm, unused by the fixture);
   `Darwin/GuestRuntime.cpp`, `Pthread/src/MainThreadMacOs.cpp` and
   `Pthread/src/GuestTlsMacOs.cpp` are added explicitly.
5. **`core/aot/examples/gpu_cube/{verify,images,test_images}.py` extended for the Metal capture
   path** (the fork builds no Vulkan driver): `--capture metal` reads the driver's PNG captures
   and JSON manifest instead of `APS5_DUMP_FRAMES` BMPs plus the `capture-trace.log` flip lines.
   `images.read_png` decodes the PNGs to the same RGB the BMP reader returns. The BMP path and
   all its checks are unchanged.
