# Fork-only: native ARM64 graphics runtime for the AOT gpu_cube fixture, built on the fork's
# Metal backend. This replaces the upstream file (Vulkan driver + MoltenVK) for
# ANYPS5_NATIVE_AOT_GRAPHICS. The source lists for libSceAgcDriver and libSceVideoOut mirror
# cmake/RosettaGraphics.cmake (the Rosetta direct path) but produce one static library that the
# native gpu_cube executables link, instead of x86_64 .prx modules.

get_filename_component(LIBS_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

if(NOT APPLE OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    message(FATAL_ERROR "The native runtime currently requires Apple ARM64")
endif()
if(CMAKE_OSX_ARCHITECTURES AND NOT CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
    message(FATAL_ERROR "The native runtime currently requires a single arm64 architecture")
endif()

# --- Metal backend: utilities, shader bridge and the shader recompiler -------------------------
include(${CMAKE_SOURCE_DIR}/core/shader/recompiler/CMakeLists.txt)
set(ANYPS5_METAL_SHADER_BRIDGE ON)
add_subdirectory(${CMAKE_SOURCE_DIR}/core/shader/recompiler/MetalBackend ${CMAKE_BINARY_DIR}/native/metal/bridge)
add_subdirectory(${LIBS_INCLUDE_DIR}/prx/libSceAgcDriver/Graphics/Metal ${CMAKE_BINARY_DIR}/native/metal/utilities)

add_library(native_runtime_platform INTERFACE)
target_link_libraries(native_runtime_platform INTERFACE "-framework CoreFoundation")
add_png_decoder(decoder_png_native native_runtime_platform)

set(nativeShaderGuards)
file(GLOB_RECURSE nativeShaderGuards CONFIGURE_DEPENDS
    "${LIBS_INCLUDE_DIR}/prx/libSceAgcDriver/*.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libSceAgcDriver/*.hpp"
    "${LIBS_INCLUDE_DIR}/prx/libSceAgcDriver/*.h")
list(FILTER nativeShaderGuards EXCLUDE REGEX "/(tests|tools)/")
add_shader_recompiler(shader_recompiler_native native_runtime_platform GUARD_SOURCES ${nativeShaderGuards})

# --- one static library with the HLE runtime and the Metal graphics driver ---------------------
add_library(anyps5_native_graphics STATIC)

# libc/libkernel plus every HLE component the guest start-up path imports. An import no component
# defines is left undefined by the archives, so the bounded title image namespaces it to
# `__aps5_guest_<name>` and the stub generator lowers it to a bare `ret` (or a trampoline to the
# host C library): the guest call then silently returns zero. The components below are the ones the
# recorded boot reaches before the title's main loop; each is host-portable (no x86_64 asm).
# libSceSaveData.native is the variant that carries the transaction-resource entry points.
set(nativeComponents libc libkernel libSceAgc libScePad libSceMouse libSceKeyboard libSceFiber
    libSceFont libSceFontFt
    libSceSysmodule libSceCommonDialog libSceSystemGesture libSceSaveData.native
    libSceNpGameIntent libSceSystemService libSceAppContent libSceUserService libSceIme libSceJson2)
set(nativeUnsupportedSources
    "${LIBS_INCLUDE_DIR}/prx/libc/src/ApplicationProcessParameters.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libc/src/Strings.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libc/src/Math.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libc/src/Formatting.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libc/src/ScanningWide.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libc/src/FormattingWide.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libc/src/JumpBuffer.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libkernel/System/src/Exception.cpp"
    "${LIBS_INCLUDE_DIR}/prx/libkernel/System/src/UserContext.cpp"

    # Fork-only x86_64 inline asm in libkernel sources; the fixture does not use the signal set calls.
    "${LIBS_INCLUDE_DIR}/prx/libkernel/System/src/SignalSets.cpp")
foreach(component IN LISTS nativeComponents)
    get_target_property(componentSources ${component} SOURCES)
    get_target_property(componentDirectory ${component} SOURCE_DIR)
    foreach(source IN LISTS componentSources)
        if(NOT IS_ABSOLUTE "${source}")
            set(source "${componentDirectory}/${source}")
        endif()
        if(NOT source IN_LIST nativeUnsupportedSources)
            target_sources(anyps5_native_graphics PRIVATE "${source}")
        endif()
    endforeach()
    get_target_property(componentIncludes ${component} INCLUDE_DIRECTORIES)
    if(componentIncludes)
        target_include_directories(anyps5_native_graphics PRIVATE ${componentIncludes})
    endif()
    get_target_property(componentDefines ${component} COMPILE_DEFINITIONS)
    if(componentDefines)
        target_compile_definitions(anyps5_native_graphics PRIVATE ${componentDefines})
    endif()
endforeach()

# The native image links libc and libkernel into one binary and both define exit_nid_postfix.
# libc's implementation (with APS5_TRACE_EXIT) is the one the guest uses, so the libkernel copy is
# compiled out here; the Rosetta path still builds libkernel's own prx unchanged.
set_source_files_properties("${LIBS_INCLUDE_DIR}/prx/libkernel/System/src/Process.cpp"
    PROPERTIES COMPILE_DEFINITIONS "APS5_NATIVE_LIBC_OWNS_EXIT=1")

# Metal libSceAgcDriver and libSceVideoOut (cmake/RosettaGraphics.cmake source lists, arm64 static).
set(aotAgcDriver ${LIBS_INCLUDE_DIR}/prx/libSceAgcDriver)
target_sources(anyps5_native_graphics PRIVATE
    ${aotAgcDriver}/Unimplemented.cpp
    ${aotAgcDriver}/Eq/src/Event.cpp
    ${aotAgcDriver}/Eq/src/Query.cpp
    ${aotAgcDriver}/Resource/src/Lifecycle.cpp
    ${aotAgcDriver}/Resource/src/Registration.cpp
    ${aotAgcDriver}/State/src/Configuration.cpp
    ${aotAgcDriver}/State/src/Status.cpp
    ${aotAgcDriver}/Submit/src/Acb.cpp
    ${aotAgcDriver}/Submit/src/CommandBuffer.cpp
    ${aotAgcDriver}/Submit/src/Dcb.cpp
    ${aotAgcDriver}/Submit/src/Submission.cpp
    ${aotAgcDriver}/Execution/src/AspectFit.cpp
    ${aotAgcDriver}/Execution/src/Pm4.cpp
    ${aotAgcDriver}/Execution/src/ComputeDispatch.cpp
    ${aotAgcDriver}/Execution/src/DrawDispatch.cpp
    ${aotAgcDriver}/Execution/src/IndirectDraw.cpp
    ${aotAgcDriver}/Execution/src/NativeGuestMemory.cpp
    ${aotAgcDriver}/Execution/src/SubmissionCapture.cpp
    ${aotAgcDriver}/Execution/src/ShaderCapture.cpp
    ${aotAgcDriver}/Execution/src/SubmissionValidation.cpp
    ${aotAgcDriver}/Execution/src/ShaderMemory.cpp
    ${aotAgcDriver}/Execution/src/Driver/EntryPoints.cpp
    ${aotAgcDriver}/Execution/src/DisplayBuffer.cpp
    ${aotAgcDriver}/Execution/src/DisplayFormat.cpp
    ${aotAgcDriver}/Execution/Metal/MetalDriver.mm
    ${aotAgcDriver}/Execution/Metal/MetalPacketExecution.mm
    ${aotAgcDriver}/Execution/Metal/DirectDriver.mm
    ${aotAgcDriver}/Graphics/src/ComputeStageInfo.cpp
    ${aotAgcDriver}/Graphics/src/State.cpp
    ${aotAgcDriver}/Graphics/src/SurfaceMetadata.cpp
    ${aotAgcDriver}/Graphics/src/DccClearEncoding.cpp
    ${aotAgcDriver}/Graphics/src/ShaderInputState.cpp
    ${aotAgcDriver}/Graphics/src/ColorTargetLayout.cpp
    ${aotAgcDriver}/Graphics/src/MeshDraw.cpp
    ${aotAgcDriver}/Graphics/Metal/MetalComputeDispatch.mm
    ${aotAgcDriver}/Graphics/Metal/MetalRenderState.mm
    ${aotAgcDriver}/Graphics/Metal/MetalTexture.mm
    ${aotAgcDriver}/Graphics/Metal/MetalDraw.mm
    ${aotAgcDriver}/Graphics/Metal/MetalShaderResources.mm
    ${aotAgcDriver}/Graphics/Metal/MetalDepthSurface.mm
    ${aotAgcDriver}/Graphics/Metal/MetalPresentation.mm
    ${aotAgcDriver}/Graphics/Metal/FrameCapture.mm
    ${aotAgcDriver}/Graphics/Metal/MetalDccExtent.cpp
    ${aotAgcDriver}/Graphics/Metal/MetalHostExports.cpp)

# The guest start trampoline (Aps5StartGuest) and the AppKit main-thread dispatcher live in the
# fork's Darwin runtime (x86_64-only) and in upstream's MainThreadMacOs.cpp (the native arm64
# start that keeps the main thread in its run loop). The generic libkernel target adds neither.
target_sources(anyps5_native_graphics PRIVATE
    ${LIBS_INCLUDE_DIR}/prx/libkernel/Darwin/GuestRuntime.cpp
    ${LIBS_INCLUDE_DIR}/prx/libkernel/Pthread/src/MainThreadMacOs.cpp
    ${LIBS_INCLUDE_DIR}/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp)

set(aotVideoOut ${LIBS_INCLUDE_DIR}/prx/libSceVideoOut)
target_sources(anyps5_native_graphics PRIVATE
    ${aotVideoOut}/Unimplemented.cpp
    ${aotVideoOut}/src/Event.cpp
    ${aotVideoOut}/src/BufferMetadata.cpp
    ${aotVideoOut}/src/VideoOutState.cpp
    ${aotVideoOut}/src/Buffer.cpp
    ${aotVideoOut}/src/Output.cpp
    ${aotVideoOut}/src/VideoOutDriver.cpp
    ${aotVideoOut}/src/PadInput.cpp
    ${aotVideoOut}/src/MouseInput.cpp
    ${aotVideoOut}/src/KeyboardInput.cpp
    ${aotVideoOut}/src/InputMapping.cpp
    ${LIBS_INCLUDE_DIR}/prx/libkernel/Time/TimedWait.cpp
    ${aotVideoOut}/src/NativeHostWindow.mm
    ${aotVideoOut}/src/DirectHostApplication.mm
    ${aotVideoOut}/src/DirectDisplayWindow.mm)

target_compile_options(anyps5_native_graphics PRIVATE "$<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>")
target_compile_definitions(anyps5_native_graphics PRIVATE
    ANYPS5_METAL_GUEST_REPLAY=1 ANYPS5_METAL_BACKEND=1 ANYPS5_ROSETTA_DIRECT=1)
target_include_directories(anyps5_native_graphics PRIVATE
    ${LIBS_INCLUDE_DIR}
    ${ANYPS5_VULKAN_HEADERS_INCLUDE_DIR}
    ${ANYPS5_SDL2_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/core/shader/recompiler)
target_link_libraries(anyps5_native_graphics PUBLIC
    jpeg_turbo
    SDL2-static
    shader_recompiler_native
    decoder_png_native
    native_runtime_platform
    anyps5_native_image
    anyps5_metal_utilities
    freetype
    "-framework ImageIO"
    "-framework CoreGraphics"
    "-framework Metal"
    "-framework QuartzCore")
set_target_properties(anyps5_native_graphics PROPERTIES CXX_EXTENSIONS OFF POSITION_INDEPENDENT_CODE ON)
target_link_options(anyps5_native_graphics INTERFACE LINKER:-dead_strip)

# --- gpu_cube fixture -------------------------------------------------------------------------
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(cubeExample "${CMAKE_SOURCE_DIR}/core/aot/examples/gpu_cube")
file(GLOB cubeBuildInputs CONFIGURE_DEPENDS "${cubeExample}/*.py" "${cubeExample}/contracts.json" "${CMAKE_SOURCE_DIR}/core/aot/*.py")
set(cubeInputHashes "${CMAKE_C_COMPILER_ID}-${CMAKE_C_COMPILER_VERSION}")
foreach(input IN LISTS cubeBuildInputs)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${input}")
    file(SHA256 "${input}" inputHash)
    string(APPEND cubeInputHashes "${inputHash}")
endforeach()
string(SHA256 cubeInputKey "${cubeInputHashes}")
set(cubeArtifacts "${CMAKE_CURRENT_BINARY_DIR}/gpu-cube-${cubeInputKey}")
set(cubePythonPath "${CMAKE_SOURCE_DIR}/core/aot:${CMAKE_SOURCE_DIR}/3rdparty/capstone/bindings/python:${CMAKE_SOURCE_DIR}/3rdparty/pyelftools")
add_custom_command(OUTPUT "${cubeArtifacts}/module.o" "${cubeArtifacts}/reference.o" "${cubeArtifacts}/build.json"
    COMMAND ${CMAKE_COMMAND} -E env "PYTHONPATH=${cubePythonPath}" "LIBCAPSTONE_PATH=$<TARGET_FILE_DIR:capstone_shared>"
        ${Python3_EXECUTABLE} "${cubeExample}/build.py" --sdk "${CMAKE_SOURCE_DIR}/3rdparty/ps5link-sdk" --output "${cubeArtifacts}"
    DEPENDS capstone_shared ${cubeBuildInputs}
    VERBATIM)
set_source_files_properties("${cubeArtifacts}/module.o" "${cubeArtifacts}/reference.o" PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
add_executable(native_gpu_cube EXCLUDE_FROM_ALL NativeCubeLauncher.cpp "${cubeArtifacts}/module.o")
add_executable(native_gpu_cube_reference EXCLUDE_FROM_ALL NativeCubeReference.cpp "${cubeArtifacts}/reference.o")
target_link_libraries(native_gpu_cube PRIVATE anyps5_native_graphics)
target_link_libraries(native_gpu_cube_reference PRIVATE anyps5_native_graphics)
# The Metal driver loads AnyPS5Utilities.metallib next to the executable (DirectDriver.mm).
# One shared copy avoids two POST_BUILD copies racing on the same path.
get_target_property(anyps5NativeMetallib anyps5_metal_utilities ANYPS5_METALLIB)
set(cubeMetallib "${CMAKE_CURRENT_BINARY_DIR}/AnyPS5Utilities.metallib")
add_custom_command(OUTPUT "${cubeMetallib}"
    COMMAND ${CMAKE_COMMAND} -E copy "${anyps5NativeMetallib}" "${cubeMetallib}"
    DEPENDS anyps5_metal_shaders "${anyps5NativeMetallib}"
    VERBATIM)
add_custom_target(native_gpu_cube_metallib DEPENDS "${cubeMetallib}")
foreach(cubeTarget IN ITEMS native_gpu_cube native_gpu_cube_reference)
    add_dependencies(${cubeTarget} native_gpu_cube_metallib)
endforeach()
add_custom_target(native_gpu_cube_build DEPENDS native_gpu_cube native_gpu_cube_reference)
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/gpu-cube-paths.json"
    CONTENT "{\"aot\":\"$<TARGET_FILE:native_gpu_cube>\",\"reference\":\"$<TARGET_FILE:native_gpu_cube_reference>\",\"build\":\"${cubeArtifacts}\"}\n")

add_custom_target(native_gpu_cube_check
    COMMAND ${Python3_EXECUTABLE} "${cubeExample}/verify.py" --capture metal
        --paths "${CMAKE_CURRENT_BINARY_DIR}/gpu-cube-paths.json" --output-parent "${CMAKE_CURRENT_BINARY_DIR}/graphics-runs"
    DEPENDS native_gpu_cube native_gpu_cube_reference
    USES_TERMINAL VERBATIM)

add_test(NAME native_graphics_image_comparison COMMAND ${Python3_EXECUTABLE} "${cubeExample}/test_images.py")
set_tests_properties(native_graphics_image_comparison PROPERTIES TIMEOUT 30)
add_test(NAME native_graphics_reference_policy COMMAND ${Python3_EXECUTABLE} "${cubeExample}/test_reference.py")
set_tests_properties(native_graphics_reference_policy PROPERTIES TIMEOUT 30)

foreach(target IN ITEMS native_gpu_cube native_gpu_cube_reference)
    if(target STREQUAL "native_gpu_cube")
        set(cubeObject module.o)
    else()
        set(cubeObject reference.o)
    endif()
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${Python3_EXECUTABLE} "${cubeExample}/artifact.py"
            --binary "$<TARGET_FILE:${target}>" --object "${cubeArtifacts}/${cubeObject}" --build "${cubeArtifacts}/build.json"
            --archive "$<TARGET_FILE:anyps5_native_graphics>"
            --archive "$<TARGET_FILE:anyps5_native_image>"
            --archive "$<TARGET_FILE:shader_recompiler_native>"
            --archive "$<TARGET_FILE:decoder_png_native>"
            --archive "$<TARGET_FILE:SDL2-static>"
        VERBATIM)
endforeach()

# --- standalone runtime tests -------------------------------------------------------------------
# Each of these includes the translation unit it covers, so it links only Threads and never
# anyps5_native_image, whose archive holds the same symbols.
if(BUILD_TESTING)
    find_package(Threads REQUIRED)
    add_test_executable(native_aot_hle_log_open_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/NativeReviewFixHleLogTests.cpp")
    add_test_executable(native_aot_image_overlap_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/NativeReviewFixImageTests.cpp")
    add_test_executable(native_aot_tls_release_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/NativeReviewFixTlsTests.cpp")
    foreach(reviewTest IN ITEMS native_aot_hle_log_open_tests native_aot_image_overlap_tests native_aot_tls_release_tests)
        target_include_directories(${reviewTest} PRIVATE ${LIBS_INCLUDE_DIR})
        target_compile_features(${reviewTest} PRIVATE cxx_std_20)
        set_target_properties(${reviewTest} PROPERTIES CXX_EXTENSIONS OFF)
        target_link_libraries(${reviewTest} PRIVATE Threads::Threads)
    endforeach()
    # The guest arena reads its slide from the environment before it is first used, so this test
    # compiles GuestArena and its dependencies directly instead of linking a shared runtime.
    add_test_executable(native_aot_guest_arena_tests "${CMAKE_CURRENT_SOURCE_DIR}/tests/NativeGuestArenaTests.cpp"
        "${LIBS_INCLUDE_DIR}/prx/libc/src/GuestArena.cpp"
        "${LIBS_INCLUDE_DIR}/prx/libc/src/GuestWriteWatch.cpp"
        "${LIBS_INCLUDE_DIR}/prx/libc/src/GuestAllocations.cpp")
    target_include_directories(native_aot_guest_arena_tests PRIVATE ${LIBS_INCLUDE_DIR})
    target_compile_features(native_aot_guest_arena_tests PRIVATE cxx_std_20)
    set_target_properties(native_aot_guest_arena_tests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(native_aot_guest_arena_tests PRIVATE Threads::Threads)
    add_test(NAME native_aot_guest_arena COMMAND native_aot_guest_arena_tests)
    set_tests_properties(native_aot_guest_arena PROPERTIES TIMEOUT 30)
    # The Python suite in core/aot/tests already registers as native_aot_hle_log.<class>.<case>.
    add_test(NAME native_aot_hle_log_open COMMAND native_aot_hle_log_open_tests)
    # 100 forked trials, each racing 16 threads to open the log.
    set_tests_properties(native_aot_hle_log_open PROPERTIES TIMEOUT 120)
    add_test(NAME native_aot_image_overlap COMMAND native_aot_image_overlap_tests)
    set_tests_properties(native_aot_image_overlap PROPERTIES TIMEOUT 60)
    add_test(NAME native_aot_tls_release COMMAND native_aot_tls_release_tests)
    set_tests_properties(native_aot_tls_release PROPERTIES TIMEOUT 60)
endif()
