if(NOT APPLE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The native AOT compiler supports Apple ARM64 execution or Linux cross-compilation")
endif()
if(APPLE AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    message(FATAL_ERROR "Native AOT execution tests require an Apple ARM64 host")
endif()
if(CMAKE_OSX_ARCHITECTURES AND NOT CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
    message(FATAL_ERROR "The experimental native AOT tool requires an arm64 build")
endif()

set(aotNativeExecution OFF)
if(APPLE OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    set(aotNativeExecution ON)
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
if(NOT APPLE)
    set(aotClang clang CACHE STRING "Clang executable for Apple ARM64 cross-compilation")
    execute_process(COMMAND ${aotClang} --version RESULT_VARIABLE aotClangStatus OUTPUT_QUIET ERROR_QUIET)
    if(NOT aotClangStatus EQUAL 0)
        message(FATAL_ERROR "Set aotClang to a Clang executable with the AArch64 backend")
    endif()
    set(aotClangEnvironment "ANYPS5_AOT_CLANG=${aotClang}")
endif()
enable_language(C)
set(BUILD_SHARED_LIBS ON)
set(BUILD_STATIC_LIBS OFF)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF)
set(CAPSTONE_X86_SUPPORT ON)
set(CAPSTONE_BUILD_MACOS_THIN ON)
set(CAPSTONE_BUILD_TESTS OFF)
set(CAPSTONE_BUILD_CSTOOL OFF)
set(CAPSTONE_BUILD_CSTEST OFF)
add_subdirectory(${CMAKE_SOURCE_DIR}/3rdparty/capstone ${CMAKE_CURRENT_BINARY_DIR}/capstone EXCLUDE_FROM_ALL)

set(aotPythonPath "${CMAKE_SOURCE_DIR}/3rdparty/capstone/bindings/python:${CMAKE_SOURCE_DIR}/3rdparty/pyelftools:${CMAKE_CURRENT_SOURCE_DIR}")
configure_file(launcher.py.in native_aot.py @ONLY)
add_custom_target(native_aot ALL DEPENDS capstone_shared)
add_library(anyps5_native_image STATIC "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotImage.cpp"
    "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotPointer.cpp"
    "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotDispatch.cpp"
    "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotTls.cpp"
    "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotBundle.cpp"
    "${CMAKE_SOURCE_DIR}/core/libs/prx/libkernel/Pthread/src/GuestTlsMacOs.cpp")
target_compile_definitions(anyps5_native_image PRIVATE APS5_NATIVE_TLS_POSIX=1)
find_package(Threads REQUIRED)
target_link_libraries(anyps5_native_image PUBLIC Threads::Threads)
if(APPLE)
    target_sources(anyps5_native_image PRIVATE "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotReadonly.cpp")
else()
    target_sources(anyps5_native_image PRIVATE "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotReadonlyLinux.cpp")
endif()
target_include_directories(anyps5_native_image PUBLIC "${CMAKE_SOURCE_DIR}/core/libs")
set_target_properties(anyps5_native_image PROPERTIES CXX_EXTENSIONS OFF)

if(BUILD_TESTING)
    add_test_executable(native_aot_thread_boundary_tests "${CMAKE_SOURCE_DIR}/core/libs/tests/NativeAotThreads.cpp"
        "${CMAKE_SOURCE_DIR}/core/libs/native/NativeAotThreads.cpp")
    target_link_libraries(native_aot_thread_boundary_tests PRIVATE anyps5_native_image)
    add_test(NAME native_aot_thread_boundary COMMAND native_aot_thread_boundary_tests)
    set_tests_properties(native_aot_thread_boundary PROPERTIES TIMEOUT 30)
    add_test_executable(native_aot_bundle_tests "${CMAKE_SOURCE_DIR}/core/libs/tests/NativeAotBundle.cpp")
    target_link_libraries(native_aot_bundle_tests PRIVATE anyps5_native_image)
    add_test(NAME native_aot_bundle COMMAND native_aot_bundle_tests)
    set_tests_properties(native_aot_bundle PROPERTIES TIMEOUT 30)
    add_test_executable(native_aot_graphics_layout_tests "${CMAKE_SOURCE_DIR}/core/libs/tests/NativeAotGraphicsLayouts.cpp")
    target_include_directories(native_aot_graphics_layout_tests PRIVATE "${CMAKE_SOURCE_DIR}/core/libs")
    add_test(NAME native_aot_graphics_layouts COMMAND native_aot_graphics_layout_tests)
    set_tests_properties(native_aot_graphics_layouts PROPERTIES TIMEOUT 30)
    add_test_executable(native_aot_readonly_tests "${CMAKE_SOURCE_DIR}/core/libs/tests/NativeAotReadonly.cpp")
    target_link_libraries(native_aot_readonly_tests PRIVATE anyps5_native_image)
    add_test(NAME native_aot_readonly COMMAND native_aot_readonly_tests)
    set_tests_properties(native_aot_readonly PROPERTIES TIMEOUT 30)
    add_test_executable(native_aot_image_tests "${CMAKE_SOURCE_DIR}/core/libs/tests/NativeAotImage.cpp")
    target_link_libraries(native_aot_image_tests PRIVATE anyps5_native_image)
    add_test(NAME native_aot_image COMMAND native_aot_image_tests)
    set_tests_properties(native_aot_image PROPERTIES TIMEOUT 30)
    if(APPLE)
        file(GLOB testSources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.py")
    else()
        set(testSources "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_portable.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_contract_recipe.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_provider_catalog.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_debug_candidates.py"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_load_facts.py")
    endif()
    foreach(testSource IN LISTS testSources)
        get_filename_component(suite "${testSource}" NAME_WE)
        string(REGEX REPLACE "^test_" "" suite "${suite}")
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${testSource}")
        execute_process(COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/tests/list_cases.py" "${testSource}"
            OUTPUT_VARIABLE cases OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
        string(REPLACE "\n" ";" cases "${cases}")
        foreach(case IN LISTS cases)
            add_test(NAME native_aot_${suite}.${case}
                COMMAND ${CMAKE_COMMAND} -E env ${aotClangEnvironment}
                    "LIBCAPSTONE_PATH=$<TARGET_FILE_DIR:capstone_shared>"
                    "PYTHONPATH=${aotPythonPath}"
                    ${Python3_EXECUTABLE} "${testSource}" "${case}")
            set_tests_properties(native_aot_${suite}.${case} PROPERTIES TIMEOUT 30)
        endforeach()
    endforeach()
endif()

option(ANYPS5_NATIVE_AOT_EXAMPLE "Build the source-based native runtime example" OFF)
if(ANYPS5_NATIVE_AOT_EXAMPLE)
    set(ps5linkSource "${CMAKE_SOURCE_DIR}/3rdparty/ps5link-sdk/linker")
    if(NOT EXISTS "${ps5linkSource}/link_real.c")
        message(FATAL_ERROR "Initialize the pinned 3rdparty/ps5link-sdk source submodule")
    endif()
    add_executable(aot_ps5link
        ${ps5linkSource}/link_real.c ${ps5linkSource}/elf_object.c
        ${ps5linkSource}/linker.c ${ps5linkSource}/dynwriter.c
        ${ps5linkSource}/catalog.c ${ps5linkSource}/catalog_extra.c
        ${ps5linkSource}/catalog_lookup.c ${ps5linkSource}/nid.c ${ps5linkSource}/sha1.c)
    add_library(anyps5_native_runtime STATIC
        ../libs/prx/libc/src/LocaleSupport.cpp
        ../libs/prx/libc/src/ApplicationHeap.cpp
        ../libs/prx/libc/src/GuestHeap.cpp
        ../libs/prx/libc/src/GuestArena.cpp
        ../libs/prx/libc/src/GuestAllocations.cpp
        ../libs/prx/libkernel/Time/TimedWait.cpp
        ../libs/prx/libkernel/System/src/Notification.cpp
        ../libs/native/NativeAotTime.cpp)
    target_include_directories(anyps5_native_runtime PUBLIC "${CMAKE_SOURCE_DIR}/core/libs")
    target_compile_options(anyps5_native_runtime PRIVATE -ffunction-sections -fdata-sections)
    target_link_libraries(anyps5_native_runtime PUBLIC anyps5_native_image)
    if(aotNativeExecution)
        target_sources(anyps5_native_runtime PRIVATE ../libs/native/NativeAotMain.cpp)
    endif()
    if(BUILD_TESTING)
        add_test_executable(native_aot_runtime_tests "${CMAKE_SOURCE_DIR}/core/libs/tests/NativeAotRuntime.cpp")
        target_link_libraries(native_aot_runtime_tests PRIVATE anyps5_native_runtime)
        if(APPLE)
            target_link_options(native_aot_runtime_tests PRIVATE -Wl,-dead_strip)
        else()
            target_link_options(native_aot_runtime_tests PRIVATE -Wl,--gc-sections)
        endif()
        add_test(NAME native_aot_runtime COMMAND native_aot_runtime_tests)
        set_tests_properties(native_aot_runtime PROPERTIES TIMEOUT 30)
    endif()
    set(aotExampleCommand ${CMAKE_COMMAND} -E env ${aotClangEnvironment}
        "LIBCAPSTONE_PATH=$<TARGET_FILE_DIR:capstone_shared>"
        "PYTHONPATH=${aotPythonPath}"
        ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/examples/hello_notify.py"
        --sdk "${CMAKE_SOURCE_DIR}/3rdparty/ps5link-sdk"
        --linker $<TARGET_FILE:aot_ps5link>
        --output "${CMAKE_CURRENT_BINARY_DIR}/hello-notify")
    if(aotNativeExecution)
        list(APPEND aotExampleCommand --runtime $<TARGET_FILE:anyps5_native_runtime>
            --image-runtime $<TARGET_FILE:anyps5_native_image>)
        if(NOT APPLE)
            list(APPEND aotExampleCommand --target linux-arm64)
        endif()
        add_custom_target(native_aot_hello_notify
            COMMAND ${aotExampleCommand} --run
            DEPENDS aot_ps5link anyps5_native_runtime capstone_shared
            USES_TERMINAL)
        add_custom_target(native_aot_hello_notify_original
            COMMAND ${aotExampleCommand} --original-delay --run
            DEPENDS aot_ps5link anyps5_native_runtime capstone_shared
            USES_TERMINAL)
        if(BUILD_TESTING)
            add_test(NAME native_aot_hello_notify COMMAND ${aotExampleCommand} --run)
            set_tests_properties(native_aot_hello_notify PROPERTIES TIMEOUT 30)
        endif()
    else()
        add_custom_target(native_aot_hello_notify
            COMMAND ${aotExampleCommand} --compile-only
            DEPENDS aot_ps5link capstone_shared USES_TERMINAL)
        if(BUILD_TESTING)
            add_test(NAME native_aot_hello_notify_compile COMMAND ${aotExampleCommand} --compile-only)
            set_tests_properties(native_aot_hello_notify_compile PROPERTIES TIMEOUT 30)
        endif()
    endif()
    if(APPLE)
        set(padCompileCommand ${CMAKE_COMMAND} -E env "LIBCAPSTONE_PATH=$<TARGET_FILE_DIR:capstone_shared>"
            "PYTHONPATH=${aotPythonPath}" ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/examples/pad_input/build.py"
            --sdk "${CMAKE_SOURCE_DIR}/3rdparty/ps5link-sdk" --linker $<TARGET_FILE:aot_ps5link>
            --output-parent "${CMAKE_CURRENT_BINARY_DIR}/pad-compile-runs")
        add_custom_target(native_aot_pad_input_compile COMMAND ${padCompileCommand}
            DEPENDS aot_ps5link capstone_shared USES_TERMINAL)
        if(BUILD_TESTING)
            add_test(NAME native_aot_pad_input_compile COMMAND ${padCompileCommand})
            add_test(NAME native_aot_pad_input_optimized_compile COMMAND ${padCompileCommand} --optimization O2)
            set_tests_properties(native_aot_pad_input_optimized_compile PROPERTIES TIMEOUT 30)
            set_tests_properties(native_aot_pad_input_compile PROPERTIES TIMEOUT 30)
        endif()
    endif()
endif()
