cmake_minimum_required(VERSION 3.18)
project(UserDataMonitoring LANGUAGES C CXX)

# Set standards
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

link_directories(${CMAKE_SOURCE_DIR}/src/sga-common/mariadb)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBJSONC REQUIRED json-c)

# Create bin and tmp directories
set(OUTPUT_DIR ${CMAKE_SOURCE_DIR}/bin)
file(MAKE_DIRECTORY ${OUTPUT_DIR})
set(TMP_DIR ${CMAKE_SOURCE_DIR}/tmp)
file(MAKE_DIRECTORY ${TMP_DIR})

# Paths to libbpf and bpftool
set(LIBBPF_DIR ${CMAKE_SOURCE_DIR}/libbpf)
set(LIBBPF_LIB ${LIBBPF_DIR}/libbpf.a)
set(LIBBPF_INCLUDE_DIR ${LIBBPF_DIR}/src)
set(BPFTOOL ${CMAKE_SOURCE_DIR}/tools/bpftool)
set(LLVM_STRIP "llvm-strip")
set(CLANG "clang")
set(ARCH "x86")

if (NOT EXISTS ${LIBBPF_LIB})
    message(FATAL_ERROR "Prebuilt libbpf.a not found in ${LIBBPF_LIB}")
endif()
if (NOT IS_DIRECTORY ${LIBBPF_INCLUDE_DIR})
    message(FATAL_ERROR "libbpf include directory not found at ${LIBBPF_INCLUDE_DIR}")
endif()
if (NOT EXISTS ${BPFTOOL})
    message(FATAL_ERROR "Bpftool not found at ${BPFTOOL}")
endif()

# Add imported library for libbpf
add_library(bpf STATIC IMPORTED)
set_target_properties(bpf PROPERTIES
    IMPORTED_LOCATION ${LIBBPF_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${LIBBPF_INCLUDE_DIR}
)

message("-- Libbpf found")
message("-- Bpftool found")

# Compile the .bpf.o object and generate skeleton header
add_custom_command(
    OUTPUT ${TMP_DIR}/mapinmap.bpf.o
    COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${ARCH} -DHAVE_TC_EXT_1
            -I${LIBBPF_INCLUDE_DIR} -c ${CMAKE_SOURCE_DIR}/src/mapinmap.bpf.c
            -o ${TMP_DIR}/mapinmap.bpf.o
    COMMAND ${LLVM_STRIP} -g ${TMP_DIR}/mapinmap.bpf.o
)
add_custom_command(
    OUTPUT ${TMP_DIR}/mapinmap.skel.h
    COMMAND ${BPFTOOL} gen skeleton ${TMP_DIR}/mapinmap.bpf.o > ${TMP_DIR}/mapinmap.skel.h
    DEPENDS ${TMP_DIR}/mapinmap.bpf.o
)
add_custom_target(generate_bpf ALL
    DEPENDS ${TMP_DIR}/mapinmap.bpf.o ${TMP_DIR}/mapinmap.skel.h
)

# Compile sources
add_executable(mapinmap
    ${CMAKE_SOURCE_DIR}/src/sga-common/sga_sqldb.cpp
    ${CMAKE_SOURCE_DIR}/src/sga-common/mariadb/mysql.h
    ${CMAKE_SOURCE_DIR}/src/logger-common.cpp
    ${CMAKE_SOURCE_DIR}/src/sga-common/lfqueue.c
    ${CMAKE_SOURCE_DIR}/src/sga-common/sga_xdp.cpp
    ${CMAKE_SOURCE_DIR}/src/sga-common/sga_socket.cpp
    ${CMAKE_SOURCE_DIR}/src/sga-common/sga_etc.cpp
    ${CMAKE_SOURCE_DIR}/src/sga-common/sga_dbconn.cpp
    ${CMAKE_SOURCE_DIR}/src/sga-common/packet_stream.cpp
    ${CMAKE_SOURCE_DIR}/src/sga-common/packet_adg.cpp
    ${CMAKE_SOURCE_DIR}/src/sga_tctap.cpp
    ${CMAKE_SOURCE_DIR}/src/mapinmap.cpp
)

# Ensure the BPF targets build first
add_dependencies(mapinmap generate_bpf)

# Add include paths (private = only for this target)
target_include_directories(mapinmap PRIVATE
    ${LIBBPF_INCLUDE_DIR}
    ${LIBJSONC_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/src/sga-common
    ${CMAKE_SOURCE_DIR}/src/sga-common/mariadb
)

target_compile_definitions(mapinmap PRIVATE
    USE_BTF
    HAVE_TC_EXT_1
)

# Link libraries
target_link_libraries(mapinmap PRIVATE
    bpf
    ${LIBJSONC_LIBRARIES}
    elf
    z
    pthread
    ${CMAKE_SOURCE_DIR}/src/sga-common/lib/libmariadb.so.3
)

# Set runtime output
set_target_properties(mapinmap PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR}
)