set(MKCHECK2_BPF_COMPILER "clang" CACHE STRING "BPF compiler to use")
set(MKCHECK2_BPF_ARCH "${CMAKE_SYSTEM_PROCESSOR}" CACHE STRING "BPF target architecture")

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h"
  COMMAND bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h"
  DEPENDS /sys/kernel/btf/vmlinux
  COMMENT "Generating vmlinux.h")

add_custom_target(vmlinux_h DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h")

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/mkcheck2.bpf.o"
  COMMAND ${MKCHECK2_BPF_COMPILER} -target bpf -c
    -g -O3 -Wall
    -I$<TARGET_PROPERTY:mkcheck2abi,INCLUDE_DIRECTORIES>
    -I${CMAKE_CURRENT_BINARY_DIR}
    -D __TARGET_ARCH_${MKCHECK2_BPF_ARCH}
    -o "${CMAKE_CURRENT_BINARY_DIR}/mkcheck2.bpf.o"
    "${CMAKE_CURRENT_SOURCE_DIR}/mkcheck2.bpf.c"
  COMMAND llvm-strip -g "${CMAKE_CURRENT_BINARY_DIR}/mkcheck2.bpf.o"
  DEPENDS mkcheck2.bpf.c mkcheck2.h vmlinux_h)

add_custom_command(
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/include/mkcheck2.skelton.h"
  COMMAND bpftool gen skeleton "${CMAKE_CURRENT_BINARY_DIR}/mkcheck2.bpf.o" > "${CMAKE_CURRENT_BINARY_DIR}/include/mkcheck2.skelton.h"
  DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/mkcheck2.bpf.o")


file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include")
configure_file(module.modulemap.in include/module.modulemap @ONLY)

add_library(mkcheck2bpf_skelton INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/include/mkcheck2.skelton.h")
target_include_directories(mkcheck2bpf_skelton INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/include")
target_sources(mkcheck2bpf_skelton INTERFACE
  "${CMAKE_CURRENT_BINARY_DIR}/include/module.modulemap"
  "${CMAKE_CURRENT_BINARY_DIR}/include/mkcheck2.skelton.h")
