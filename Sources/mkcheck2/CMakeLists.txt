add_executable(mkcheck2 mkcheck2.swift)
target_link_libraries(mkcheck2 bpf)
target_include_directories(mkcheck2 PRIVATE
    $<TARGET_PROPERTY:mkcheck2abi,INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:mkcheck2bpf_skelton,INTERFACE_INCLUDE_DIRECTORIES>)

add_dependencies(mkcheck2 mkcheck2abi mkcheck2bpf_skelton)
