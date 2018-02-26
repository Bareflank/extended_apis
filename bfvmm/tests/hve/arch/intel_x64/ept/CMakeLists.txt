list(APPEND ARGN
    DEPENDS eapis_ept
    DEPENDS bfvmm_memory_manager
    DEFINES STATIC_HVE
    DEFINES STATIC_MEMORY_MANAGER
    DEFINES STATIC_INTRINSICS
)

do_test(test_page_table_entry
    SOURCES test_intrinsics.cpp
    ${ARGN}
)

do_test(test_memory_map
    SOURCES test_memory_map.cpp
    ${ARGN}
)

do_test(test_ept_helpers
    SOURCES test_helpers.cpp
    ${ARGN}
)

install(TARGETS test_memory_map DESTINATION ${PREFIX}/bin)
