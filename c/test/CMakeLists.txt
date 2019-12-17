
set(HEADER_LIST
    "${CryptopalsC_SOURCE_DIR}/inc/errors.h"
    "${CryptopalsC_SOURCE_DIR}/inc/codec/codec.h")

add_executable(unit
    unit.c
    ${HEADER_LIST})

target_link_libraries(unit codec)

add_test(NAME Unit COMMAND unit)

