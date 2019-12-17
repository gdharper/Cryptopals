
set(HEADER_LIST
    "${CryptopalsC_SOURCE_DIR}/inc/errors.h"
    "${CryptopalsC_SOURCE_DIR}/inc/codec/codec.h")

add_executable(cryptopals
    cryptopals.c
    ${HEADER_LIST})

target_link_libraries(cryptopals codec)

