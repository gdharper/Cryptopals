
set(HEADER_LIST
    "${CryptopalsC_SOURCE_DIR}/inc/errors.h"
    "${CryptopalsC_SOURCE_DIR}/inc/codec/codec.h"
    "${CryptopalsC_SOURCE_DIR}/inc/codec/b64lookup.h"
    "${CryptopalsC_SOURCE_DIR}/inc/codec/hexlookup.h")

add_library(codec
    STATIC
    codec.c
    ${HEADER_LIST})

target_include_directories(codec
    PUBLIC
    "../inc"
    "../inc/codec")

