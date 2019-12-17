#ifndef _CRYPTO_CODEC_
#define _CRYPTO_CODEC_

#include <stddef.h>
#include <stdint.h>

#include "errors.h"

void
HexChar_Encode(const uint8_t byte, char* hexHigh, char* hexLow);

CryptoResult
HexChar_Decode(const char hexHigh, const char hexLow, uint8_t* byte);

CryptoResult
Base64_Encode(
    const uint8_t* bytes,
    const size_t byteCount,
    uint8_t* b64Buf,
    const size_t bufSize,
    size_t* required);

CryptoResult
Base64_Decode(
    const uint8_t* b64Bytes,
    const size_t b64Count,
    uint8_t* byteBuf,
    const size_t bufSize,
    size_t* required);

#endif

