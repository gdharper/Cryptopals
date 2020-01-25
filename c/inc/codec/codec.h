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
    const uint32_t byteCount,
    uint8_t* b64Buf,
    const uint32_t bufSize,
    uint32_t* required);

CryptoResult
Base64_Decode(
    const uint8_t* b64Bytes,
    const uint32_t b64Count,
    uint8_t* byteBuf,
    const uint32_t bufSize,
    uint32_t* required);

#endif

