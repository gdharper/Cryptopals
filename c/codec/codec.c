
#include <stdbool.h>

#include "b64lookup.h"
#include "codec.h"
#include "hexlookup.h"


void
HexChar_Encode(const uint8_t byte, char* hexHigh, char* hexLow)
{
    static const char encode[] = "0123456789abcdef";
    *hexHigh = encode[(byte >> 4)];
    *hexLow = encode[(byte & 0x0f)];
}


#define NYBS_TO_BYTE(_high, _low) (((_high) << 4) | (_low & 0x0f))
CryptoResult
HexChar_Decode(const char hexHigh, const char hexLow, uint8_t* byte)
{
    RETURN_RESULT_IF((hexLow < 0 || hexHigh < 0), Crypto_Err_InvalidArg);
    const uint8_t high = g_Hex[hexHigh];
    const uint8_t low = g_Hex[hexLow];
    
    *byte = NYBS_TO_BYTE(high, low);
    RETURN_RESULT_IF((low == INV_SYM || high == INV_SYM),
            Crypto_Err_InvalidArg);
    return Crypto_Ok;
}


#define PADDING '='

CryptoResult Base64_Encode(
    const uint8_t* bytes,
    const uint32_t byteCount,
    uint8_t* b64Buf,
    const uint32_t bufSize,
    uint32_t* required)
{
    static const uint8_t b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    const uint32_t req = (byteCount / 3 + ((byteCount % 3) ? 1 : 0)) * 4;
    *required = req;
    RETURN_RESULT_IF(bufSize < req, Crypto_Err_BufferTooSmall);

    uint32_t r, i = 0;
    for (r = byteCount; r > 2; r -= 3)
    {
        b64Buf[i] = b64[bytes[byteCount-r] >> 2];
        b64Buf[i+1] = b64[(((bytes[byteCount-r] & 0x03) << 6) >> 2)
                        | (bytes[byteCount-r+1] >> 4)];
        b64Buf[i+2] = b64[(((bytes[byteCount-r+1] & 0x0f) << 4) >> 2)
                        | (bytes[byteCount-r+2] >> 6)];
        b64Buf[i+3] = b64[(((bytes[byteCount-r+2] & 0x3f) << 2) >> 2)];

        i += 4;
    }

    if (r == 2)
    {
        b64Buf[i] = b64[bytes[byteCount-r] >> 2];
        b64Buf[i+1] = b64[(((bytes[byteCount-r] & 0x03) << 6) >> 2)
                        | (bytes[byteCount-r+1] >> 4)];
        b64Buf[i+2] = b64[(((bytes[byteCount-r+1] & 0x0f) << 4) >> 2)];
        b64Buf[i+3] = PADDING;
    }
    else if (r)
    {
        b64Buf[i+0] = b64[bytes[byteCount-r] >> 2];
        b64Buf[i+1] = b64[(((bytes[byteCount-r] & 0x03) << 6) >> 2)];
        b64Buf[i+2] = PADDING;
        b64Buf[i+3] = PADDING;
    }
    
    return Crypto_Ok;
}

CryptoResult Base64_Decode(
    const uint8_t* b64Bytes,
    const uint32_t b64Count,
    uint8_t* byteBuf,
    const uint32_t bufSize,
    uint32_t* required)
{
    const uint32_t req = (b64Count / 4 + ((b64Count % 4) ? 1 : 0)) * 3;
    if (bufSize < req)
    {
        *required = req;
        return Crypto_Err_BufferTooSmall;
    }

    uint8_t b[4];
    uint32_t r = b64Count, n = 0;
    for (r = b64Count; r > 4; r -= 4)
    {
        if ((b64Bytes[b64Count - r]
             |b64Bytes[b64Count - r+1]
             |b64Bytes[b64Count - r+2]
             |b64Bytes[b64Count - r+3]) & INV_VAL)
        {
            *required = n;
            return Crypto_Err_InvalidArg;
        }

        b[0] = g_B64[b64Bytes[b64Count - r]];
        b[1] = g_B64[b64Bytes[b64Count - r+1]];
        b[2] = g_B64[b64Bytes[b64Count - r+2]];
        b[3] = g_B64[b64Bytes[b64Count - r+3]];
        if ((b[0]|b[1]|b[2]|b[3]) & INV_VAL)
        {
            *required = n;
            return Crypto_Err_InvalidArg;
        }

        byteBuf[n+0] = ((b[0] & 0x3f) << 2) | (b[1] >> 4);
        byteBuf[n+1] = ((b[1] & 0x0f) << 4) | (b[2] >> 2);
        byteBuf[n+2] = ((b[2] & 0x03) << 6) | (b[3]);
        n += 3;
    }

    uint32_t o = 0;
    if (r == 4 && b64Bytes[b64Count - r + 3] == PADDING)
    {
        o = (b64Bytes[b64Count - r + 2] == PADDING) ? 2 : 1;
        r = (b64Bytes[b64Count - r + 2] == PADDING) ? 2 : 3;
    }
    else if (r == 3 && b64Bytes[b64Count - r + 2] == PADDING)
    {
        r = 2;
        o = 1;
    }
    
    switch (r)
    {
        case 0:
            *required = n;
            return Crypto_Ok;
        case 1:
            return Crypto_Err_InvalidArg;
        case 2:
            RETURN_RESULT_IF(((b64Bytes[b64Count - r - o]
                             |b64Bytes[1+b64Count - r - o]) & INV_VAL),
                    Crypto_Err_InvalidArg);
            b[0] = g_B64[b64Bytes[b64Count - r - o]];
            b[1] = g_B64[b64Bytes[1+b64Count - r -o]];
            RETURN_RESULT_IF(((b[0]|b[1]) & INV_VAL), Crypto_Err_InvalidArg);
            byteBuf[n] = ((b[0] & 0x3f) << 2) | (b[1] >> 4);
            *required = n + 1;
            return Crypto_Ok;
        case 3:
            RETURN_RESULT_IF(((b64Bytes[b64Count - r - o]
                             |b64Bytes[1+b64Count - r - o]
                             |b64Bytes[2+b64Count - r - o]) & INV_VAL),
                    Crypto_Err_InvalidArg);
            b[0] = g_B64[b64Bytes[b64Count - r - o]];
            b[1] = g_B64[b64Bytes[1+b64Count - r - o]];
            b[2] = g_B64[b64Bytes[2+b64Count - r - o]];
            RETURN_RESULT_IF(((b[0]|b[1]|b[2]) & INV_VAL), Crypto_Err_InvalidArg);
            byteBuf[n+0] = ((b[0] & 0x3f) << 2) | (b[1] >> 4);
            byteBuf[n+1] = ((b[1] & 0x0f) << 4) | (b[2] >> 2);
            *required = n + 2;
            return Crypto_Ok;
        default:
            RETURN_RESULT_IF(((b64Bytes[b64Count - r - o]
                              |b64Bytes[b64Count - r + 1]
                              |b64Bytes[b64Count - r + 2]
                              |b64Bytes[b64Count - r + 3]) & INV_VAL),
                    Crypto_Err_InvalidArg);
            b[0] = g_B64[b64Bytes[b64Count - r]];
            b[1] = g_B64[b64Bytes[b64Count - r + 1]];
            b[2] = g_B64[b64Bytes[b64Count - r + 2]];
            b[3] = g_B64[b64Bytes[b64Count - r + 3]];
            RETURN_RESULT_IF(((b[0]|b[1]|b[2]|b[3]) & INV_VAL), Crypto_Err_InvalidArg);
            byteBuf[n+0] = ((b[0] & 0x3f) << 2) | (b[1] >> 4);
            byteBuf[n+1] = ((b[1] & 0x0f) << 4) | (b[2] >> 2);
            byteBuf[n+2] = ((b[2] & 0x03) << 6) | (b[3]);
            *required = n + 3;
            return Crypto_Ok;
    }
}

