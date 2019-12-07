
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "codec.h"

static int Unit_HexChar_Decode()
{
    const char in[] = {'0','1','2','3','4','5','6','7','8','9','a',
                       'b','c','d','e','f','A','B','C','D','E','F'};
    const uint8_t out[] = {0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,
                           0xb,0xc,0xd,0xe,0xf,0xa,0xb,0xc,0xd,0xe,0xf};
    assert(sizeof(in) == sizeof(out));

    uint8_t byte;
    for (int i = 0; i < sizeof(in); i++)
    {
        if (CRYPTO_FAILED(HexChar_Decode('0', in[i], &byte))
            || byte != out[i]) return i + 1;
    }

    if (HexChar_Decode(-1, '0', &byte) 
        != Crypto_Err_InvalidArg) return -1;

    if (HexChar_Decode('0', -2, &byte)
        != Crypto_Err_InvalidArg) return -2;

    if (HexChar_Decode(-3, -3, &byte)
        != Crypto_Err_InvalidArg) return -3;

    if (HexChar_Decode('G', 'G', &byte)
        != Crypto_Err_InvalidArg) return -4;

    return 0;
}

static int Unit_HexChar_Encode()
{
    const char hexout[] = "0123456789abcdef";
    char high, low;
    for (int h = 0; h < 0x10; h++)
    {
        for (int l = 0; l < 0x10; l++)
        {
            HexChar_Encode((h << 4) | (l & 0x0f), &high, &low);
            if(high != hexout[h] || low != hexout[l]) return 1 + h + l;
        }
    }

    return 0;
}


static int Unit_HexChar_Decode_Encode()
{
    const char in[] = "0123456789abcdef";
    uint8_t bytes[8];
    char out[16];
    
    int i = 0;
    const char* c = in;
    while (*c)
    {
        if (CRYPTO_FAILED(HexChar_Decode(*c, *(c+1), &bytes[i]))) return i;
        c += 2;
        i++;
    }

    for (i = 0; i < 8; i++)
    {
        HexChar_Encode(bytes[i], &out[i * 2], &out[i*2 + 1]);
    }

    if (memcmp(in, out, 16)) return -1;

    return 0;
}

static int Unit_Base64_Encode()
{
    const uint8_t padding = '=';

    uint32_t req = 0;
    // Test all single bytes
    for (uint8_t i = 0; i < 64; i ++)
    {
        uint8_t out[4];
        if (CRYPTO_FAILED(Base64_Encode(&i, 1, out, 4, &req))
            || out[2] != padding
            || out[3] != padding
            || req != 4)
        {
            return i+1;
        }
    }

    const uint8_t temp[] = { 0, 1, 2, 3, 4, 5 };
    if (Base64_Encode(
                temp,
                sizeof(temp),
                NULL,
                0,
                &req) != Crypto_Err_BufferTooSmall
        || req != 8) return -1;
    for (int s = 1; s <= sizeof(temp); s++)
    {
        uint8_t out[8];
        if (CRYPTO_FAILED(Base64_Encode(
                            temp,
                            s,
                            out,
                            sizeof(out),
                            &req))) return s + 65;
    }

    return 0;
}

static int Unit_Base64_Decode()
{
    const uint8_t b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < strlen(b64) - 2; i++)
    {
        uint8_t in[4] = {b64[i], b64[i+1], '=', '='};
        uint8_t out[3] = { 0 };
        uint32_t req;
        if (CRYPTO_FAILED(Base64_Decode(in, sizeof(in), out, sizeof(out), &req))
            || strlen(out) != 1) return i;
    }

    for (int i = 0; i < strlen(b64) - 3; i++)
    {
        uint8_t in[4] = {b64[i], b64[i+1], b64[i+2], '='};
        uint8_t out[3] = { 0 };
        uint32_t req;
        if (CRYPTO_FAILED(Base64_Decode(in, sizeof(in), out, sizeof(out), &req))
            || strlen(out) != 2) return i + strlen(b64);
    }
    
    for (int i = 0; i < strlen(b64) - 4; i++)
    {
        uint8_t in[4] = {b64[i], b64[i+1], b64[i+2], b64[i+3]};
        uint8_t out[3] = { 0 };
        uint32_t req;
        if (CRYPTO_FAILED(Base64_Decode(in, sizeof(in), out, sizeof(out), &req))
            || strlen(out) != 3) return i + 2*strlen(b64);
    }

    for (int i = 0; i < strlen(b64) - 11; i++)
    {
        uint8_t in[11];
        for (int j = 0; j < 11; j++) in[j] = b64[i + j];
        uint8_t out[10] = { 0 };
        uint32_t req;
        if (CRYPTO_FAILED(Base64_Decode(in, sizeof(in), out, sizeof(out), &req))
            || strlen(out) != 9) return i + 3*strlen(b64);
    }

    return 0;
}

static int Unit_Base64_Encode_Decode()
{
    uint8_t in[255];
    for (int i = 0; i < sizeof(in); i++) in[i] = i;
    uint8_t b64[sizeof(in) * 2];
    uint32_t req;
    if (CRYPTO_FAILED(Base64_Encode(in, sizeof(in), b64, sizeof(b64), &req))) return 1;
    uint8_t out[sizeof(in)];
    if (CRYPTO_FAILED(Base64_Decode(b64, req, out, sizeof(out), &req))) return 2;
    if (memcmp(in, out, sizeof(in))) return 3;
    return 0;
}


int main(void)
{
    int status = 0xffffffff;
    status = Unit_HexChar_Decode();
    if (status)
    {
        printf("HexChar_Decode unit test failed: %d\n", status);
        goto Exit;
    }

    status = Unit_HexChar_Encode();
    if (status)
    {
        printf("HexChar_Encode unit test failed: %d\n", status);
        goto Exit;
    }

    status = Unit_HexChar_Decode_Encode();
    if (status)
    {
        printf("HexChar_Decode_Encode unit test failed: %d\n", status);
        goto Exit;
    }

    status = Unit_Base64_Encode();
    if (status)
    {
        printf("Base64_Encode unit test failed: %d\n", status);
        goto Exit;
    }

    status = Unit_Base64_Decode();
    if (status)
    {
        printf("Base64_Decode unit test failed: %d\n", status);
        goto Exit;
    }

    status = Unit_Base64_Encode_Decode();
    if (status)
    {
        printf("Base64_Encode_Decode unit test failed: %d\n", status);
        goto Exit;
    }

Exit:
    if (!status)
    {
        printf("All tests passed!\n");
    }

    return status;
}

