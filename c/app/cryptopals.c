#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codec.h"
#include "errors.h"


static bool one_one()
{
    const char in[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    uint8_t* raw = NULL;
    uint8_t* out = NULL;
    const uint8_t expected[] =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    
    bool succeeded = true;
    printf("Set 1\n");
    printf("\n");
    printf("Challenge 1\n");

    uint32_t inBytes = strlen(in);
    raw = malloc(inBytes);
    uint32_t idx = 0;
    for (const char* i = in; *i; i += 2)
    {
        if (CRYPTO_FAILED(HexChar_Decode(*i, *(i+1), &raw[idx])))
        {
            printf("Hex string decode failed!\n");
            succeeded = false;
            goto Exit;
        }

        idx += 1;
    }

    out = malloc(inBytes);
    uint32_t req = 0;
    if (CRYPTO_FAILED(Base64_Encode(raw, idx, out, inBytes, &req)))
    {
        printf("Base64 encode failed!\n");
        succeeded = false;
        goto Exit;
    }

    if (memcmp(out, expected, req) != 0)
    {
        printf("Base64 encode incorrect!\n");
        succeeded = false;
        goto Exit;
    }

    if (CRYPTO_FAILED(Base64_Decode(out, req, raw, inBytes, &req)))
    {
        printf("Base64 decode failed!\n");
        succeeded = false;
        goto Exit;
    }

    printf("Set 1 challenge 1 succeess!\n");
 Exit:
    if (out) free(out);
    if (raw) free(raw);
    return succeeded;
}

int main(int argc, char** argv)
{
    printf("Crytopals Cryptography Challenges\n");
    printf("\n");
    
    if (!one_one())
    {
        printf("Set 1 Challenge 1 failed\n");
        return 1;
    }
   
    printf("All Challenges Succeeded!\n");
    return 0;
}


