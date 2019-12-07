
#ifndef _B64_LOOKUP_
#define _B64_LOOKUP_

#include <stdint.h>

#define INV_VAL 0x80

const char g_B64[0x80] = 
{
    INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,
    INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,
    INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,
    INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,
    INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,
    INV_VAL,INV_VAL,INV_VAL,62,     INV_VAL,INV_VAL,INV_VAL,63,
    52,     53,     54,     55,     56,     57,     58,     59,
    60,     61,     INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,
    INV_VAL,0,      1,      2,      3,      4,      5,      6,
    7,      8,      9,      10,     11,     12,     13,     14,
    15,     16,     17,     18,     19,     20,     21,     22,
    23,     24,     25,     INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL,
    INV_VAL,26,     27,     28,     29,     30,     31,     32,
    33,     34,     35,     36,     37,     38,     39,     40,
    41,     42,     43,     44,     45,     46,     47,     48,
    49,     50,     51,     INV_VAL,INV_VAL,INV_VAL,INV_VAL,INV_VAL
};

#endif

