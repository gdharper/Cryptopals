#ifndef _ERRORS_
#define _ERRORS_

typedef enum _CryptoResult
{
    Crypto_Ok,
    Crypto_Err_BufferTooSmall,
    Crypto_Err_InvalidArg,
    
} CryptoResult;

#define CRYPTO_FAILED(_res) ((_res) != Crypto_Ok)

#define EXIT_IF_FAILED(_res) if (CRYPTO_FAILED((_res))) { goto Exit; }

#define EXIT_WITH_RESULT(_res) res = (_res); goto Exit

#define EXIT_WITH_RESULT_IF(_res, _bool) if (_bool) { EXIT_WITH_RESULT(_res); }

#define EXIT_IF(_bool) if (_bool) { goto Exit; }

#define RETURN_RESULT_IF(_res, _bool) if (_bool) { return (_res); }

#define RETURN_IF(_bool) if (_bool) { return; }

#endif

