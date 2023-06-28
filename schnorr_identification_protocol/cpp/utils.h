#ifndef BN_UTILS_H
#define BN_UTILS_H

#include <openssl/bn.h>
#include <arpa/inet.h>

class Utils {
public:
    static int bnToInt(const BIGNUM* bn);
    BIGNUM* intToBn(const int* i);
};

#endif 
