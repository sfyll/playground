#include <openssl/bn.h>
#include "utils.h"
#include <cstdlib>  
#include <cstring>  

int Utils::bnToInt(const BIGNUM* bn) {
    char* decStr = BN_bn2dec(bn);
    int value = std::atoi(decStr);  
    OPENSSL_free(decStr);
    return value;
}

BIGNUM*  Utils::intToBn(const int* i) {
    unsigned char buffer[sizeof(int)];
    int m = htonl(*i); 

    memcpy(buffer, &m, sizeof(m)); 

    BIGNUM* bn = BN_bin2bn(buffer, sizeof(buffer), nullptr);

    return bn;
}