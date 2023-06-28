#ifndef VERIFIER_H
#define VERIFIER_H

#include <openssl/bn.h>
#include <iostream> 
#include "utils.h"

class Verifier {
public:
    BIGNUM* generator; 
    BIGNUM* prime;

    Verifier(BIGNUM* generator, BIGNUM* prime)
        : generator(generator), prime(prime), ctx(nullptr) {
        ctx = BN_CTX_new();
    }
    
    ~Verifier() {
        BN_CTX_free(ctx);
    }

    BIGNUM* generateChallenge();
    BIGNUM* verifyProof(const BIGNUM* witness, const BIGNUM* proof, const BIGNUM* commitment);

private:
    BN_CTX* ctx;  
    BIGNUM* challenge;

};

#endif 
