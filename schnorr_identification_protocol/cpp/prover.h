#ifndef PROVER_H
#define PROVER_H

#include <openssl/bn.h>
#include <iostream> 

class Utils; 

class Prover {
public:
    BIGNUM* generator; 
    BIGNUM* prime;

    Prover(BIGNUM* generator, BIGNUM* prime, BIGNUM* secret_x = nullptr)
        : generator(generator), prime(prime), secret_x(secret_x), ctx(BN_CTX_new()) {
        if (secret_x == nullptr) {
            this->secret_x = BN_new();
            BN_rand(this->secret_x, 256, 1, 0);
            BN_mod(this->secret_x, this->secret_x, prime, this->ctx);
        }
    }

    ~Prover() {
        BN_free(secret_x);
        BN_free(commitmentExponentK);
        BN_CTX_free(ctx);
    }


    BIGNUM* commitment();
    BIGNUM* generateWitness(const BIGNUM* c);
    BIGNUM* generateProof();

private:
    BN_CTX* ctx;  
    BIGNUM* commitmentExponentK;
    BIGNUM* secret_x;
};

#endif 
