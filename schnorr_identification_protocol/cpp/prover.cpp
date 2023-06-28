#include "prover.h"
#include "utils.h"
#include <random>

BIGNUM* Prover::commitment() {
    commitmentExponentK = BN_new();

    BN_rand(commitmentExponentK, 256, 1, 0);
    BN_mod(commitmentExponentK, commitmentExponentK, prime, ctx);

    BIGNUM* t = BN_new();

    int commitmentExponentKInt = Utils::bnToInt(commitmentExponentK);
    int primeInt = Utils::bnToInt(prime);
    int gInt = Utils::bnToInt(generator);

    BN_mod_exp(t, generator, commitmentExponentK, prime, ctx); 
    int tInt = Utils::bnToInt(t);

    return t;
}

BIGNUM* Prover::generateWitness(const BIGNUM* c) {
    BIGNUM* temp = BN_new();
    BN_mul(temp, c, secret_x, ctx);

    BIGNUM* w = BN_new();
    
    BN_add(w, temp, commitmentExponentK);
    BN_free(temp);
    return w;
}

BIGNUM* Prover::generateProof() {
    BIGNUM* secret_proof = BN_new();
    
    BN_mod_exp(secret_proof, generator, secret_x, prime, ctx); 

    return secret_proof;
}

