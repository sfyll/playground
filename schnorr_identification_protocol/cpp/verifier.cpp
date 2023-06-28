#include "verifier.h"
#include <random>

BIGNUM* Verifier::generateChallenge() {
    challenge = BN_new();
    
    BN_rand(challenge, 256, 1, 0);
    BN_mod(challenge, challenge, prime, ctx);

    return challenge;
}

BIGNUM* Verifier::verifyProof(const BIGNUM* witness, const BIGNUM* proof, const BIGNUM* commitment) {
    BIGNUM* lhs = BN_new();
    BN_mod_exp(lhs, generator, witness, prime, ctx);

    BIGNUM* proofRaisedToChallenge = BN_new();
    BN_mod_exp(proofRaisedToChallenge, proof, challenge, prime, ctx);

    BIGNUM* rhs = BN_new();
    BN_mod_mul(rhs, proofRaisedToChallenge, commitment, prime, ctx);

    int result = BN_cmp(lhs, rhs);

    BN_free(lhs);
    BN_free(proofRaisedToChallenge);
    BN_free(rhs);

    BIGNUM* resultBN = BN_new();
    BN_set_word(resultBN, result == 0 ? 1 : 0);
    return resultBN;
}
