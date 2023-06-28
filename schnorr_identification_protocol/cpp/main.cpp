#include <iostream>
#include <openssl/bn.h>
#include "prover.h"
#include "verifier.h"

int main() {
    BIGNUM* generator = BN_new();
    BN_dec2bn(&generator, "5");
    
    BIGNUM* prime = BN_new();
    BN_dec2bn(&prime, "97");
    
    
    Verifier verifier(generator, prime);

    Prover prover(generator, prime);
    
    BIGNUM* commitment = prover.commitment();

    std::cout << "value (c): " << BN_bn2hex(commitment) << std::endl;

    BIGNUM* challenge = verifier.generateChallenge();

    std::cout << "value (challenge): " << BN_bn2hex(challenge) << std::endl;

    BIGNUM* witness = prover.generateWitness(challenge);

    std::cout << "value (witness): " << BN_bn2hex(witness) << std::endl;

    BIGNUM* proof = prover.generateProof();

    std::cout << "value (proof): " << BN_bn2hex(proof) << std::endl;

    BIGNUM* result = verifier.verifyProof(witness, proof, commitment);

    if (BN_cmp(result, BN_value_one()) == 0) {
        std::cout << "Proof is correct." << std::endl;
    } else {
        std::cout << "Proof is incorrect." << std::endl;
    }

    // Cleanup
    BN_free(commitment);
    BN_free(challenge);
    BN_free(witness);
    BN_free(proof);
    BN_free(result);
    BN_free(generator);
    BN_free(prime);

    return 0;
}
