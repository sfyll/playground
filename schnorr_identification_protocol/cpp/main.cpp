#include <iostream>
#include <openssl/bn.h>
#include "prover.h"
#include "verifier.h"
#include <zmq.hpp>

void proverSendProof(zmq::socket_t& socket, Prover& prover) {
    BIGNUM* proof = prover.generateProof();
    std::string proofHex = BN_bn2hex(proof);

    zmq::message_t proofMsg(proofHex.size());

    memcpy(proofMsg.data(), proofHex.data(), proofHex.size());

    socket.send(proofMsg, zmq::send_flags::none);

    std::cout << "Prover sending the proof g^x across: " << proofHex << std::endl;

    BN_free(proof); 
}

void proverSendCommitment(zmq::socket_t& socket, Prover& prover) {
    BIGNUM* commitment = prover.commitment();
    std::string commitmentHex = BN_bn2hex(commitment);

    zmq::message_t commitmentMsg(commitmentHex.size());

    memcpy(commitmentMsg.data(), commitmentHex.data(), commitmentHex.size());

    socket.send(commitmentMsg, zmq::send_flags::none);

    std::cout << "Prover sending the commitment g^k across: " << commitmentHex << std::endl;

    BN_free(commitment); 
}

void proverReceiveChallengeAndSendWitness(zmq::socket_t& socket, Prover& prover, BIGNUM* receivedChallenge) {
    BIGNUM* witness = prover.generateWitness(receivedChallenge);
    std::string witnessHex = BN_bn2hex(witness);

    zmq::message_t witnessMsg(witnessHex.size());

    memcpy(witnessMsg.data(), witnessHex.data(), witnessHex.size());

    socket.send(witnessMsg, zmq::send_flags::none);

    std::cout << "Prover sending the Witness s = c*x + k across: " << witnessHex << std::endl;

    BN_free(witness); 
}

void verifierReceiveProofAndAskForCommitment(zmq::socket_t& socket, Verifier& verifier)
{
    zmq::message_t receivedProof;
    socket.recv(receivedProof, zmq::recv_flags::none);
    BIGNUM* proof = BN_new();
    BN_hex2bn(&proof, static_cast<char*>(receivedProof.data()));
    verifier.storeProof(proof);
    
    std::string ask = "Send Commitment Across Please";

    zmq::message_t askMsg(ask.size());

    memcpy(askMsg.data(), ask.data(), ask.size());

    socket.send(askMsg, zmq::send_flags::none);

    std::cout << "Verifier storing the proof and asking for the commitment value: "  << std::endl;

    BN_free(proof);
}

void verifierReceiveCommitmentAndSendChallenge(zmq::socket_t& socket, Verifier& verifier)
{
        zmq::message_t receivedCommitment;
        socket.recv(receivedCommitment, zmq::recv_flags::none);
        BIGNUM* commitment = BN_new();
        BN_hex2bn(&commitment, static_cast<char*>(receivedCommitment.data()));
        verifier.storeCommitment(commitment);


        // Process the request (generate challenge)
        BIGNUM* challenge = verifier.generateChallenge();

        // Send the challenge to the Prover
        zmq::message_t response(sizeof(challenge));
        memcpy(response.data(), BN_bn2hex(challenge), sizeof(challenge));
        socket.send(response, zmq::send_flags::none);

        std::cout << "Verifier storing the commitment and sending across the challenge: " << challenge  << std::endl;
}

void verifierReceiveWitnessAndVerifyIdentification(zmq::socket_t& socket, Verifier& verifier)
{
        zmq::message_t receivedWitness;
        socket.recv(receivedWitness, zmq::recv_flags::none);
        BIGNUM* witness = BN_new();
        BN_hex2bn(&witness, static_cast<char*>(receivedWitness.data()));

        BIGNUM* result = verifier.verifyProof(witness);
        std::cout << "Computing the proof ..." << std::endl;
        if (BN_cmp(result, BN_value_one()) == 0) {
            std::cout << "Proof is correct." << std::endl;
        } else {
            std::cout << "Proof is incorrect." << std::endl;
        }

        BN_free(witness);
}


int main() {
    constexpr int TIMEOUT = 10000; // Timeout value in milliseconds

    std::cout << "Initiating shared variables ..." << std::endl;

    BIGNUM* generator = BN_new();
    BN_dec2bn(&generator, "5");
    
    BIGNUM* prime = BN_new();
    BN_dec2bn(&prime, "97");
    
    std::cout << "generator g: " << BN_bn2hex(generator) << std::endl;
    std::cout << "prime p: " << BN_bn2hex(prime) << std::endl;

    Verifier verifier(generator, prime);
    Prover prover(generator, prime);
    
    // Create a ZMQ context
    zmq::context_t context(1);

    // Create a ZMQ socket for the Verifier
    zmq::socket_t verifierSocket(context, ZMQ_REP);
    verifierSocket.bind("tcp://*:5001");

    // Create a ZMQ socket for the Prover
    zmq::socket_t proverSocket(context, ZMQ_REQ);
    proverSocket.connect("tcp://localhost:5001");

    proverSendProof(proverSocket, prover);

    // Create a vector to hold the sockets
    std::vector<zmq::pollitem_t> items;
    items.push_back({ static_cast<void*>(verifierSocket), 0, ZMQ_POLLIN, 0 });
    items.push_back({ static_cast<void*>(proverSocket), 0, ZMQ_POLLIN, 0 });

    int step = 0;

    while (true) {

        int rc = zmq::poll(items.data(), items.size(), TIMEOUT);

        if (rc == -1) {
        // Error occurred during polling, handle it accordingly
        // For example, you can break the loop or take appropriate action
        break;
        } else if (rc == 0) {
        // Timeout occurred, no events received within the specified time
        // Handle it accordingly, such as continuing the loop
        continue;
        }

        // Handle messages from the Verifier
        if (items[0].revents & ZMQ_POLLIN) {
            if (step == 0)
            {
            verifierReceiveProofAndAskForCommitment(verifierSocket, verifier);
            step++;
            }
            else if (step == 2)
            {
            verifierReceiveCommitmentAndSendChallenge(verifierSocket, verifier);
            step++;
            }
            else if (step == 4)
            {
            verifierReceiveWitnessAndVerifyIdentification(verifierSocket, verifier);
            std::cout << "Ending communication ..."<< std::endl; 
            break;
            }
        }


        // Handle messages from the Prover
        if (items[1].revents & ZMQ_POLLIN) {
            zmq::message_t receivedMsg;
            proverSocket.recv(receivedMsg, zmq::recv_flags::none);
            std::string receivedStr(static_cast<char*>(receivedMsg.data()), receivedMsg.size());
            
            if (receivedStr == "Send Commitment Across Please") {
                    proverSendCommitment(proverSocket, prover);
                    step++;
                }
            else {
                    BIGNUM* challenge = BN_new();
                    BN_hex2bn(&challenge, static_cast<char*>(receivedMsg.data()));
                    proverReceiveChallengeAndSendWitness(proverSocket, prover, challenge);
                    step++;
            }

        }
    }

    // Cleanup
    BN_free(generator);
    BN_free(prime);

    return 0;
}
