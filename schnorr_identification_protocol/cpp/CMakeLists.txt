cmake_minimum_required(VERSION 3.12)
project(SchnorrProtocol)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable with debug symbols
add_executable(schnorr main.cpp prover.cpp verifier.cpp utils.cpp)
target_compile_options(schnorr PRIVATE -g)

# Link against OpenSSL
target_link_libraries(schnorr PRIVATE OpenSSL::Crypto)
