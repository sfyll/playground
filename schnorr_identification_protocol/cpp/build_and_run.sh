#!/bin/bash

# Create and navigate to the build directory
mkdir -p build
cd build

# Generate the build files using CMake
cmake ..

# Build the project
cmake --build .

# Run the executable
./schnorr

