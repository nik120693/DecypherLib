cmake_minimum_required(VERSION 3.14)
project(DecypherLib)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -O3") 
include_directories(include)

set(SOURCE_FILES 
    src/EnvParser.cpp
    src/CaesarCipher.cpp
    src/VigenereCipher.cpp
    src/AtbashCipher.cpp
    src/RailFenceCipher.cpp
    src/AffineCipher.cpp
    src/BeaufortCipher.cpp
    src/EnigmaCipher.cpp
    src/BigInt.cpp
    src/RSACipher.cpp
    src/ECCipher.cpp
    src/LWECipher.cpp
    src/AESCipher.cpp
    src/Dictionary.cpp
    src/TuringBombe.cpp
    src/SHA256.cpp
    src/StatisticalAnalyzer.cpp
    src/KasiskiEngine.cpp
    src/KeyDerivation.cpp
    src/FileCarver.cpp
    src/CoreUtils.cpp
    src/ClassicalHandlers.cpp
    src/MechanicalHandlers.cpp
    src/ModernHandlers.cpp
    src/AsymmetricHandlers.cpp
    src/ForensicHandlers.cpp
)
add_executable(decypher_app src/main.cpp ${SOURCE_FILES})
add_executable(decypher_test tests/test_main.cpp ${SOURCE_FILES})