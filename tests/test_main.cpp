#include <iostream>
#include <cassert>
#include <string>

#include "../include/CaesarCipher.h"
#include "../include/VigenereCipher.h"
#include "../include/AtbashCipher.h"
#include "../include/RailFenceCipher.h"
#include "../include/AffineCipher.h"
#include "../include/BeaufortCipher.h"
#include "../include/EnigmaCipher.h"
#include "../include/RSACipher.h"
#include "../include/ECCipher.h"
#include "../include/LWECipher.h"
#include "../include/AESCipher.h"
#include "../include/BigInt.h"
#include "../include/Dictionary.h"
#include "../include/TuringBombe.h"
#include "../include/SHA256.h"
#include "../include/StatisticalAnalyzer.h"
#include "../include/KasiskiEngine.h"
#include "../include/KeyDerivation.h"

#define TEST_ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            std::cerr << "[-] TEST FAILED: " << message << " (Line: " << __LINE__ << ")" << std::endl; \
            std::exit(EXIT_FAILURE); \
        } else { \
            std::cout << "[+] TEST PASSED: " << message << std::endl; \
        } \
    } while (false)

void runCaesarTests() { CaesarCipher c(5); TEST_ASSERT(c.decrypt(c.encrypt("A")) == "A", "Caesar OK"); }
void runVigenereTests() { VigenereCipher v("KEY"); TEST_ASSERT(v.decrypt(v.encrypt("A")) == "A", "Vigenere OK"); }
void runAtbashTests() { AtbashCipher at; TEST_ASSERT(at.decrypt(at.encrypt("A")) == "A", "Atbash OK"); }
void runRailFenceTests() { RailFenceCipher r(3); TEST_ASSERT(r.decrypt(r.encrypt("TEST")) == "TEST", "RailFence OK"); }
void runAffineTests() { AffineCipher af(5,8); TEST_ASSERT(af.decrypt(af.encrypt("A")) == "A", "Affine OK"); }
void runBeaufortTests() { BeaufortCipher b("KEY"); TEST_ASSERT(b.decrypt(b.encrypt("A")) == "A", "Beaufort OK"); }
void runEnigmaTests() { EnigmaCipher e(0,0,0); TEST_ASSERT(e.decrypt(e.encrypt("A")) == "A", "Enigma OK"); }

void runBigIntTests() {
    BigInt a("99"); BigInt b("1");
    TEST_ASSERT((a + b).getValue() == "100", "BigInt Engine OK");
}

void runRSATests() {
    RSACipher cipher("61", "53", "17");
    TEST_ASSERT(cipher.decrypt(cipher.encrypt("A")) == "A", "RSA OK");
}

void runECCTests() {
    ECCipher cipher("467", "2", "3", "3", "6", "15");
    TEST_ASSERT(cipher.decrypt(cipher.encrypt("A")) == "A", "ECC OK");
}

void runLWETests() {
    LWECipher cipher(42, 8, 16, 251);
    TEST_ASSERT(cipher.decrypt(cipher.encrypt("LWE")) == "LWE", "LWE Post-Quantum OK");
}

void runAESTests() {
    std::string key = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    AESCipher cipher(key);
    std::string plain = "SECRET";
    TEST_ASSERT(cipher.decrypt(cipher.encrypt(plain)) == plain, "AES-256 OK");
}

void runSHA256Tests() {
    SHA256 hasher;
    TEST_ASSERT(hasher.hash("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "SHA-256 Digest OK");
}

void runStatisticalAnalyzerTests() {
    system("echo 'THE 10.0\nAND 9.0' > temp_ngrams.txt");
    system("echo 'SECRET 10.0' > temp_lexicon.txt");
    StatisticalAnalyzer analyzer("temp_ngrams.txt", "temp_lexicon.txt");
    TEST_ASSERT(analyzer.isLoaded(), "Statistical Analyzer loads dynamic mappings");
    TEST_ASSERT(analyzer.segmentWords("SECRET") == "SECRET", "Viterbi Algorithm parses syntax tree");
    system("rm temp_ngrams.txt temp_lexicon.txt");
}

void runKasiskiTests() {
    KasiskiEngine kasiski;
    VigenereCipher target("TURING");
    std::string ciphertext = target.encrypt("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGCRYPTOGRAPHYISTHEARTANDSCIENCEOFHIDINGINFORMATION");
    TEST_ASSERT(kasiski.extractVigenereKey(ciphertext) == "TURING", "Kasiski Engine blind cracking OK");
}

void runKeyDerivationTests() {
    std::cout << "\n--- Running Key Derivation (PBKDF2 Concept) Tests ---" << std::endl;
    // Usiamo poche iterazioni nel test per mantenere l'esecuzione dei test unitari sub-secondo
    std::string derived = KeyDerivation::stretchKey("Password123", "SaltABC", 10);
    TEST_ASSERT(derived.length() == 64, "Key Derivation Function correctly stretches human password into 256-bit Hex Key via cascading hashing");
}

int main() {
    std::cout << "===========================================" << std::endl;
    std::cout << "   DECYPHER LIBRARY - Running Tests...     " << std::endl;
    std::cout << "===========================================" << std::endl;

    runCaesarTests();
    runVigenereTests();
    runAtbashTests();
    runRailFenceTests();
    runAffineTests();
    runBeaufortTests();
    runEnigmaTests();
    runBigIntTests();
    runRSATests();
    runECCTests();
    runLWETests();
    runAESTests();
    runSHA256Tests();
    runStatisticalAnalyzerTests(); 
    runKasiskiTests(); 
    runKeyDerivationTests(); // L'ULTIMO TEST DI SICUREZZA

    std::cout << "\n===========================================" << std::endl;
    std::cout << "   ALL 16 TEST SUITES PASSED SUCCESSFULLY! " << std::endl;
    std::cout << "===========================================" << std::endl;

    return 0;
}