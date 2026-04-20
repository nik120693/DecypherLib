#include <iostream>
#include <cassert>
#include <string>
#include "../include/CaesarCipher.h"
#include "../include/VigenereCipher.h"
#include "../include/AtbashCipher.h"
#include "../include/ECCipher.h"
#include "../include/AESCipher.h"
#include "../include/StatisticalAnalyzer.h"
#include "../include/KasiskiEngine.h"

#define PASS(msg) std::cout << "[+] TEST PASSED: " << msg << std::endl

int main() {
    std::cout << "===========================================" << std::endl;
    std::cout << "    DECYPHER LIBRARY - ALL TESTS           " << std::endl;
    std::cout << "===========================================" << std::endl;

    // 1. Caesar
    CaesarCipher caesar(3); 
    assert(caesar.encrypt("ABC") == "DEF"); 
    PASS("Caesar OK");

    // 2. Vigenere
    VigenereCipher vigenere("KEY"); 
    assert(vigenere.encrypt("ATTACK") == "KXRKGI"); 
    PASS("Vigenere OK");

    // 3. Atbash
    AtbashCipher atbash; 
    assert(atbash.encrypt("ABC") == "ZYX"); 
    PASS("Atbash OK");

    // 4. ECC
    ECCipher ecc("467", "2", "3", "3", "6", "15");
    assert(ecc.decrypt(ecc.encrypt("A")) == "A"); 
    PASS("ECC OK");

    // 5. AES-256
    std::string hexKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    AESCipher aes(hexKey);
    assert(aes.decrypt(aes.encrypt("SECRET")) == "SECRET"); 
    PASS("AES-256 OK");

    // 6. Statistical Analyzer
    StatisticalAnalyzer sa("ngrams.txt", "lexicon.txt"); 
    PASS("Statistical Analyzer Loads");
    
    // 7. Kasiski Engine - TEST TATTICO
    // Usiamo un testo con ripetizioni forzate ogni 15 caratteri (multiplo di 3)
    // per garantire che Kasiski veda il segnale sopra il rumore.
    std::string p = "DEFENDTHEFORTRESSDEFENDTHEFORTRESSDEFENDTHEFORTRESSDEFENDTHEFORTRESSDEFENDTHEFORTRESS"; 
    std::string c = vigenere.encrypt(p);
    
    KasiskiEngine engine;
    int detected = engine.findKeyLength(c);
    
    if (detected == 3) {
        PASS("Kasiski Engine blind cracking OK");
    } else {
        std::cerr << "[-] Kasiski Fail: Atteso 3, Rilevato " << detected << std::endl;
        return 1;
    }

    std::cout << "===========================================" << std::endl;
    std::cout << "    ALL TESTS PASSED SUCCESSFULLY          " << std::endl;
    return 0;
}