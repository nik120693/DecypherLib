#include "../include/VigenereCipher.h"
#include <cctype>

VigenereCipher::VigenereCipher(const std::string& keyword) : key(keyword) {
    // Sanificazione della chiave: trasformiamo tutto in maiuscolo per standardizzazione
    for (char& c : this->key) {
        c = std::toupper(c);
    }
    if (this->key.empty()) {
        this->key = "KEY"; // Fallback di sicurezza
    }
}

std::string VigenereCipher::encrypt(const std::string& plaintext) const {
    std::string result = "";
    int keyIndex = 0;
    int keyLength = key.length();

    for (char c : plaintext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            int shift = key[keyIndex % keyLength] - 'A'; // Calcola lo shift in base alla lettera della chiave corrente
            
            result += static_cast<char>((c - base + shift) % 26 + base);
            keyIndex++; // Avanza nella chiave solo se il carattere era una lettera
        } else {
            result += c;
        }
    }
    return result;
}

std::string VigenereCipher::decrypt(const std::string& ciphertext) const {
    std::string result = "";
    int keyIndex = 0;
    int keyLength = key.length();

    for (char c : ciphertext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            int shift = key[keyIndex % keyLength] - 'A';
            
            result += static_cast<char>((c - base - shift + 26) % 26 + base);
            keyIndex++;
        } else {
            result += c;
        }
    }
    return result;
}

std::string VigenereCipher::getName() const {
    return "Vigenere Cipher";
}