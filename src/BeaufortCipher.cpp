#include "../include/BeaufortCipher.h"
#include <cctype>

BeaufortCipher::BeaufortCipher(const std::string& keyword) : key(keyword) {
    for (char& c : this->key) {
        c = std::toupper(c);
    }
    if (this->key.empty()) {
        this->key = "FORT"; // Chiave di emergenza
    }
}

std::string BeaufortCipher::encrypt(const std::string& plaintext) const {
    std::string result = "";
    int keyIndex = 0;
    int keyLength = key.length();

    for (char c : plaintext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            int pVal = c - base; // Valore numerico della lettera in chiaro
            int kVal = key[keyIndex % keyLength] - 'A'; // Valore numerico della chiave
            
            // Formula: (Chiave - Testo) Modulo 26
            int cVal = (kVal - pVal) % 26;
            if (cVal < 0) {
                cVal += 26; // Gestione modulo per numeri negativi in C++
            }
            
            result += static_cast<char>(cVal + base);
            keyIndex++;
        } else {
            result += c;
        }
    }
    return result;
}

std::string BeaufortCipher::decrypt(const std::string& ciphertext) const {
    // Essendo Beaufort un cifrario reciproco, P = (K - C) mod 26
    return this->encrypt(ciphertext);
}

std::string BeaufortCipher::getName() const {
    return "Beaufort Cipher";
}