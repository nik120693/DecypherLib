#include "../include/AtbashCipher.h"
#include <cctype>

std::string AtbashCipher::encrypt(const std::string& plaintext) const {
    std::string result = "";
    for (char c : plaintext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            // Sottraiamo la distanza dalla base a 25 (che rappresenta 'z' o 'Z')
            result += static_cast<char>(base + (25 - (c - base)));
        } else {
            result += c;
        }
    }
    return result;
}

std::string AtbashCipher::decrypt(const std::string& ciphertext) const {
    // La cifratura di Atbash è un'involuzione: applicarla due volte restituisce il testo originale.
    return this->encrypt(ciphertext);
}

std::string AtbashCipher::getName() const {
    return "Atbash Cipher";
}