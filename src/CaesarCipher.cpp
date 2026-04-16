#include "../include/CaesarCipher.h"
#include <cctype>

CaesarCipher::CaesarCipher(int shiftValue) : shift(shiftValue % 26) {
    if (this->shift < 0) {
        this->shift += 26; // Gestisce gli shift negativi
    }
}

std::string CaesarCipher::encrypt(const std::string& plaintext) const {
    std::string result = "";
    for (char c : plaintext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            // Formula di traslazione per il cifrario di Cesare
            result += static_cast<char>((c - base + shift) % 26 + base);
        } else {
            result += c; // Lascia inalterati spazi e punteggiatura
        }
    }
    return result;
}

std::string CaesarCipher::decrypt(const std::string& ciphertext) const {
    std::string result = "";
    for (char c : ciphertext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            // Formula inversa: aggiungiamo 26 per evitare risultati negativi prima del modulo
            result += static_cast<char>((c - base - shift + 26) % 26 + base);
        } else {
            result += c;
        }
    }
    return result;
}

std::string CaesarCipher::getName() const {
    return "Caesar Cipher";
}