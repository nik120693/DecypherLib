#include "../include/AffineCipher.h"
#include <cctype>
#include <iostream>

// Implementazione ricorsiva del Massimo Comune Divisore
int AffineCipher::gcd(int num1, int num2) const {
    return num2 == 0 ? num1 : gcd(num2, num1 % num2);
}

// Calcolo dell'inverso moltiplicativo modulare tramite forza bruta (essendo il dominio piccolo, 1-25)
int AffineCipher::modInverse(int a, int m) const {
    for (int x = 1; x < m; x++) {
        if (((a % m) * (x % m)) % m == 1) {
            return x;
        }
    }
    return 1; // Fallback matematico (non dovrebbe mai essere raggiunto se 'a' è validato)
}

AffineCipher::AffineCipher(int keyA, int keyB) {
    // Validazione stringente della chiave 'a'. Se non è coprima con 26, forziamo a = 1.
    // Se a=1, il cifrario affine degenera semplicemente nel cifrario di Cesare con shift 'b'.
    if (gcd(keyA, 26) != 1) {
        std::cerr << "[WARNING] Affine Cipher: La chiave 'A' (" << keyA << ") non è coprima con 26. Forzata a 1 per evitare collisioni." << std::endl;
        this->a = 1;
    } else {
        this->a = keyA;
    }
    
    // Assicuriamoci che 'b' sia positivo e nel range 0-25
    this->b = (keyB % 26 + 26) % 26;
    
    // Calcoliamo una volta sola l'inverso per ottimizzare le performance di decrittazione
    this->a_inv = modInverse(this->a, 26);
}

std::string AffineCipher::encrypt(const std::string& plaintext) const {
    std::string result = "";
    for (char c : plaintext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            int x = c - base;
            // Formula: E(x) = (a * x + b) % 26
            int encrypted_val = (a * x + b) % 26;
            result += static_cast<char>(encrypted_val + base);
        } else {
            result += c;
        }
    }
    return result;
}

std::string AffineCipher::decrypt(const std::string& ciphertext) const {
    std::string result = "";
    for (char c : ciphertext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            int x = c - base;
            // Dobbiamo assicurarci che (x - b) sia positivo prima di applicare il modulo
            int diff = (x - b) % 26;
            if (diff < 0) {
                diff += 26;
            }
            // Formula: D(x) = a_inv * (x - b) % 26
            int decrypted_val = (a_inv * diff) % 26;
            result += static_cast<char>(decrypted_val + base);
        } else {
            result += c;
        }
    }
    return result;
}

std::string AffineCipher::getName() const {
    return "Affine Cipher";
}