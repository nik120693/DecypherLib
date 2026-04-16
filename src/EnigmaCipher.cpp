#include "../include/EnigmaCipher.h"
#include <cctype>

EnigmaCipher::EnigmaCipher(int p1, int p2, int p3) {
    // Normalizziamo le posizioni iniziali nel range 0-25
    this->initialPos1 = (p1 % 26 + 26) % 26;
    this->initialPos2 = (p2 % 26 + 26) % 26;
    this->initialPos3 = (p3 % 26 + 26) % 26;
}

int EnigmaCipher::forwardPass(int input, const std::string& rotor, int offset) const {
    // Il segnale entra deviato dalla rotazione attuale del rotore
    int contactIn = (input + offset) % 26;
    int mapped = rotor[contactIn] - 'A';
    // Il segnale esce subendo la deviazione inversa dovuta alla rotazione
    int contactOut = (mapped - offset + 26) % 26;
    return contactOut;
}

int EnigmaCipher::reversePass(int input, const std::string& rotor, int offset) const {
    int contactIn = (input + offset) % 26;
    char target = static_cast<char>(contactIn + 'A');
    
    // Cerchiamo a quale indice si trova la lettera per invertire il cablaggio
    int mapped = rotor.find(target);
    
    int contactOut = (mapped - offset + 26) % 26;
    return contactOut;
}

std::string EnigmaCipher::encrypt(const std::string& plaintext) const {
    std::string result = "";
    
    // Cloniamo lo stato iniziale per mantenere il metodo 'const'
    int p1 = initialPos1;
    int p2 = initialPos2;
    int p3 = initialPos3;

    for (char c : plaintext) {
        if (std::isalpha(c)) {
            char base = std::islower(c) ? 'a' : 'A';
            int signal = c - base;

            // STEPPING MECCANICO (Odometro semplice)
            // Il rotore 3 avanza sempre prima di cifrare la lettera
            p3 = (p3 + 1) % 26;
            if (p3 == 0) { // Se il rotore 3 completa un giro
                p2 = (p2 + 1) % 26;
                if (p2 == 0) { // Se il rotore 2 completa un giro
                    p1 = (p1 + 1) % 26;
                }
            }

            // PERCORSO DEL SEGNALE ELETTRICO
            // 1. Passaggio in andata: Rotore 3 -> Rotore 2 -> Rotore 1
            signal = forwardPass(signal, ROTOR_3, p3);
            signal = forwardPass(signal, ROTOR_2, p2);
            signal = forwardPass(signal, ROTOR_1, p1);

            // 2. Riflettore
            signal = REFLECTOR_B[signal] - 'A';

            // 3. Passaggio di ritorno: Rotore 1 -> Rotore 2 -> Rotore 3
            signal = reversePass(signal, ROTOR_1, p1);
            signal = reversePass(signal, ROTOR_2, p2);
            signal = reversePass(signal, ROTOR_3, p3);

            // Output finale
            result += static_cast<char>(signal + base);
        } else {
            // I caratteri non alfabetici bypassano la macchina Enigma
            result += c;
        }
    }
    return result;
}

std::string EnigmaCipher::decrypt(const std::string& ciphertext) const {
    // La presenza del riflettore rende Enigma una involuzione matematica perfetta.
    return this->encrypt(ciphertext);
}

std::string EnigmaCipher::getName() const {
    return "Enigma Machine (M3)";
}