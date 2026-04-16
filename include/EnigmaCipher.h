#ifndef ENIGMA_CIPHER_H
#define ENIGMA_CIPHER_H

#include "Cipher.h"
#include <string>

class EnigmaCipher : public Cipher {
private:
    // Posizioni iniziali dei 3 rotori (0-25)
    int initialPos1;
    int initialPos2;
    int initialPos3;

    // Cablaggi storici dei rotori Enigma I e Riflettore B
    const std::string ROTOR_1 = "EKMFLGDQVZNTOWYHXUSPAIBRCJ";
    const std::string ROTOR_2 = "AJDKSIRUXBLHWTMCQGZNPYFVOE";
    const std::string ROTOR_3 = "BDFHJLCPRTXVZNYEIWGAKMUSQO";
    const std::string REFLECTOR_B = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

    // Funzione helper per il passaggio del segnale in andata (da destra a sinistra)
    int forwardPass(int input, const std::string& rotor, int offset) const;
    
    // Funzione helper per il passaggio del segnale in ritorno (da sinistra a destra)
    int reversePass(int input, const std::string& rotor, int offset) const;

public:
    // Il costruttore accetta la posizione di partenza dei 3 rotori
    explicit EnigmaCipher(int p1, int p2, int p3);

    std::string encrypt(const std::string& plaintext) const override;
    
    // Enigma è simmetrica: la decrittazione equivale alla cifratura con gli stessi settaggi
    std::string decrypt(const std::string& ciphertext) const override;
    
    std::string getName() const override;
};

#endif // ENIGMA_CIPHER_H