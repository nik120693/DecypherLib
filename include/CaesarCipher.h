#ifndef CAESAR_CIPHER_H
#define CAESAR_CIPHER_H

#include "Cipher.h"

class CaesarCipher : public Cipher {
private:
    int shift;

public:
    // Il costruttore accetta lo shift (di default 3 come lo storico Cesare)
    explicit CaesarCipher(int shiftValue = 3);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif // CAESAR_CIPHER_H