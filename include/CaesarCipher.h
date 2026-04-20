#ifndef CAESAR_CIPHER_H
#define CAESAR_CIPHER_H

#include "Cipher.h"
#include <string>

class CaesarCipher : public Cipher {
private:
    int shift;

public:
    explicit CaesarCipher(int k);
    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif