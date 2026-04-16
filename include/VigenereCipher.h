#ifndef VIGENERE_CIPHER_H
#define VIGENERE_CIPHER_H

#include "Cipher.h"
#include <string>

class VigenereCipher : public Cipher {
private:
    std::string key;

public:
    explicit VigenereCipher(const std::string& keyword);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif // VIGENERE_CIPHER_H