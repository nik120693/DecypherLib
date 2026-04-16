#ifndef ATBASH_CIPHER_H
#define ATBASH_CIPHER_H

#include "Cipher.h"

class AtbashCipher : public Cipher {
public:
    // Costruttore di default
    AtbashCipher() = default;

    std::string encrypt(const std::string& plaintext) const override;
    
    // Essendo simmetrico, decrypt richiamerà semplicemente encrypt
    std::string decrypt(const std::string& ciphertext) const override;
    
    std::string getName() const override;
};

#endif // ATBASH_CIPHER_H