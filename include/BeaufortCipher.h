#ifndef BEAUFORT_CIPHER_H
#define BEAUFORT_CIPHER_H

#include "Cipher.h"
#include <string>

class BeaufortCipher : public Cipher {
private:
    std::string key;

public:
    explicit BeaufortCipher(const std::string& keyword);

    std::string encrypt(const std::string& plaintext) const override;
    
    // La decrittazione richiamerà semplicemente l'encrypt, essendo simmetrico
    std::string decrypt(const std::string& ciphertext) const override;
    
    std::string getName() const override;
};

#endif // BEAUFORT_CIPHER_H