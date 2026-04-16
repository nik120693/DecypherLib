#ifndef RAIL_FENCE_CIPHER_H
#define RAIL_FENCE_CIPHER_H

#include "Cipher.h"
#include <vector>

class RailFenceCipher : public Cipher {
private:
    int rails;

public:
    // Costruttore: richiede il numero di binari (almeno 2)
    explicit RailFenceCipher(int numRails);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif // RAIL_FENCE_CIPHER_H