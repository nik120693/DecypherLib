#ifndef ECC_CIPHER_H
#define ECC_CIPHER_H

#include "Cipher.h"
#include <string>

class ECCipher : public Cipher {
private:
    long long p_val, a_val, b_val, gx_val, gy_val, priv_key;

public:
    explicit ECCipher(const std::string& prime_p, const std::string& coeff_a, const std::string& coeff_b,
                     const std::string& gx, const std::string& gy, const std::string& priv);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif