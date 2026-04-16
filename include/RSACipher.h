#ifndef RSA_CIPHER_H
#define RSA_CIPHER_H

#include "Cipher.h"
#include "BigInt.h"
#include <string>

class RSACipher : public Cipher {
private:
    BigInt p;
    BigInt q;
    BigInt n;
    BigInt phi;
    BigInt e; 
    BigInt d; 

    BigInt gcd(BigInt a, BigInt b) const;

public:
    explicit RSACipher(const std::string& prime_p, const std::string& prime_q, const std::string& public_e);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;

    // --- NUOVE FUNZIONI DI FIRMA DIGITALE (DIGITAL SIGNATURE) ---
    // Firma un hash usando la chiave privata 'd'
    std::string sign(const std::string& messageHash) const;
    
    // Verifica un hash usando la chiave pubblica 'e'
    bool verify(const std::string& originalHash, const std::string& signature) const;
};

#endif // RSA_CIPHER_H