#ifndef EC_CIPHER_H
#define EC_CIPHER_H

#include "Cipher.h"
#include "BigInt.h"
#include <string>

// Rappresentazione di un Punto Cartesiano sulla curva
struct ECCPoint {
    BigInt x;
    BigInt y;
    bool isInfinity;
};

class ECCipher : public Cipher {
private:
    BigInt p; // Modulo (numero primo)
    BigInt a; // Coefficiente curva
    BigInt b; // Coefficiente curva
    ECCPoint G; // Punto Generatore (Base Point)
    BigInt privateKey; // d
    ECCPoint publicKey; // Q = d * G

    // Sottrazione modulare sicura (A - B) mod P
    BigInt subMod(BigInt val1, BigInt val2) const;

    // Addizione Geometrica di due Punti sulla Curva
    ECCPoint pointAdd(const ECCPoint& P, const ECCPoint& Q) const;

    // Moltiplicazione Scalare (Double-and-Add Algorithm)
    ECCPoint scalarMultiply(BigInt k, const ECCPoint& P) const;

public:
    explicit ECCipher(const std::string& prime_p, const std::string& coeff_a, const std::string& coeff_b,
                      const std::string& gx, const std::string& gy, const std::string& priv_key);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif // EC_CIPHER_H