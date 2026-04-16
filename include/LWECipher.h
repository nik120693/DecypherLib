#ifndef LWE_CIPHER_H
#define LWE_CIPHER_H

#include "Cipher.h"
#include <vector>
#include <string>

class LWECipher : public Cipher {
private:
    int n; // Dimensione del vettore segreto
    int m; // Numero di equazioni
    int q; // Modulo

    // Chiave Privata
    std::vector<int> s;

    // Chiave Pubblica (Matrice A e vettore b)
    std::vector<std::vector<int>> A;
    std::vector<int> b;

    // Utility matematica per il modulo in C++ (previene risultati negativi)
    int mod(int val, int m) const;

public:
    // Il costruttore inizializza i reticoli algebrici
    explicit LWECipher(int seed, int n_val, int m_val, int q_val);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif // LWE_CIPHER_H