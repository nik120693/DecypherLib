#ifndef AFFINE_CIPHER_H
#define AFFINE_CIPHER_H

#include "Cipher.h"

class AffineCipher : public Cipher {
private:
    int a;
    int b;
    int a_inv; // Inverso moltiplicativo di 'a'

    // Metodo per calcolare il Massimo Comune Divisore (Algoritmo di Euclide)
    int gcd(int num1, int num2) const;
    
    // Metodo per trovare l'inverso modulare di 'a' rispetto a 'm'
    int modInverse(int a, int m) const;

public:
    // Costruttore che accetta le due chiavi algebriche
    explicit AffineCipher(int keyA, int keyB);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif // AFFINE_CIPHER_H