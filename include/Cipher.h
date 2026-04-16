#ifndef CIPHER_H
#define CIPHER_H

#include <string>

class Cipher {
public:
    virtual ~Cipher() = default;

    // Metodo per cifrare una stringa in chiaro
    virtual std::string encrypt(const std::string& plaintext) const = 0;

    // Metodo per decifrare una stringa cifrata
    virtual std::string decrypt(const std::string& ciphertext) const = 0;

    // Metodo per identificare il nome del cifrario
    virtual std::string getName() const = 0;
};

#endif // CIPHER_H