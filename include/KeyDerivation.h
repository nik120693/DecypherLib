#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <string>

class KeyDerivation {
public:
    // Esegue l'Hash Stretching concatenando password e salt per 'iterations' volte.
    // Ritorna una stringa esadecimale di 64 caratteri (256 bit), ideale per AES-256.
    static std::string stretchKey(const std::string& password, const std::string& salt, int iterations);
};

#endif // KEY_DERIVATION_H