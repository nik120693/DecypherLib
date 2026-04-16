#include "../include/KeyDerivation.h"
#include "../include/SHA256.h"

std::string KeyDerivation::stretchKey(const std::string& password, const std::string& salt, int iterations) {
    SHA256 hasher;
    
    // Inizializzazione: concatenazione di Password e Salt
    std::string currentHash = password + salt;
    
    // Loop computazionale di Hash Stretching
    for (int i = 0; i < iterations; ++i) {
        currentHash = hasher.hash(currentHash);
    }
    
    // Il risultato finale è un digest SHA-256 purificato
    return currentHash;
}