#ifndef TURING_BOMBE_H
#define TURING_BOMBE_H

#include <string>
#include <vector>
#include <tuple>

class TuringBombe {
public:
    // Implementa un attacco Known-Plaintext (Crib) multithreaded.
    // Ritorna un vettore di tuple. Ogni tupla contiene: 
    // [0] Posizione Rotore 1, [1] Posizione Rotore 2, [2] Posizione Rotore 3, [3] Intero testo decrittato.
    static std::vector<std::tuple<int, int, int, std::string>> crackEnigma(const std::string& ciphertext, const std::string& crib);
};

#endif // TURING_BOMBE_H