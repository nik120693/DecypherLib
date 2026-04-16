#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <vector>
#include <cstdint>

class SHA256 {
private:
    // Le 8 variabili di stato dell'algoritmo (valori iniziali frazionari di radici quadrate di primi)
    uint32_t h[8];

    // Costanti K per i 64 round dell'algoritmo
    static const uint32_t K[64];

    // Operazioni bit-a-bit macro
    uint32_t rotr(uint32_t n, uint32_t x) const; // Rotazione a destra
    uint32_t shr(uint32_t n, uint32_t x) const;  // Shift a destra
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z) const; // Choose
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z) const; // Majority
    uint32_t sigma0(uint32_t x) const;
    uint32_t sigma1(uint32_t x) const;
    uint32_t Gamma0(uint32_t x) const;
    uint32_t Gamma1(uint32_t x) const;

    // Funzione principale per comprimere un singolo blocco di 512 bit (64 byte)
    void processChunk(const std::vector<uint8_t>& chunk);

public:
    SHA256();
    
    // Processa la stringa e restituisce il digest in formato esadecimale (64 char)
    std::string hash(const std::string& input);
};

#endif // SHA256_H