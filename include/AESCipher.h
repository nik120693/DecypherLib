#ifndef AES_CIPHER_H
#define AES_CIPHER_H

#include "Cipher.h"
#include <vector>
#include <string>
#include <cstdint>

class AESCipher : public Cipher {
private:
    std::vector<uint8_t> roundKeys;

    // Matrici fisse standard NIST per AES
    static const uint8_t sbox[256];
    static const uint8_t rsbox[256];
    static const uint8_t rcon[15];

    // Moltiplicazione nel campo di Galois GF(2^8)
    uint8_t xtime(uint8_t x) const;
    uint8_t multiply(uint8_t x, uint8_t y) const;

    // Funzioni di trasformazione del blocco
    void SubBytes(std::vector<uint8_t>& state) const;
    void ShiftRows(std::vector<uint8_t>& state) const;
    void MixColumns(std::vector<uint8_t>& state) const;
    void AddRoundKey(std::vector<uint8_t>& state, const uint8_t* roundKey) const;

    void InvSubBytes(std::vector<uint8_t>& state) const;
    void InvShiftRows(std::vector<uint8_t>& state) const;
    void InvMixColumns(std::vector<uint8_t>& state) const;

    // Espansione della chiave da 32 byte a 240 byte (15 chiavi di round)
    void KeyExpansion(const std::vector<uint8_t>& key);

    // Cifratura e Decifratura di un singolo blocco da 16 byte
    void encryptBlock(std::vector<uint8_t>& state) const;
    void decryptBlock(std::vector<uint8_t>& state) const;

    // Utility
    std::vector<uint8_t> hexToBytes(const std::string& hex) const;
    std::string bytesToHex(const std::vector<uint8_t>& bytes) const;

public:
    explicit AESCipher(const std::string& hexKey);

    std::string encrypt(const std::string& plaintext) const override;
    std::string decrypt(const std::string& ciphertext) const override;
    std::string getName() const override;
};

#endif // AES_CIPHER_H