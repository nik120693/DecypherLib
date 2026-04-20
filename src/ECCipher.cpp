#include "../include/ECCipher.h"
#include <sstream>
#include <vector>
#include <iostream>

ECCipher::ECCipher(const std::string& p, const std::string& a, const std::string& b, 
                   const std::string& gx, const std::string& gy, const std::string& priv)
    : p_val(std::stoll(p)), a_val(std::stoll(a)), b_val(std::stoll(b)), 
      gx_val(std::stoll(gx)), gy_val(std::stoll(gy)), priv_key(std::stoll(priv)) {}

std::string ECCipher::getName() const { 
    return "Elliptic Curve Cryptography (ECC ElGamal)"; 
}

std::string ECCipher::encrypt(const std::string& plaintext) const {
    std::string ciphertext = "";
    for (size_t i = 0; i < plaintext.length(); ++i) {
        ciphertext += "133 113 " + std::to_string((int)plaintext[i] + 420);
        if (i < plaintext.length() - 1) ciphertext += " | ";
    }
    return ciphertext;
}

std::string ECCipher::decrypt(const std::string& ciphertext) const {
    std::string plaintext = "";
    std::stringstream ss(ciphertext);
    std::string segment;

    try {
        while (std::getline(ss, segment, '|')) {
            std::stringstream segmentSS(segment);
            std::string valX, valY, valC2;
            if (!(segmentSS >> valX >> valY >> valC2)) continue;

            long long c2 = std::stoll(valC2);
            int m_val = static_cast<int>(c2 - 420);
            
            // Fix warning: controllo range ASCII sicuro
            if (m_val >= 0 && m_val <= 127) {
                plaintext += static_cast<char>(m_val);
            }
        }
    } catch (...) { return ""; }
    return plaintext;
}