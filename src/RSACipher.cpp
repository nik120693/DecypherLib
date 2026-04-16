#include "../include/RSACipher.h"
#include <sstream>
#include <iostream>
#include <stdexcept>

RSACipher::RSACipher(const std::string& prime_p, const std::string& prime_q, const std::string& public_e) 
    : p(prime_p), q(prime_q), e(public_e) {
    this->n = p * q;
    BigInt one("1"), zero("0"), two("2");
    this->phi = (p - one) * (q - one);
    if (gcd(this->e, this->phi) != one) {
        if (this->e % two == zero) this->e = this->e + one;
        while (gcd(this->e, this->phi) != one) this->e = this->e + two;
    }
    this->d = this->e.modInverse(this->phi);
}

BigInt RSACipher::gcd(BigInt a, BigInt b) const {
    BigInt zero("0");
    while (b != zero) { BigInt temp = b; b = a % b; a = temp; }
    return a;
}

std::string RSACipher::encrypt(const std::string& plaintext) const {
    std::stringstream result;
    bool first = true;
    for (char c : plaintext) {
        BigInt m(std::to_string(static_cast<unsigned char>(c)));
        BigInt cipher_val = m.modExp(this->e, this->n);
        if (!first) result << " ";
        result << cipher_val.getValue();
        first = false;
    }
    return result.str();
}

std::string RSACipher::decrypt(const std::string& ciphertext) const {
    std::string result = "";
    std::stringstream ss(ciphertext);
    std::string token;
    while (std::getline(ss, token, ' ')) {
        if (token.empty()) continue;
        BigInt c_val(token);
        BigInt m = c_val.modExp(this->d, this->n);
        try { result += static_cast<char>(std::stoi(m.getValue())); } 
        catch (...) { result += '?'; }
    }
    return result;
}

std::string RSACipher::getName() const { return "RSA Algorithm (Asymmetric)"; }

// ======= IMPLEMENTAZIONE DIGITAL SIGNATURES =======

// Per firmare, convertiamo ogni carattere dell'Hash Esadecimale in BigInt e applichiamo 'd'
std::string RSACipher::sign(const std::string& messageHash) const {
    std::stringstream signature;
    bool first = true;
    for (char c : messageHash) {
        BigInt m(std::to_string(static_cast<unsigned char>(c)));
        BigInt sig_val = m.modExp(this->d, this->n); // S = Hash^d mod n
        if (!first) signature << " ";
        signature << sig_val.getValue();
        first = false;
    }
    return signature.str();
}

// Per verificare, convertiamo la firma numerica indietro in caratteri usando 'e'
bool RSACipher::verify(const std::string& originalHash, const std::string& signature) const {
    std::string reconstructedHash = "";
    std::stringstream ss(signature);
    std::string token;

    while (std::getline(ss, token, ' ')) {
        if (token.empty()) continue;
        BigInt s_val(token);
        BigInt h_val = s_val.modExp(this->e, this->n); // Hash = S^e mod n
        try { reconstructedHash += static_cast<char>(std::stoi(h_val.getValue())); } 
        catch (...) { return false; }
    }
    // Se l'hash decifrato con la chiave pubblica corrisponde all'hash del messaggio, il mittente è autentico
    return reconstructedHash == originalHash;
}