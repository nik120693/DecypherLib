#include "../include/LWECipher.h"
#include <random>
#include <sstream>
#include <iostream>
#include <cmath>

int LWECipher::mod(int val, int m) const {
    int res = val % m;
    if (res < 0) res += m;
    return res;
}

LWECipher::LWECipher(int seed, int n_val, int m_val, int q_val) 
    : n(n_val), m(m_val), q(q_val) {
    
    std::mt19937 gen(seed);
    std::uniform_int_distribution<int> dist_q(0, q - 1);
    std::uniform_int_distribution<int> dist_err(-2, 2); 

    s.resize(n);
    for (int i = 0; i < n; ++i) {
        s[i] = dist_q(gen);
    }

    A.resize(m, std::vector<int>(n));
    b.resize(m);

    for (int i = 0; i < m; ++i) {
        int dot_product = 0;
        for (int j = 0; j < n; ++j) {
            A[i][j] = dist_q(gen);
            dot_product += A[i][j] * s[j];
        }
        int error = dist_err(gen);
        b[i] = mod(dot_product + error, q);
    }
}

std::string LWECipher::encrypt(const std::string& plaintext) const {
    std::stringstream result;
    std::mt19937 gen_enc(12345); 
    std::uniform_int_distribution<int> dist_bin(0, 1);

    bool firstBit = true;

    for (char c : plaintext) {
        for (int bitPos = 7; bitPos >= 0; --bitPos) {
            int bit = (c >> bitPos) & 1;

            std::vector<int> r(m);
            for (int i = 0; i < m; ++i) r[i] = dist_bin(gen_enc);

            std::vector<int> u(n, 0);
            for (int j = 0; j < n; ++j) {
                for (int i = 0; i < m; ++i) {
                    u[j] += A[i][j] * r[i];
                }
                u[j] = mod(u[j], q);
            }

            int v = 0;
            for (int i = 0; i < m; ++i) {
                v += b[i] * r[i];
            }
            v = mod(v + bit * (q / 2), q);

            if (!firstBit) result << " ";
            for (int j = 0; j < n; ++j) {
                result << u[j] << ",";
            }
            result << v;
            firstBit = false;
        }
    }
    return result.str();
}

std::string LWECipher::decrypt(const std::string& ciphertext) const {
    std::string result = "";
    std::stringstream ss(ciphertext);
    std::string bitChunk;
    
    int currentChar = 0;
    int bitCount = 0;

    while (std::getline(ss, bitChunk, ' ')) {
        if (bitChunk.empty()) continue;

        std::vector<int> u(n);
        size_t currentPos = 0;
        for (int j = 0; j < n; ++j) {
            size_t nextComma = bitChunk.find(',', currentPos);
            u[j] = std::stoi(bitChunk.substr(currentPos, nextComma - currentPos));
            currentPos = nextComma + 1;
        }
        int v = std::stoi(bitChunk.substr(currentPos));

        int dot_product = 0;
        for (int j = 0; j < n; ++j) {
            dot_product += s[j] * u[j];
        }
        int val = mod(v - dot_product, q);

        int bit = 0;
        if (std::abs(val - (q / 2)) < std::abs(val - 0) && std::abs(val - (q / 2)) < std::abs(val - q)) {
            bit = 1;
        }

        currentChar = (currentChar << 1) | bit;
        bitCount++;

        if (bitCount == 8) {
            result += static_cast<char>(currentChar);
            currentChar = 0;
            bitCount = 0;
        }
    }
    return result;
}

std::string LWECipher::getName() const {
    return "Lattice-Based Post-Quantum (LWE)";
}