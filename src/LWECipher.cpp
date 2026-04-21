#include "../include/LWECipher.h"
#include <sstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <iomanip>
#include <random>
#include <cmath>
#include <algorithm> 

// =========================================================================
// STRUTTURA TOPOLOGICA: Parametri Regev LWE
// =========================================================================
struct LWEKeys {
    int q = 251;   // Modulo primo (Campo GF(q))
    int n = 8;     // Dimensione del vettore segreto
    int m = 16;    // Numero di equazioni del reticolo
    std::vector<int> S;                         // Vettore Segreto (Private Key)
    std::vector<std::vector<int>> A;            // Matrice Pubblica A
    std::vector<int> B;                         // Vettore Pubblico B (A*S + E)
};

// =========================================================================
// MOTORE MATEMATICO (Generazione Deterministica per Compatibilità Header)
// =========================================================================
LWEKeys generateLatticeKeys() {
    LWEKeys keys;
    // Seme deterministico (42) per sincronizzare Encrypt/Decrypt senza variabili di stato header
    std::mt19937 gen(42); 
    std::uniform_int_distribution<> distQ(0, keys.q - 1);
    std::uniform_int_distribution<> distErr(-2, 2); // Rumore intenzionale (Error Distribution)

    // 1. Generazione Vettore Segreto (S)
    keys.S.resize(keys.n);
    for(int i = 0; i < keys.n; i++) keys.S[i] = distQ(gen);

    // 2. Generazione Matrice A e Vettore Pubblico B = A*S + E
    keys.A.resize(keys.m, std::vector<int>(keys.n));
    keys.B.resize(keys.m);
    
    for(int i = 0; i < keys.m; i++) {
        int dotProduct = 0;
        for(int j = 0; j < keys.n; j++) {
            keys.A[i][j] = distQ(gen);
            dotProduct = (dotProduct + keys.A[i][j] * keys.S[j]) % keys.q;
        }
        int error = distErr(gen);
        keys.B[i] = (dotProduct + error) % keys.q;
        if (keys.B[i] < 0) keys.B[i] += keys.q;
    }
    return keys;
}

// =========================================================================
// CLASSE PRINCIPALE: LWE LATTICE
// =========================================================================

LWECipher::LWECipher(int, int, int, int) {} // Costruttore di default

std::string LWECipher::getName() const { 
    return "Learning With Errors (LWE) Post-Quantum Cryptography"; 
}

std::string LWECipher::encrypt(const std::string& plaintext) const {
    LWEKeys keys = generateLatticeKeys();
    std::stringstream ciphertext;
    
    std::mt19937 encGen(std::random_device{}()); 
    std::uniform_int_distribution<> distR(0, 1);

    int qHalf = keys.q / 2;

    for (size_t charIdx = 0; charIdx < plaintext.length(); ++charIdx) {
        char m_char = plaintext[charIdx];
        
        for (int b = 7; b >= 0; --b) {
            int bit = (m_char >> b) & 1;
            
            std::vector<int> R(keys.m);
            for(int i = 0; i < keys.m; i++) R[i] = distR(encGen);

            std::vector<int> U(keys.n, 0);
            int V = 0;

            for(int i = 0; i < keys.m; i++) {
                if (R[i] == 1) {
                    for(int j = 0; j < keys.n; j++) {
                        U[j] = (U[j] + keys.A[i][j]) % keys.q;
                    }
                    V = (V + keys.B[i]) % keys.q;
                }
            }
            V = (V + bit * qHalf) % keys.q;

            // FIX: Serializzazione allineata con i due punti
            for(int j = 0; j < keys.n; j++) {
                ciphertext << U[j];
                if (j < keys.n - 1) ciphertext << ",";
            }
            ciphertext << ":" << V; // <-- Iniezione del separatore corretto
            
            if (charIdx != plaintext.length() - 1 || b != 0) {
                ciphertext << "|";
            }
        }
    }
    return ciphertext.str();
}

std::string LWECipher::decrypt(const std::string& ciphertext) const {
    LWEKeys keys = generateLatticeKeys(); 
    std::string plaintext = "";
    std::stringstream ss(ciphertext);
    std::string block;

    int qHalf = keys.q / 2;
    int bitCount = 0;
    char currentChar = 0;

    while (std::getline(ss, block, '|')) {
        // FIX: Sanitizzazione aggressiva contro la frammentazione del terminale
        block.erase(std::remove(block.begin(), block.end(), '\n'), block.end());
        block.erase(std::remove(block.begin(), block.end(), '\r'), block.end());
        block.erase(std::remove(block.begin(), block.end(), ' '), block.end());
        block.erase(std::remove(block.begin(), block.end(), '\t'), block.end());

        if(block.empty()) continue;

        size_t colonPos = block.find(':');
        if (colonPos == std::string::npos) {
            continue; 
        }

        std::string uStr = block.substr(0, colonPos);
        int V = std::stoi(block.substr(colonPos + 1));

        std::vector<int> U;
        std::stringstream uss(uStr);
        std::string uVal;
        while(std::getline(uss, uVal, ',')) {
            U.push_back(std::stoi(uVal));
        }

        if ((int)U.size() != keys.n) continue;

        // V' = V - U^T * S
        int dot = 0;
        for(int j = 0; j < keys.n; j++) {
            dot = (dot + U[j] * keys.S[j]) % keys.q;
        }
        int decV = (V - dot) % keys.q;
        if (decV < 0) decV += keys.q;

        // Decodifica tollerante agli errori
        int bit = 0;
        int dist0 = std::min(decV, keys.q - decV);
        int dist1 = std::abs(decV - qHalf);
        if (dist1 < dist0) bit = 1;

        currentChar = (currentChar << 1) | bit;
        bitCount++;

        if (bitCount == 8) {
            plaintext += currentChar;
            bitCount = 0;
            currentChar = 0;
        }
    }
    return plaintext;
}