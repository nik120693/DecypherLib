#include "../include/ECCipher.h"
#include <sstream>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <iomanip>

// =========================================================================
// STRUTTURA TOPOLOGICA: Geometria sul Campo Finito GF(p)
// =========================================================================
struct ECPoint {
    long long x;
    long long y;
    bool isInfinity;
};

// =========================================================================
// ALGEBRA MODULARE ESTESA
// =========================================================================

long long modulo(long long a, long long m) {
    long long res = a % m;
    return res < 0 ? res + m : res;
}

// Algoritmo di Euclide Esteso
long long modInverse(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;
    if (m == 1) return 0;
    a = modulo(a, m);
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

// Fast Exponentiation
long long modPow(long long base, long long exp, long long mod) {
    long long res = 1;
    base = modulo(base, mod);
    while (exp > 0) {
        if (exp % 2 == 1) res = modulo(res * base, mod);
        base = modulo(base * base, mod);
        exp /= 2;
    }
    return res;
}

// =========================================================================
// MOTORI GEOMETRICI DELLA CURVA ELLITTICA
// =========================================================================

ECPoint addPoints(ECPoint P, ECPoint Q, long long a, long long p) {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    long long num, den, lambda;

    if (P.x == Q.x && P.y == Q.y) {
        // Tangente (Doubling)
        if (P.y == 0) return {0, 0, true};
        num = modulo(3 * P.x * P.x + a, p);
        den = modulo(2 * P.y, p);
    } else {
        // Secante (Addition)
        if (P.x == Q.x) return {0, 0, true}; // Inversi
        num = modulo(Q.y - P.y, p);
        den = modulo(Q.x - P.x, p);
    }

    lambda = modulo(num * modInverse(den, p), p);
    long long x3 = modulo(lambda * lambda - P.x - Q.x, p);
    long long y3 = modulo(lambda * (P.x - x3) - P.y, p);

    return {x3, y3, false};
}

ECPoint multiplyPoint(ECPoint P, long long k, long long a, long long p) {
    ECPoint R = {0, 0, true};
    ECPoint N = P;
    while (k > 0) {
        if (k % 2 == 1) R = addPoints(R, N, a, p);
        N = addPoints(N, N, a, p);
        k /= 2;
    }
    return R;
}

// =========================================================================
// CLASSE PRINCIPALE: ECC ELGAMAL
// =========================================================================

ECCipher::ECCipher(const std::string& p, const std::string& a, const std::string& b, 
                   const std::string& gx, const std::string& gy, const std::string& priv)
    : p_val(std::stoll(p)), a_val(std::stoll(a)), b_val(std::stoll(b)), 
      gx_val(std::stoll(gx)), gy_val(std::stoll(gy)), priv_key(std::stoll(priv)) {}

std::string ECCipher::getName() const { 
    return "Elliptic Curve Cryptography (True ElGamal GF(p) - Nibble Split)"; 
}

std::string ECCipher::encrypt(const std::string& plaintext) const {
    std::stringstream ciphertext;
    ECPoint G = {gx_val, gy_val, false};
    
    ECPoint Pb = multiplyPoint(G, priv_key, a_val, p_val);
    long long k_ephemeral = 5; // Modificato per evitare cicli di ordine
    ECPoint C1 = multiplyPoint(G, k_ephemeral, a_val, p_val);
    long long KAPPA = 30; 

    std::vector<int> nibbles;
    for (char c : plaintext) {
        nibbles.push_back((c >> 4) & 0x0F); 
        nibbles.push_back(c & 0x0F);        
    }

    for (size_t i = 0; i < nibbles.size(); ++i) {
        long long m = nibbles[i];
        ECPoint Pm = {0, 0, true};
        
        for (long long j = 0; j < KAPPA; ++j) {
            long long x = m * KAPPA + j;
            if (x >= p_val) break;
            
            long long z = modulo(x*x*x + a_val*x + b_val, p_val);
            
            if (z == 0) {
                Pm = {x, 0, false};
                break;
            } else if (modPow(z, (p_val - 1) / 2, p_val) == 1) {
                long long y = modPow(z, (p_val + 1) / 4, p_val);
                if (modulo(y * y, p_val) == z) { // Controllo Fisico Assoluto
                    Pm = {x, y, false};
                    break;
                }
            }
        }

        if (Pm.isInfinity) {
            throw std::runtime_error("Fallimento Koblitz: Impossibile mappare il carattere sulla curva.");
        }

        ECPoint kPb = multiplyPoint(Pb, k_ephemeral, a_val, p_val);
        ECPoint C2 = addPoints(Pm, kPb, a_val, p_val);

        // Serializzazione potenziata (Inclusione flag Infinito)
        ciphertext << C1.x << " " << C1.y << " " << (C1.isInfinity ? 1 : 0) << " "
                   << C2.x << " " << C2.y << " " << (C2.isInfinity ? 1 : 0);
        if (i < nibbles.size() - 1) ciphertext << " | ";
    }

    return ciphertext.str();
}

std::string ECCipher::decrypt(const std::string& ciphertext) const {
    std::string plaintext = "";
    std::stringstream ss(ciphertext);
    std::string segment;
    long long KAPPA = 30;
    
    std::vector<int> nibbles;

    while (std::getline(ss, segment, '|')) {
        std::stringstream segmentSS(segment);
        long long c1x, c1y, c2x, c2y;
        int c1inf, c2inf;
        
        // Deserializzazione potenziata
        if (!(segmentSS >> c1x >> c1y >> c1inf >> c2x >> c2y >> c2inf)) continue;

        ECPoint C1 = {c1x, c1y, c1inf != 0};
        ECPoint C2 = {c2x, c2y, c2inf != 0};
        
        ECPoint S = multiplyPoint(C1, priv_key, a_val, p_val);
        ECPoint negS = {S.x, modulo(-S.y, p_val), S.isInfinity};
        
        ECPoint Pm = addPoints(C2, negS, a_val, p_val);

        int m_val = static_cast<int>(Pm.x / KAPPA);
        nibbles.push_back(m_val);
    }

    for (size_t i = 0; i + 1 < nibbles.size(); i += 2) {
        char c = static_cast<char>((nibbles[i] << 4) | nibbles[i+1]);
        plaintext += c;
    }
    
    return plaintext;
}