#include "../include/ECCipher.h"
#include <sstream>
#include <iostream>

ECCipher::ECCipher(const std::string& prime_p, const std::string& coeff_a, const std::string& coeff_b,
                   const std::string& gx, const std::string& gy, const std::string& priv_key) 
    : p(prime_p), a(coeff_a), b(coeff_b), privateKey(priv_key) {
    
    G = {BigInt(gx), BigInt(gy), false};
    publicKey = scalarMultiply(privateKey, G); // Derivazione automatica chiave pubblica
}

BigInt ECCipher::subMod(BigInt val1, BigInt val2) const {
    BigInt rem1 = val1 % p;
    BigInt rem2 = val2 % p;
    if (rem1 >= rem2) {
        return rem1 - rem2;
    } else {
        return p - (rem2 - rem1);
    }
}

ECCPoint ECCipher::pointAdd(const ECCPoint& P, const ECCPoint& Q) const {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    BigInt zero("0"), two("2"), three("3");

    if (P.x == Q.x) {
        if (P.y != Q.y || P.y == zero) {
            return {zero, zero, true}; // Punto all'infinito
        }
        // Tangente (P = Q): Raddoppio del punto
        BigInt num = ((three * P.x * P.x) + a) % p;
        BigInt den = (two * P.y) % p;
        BigInt lambda = (num * den.modInverse(p)) % p;

        BigInt x3 = subMod(subMod(lambda * lambda, P.x), P.x);
        BigInt y3 = subMod((lambda * subMod(P.x, x3)), P.y);
        return {x3, y3, false};
    } else {
        // Secante (P != Q): Addizione Standard
        BigInt num = subMod(Q.y, P.y);
        BigInt den = subMod(Q.x, P.x);
        BigInt lambda = (num * den.modInverse(p)) % p;

        BigInt x3 = subMod(subMod(lambda * lambda, P.x), Q.x);
        BigInt y3 = subMod((lambda * subMod(P.x, x3)), P.y);
        return {x3, y3, false};
    }
}

ECCPoint ECCipher::scalarMultiply(BigInt k, const ECCPoint& P) const {
    ECCPoint R = {BigInt("0"), BigInt("0"), true};
    ECCPoint Q_pt = P;
    BigInt zero("0"), two("2");

    // Double-and-Add Algorithm
    while (k > zero) {
        if (k % two != zero) {
            R = pointAdd(R, Q_pt);
        }
        Q_pt = pointAdd(Q_pt, Q_pt);
        k = k / two;
    }
    return R;
}

std::string ECCipher::encrypt(const std::string& plaintext) const {
    std::stringstream result;
    BigInt k("7"); // K effimero fisso per riproducibilità nei test. Nel mondo reale è generato random ad ogni cifratura.
    bool first = true;

    for (char c : plaintext) {
        BigInt m(std::to_string(static_cast<unsigned char>(c)));
        
        ECCPoint C1 = scalarMultiply(k, G);
        ECCPoint S = scalarMultiply(k, publicKey); // Segreto condiviso geometrico
        
        BigInt c_val = (m + S.x) % p; // ElGamal masking sull'asse X

        if (!first) result << " | ";
        // Il pacchetto finale contiene le coordinate del punto C1 e il payload scalare
        result << C1.x.getValue() << " " << C1.y.getValue() << " " << c_val.getValue();
        first = false;
    }
    return result.str();
}

std::string ECCipher::decrypt(const std::string& ciphertext) const {
    std::string result = "";
    std::stringstream ss(ciphertext);
    std::string tokenGroup;

    while (std::getline(ss, tokenGroup, '|')) {
        std::stringstream groupStream(tokenGroup);
        std::string c1x_str, c1y_str, c_val_str;
        groupStream >> c1x_str >> c1y_str >> c_val_str;

        ECCPoint C1 = {BigInt(c1x_str), BigInt(c1y_str), false};
        BigInt c_val(c_val_str);

        ECCPoint S = scalarMultiply(privateKey, C1); // Ripristino segreto condiviso
        
        BigInt m = subMod(c_val, S.x); // Smacheramento
        result += static_cast<char>(std::stoi(m.getValue()));
    }
    return result;
}

std::string ECCipher::getName() const {
    return "Elliptic Curve Cryptography (ECC ElGamal)";
}