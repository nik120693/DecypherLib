#include "../include/KasiskiEngine.h"
#include <cctype>
#include <cmath>
#include <map>
#include <iostream>

const double KasiskiEngine::englishFreqs[26] = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 
    0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 
    0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150, 
    0.01974, 0.00074
};

std::string KasiskiEngine::cleanText(const std::string& text) const {
    std::string res;
    for (char c : text) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            res += std::toupper(static_cast<unsigned char>(c));
        }
    }
    return res;
}

double KasiskiEngine::calculateIoC(const std::string& text) const {
    int N = text.length();
    if (N <= 1) return 0.0;

    int counts[26] = {0};
    for (char c : text) counts[c - 'A']++;

    double sum = 0.0;
    for (int i = 0; i < 26; ++i) {
        sum += counts[i] * (counts[i] - 1);
    }
    return sum / (N * (N - 1));
}

std::string KasiskiEngine::getCoset(const std::string& text, int keyLength, int offset) const {
    std::string coset = "";
    for (size_t i = offset; i < text.length(); i += keyLength) {
        coset += text[i];
    }
    return coset;
}

char KasiskiEngine::guessKeyLetter(const std::string& coset) const {
    int len = coset.length();
    double minChiSquare = 1e9;
    char bestGuess = 'A';

    for (int shift = 0; shift < 26; ++shift) {
        int counts[26] = {0};
        for (char c : coset) {
            int decryptedChar = (c - 'A' - shift + 26) % 26;
            counts[decryptedChar]++;
        }

        double chiSquare = 0.0;
        for (int i = 0; i < 26; ++i) {
            double expected = len * englishFreqs[i];
            if (expected > 0) {
                double diff = counts[i] - expected;
                chiSquare += (diff * diff) / expected;
            }
        }

        if (chiSquare < minChiSquare) {
            minChiSquare = chiSquare;
            bestGuess = 'A' + shift;
        }
    }
    return bestGuess;
}

std::string KasiskiEngine::extractVigenereKey(const std::string& ciphertext) const {
    std::string cleaned = cleanText(ciphertext);
    // BLOCCO DI SICUREZZA 1: Il testo deve avere una lunghezza minima statistica
    if (cleaned.length() < 60) return ""; 

    int bestKeyLength = 1;
    double bestIoC = 0.0;

    for (int len = 2; len <= 20; ++len) {
        // BLOCCO DI SICUREZZA 2 (Ant-Overfitting): Almeno 5 caratteri per coseto.
        if (cleaned.length() / len < 5) break;

        double avgIoC = 0.0;
        for (int i = 0; i < len; ++i) {
            std::string coset = getCoset(cleaned, len, i);
            avgIoC += calculateIoC(coset);
        }
        avgIoC /= len;

        if (avgIoC > bestIoC) {
            bestIoC = avgIoC;
            bestKeyLength = len;
        }
    }

    if (bestIoC < 0.055) return "";

    std::string deducedKey = "";
    for (int i = 0; i < bestKeyLength; ++i) {
        std::string coset = getCoset(cleaned, bestKeyLength, i);
        deducedKey += guessKeyLetter(coset);
    }

    return deducedKey;
}