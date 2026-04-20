#include "../include/KasiskiEngine.h"
#include <map>
#include <vector>
#include <algorithm>
#include <cmath>

double KasiskiEngine::calculateIC(const std::string& text) {
    if (text.length() <= 1) return 0.0;
    std::map<char, int> counts;
    int n = 0;
    for (char c : text) {
        if (std::isalpha(c)) {
            counts[std::toupper(c)]++;
            n++;
        }
    }
    double ic = 0.0;
    for (auto const& [x, count] : counts) {
        ic += (double)count * (count - 1);
    }
    return ic / ((double)n * (n - 1));
}

int KasiskiEngine::findKeyLength(const std::string& ciphertext) {
    std::map<int, int> kasiskiVotes;
    int seqLen = 3;

    // 1. Esame di Kasiski: Cerca ripetizioni e vota i divisori delle distanze
    for (int i = 0; i < (int)ciphertext.length() - seqLen; ++i) {
        std::string seq = ciphertext.substr(i, seqLen);
        for (int j = i + seqLen; j < (int)ciphertext.length() - seqLen; ++j) {
            if (ciphertext.substr(j, seqLen) == seq) {
                int dist = j - i;
                for (int factor = 2; factor <= 20; ++factor) {
                    if (dist % factor == 0) kasiskiVotes[factor]++;
                }
            }
        }
    }

    // 2. Analisi IC + Voto Combinato
    int bestLen = 1;
    double maxCombinedScore = -1.0;
    const double targetIC = 0.0667;

    for (int len = 1; len <= 20; ++len) {
        double avgIC = 0.0;
        for (int i = 0; i < len; ++i) {
            std::string slice = "";
            for (int j = i; j < (int)ciphertext.length(); j += len) {
                slice += ciphertext[j];
            }
            avgIC += calculateIC(slice);
        }
        avgIC /= len;

        // Score: Prossimità all'IC inglese + Bonus dai voti di Kasiski
        // Più l'IC è vicino a 0.0667, più lo score è alto.
        double icScore = 1.0 / (std::abs(avgIC - targetIC) + 0.01);
        double combinedScore = icScore * (1.0 + kasiskiVotes[len]);

        if (combinedScore > maxCombinedScore) {
            maxCombinedScore = combinedScore;
            bestLen = len;
        }
    }

    return bestLen;
}