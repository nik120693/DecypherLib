#include "../include/StatisticalAnalyzer.h"
#include <fstream>
#include <sstream>
#include <cmath>
#include <algorithm>
#include <vector>

StatisticalAnalyzer::StatisticalAnalyzer(const std::string& ngramsFile, const std::string& lexiconFile) {
    std::ifstream nFile(ngramsFile);
    std::string key; double value;
    
    while (nFile >> key >> value) {
        ngrams[key] = std::log10(value);
    }
    
    if (!lexiconFile.empty()) {
        std::ifstream lFile(lexiconFile);
        while (lFile >> key >> value) {
            lexicon[key] = value;
        }
    }
}

double StatisticalAnalyzer::scoreText(const std::string& text) {
    if (text.length() < 4) return -10000.0;
    double score = 0;
    for (size_t i = 0; i <= text.length() - 4; ++i) {
        std::string gram = text.substr(i, 4);
        if (ngrams.count(gram)) {
            score += ngrams[gram];
        } else {
            score += 0.0; 
        }
    }
    return score;
}

std::string StatisticalAnalyzer::segmentWords(const std::string& text) {
    if (lexicon.empty()) return text;
    int n = text.length();
    
    std::vector<double> chart(n + 1, -1e18);
    std::vector<int> backpointer(n + 1, 0);
    chart[0] = 0;
    
    for (int i = 1; i <= n; ++i) {
        for (int j = std::max(0, i - 20); j < i; ++j) {
            std::string word = text.substr(j, i - j);
            
            // GRAVITÀ ESPONENZIALE NEL SEGMENTATORE:
            // L'algoritmo di Viterbi ora preferirà UNIRE le lettere in parole lunghe
            // piuttosto che spezzarle in frammenti, grazie alla potenza cubica.
            double prob = lexicon.count(word) ? (std::log10(lexicon[word]) + std::pow((double)word.length(), 4.0)) : (-10.0 * (i - j));
            
            if (chart[j] + prob > chart[i]) {
                chart[i] = chart[j] + prob;
                backpointer[i] = j;
            }
        }
    }
    
    std::vector<std::string> words;
    int curr = n;
    while (curr > 0) {
        int prev = backpointer[curr];
        words.push_back(text.substr(prev, curr - prev));
        curr = prev;
    }
    std::reverse(words.begin(), words.end());
    std::string res = "";
    for (size_t i = 0; i < words.size(); ++i) res += words[i] + (i == words.size()-1 ? "" : " ");
    return res;
}

double StatisticalAnalyzer::calculateMultiAnchorFitness(const std::string& text) {
    double fitness = scoreText(text);
    if (lexicon.empty()) return fitness;

    std::string seg = segmentWords(text);
    std::stringstream ss(seg);
    std::string w;
    
    double exponentialWordScore = 0;
    int validWordsCount = 0;
    
    while (ss >> w) {
        if (lexicon.count(w)) {
            double len = (double)w.length();
            // LA CHIAVE DI VOLTA MATEMATICA:
            // Le parole lunghe generano un punteggio che il rumore non può raggiungere.
            exponentialWordScore += std::pow(len, 3.0);
            
            // Contiamo quante parole di senso compiuto (>= 3 lettere) esistono
            if (len >= 3.0) {
                validWordsCount++;
            }
        }
    }
    
    // FILTRO ANTI-FRAMMENTAZIONE:
    // Se la frase non contiene almeno 3 parole reali, applichiamo una penalità letale.
    if (validWordsCount < 3) {
        return fitness - 5000.0;
    }
    
    return fitness + (exponentialWordScore * 10.0);
}