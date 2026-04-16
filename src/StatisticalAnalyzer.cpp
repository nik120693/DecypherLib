#include "../include/StatisticalAnalyzer.h"
#include <cctype>
#include <cmath>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>

StatisticalAnalyzer::StatisticalAnalyzer(const std::string& ngramFilename, const std::string& lexiconFilename) 
    : loadedSuccessfully(false) {
    loadNGramsFromFile(ngramFilename);
    if (!lexiconFilename.empty()) {
        loadLexiconFromFile(lexiconFilename);
    }
}

void StatisticalAnalyzer::loadNGramsFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::stringstream ss(line);
        std::string ngram; double weight;
        if (ss >> ngram >> weight) nGrams[cleanText(ngram)] = weight;
    }
    file.close();
    loadedSuccessfully = true;
}

void StatisticalAnalyzer::loadLexiconFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "[WARNING] Impossibile caricare il lessico: " << filename << std::endl;
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::stringstream ss(line);
        std::string word; double weight;
        if (ss >> word >> weight) lexicon[cleanText(word)] = weight;
    }
    file.close();
}

bool StatisticalAnalyzer::isLoaded() const { return loadedSuccessfully; }

std::string StatisticalAnalyzer::cleanText(const std::string& text) const {
    std::string res;
    for (char c : text) {
        if (std::isalpha(static_cast<unsigned char>(c))) res += std::toupper(static_cast<unsigned char>(c));
    }
    return res;
}

double StatisticalAnalyzer::calculateIoC(const std::string& text) const {
    std::string cleaned = cleanText(text);
    int N = cleaned.length();
    if (N <= 1) return 0.0;
    int counts[26] = {0};
    for (char c : cleaned) counts[c - 'A']++;
    double sum = 0.0;
    for (int i = 0; i < 26; ++i) sum += counts[i] * (counts[i] - 1);
    return sum / (N * (N - 1));
}

double StatisticalAnalyzer::scoreText(const std::string& text) const {
    if (!loadedSuccessfully) return 0.0;
    std::string cleaned = cleanText(text);
    if (cleaned.length() < 3) return 0.0;
    double score = 0.0;
    for (size_t i = 0; i <= cleaned.length() - 3; ++i) {
        std::string tri = cleaned.substr(i, 3);
        if (nGrams.find(tri) != nGrams.end()) score += nGrams.at(tri);
    }
    if (cleaned.length() >= 4) {
        for (size_t i = 0; i <= cleaned.length() - 4; ++i) {
            std::string quad = cleaned.substr(i, 4);
            if (nGrams.find(quad) != nGrams.end()) score += nGrams.at(quad);
        }
    }
    return score / cleaned.length();
}

// PROGRAMMAZIONE DINAMICA (VITERBI WORD SEGMENTATION)
std::string StatisticalAnalyzer::segmentWords(const std::string& text) const {
    if (lexicon.empty() || text.empty()) return text; // Ritorna l'originale se non c'è vocabolario
    
    std::string cleaned = cleanText(text);
    int n = cleaned.length();
    
    // dp[i] memorizza il punteggio massimo per segmentare la sottostringa cleaned[0...i-1]
    std::vector<double> dp(n + 1, -1e9); 
    // parent[i] memorizza l'indice precedente per ricostruire il percorso
    std::vector<int> parent(n + 1, -1);
    dp[0] = 0.0;

    for (int i = 1; i <= n; ++i) {
        // Opzione 1: Fallback di sicurezza. Isola un carattere sconosciuto con una pesante penalità
        if (dp[i-1] - 15.0 > dp[i]) {
            dp[i] = dp[i-1] - 15.0;
            parent[i] = i - 1;
        }

        // Opzione 2: Cerca nel dizionario tutte le possibili combinazioni che finiscono in i
        for (int j = 0; j < i; ++j) {
            std::string word = cleaned.substr(j, i - j);
            if (lexicon.find(word) != lexicon.end()) {
                double score = dp[j] + lexicon.at(word);
                if (score > dp[i]) {
                    dp[i] = score;
                    parent[i] = j;
                }
            }
        }
    }

    // Backtracking per ricostruire la frase
    if (parent[n] == -1) return text;

    std::string result = "";
    int curr = n;
    while (curr > 0) {
        int p = parent[curr];
        std::string word = cleaned.substr(p, curr - p);
        result = word + (result.empty() ? "" : " ") + result;
        curr = p;
    }
    return result;
}