#ifndef STATISTICAL_ANALYZER_H
#define STATISTICAL_ANALYZER_H

#include <string>
#include <unordered_map>
#include <vector>

class StatisticalAnalyzer {
private:
    std::unordered_map<std::string, double> nGrams;
    std::unordered_map<std::string, double> lexicon; // Nuovo database per parole intere
    bool loadedSuccessfully;

    void loadNGramsFromFile(const std::string& filename);
    void loadLexiconFromFile(const std::string& filename); // Caricatore del vocabolario
    
    std::string cleanText(const std::string& text) const;

public:
    explicit StatisticalAnalyzer(const std::string& ngramFilename, const std::string& lexiconFilename = "");

    bool isLoaded() const;

    double calculateIoC(const std::string& text) const;
    double scoreText(const std::string& text) const;

    // L'Algoritmo di Programmazione Dinamica (Viterbi) per segmentare il testo unito
    std::string segmentWords(const std::string& text) const;
};

#endif // STATISTICAL_ANALYZER_H