#ifndef STATISTICAL_ANALYZER_H
#define STATISTICAL_ANALYZER_H

#include <string>
#include <unordered_map>

class StatisticalAnalyzer {
private:
    std::unordered_map<std::string, double> ngrams;
    std::unordered_map<std::string, double> lexicon;

public:
    // Parametro opzionale per retrocompatibilità con i test
    StatisticalAnalyzer(const std::string& ngramsFile, const std::string& lexiconFile = "");
    
    double scoreText(const std::string& text);
    std::string segmentWords(const std::string& text);
    double calculateMultiAnchorFitness(const std::string& text);
};

#endif