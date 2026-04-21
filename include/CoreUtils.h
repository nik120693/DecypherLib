#ifndef CORE_UTILS_H
#define CORE_UTILS_H

#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <iomanip>

#include "StatisticalAnalyzer.h"
#include "KasiskiEngine.h"

extern std::mutex resultMutex;
extern std::mutex coutMutex;

struct DecryptResult {
    std::string keyInfo;
    std::string plaintext;
    double fitness;
};

extern std::vector<DecryptResult> topResults;

void updateTopResults(const DecryptResult& res);
std::string loadCiphertext(const std::string& filename = "ciphertext.txt");
std::string filterAlpha(const std::string& input);
std::string hexToRaw(const std::string& hex);
void runHeuristicProfiler(const std::string& rawTarget);
void printTopResults(StatisticalAnalyzer& sa);

#endif // CORE_UTILS_H
