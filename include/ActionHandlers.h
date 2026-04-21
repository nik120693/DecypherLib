#ifndef ACTION_HANDLERS_H
#define ACTION_HANDLERS_H

#include <string>
#include "StatisticalAnalyzer.h"
#include "KasiskiEngine.h"

// Classical Ciphers
void handleCaesar(const std::string& rawTarget, StatisticalAnalyzer& sa);
void handleAtbash(const std::string& rawTarget, StatisticalAnalyzer& sa);
void handleVigenere(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa, KasiskiEngine& ke);
void handleRailFence(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa);
void handleAffine(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa);
void handleBeaufort(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa);

// Mechanical Ciphers
void handleEnigma(const std::string& rawTarget, const std::string& alphaTarget);
void handleTuringBombe(const std::string& rawTarget, const std::string& alphaTarget);

// Modern Ciphers
void handleAES(const std::string& rawTarget, StatisticalAnalyzer& sa);
void handleSHA256(const std::string& rawTarget);

// Asymmetric & PQ Ciphers
void handleRSA(const std::string& rawTarget);
void handleECC(const std::string& rawTarget);
void handleLWE(const std::string& rawTarget);

// Forensics & Carving
void handlePCAP();
void handleFileCarver();

#endif // ACTION_HANDLERS_H
