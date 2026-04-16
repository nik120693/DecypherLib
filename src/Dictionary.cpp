#include "../include/Dictionary.h"
#include <fstream>
#include <sstream>
#include <cctype>
#include <iostream>

Dictionary::Dictionary(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "[WARNING] Impossibile caricare il dizionario da: " << filepath << std::endl;
        return;
    }

    std::string word;
    while (file >> word) {
        validWords.insert(toLower(word));
    }
    file.close();
}

std::string Dictionary::toLower(const std::string& str) const {
    std::string lowerStr = str;
    for (char& c : lowerStr) {
        c = std::tolower(static_cast<unsigned char>(c));
    }
    return lowerStr;
}

std::vector<std::string> Dictionary::tokenize(const std::string& text) const {
    std::vector<std::string> tokens;
    std::string currentToken = "";

    for (char c : text) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            currentToken += c;
        } else {
            if (!currentToken.empty()) {
                tokens.push_back(toLower(currentToken));
                currentToken = "";
            }
        }
    }
    // Aggiungi l'ultimo token se la stringa non finiva con una punteggiatura
    if (!currentToken.empty()) {
        tokens.push_back(toLower(currentToken));
    }

    return tokens;
}

int Dictionary::scoreText(const std::string& text) const {
    int score = 0;
    std::vector<std::string> words = tokenize(text);
    
    for (const std::string& word : words) {
        // La ricerca in una unordered_set è istantanea O(1)
        if (validWords.find(word) != validWords.end()) {
            score++;
        }
    }
    return score;
}

bool Dictionary::isLoaded() const {
    return !validWords.empty();
}