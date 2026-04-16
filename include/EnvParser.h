#ifndef ENV_PARSER_H
#define ENV_PARSER_H

#include <string>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iostream>

class EnvParser {
public:
    // Carica il file .env e restituisce una mappa con le variabili
    static std::unordered_map<std::string, std::string> parse(const std::string& filepath);
};

#endif // ENV_PARSER_H