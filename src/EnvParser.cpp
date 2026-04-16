#include "../include/EnvParser.h"

std::unordered_map<std::string, std::string> EnvParser::parse(const std::string& filepath) {
    std::unordered_map<std::string, std::string> envMap;
    std::ifstream file(filepath);
    
    if (!file.is_open()) {
        std::cerr << "[WARNING] Impossibile aprire il file " << filepath << ". Verranno usati i valori di default." << std::endl;
        return envMap;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Ignora righe vuote o commenti
        if (line.empty() || line[0] == '#') continue;

        std::istringstream lineStream(line);
        std::string key, value;
        
        // Estrae la chiave e il valore separati dal carattere '='
        if (std::getline(lineStream, key, '=') && std::getline(lineStream, value)) {
            // Rimuove eventuali spazi finali o iniziali (trim di base)
            key.erase(key.find_last_not_of(" \t\r\n") + 1);
            value.erase(0, value.find_first_not_of(" \t\r\n"));
            value.erase(value.find_last_not_of(" \t\r\n") + 1);
            
            envMap[key] = value;
        }
    }
    
    file.close();
    return envMap;
}