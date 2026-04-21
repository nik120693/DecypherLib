#include "../include/CoreUtils.h"

std::mutex resultMutex;
std::mutex coutMutex;
std::vector<DecryptResult> topResults;

void updateTopResults(const DecryptResult& res) {
    std::lock_guard<std::mutex> lock(resultMutex);
    topResults.push_back(res);
    std::sort(topResults.begin(), topResults.end(), [](const DecryptResult& a, const DecryptResult& b) {
        return a.fitness > b.fitness;
    });
    auto it = std::unique(topResults.begin(), topResults.end(), [](const DecryptResult& a, const DecryptResult& b) {
        return a.plaintext == b.plaintext;
    });
    topResults.erase(it, topResults.end());
    if (topResults.size() > 5) topResults.pop_back();
}

std::string loadCiphertext(const std::string& filename) {
    std::ifstream f(filename);
    if (!f) return "";
    std::stringstream b; b << f.rdbuf();
    std::string target = b.str();
    target.erase(target.find_last_not_of(" \n\r\t") + 1);
    return target;
}

std::string filterAlpha(const std::string& input) {
    std::string res = "";
    for (char c : input) if (std::isalpha(c)) res += std::toupper(c);
    return res;
}

std::string hexToRaw(const std::string& hex) {
    std::string raw = "";
    std::string cleanHex = "";
    for (char c : hex) if (std::isxdigit(c)) cleanHex += c;
    if (cleanHex.length() % 2 != 0) return ""; 
    for (size_t i = 0; i < cleanHex.length(); i += 2) {
        std::string byteString = cleanHex.substr(i, 2);
        char byte = (char) strtol(byteString.c_str(), NULL, 16);
        raw.push_back(byte);
    }
    return raw;
}

void runHeuristicProfiler(const std::string& rawTarget) {
    std::cout << "\n======================================================================" << std::endl;
    std::cout << "   [ORACOLO] PROFILAZIONE EURISTICA DEL CIPHERTEXT IN CORSO...        " << std::endl;
    std::cout << "======================================================================" << std::endl;

    if (rawTarget.empty()) {
        std::cout << "[!] SORGENTE VUOTA O NON TROVATA. Analisi impossibile." << std::endl;
        return;
    }

    std::string alphaTarget = filterAlpha(rawTarget);
    std::cout << "[DATA] Dimensione Raw: " << rawTarget.length() << " bytes | Caratteri Alfabetici: " << alphaTarget.length() << std::endl;

    if (rawTarget.find('|') != std::string::npos && rawTarget.find_first_of("0123456789") != std::string::npos) {
        std::cout << "[*] PATTERN: Rilevati delimitatori tensoriali ('|') e strutture numeriche." << std::endl;
        std::cout << "[SUGGERIMENTO ORACOLO] -> 11. ECC ElGamal" << std::endl;
        return;
    }

    bool isHex = !rawTarget.empty();
    for (char c : rawTarget) {
        if (!std::isxdigit(c) && !std::isspace(c)) { isHex = false; break; }
    }
    if (isHex && rawTarget.length() > 16) {
        std::cout << "[*] PATTERN: Struttura puramente esadecimale (Base16) identificata." << std::endl;
        std::cout << "[SUGGERIMENTO ORACOLO] -> 9. AES-256 o 13. SHA-256 Hashing" << std::endl;
        return;
    }

    if (alphaTarget.length() > 20) {
        KasiskiEngine ke;
        double globalIC = ke.calculateIC(alphaTarget);
        std::cout << "[*] SPETTRO: Indice di Coincidenza Globale (IC) = " << std::fixed << std::setprecision(4) << globalIC << std::endl;

        if (globalIC >= 0.060) {
            std::cout << "[!] DIAGNOSI: L'alta covarianza indica una mappatura 1-a-1. Il profilo alfabetico non e' stato appiattito." << std::endl;
            std::cout << "[SUGGERIMENTO ORACOLO] Cifrari Monoalfabetici -> 1. Caesar | 2. Atbash | 5. Affine" << std::endl;
        } else if (globalIC < 0.055) {
            std::cout << "[!] DIAGNOSI: Distribuzione entropica piatta. Segnale polialfabetico o meccanico a fluttuazione continua." << std::endl;
            std::cout << "[SUGGERIMENTO ORACOLO] Cifrari Complessi -> 3. Vigenere | 6. Beaufort | 7. Enigma Cipher" << std::endl;
        } else {
            std::cout << "[!] DIAGNOSI: Zona d'ombra statistica (Transizione). Testare sia mono che polialfabetici." << std::endl;
        }
    } else {
        std::cout << "[!] DIAGNOSI: Campione troppo breve per estrapolazione statistica affidabile." << std::endl;
    }
    std::cout << "======================================================================\n" << std::endl;
}

void printTopResults(StatisticalAnalyzer& sa) {
    if (topResults.empty()) {
        std::cout << "\n[STATO] : NESSUN SEGNALE COERENTE RILEVATO." << std::endl;
    } else {
        std::cout << "\n--- TOP RESULTS ---" << std::endl;
        for (size_t i = 0; i < topResults.size(); ++i) {
            std::cout << "[" << i+1 << "] KEY: " << topResults[i].keyInfo 
                      << " | FITNESS: " << std::fixed << std::setprecision(2) << topResults[i].fitness << std::endl;
            
            std::string display = topResults[i].plaintext;
            int spaceCount = std::count(display.begin(), display.end(), ' ');
            if (spaceCount <= display.length() / 20) {
                display = sa.segmentWords(display);
            }
            std::cout << "    -> " << display << std::endl;
        }
    }
}
