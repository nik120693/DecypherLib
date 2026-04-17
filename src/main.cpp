#include <iostream>
#include <vector>
#include <memory>
#include <string>
#include <unordered_map>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <cctype>

#include "../include/EnvParser.h"
#include "../include/CaesarCipher.h"
#include "../include/VigenereCipher.h"
#include "../include/AtbashCipher.h"
#include "../include/RailFenceCipher.h"
#include "../include/AffineCipher.h"
#include "../include/BeaufortCipher.h"
#include "../include/EnigmaCipher.h"
#include "../include/RSACipher.h"
#include "../include/ECCipher.h"
#include "../include/LWECipher.h"
#include "../include/AESCipher.h"
#include "../include/Dictionary.h"
#include "../include/SHA256.h"
#include "../include/StatisticalAnalyzer.h"
#include "../include/KasiskiEngine.h"
#include "../include/KeyDerivation.h"
#include "../include/FileCarver.h"
#include "../include/PCAPParser.h" 

std::mutex coutMutex;
std::mutex resultMutex;

// ==============================================================================
// MODULO CPA (CHOSEN-PLAINTEXT ATTACK): PROFILATORE AUTONOMO DELL'ORACOLO
// ==============================================================================
void AutonomousOracleProfiler(Cipher* targetCipher) {
    std::cout << "\n=====================================================" << std::endl;
    std::cout << "   AVVIO PROFILATORE AUTONOMO (ATTACCO CPA)          " << std::endl;
    std::cout << "=====================================================" << std::endl;
    
    try {
        // 1. INIEZIONE DELLE SONDE VETTORIALI
        std::string probeA  = targetCipher->encrypt("A");
        std::string probeB  = targetCipher->encrypt("B");
        std::string probeAB = targetCipher->encrypt("AB");

        // 2. ANALISI LINGUISTICA DEL DELIMITATORE
        char detectedDelimiter = ' ';
        for (char c : probeAB) {
            if (!std::isdigit(c) && c != ' ' && c != '-') {
                detectedDelimiter = c;
                break;
            }
        }

        // 3. ESTRAZIONE MATEMATICA DEGLI SCALARI FINALI (C2)
        auto extractLastInteger = [](const std::string& str) -> int {
            std::stringstream ss(str);
            std::string token;
            int lastVal = 0;
            while (ss >> token) {
                try {
                    std::string cleanToken = "";
                    for(char c : token) if(std::isdigit(c) || c == '-') cleanToken += c;
                    if(!cleanToken.empty()) lastVal = std::stoi(cleanToken);
                } catch(...) {}
            }
            return lastVal;
        };

        int valA = extractLastInteger(probeA);
        int valB = extractLastInteger(probeB);

        // 4. RISOLUZIONE DELL'EQUAZIONE LINEARE
        int differential = valB - valA;
        int sharedSecret = valA - 65; // 'A' in ASCII equivale a 65

        // Normalizzazione modulare difensiva
        if (sharedSecret < 0) {
            sharedSecret = (sharedSecret % 467 + 467) % 467; 
        }

        //std::cout << "[+] Sonde iniettate con successo. Analisi differenziale completata." << std::endl;
        //std::cout << "    -> Varianza Derivata (Delta) : " << differential << std::endl;
        //std::cout << "    -> Costante Condivisa (S_x)  : " << sharedSecret << std::endl;
        //std::cout << "    -> Delimitatore Sintattico   : '" << detectedDelimiter << "'" << std::endl;
        
        if (differential == 1) {
            std::cout << "[!] CONCLUSIONE: L'algoritmo usa una traslazione ASCII lineare (ElGamal Additivo)." << std::endl;
        } else {
            std::cout << "[!] CONCLUSIONE: L'algoritmo usa mappatura geometrica complessa o Koblitz Encoding." << std::endl;
        }
        
    } catch (...) {
        std::cerr << "[-] ERRORE: L'Oracolo ha respinto l'infiltrazione. Analisi fallita." << std::endl;
    }
    std::cout << "=====================================================\n" << std::endl;
}


int main() {
    std::cout << "=====================================================" << std::endl;
    std::cout << "   DECYPHER OMNI-DECODER - TERMINAL SIGINT EDITION   " << std::endl;
    std::cout << "=====================================================" << std::endl;

    std::unordered_map<std::string, std::string> env = EnvParser::parse(".env");

    std::string vigenereKey = "UNKNOWN"; int railFenceRails = 3;
    int affineA = 5, affineB = 8; std::string beaufortKey = "FORTRESS";
    int enigmaP1 = 0, enigmaP2 = 0, enigmaP3 = 0;
    
    std::string rsaP = "61", rsaQ = "53", rsaE = "17";
    std::string eccP = "467", eccA = "2", eccB = "3", eccGx = "3", eccGy = "6", eccPriv = "15";
    int lweSeed = 42, lweN = 8, lweM = 16, lweQ = 251;
    
    std::string masterPassword = "DEFAULT_PASSWORD";
    std::string salt = "DEFAULT_SALT";
    int kdfIterations = 1000;

    try {
        if (env.find("VIGENERE_KEY") != env.end()) vigenereKey = env["VIGENERE_KEY"];
        if (env.find("RAIL_FENCE_RAILS") != env.end()) railFenceRails = std::stoi(env["RAIL_FENCE_RAILS"]);
        if (env.find("AFFINE_A") != env.end()) affineA = std::stoi(env["AFFINE_A"]);
        if (env.find("AFFINE_B") != env.end()) affineB = std::stoi(env["AFFINE_B"]);
        if (env.find("MASTER_PASSWORD") != env.end()) masterPassword = env["MASTER_PASSWORD"];
        if (env.find("SALT") != env.end()) salt = env["SALT"];
        if (env.find("KDF_ITERATIONS") != env.end()) kdfIterations = std::stoi(env["KDF_ITERATIONS"]);
    } catch (...) {}

    std::cout << "[*] System Diagnostics: Calcolo KDF in corso..." << std::endl;
    std::string derivedAesKey = KeyDerivation::stretchKey(masterPassword, salt, kdfIterations);
    
    StatisticalAnalyzer statAnalyzer("ngrams.txt", "lexicon.txt");

    std::vector<std::unique_ptr<Cipher>> cipherRegistry;
    for (int i = 1; i <= 25; ++i) cipherRegistry.push_back(std::make_unique<CaesarCipher>(i)); 
    cipherRegistry.push_back(std::make_unique<VigenereCipher>(vigenereKey));                 
    cipherRegistry.push_back(std::make_unique<AtbashCipher>());                              
    cipherRegistry.push_back(std::make_unique<RailFenceCipher>(railFenceRails));             
    cipherRegistry.push_back(std::make_unique<AffineCipher>(affineA, affineB));              
    cipherRegistry.push_back(std::make_unique<BeaufortCipher>(beaufortKey));                 
    cipherRegistry.push_back(std::make_unique<EnigmaCipher>(enigmaP1, enigmaP2, enigmaP3));  
    cipherRegistry.push_back(std::make_unique<RSACipher>(rsaP, rsaQ, rsaE));                 
    cipherRegistry.push_back(std::make_unique<ECCipher>(eccP, eccA, eccB, eccGx, eccGy, eccPriv)); // Indice 32
    cipherRegistry.push_back(std::make_unique<LWECipher>(lweSeed, lweN, lweM, lweQ));        
    cipherRegistry.push_back(std::make_unique<AESCipher>(derivedAesKey));                    

    // ==============================================================
    // ESECUZIONE DEL PROFILATORE AUTONOMO (Zero interazione umana)
    // ==============================================================
    AutonomousOracleProfiler(cipherRegistry[32].get());

    // ==============================================================
    // ACQUISIZIONE DATI TATTICI (FILE TEXT O PCAP)
    // ==============================================================
    std::cout << "   ACQUISIZIONE DATI TATTICI (FILE TEXT O PCAP)      " << std::endl;
    std::cout << "=====================================================" << std::endl;

    std::string targetCiphertext = "";

    std::ifstream pcapTest("capture.pcap");
    if (pcapTest.good()) {
        pcapTest.close();
        targetCiphertext = PCAPParser::extractTCPPayload("capture.pcap");
    }

    if (targetCiphertext.empty()) {
        std::ifstream inputFile("ciphertext.txt");
        if (!inputFile.is_open()) {
            std::cerr << "[ERRORE] Nessun file capture.pcap o ciphertext.txt trovato." << std::endl;
            return 1;
        }

        std::stringstream buffer;
        buffer << inputFile.rdbuf();
        targetCiphertext = buffer.str();
        inputFile.close();
        targetCiphertext.erase(targetCiphertext.find_last_not_of(" \n\r\t") + 1);
    }

    if (targetCiphertext.empty()) {
        std::cerr << "[ERRORE CRITICO] Nessun dato utile fornito." << std::endl;
        return 1;
    }

    std::cout << "[PAYLOAD INTERCETTATO]:\n" << targetCiphertext.substr(0, 80) << "...\n" << std::endl;

    std::cout << "[*] DISTRIBUZIONE THREADS ASINCRONI INIZIATA..." << std::endl;
    
    // VARIABILI GLOBALI RIPULITE PER LA GESTIONE DEI BIG DATA
    double globalMaxScore = -1.0;
    std::string globalWinningAlgorithm = "Nessuno";
    std::string globalFinalDecryption = "";
    bool globalIsBinaryTarget = false; 
    std::string globalBinarySignature = "UNKNOWN";

    std::vector<std::thread> workers;

    for (const auto& cipher : cipherRegistry) {
        Cipher* cipherPtr = cipher.get();
        workers.emplace_back([&statAnalyzer, targetCiphertext, cipherPtr, &globalMaxScore, &globalWinningAlgorithm, &globalFinalDecryption, &globalIsBinaryTarget, &globalBinarySignature]() {
            std::string attempt = "";
            try { attempt = cipherPtr->decrypt(targetCiphertext); } 
            catch (...) { return; } 

            double score = statAnalyzer.scoreText(attempt); 
            std::string fileSignature = FileCarver::detectSignature(attempt);
            
            // LOCK CRITICO DI MEMORIA
            std::lock_guard<std::mutex> lockResult(resultMutex);
            
            // Rilevamento Binario Puro
            if (fileSignature != "UNKNOWN") {
                globalIsBinaryTarget = true;
                globalBinarySignature = fileSignature;
                globalWinningAlgorithm = cipherPtr->getName();
                globalFinalDecryption = attempt;
                globalMaxScore = 999999999.0; // Override Assoluto
            } 
            // Competizione NLP Standard (se non abbiamo già trovato un file binario)
            else if (!globalIsBinaryTarget && score > globalMaxScore) {
                globalMaxScore = score;
                globalWinningAlgorithm = cipherPtr->getName();
                globalFinalDecryption = attempt;
            }
            
            if (score > 0.10) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << std::left << std::setw(45) << cipherPtr->getName() 
                          << " | Fitness: " << std::fixed << std::setprecision(2) << score 
                          << " [Thread-ID: " << std::this_thread::get_id() << "]" << std::endl;
            }
        });
    }

    // SINCRONIZZAZIONE DI TUTTI I THREAD (JOIN)
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    std::cout << "\n=====================================================" << std::endl;
    std::cout << "   RISULTATO DELLA CRITTANALISI FORENSE              " << std::endl;
    std::cout << "=====================================================" << std::endl;
    
    // NUOVO FLUSSO DECISIONALE SCISSO (Senza interferenze statistiche)
    if (globalIsBinaryTarget) {
        std::string ext = ".bin";
        if (globalBinarySignature == "JPEG") ext = ".jpg";
        else if (globalBinarySignature == "PNG") ext = ".png";
        else if (globalBinarySignature == "ZIP") ext = ".zip";
        else if (globalBinarySignature == "PDF") ext = ".pdf";

        std::string outputFilename = "recovered_payload" + ext;
        FileCarver::dumpToFile(globalFinalDecryption, outputFilename);

        std::cout << "[ALGORITMO RILEVATO] : " << globalWinningAlgorithm << std::endl;
        std::cout << "[FORMATO BERSAGLIO]  : File Binario [" << globalBinarySignature << "]" << std::endl;
        std::cout << "[AZIONE TATTICA]     : Byte estratti fisicamente -> " << outputFilename << std::endl;
        std::cout << "[CONFIDENZA IA]      : ASSOLUTA (Firma Esadecimale Verificata)" << std::endl;
    } 
    else if (globalMaxScore > 0.0) { // Accettiamo qualsiasi score generato dai Big Data
        std::cout << "[ALGORITMO RILEVATO] : " << globalWinningAlgorithm << std::endl;
        std::string segmentedText = statAnalyzer.segmentWords(globalFinalDecryption);
        std::cout << "[TESTO RICOSTRUITO]  : " << segmentedText << std::endl;
        std::cout << "[CONFIDENZA IA]      : ALTA (Punteggio N-Grammi: " << globalMaxScore << ")" << std::endl;
    } else {
        std::cout << "[ALGORITMO RILEVATO] : SCONOSCIUTO / RUMORE" << std::endl;
    }

    return 0;
}