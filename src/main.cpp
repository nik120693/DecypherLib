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

std::mutex coutMutex;
std::mutex resultMutex;

int main() {
    std::cout << "=====================================================" << std::endl;
    std::cout << "   DECYPHER OMNI-DECODER - ESTREMA 2: FILE CARVING   " << std::endl;
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
    cipherRegistry.push_back(std::make_unique<ECCipher>(eccP, eccA, eccB, eccGx, eccGy, eccPriv));
    cipherRegistry.push_back(std::make_unique<LWECipher>(lweSeed, lweN, lweM, lweQ));
    cipherRegistry.push_back(std::make_unique<AESCipher>(derivedAesKey));

    // ==============================================================
    // GENERATORE DI PAYLOAD BINARIO MILITARE
    // Usiamo .back() che estrae con sicurezza assoluta l'ultimo
    // puntatore allocato (che e' sicuramente il nostro AESCipher)
    // ==============================================================
    std::string zipSignature = "PK\x03\x04"; // MAGIC NUMBER DEI FILE ZIP
    std::string fakeZipPayload = zipSignature + "---QUESTO E' IL CONTENUTO CRIPTATO DI UN ARCHIVIO SEGRETO---";
    std::cout << "\n[!] TARGET GENERATO CON AES-256 KDF. INCOLLA QUESTO IN ciphertext.txt:\n"
              << cipherRegistry.back()->encrypt(fakeZipPayload) // ACCESSO MEMORIA SICURO O(1)
              << "\n" << std::endl;

    std::cout << "=====================================================" << std::endl;
    std::cout << "   ACQUISIZIONE DATI DA: ciphertext.txt              " << std::endl;
    std::cout << "=====================================================" << std::endl;

    std::ifstream inputFile("ciphertext.txt");
    if (!inputFile.is_open()) return 1;

    std::stringstream buffer;
    buffer << inputFile.rdbuf();
    std::string targetCiphertext = buffer.str();
    inputFile.close();
    targetCiphertext.erase(targetCiphertext.find_last_not_of(" \n\r\t") + 1);

    std::cout << "[PAYLOAD INTERCETTATO]:\n" << targetCiphertext.substr(0, 80) << "...\n" << std::endl;

    std::cout << "[*] DISTRIBUZIONE THREADS ASINCRONI INIZIATA..." << std::endl;
    
    double globalMaxScore = -1.0;
    std::string globalWinningAlgorithm = "Nessuno";
    std::string globalFinalDecryption = "";

    std::vector<std::thread> workers;

    for (const auto& cipher : cipherRegistry) {
        Cipher* cipherPtr = cipher.get();
        workers.emplace_back([&statAnalyzer, targetCiphertext, cipherPtr, &globalMaxScore, &globalWinningAlgorithm, &globalFinalDecryption]() {
            std::string attempt = "";
            try { attempt = cipherPtr->decrypt(targetCiphertext); } 
            catch (...) { return; } 

            double score = 0.0;
            
            // CONTROLLO FORENSE BINARIO: Ha una firma esadecimale valida?
            std::string fileSignature = FileCarver::detectSignature(attempt);
            if (fileSignature != "UNKNOWN") {
                score = 999.0; // Vittoria Matematica Assoluta per i binari
            } else {
                score = statAnalyzer.scoreText(attempt); // Altrimenti analizza l'inglese
            }
            
            if (score > 0.10 && score < 900.0) {
                std::lock_guard<std::mutex> lock(coutMutex);
                std::cout << std::left << std::setw(45) << cipherPtr->getName() 
                          << " | Fitness: " << std::fixed << std::setprecision(2) << score 
                          << " [Thread-ID: " << std::this_thread::get_id() << "]" << std::endl;
            }

            std::lock_guard<std::mutex> lockResult(resultMutex);
            if (score > globalMaxScore) {
                globalMaxScore = score;
                globalWinningAlgorithm = cipherPtr->getName();
                globalFinalDecryption = attempt;
            }
        });
    }

    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    std::cout << "\n=====================================================" << std::endl;
    std::cout << "   RISULTATO DELLA CRITTANALISI FORENSE              " << std::endl;
    std::cout << "=====================================================" << std::endl;
    
    // GESTIONE DEI FILE BINARI CARVATI
    if (globalMaxScore >= 900.0) {
        std::string sig = FileCarver::detectSignature(globalFinalDecryption);
        std::string ext = ".bin";
        if (sig == "JPEG") ext = ".jpg";
        else if (sig == "PNG") ext = ".png";
        else if (sig == "ZIP") ext = ".zip";
        else if (sig == "PDF") ext = ".pdf";

        std::string outputFilename = "recovered_payload" + ext;
        FileCarver::dumpToFile(globalFinalDecryption, outputFilename);

        std::cout << "[ALGORITMO RILEVATO] : " << globalWinningAlgorithm << " (256-Bit Block Cipher)" << std::endl;
        std::cout << "[FORMATO BERSAGLIO]  : File Binario [" << sig << "]" << std::endl;
        std::cout << "[AZIONE TATTICA]     : Byte estratti fisicamente e salvati come -> " << outputFilename << std::endl;
        std::cout << "[CONFIDENZA IA]      : ASSOLUTA (Firma Esadecimale Verificata)" << std::endl;
    } 
    // GESTIONE DEL TESTO IN CHIARO CLASSICO
    else if (globalMaxScore >= 0.50) { 
        std::cout << "[ALGORITMO RILEVATO] : " << globalWinningAlgorithm << std::endl;
        std::string segmentedText = statAnalyzer.segmentWords(globalFinalDecryption);
        std::cout << "[TESTO RICOSTRUITO]  : " << segmentedText << std::endl;
        std::cout << "[CONFIDENZA IA]      : ALTA (Punteggio N-Grammi: " << globalMaxScore << ")" << std::endl;
    } else {
        std::cout << "[ALGORITMO RILEVATO] : SCONOSCIUTO / RUMORE" << std::endl;
    }

    return 0;
}