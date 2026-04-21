#include <iostream>
#include <string>
#include <unordered_map>
#include <limits>
#include <chrono>

#include "../include/EnvParser.h"
#include "../include/StatisticalAnalyzer.h"
#include "../include/KasiskiEngine.h"
#include "../include/CoreUtils.h"
#include "../include/ActionHandlers.h"

int main() {
    StatisticalAnalyzer sa("ngrams.txt", "lexicon.txt");
    KasiskiEngine ke;
    std::unordered_map<std::string, std::string> env = EnvParser::parse(".env");

    bool running = true;
    while (running) {
        topResults.clear();
        std::string rawTarget = loadCiphertext();
        std::string alphaTarget = filterAlpha(rawTarget);

        std::cout << "######################################################################" << std::endl;
        std::cout << "    DECYPHER OMNI-DECODER - HEURISTIC ARSENAL 51.2                    " << std::endl;
        std::cout << "######################################################################" << std::endl;
        
        runHeuristicProfiler(rawTarget);

        std::cout << " SELEZIONA IL VETTORE DI ATTACCO SPECIFICO:" << std::endl;
        std::cout << " [1] Caesar Cipher (Scansione Shift 1-25)" << std::endl;
        std::cout << " [2] Atbash Cipher" << std::endl;
        std::cout << " [3] Vigenere Cipher (Omni-Sweep Dinamico Brute + Dict)" << std::endl;
        std::cout << " [4] Rail Fence Cipher (Scansione Profondita' 2-15 con Telemetria)" << std::endl;
        std::cout << " [5] Affine Cipher (Scansione Coprimi A, Shift B)" << std::endl;
        std::cout << " [6] Beaufort Cipher (Dictionary Attack)" << std::endl;
        std::cout << " [7] Enigma Cipher (Emulatore M3)" << std::endl;
        std::cout << " [8] Turing Bombe (Known-Plaintext Attack)" << std::endl;
        std::cout << " [9] AES-256 (Decrittazione Simmetrica Multi-Thread in RAM)" << std::endl;
        std::cout << " [10] RSA Cipher (Asimmetrico)" << std::endl;
        std::cout << " [11] ECC ElGamal (Curva Ellittica)" << std::endl;
        std::cout << " [12] LWE Lattice (Post-Quantum Crypto)" << std::endl;
        std::cout << " [13] SHA-256 (Generazione Hash del File)" << std::endl;
        std::cout << " [14] PCAP Parser (Network Forensics)" << std::endl;
        std::cout << " [15] File Carver (Estrazione Magic Bytes)" << std::endl;
        std::cout << " [0] Termina ed esci" << std::endl;
        std::cout << "----------------------------------------------------------------------" << std::endl;
        std::cout << "COMANDO > ";

        int choice;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "[ERR] Input non valido. Riprovare con un intero.\n" << std::endl;
            continue;
        }

        if (choice == 0) {
            std::cout << "[SYSTEM] Termine operazioni. Disattivazione core logici." << std::endl;
            break;
        }

        auto start_time = std::chrono::high_resolution_clock::now();

        switch (choice) {
            case 1: handleCaesar(rawTarget, sa); break;
            case 2: handleAtbash(rawTarget, sa); break;
            case 3: handleVigenere(rawTarget, alphaTarget, sa, ke); break;
            case 4: handleRailFence(rawTarget, alphaTarget, sa); break;
            case 5: handleAffine(rawTarget, alphaTarget, sa); break;
            case 6: handleBeaufort(rawTarget, alphaTarget, sa); break;
            case 7: handleEnigma(rawTarget, alphaTarget); break;
            case 8: handleTuringBombe(rawTarget, alphaTarget); break;
            case 9: handleAES(rawTarget, sa); break;
            case 10: handleRSA(rawTarget); break;
            case 11: handleECC(rawTarget); break;
            case 12: handleLWE(rawTarget); break;
            case 13: handleSHA256(rawTarget); break;
            case 14: handlePCAP(); break;
            case 15: handleFileCarver(); break;
            default:
                std::cout << "[ERR] Scelta non contemplata. Selezionare un indice da 0 a 15." << std::endl;
                break;
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        std::cout << "\n[TEMPO DI ELABORAZIONE] : " << std::chrono::duration<double>(end_time - start_time).count() << "s\n" << std::endl;
    }
    return 0;
}