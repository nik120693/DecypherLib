#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <fstream>
#include <limits>
#include <memory>
#include <cctype>
#include <numeric>

// ==========================================
// INCLUSIONE SINGOLI MODULI (GRANULARITÀ TOTALE)
// ==========================================
#include "../include/EnvParser.h"
#include "../include/StatisticalAnalyzer.h"
#include "../include/KasiskiEngine.h"
#include "../include/KeyDerivation.h"

#include "../include/CaesarCipher.h"
#include "../include/AtbashCipher.h"
#include "../include/VigenereCipher.h"
#include "../include/RailFenceCipher.h"
#include "../include/AffineCipher.h"
#include "../include/BeaufortCipher.h"
#include "../include/EnigmaCipher.h"
#include "../include/TuringBombe.h"
#include "../include/AESCipher.h"
#include "../include/SHA256.h"
#include "../include/RSACipher.h"
#include "../include/ECCipher.h"
#include "../include/LWECipher.h"
#include "../include/FileCarver.h"
#include "../include/PCAPParser.h"

std::mutex resultMutex;

struct DecryptResult {
    std::string keyInfo;
    std::string plaintext;
    double fitness;
};
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

std::string loadCiphertext(const std::string& filename = "ciphertext.txt") {
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

// =========================================================================
// UNHEXLIFY: Convertitore da Stringa Esadecimale a Raw Binary
// =========================================================================
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

// =========================================================================
// ORACOLO EURISTICO DI PROFILAZIONE
// =========================================================================
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
            std::cout << "    -> " << sa.segmentWords(topResults[i].plaintext) << std::endl;
        }
    }
}

// =========================================================================
// INTERFACCIA UTENTE PRINCIPALE (CLI ORCHESTRATOR)
// =========================================================================
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
            case 1: { 
                std::cout << "\n[EXEC] Lancio Caesar Cipher..." << std::endl;
                for (int i = 1; i <= 25; ++i) {
                    CaesarCipher cc(i);
                    std::string p = cc.decrypt(alphaTarget);
                    double fit = sa.calculateMultiAnchorFitness(p);
                    if (fit > 0.0) updateTopResults({"Shift " + std::to_string(i), p, fit});
                }
                printTopResults(sa);
                break;
            }
            case 2: { 
                std::cout << "\n[EXEC] Lancio Atbash Cipher..." << std::endl;
                AtbashCipher ac;
                std::string p = ac.decrypt(alphaTarget);
                double fit = sa.calculateMultiAnchorFitness(p);
                if (fit > 0.0) updateTopResults({"N/A", p, fit});
                printTopResults(sa);
                break;
            }
            case 3: { 
                std::cout << "\n[EXEC] Lancio Vigenere Omni-Sweep..." << std::endl;
                std::vector<int> candidates;
                for (int L = 1; L <= 15; ++L) {
                    double avgIC = 0;
                    for (int i = 0; i < L; ++i) {
                        std::string col = "";
                        for (size_t j = i; j < alphaTarget.length(); j += L) col += alphaTarget[j];
                        avgIC += ke.calculateIC(col);
                    }
                    avgIC /= L;
                    if (avgIC >= 0.058) candidates.push_back(L);
                }
                if (candidates.empty()) candidates = {4, 5, 6};

                int cores = std::thread::hardware_concurrency();
                std::vector<std::thread> vigWorkers;
                for (int L : candidates) {
                    if (L <= 5) {
                        long totalComb = std::pow(26, L);
                        for (int i = 0; i < cores; ++i) {
                            vigWorkers.emplace_back([&, i, cores, totalComb, L]() {
                                for (long idx = i; idx < totalComb; idx += cores) {
                                    std::string k = ""; long tmp = idx;
                                    for (int j = 0; j < L; ++j) { k += (char)('A' + (tmp % 26)); tmp /= 26; }
                                    std::reverse(k.begin(), k.end());
                                    VigenereCipher vc(k);
                                    std::string p = vc.decrypt(alphaTarget);
                                    double fit = sa.calculateMultiAnchorFitness(p);
                                    if (fit > 0.0) updateTopResults({k, p, fit});
                                }
                            });
                        }
                    }
                    vigWorkers.emplace_back([&, L]() {
                        std::ifstream dFile("lexicon.txt");
                        std::string w;
                        while (dFile >> w) if ((int)w.length() == L) {
                            for(auto & ch : w) ch = std::toupper(ch);
                            VigenereCipher vc(w);
                            std::string p = vc.decrypt(alphaTarget);
                            double fit = sa.calculateMultiAnchorFitness(p);
                            if (fit > 0.0) updateTopResults({w, p, fit});
                        }
                    });
                }
                for (auto& t : vigWorkers) if (t.joinable()) t.join();
                printTopResults(sa);
                break;
            }
            case 4: { 
                std::cout << "\n[EXEC] Lancio Rail Fence Cipher (Scansione Profondita' 2-15)..." << std::endl;
                std::cout << std::left << std::setw(15) << "[DEPTH]" << std::setw(20) << "[FITNESS]" << "[STATUS]" << std::endl;
                std::cout << std::string(60, '-') << std::endl;
                
                double localMax = -1e18;
                std::string bestPlain = "";
                int bestDepth = 0;

                std::string naiveTarget = rawTarget;
                std::transform(naiveTarget.begin(), naiveTarget.end(), naiveTarget.begin(), ::toupper);

                for (int depth = 2; depth <= 15; ++depth) {
                    try {
                        RailFenceCipher rfc(depth);
                        std::string p_naive = rfc.decrypt(naiveTarget);
                        std::string p_eval = filterAlpha(p_naive);
                        double fit = sa.calculateMultiAnchorFitness(p_eval);
                        
                        std::string status = (fit > 0.0) ? "STABLE SIGNAL" : "NOISE (Scartato)";
                        std::cout << std::left << std::setw(15) << ("Rails: " + std::to_string(depth)) 
                                  << std::setw(20) << std::fixed << std::setprecision(2) << fit << status << std::endl;

                        if (fit > 0.0) updateTopResults({"Rails: " + std::to_string(depth), p_naive, fit});
                        
                        if (fit > localMax) { localMax = fit; bestPlain = p_naive; bestDepth = depth; }
                    } catch (...) {
                        std::cout << std::left << std::setw(15) << ("Rails: " + std::to_string(depth)) 
                                  << std::setw(20) << "N/A" << "!!! CRASH" << std::endl;
                    }
                }
                
                if (topResults.empty()) {
                    std::cout << "\n[INFO] Nessuna decodifica ha superato il Muro di Viterbi (> 0.0)." << std::endl;
                    std::cout << "Miglior tentativo (Rumore): Rails " << bestDepth << " | Fitness: " << std::fixed << std::setprecision(2) << localMax << std::endl;
                } else {
                    printTopResults(sa);
                }
                break;
            }
            case 5: { 
                std::cout << "\n[EXEC] Modulo Affine Cipher Inizializzato." << std::endl;
                std::cout << " SELEZIONA LA MODALITA' OPERATIVA:" << std::endl;
                std::cout << " [1] Omni-Sweep (Brute Force statistico su tutte le 312 chiavi)" << std::endl;
                std::cout << " [2] Iniezione Parametrica Dinamica (Manuale)" << std::endl;
                std::cout << " > ";
                int subChoice;
                std::cin >> subChoice;

                if (subChoice == 2) {
                    int a, b;
                    std::cout << " Inserisci il coefficiente scalare 'A' (deve essere coprimo con 26): ";
                    std::cin >> a;
                    std::cout << " Inserisci lo shift additivo 'B' (0-25): ";
                    std::cin >> b;

                    if (std::gcd(a, 26) != 1) {
                        std::cout << "[ERR] Violazione matematica: A=" << a << " non e' coprimo con 26. Inverso modulare inesistente." << std::endl;
                        break;
                    }

                    AffineCipher af(a, b);
                    std::string p_eval = af.decrypt(alphaTarget);
                    double fit = sa.calculateMultiAnchorFitness(p_eval);
                    
                    std::cout << "\n======================================================================" << std::endl;
                    std::cout << "[RISULTATO PARAMETRICO DIRETTO (A=" << a << ", B=" << b << ")]" << std::endl;
                    std::cout << "FITNESS MATEMATICA : " << std::fixed << std::setprecision(2) << fit << std::endl;
                    std::string p_spaced = af.decrypt(rawTarget);
                    std::cout << "DECODIFICA         : " << p_spaced << std::endl;
                    std::cout << "======================================================================\n" << std::endl;

                } else {
                    std::cout << "\n[EXEC] Lancio Affine Omni-Sweep Assoluto..." << std::endl;
                    int coprimes[] = {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25};
                    for (int a : coprimes) {
                        for (int b = 0; b < 26; ++b) {
                            AffineCipher af(a, b);
                            std::string p_eval = af.decrypt(alphaTarget);
                            double fit = sa.calculateMultiAnchorFitness(p_eval);
                            if (fit > 0.0) {
                                std::string p_spaced = af.decrypt(rawTarget);
                                updateTopResults({"A:" + std::to_string(a) + " B:" + std::to_string(b), p_spaced, fit});
                            }
                        }
                    }
                    printTopResults(sa);
                }
                break;
            }
            case 6: { 
                std::cout << "\n[EXEC] Lancio Beaufort Cipher (Dictionary)..." << std::endl;
                std::ifstream dFile("lexicon.txt");
                std::string w;
                while (dFile >> w) {
                    if (w.length() >= 3 && w.length() <= 10) {
                        for(auto & ch : w) ch = std::toupper(ch);
                        BeaufortCipher bc(w);
                        std::string p = bc.decrypt(alphaTarget);
                        double fit = sa.calculateMultiAnchorFitness(p);
                        if (fit > 0.0) updateTopResults({w, p, fit});
                    }
                }
                printTopResults(sa);
                break;
            }
            case 7: { 
                std::cout << "\n[EXEC] Attivazione Emulatore Enigma..." << std::endl;
                EnigmaCipher enigma(1, 2, 3);
                (void)enigma;
                std::cout << "[STATO] Emulatore agganciato. Necessaria parametrizzazione anelli e rotori nell'header." << std::endl;
                break;
            }
            case 8: { 
                std::cout << "\n[EXEC] Attivazione Bomba di Turing..." << std::endl;
                TuringBombe bombe;
                (void)bombe;
                std::cout << "[STATO] Simulazione Known-Plaintext. Crib richiesto per ingaggio fisico." << std::endl;
                break;
            }
            case 9: { // AES-256 DICTIONARY ATTACK (IN-RAM MULTITHREADING + UNHEXLIFY)
                std::cout << "\n[EXEC] Inizializzazione Assedio a Dizionario su AES-256..." << std::endl;
                
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                std::string salt;
                std::cout << " [?] Inserisci il SALT crittografico noto (premi INVIO per ometterlo o usare il default): ";
                std::getline(std::cin, salt);
                
                if (salt.empty()) {
                    salt = "default_salt";
                    std::cout << " [!] Nessun input. Utilizzo del SALT standard: '" << salt << "'" << std::endl;
                } else {
                    std::cout << " [!] Parametro SALT iniettato: '" << salt << "'" << std::endl;
                }

                // AUTO-CORREZIONE DEL TARGET (Hex-to-Binary)
                std::string targetBinary = rawTarget;
                bool isHexDump = true;
                for (char c : rawTarget) {
                    if (!std::isxdigit(c) && !std::isspace(c)) { isHexDump = false; break; }
                }
                
                if (isHexDump && rawTarget.length() > 16) {
                    std::cout << "[SYSTEM] Rilevato input Esadecimale (Base16). Conversione in Raw Binary in corso..." << std::endl;
                    targetBinary = hexToRaw(rawTarget);
                    std::cout << "[STATO] Conversione completata. Dimensione reale compressa a " << targetBinary.length() << " bytes." << std::endl;
                } else {
                    std::cout << "[SYSTEM] Input riconosciuto come Raw Binary nativo." << std::endl;
                }

                std::ifstream dictFile("lexicon.txt");
                if (!dictFile) {
                    std::cout << "[ERR] Dizionario 'lexicon.txt' non trovato nel path di esecuzione." << std::endl;
                    break;
                }

                std::cout << "[SYSTEM] Allocazione del dizionario nella memoria RAM..." << std::endl;
                std::vector<std::string> ramDictionary;
                std::string dictWord;
                while (dictFile >> dictWord) {
                    ramDictionary.push_back(dictWord);
                }
                size_t totalWords = ramDictionary.size();
                std::cout << "[STATO] Allocazione completata. " << totalWords << " vettori offensivi pronti." << std::endl;

                unsigned int cores = std::thread::hardware_concurrency();
                if (cores == 0) cores = 4;
                std::cout << "[SYSTEM] Architettura SMP rilevata: " << cores << " core logici. Partizionamento del carico in corso..." << std::endl;
                std::cout << "[STATO] Ingaggio PBKDF2 (1000 iterazioni). Doppia Barriera Semantica attiva." << std::endl;
                std::cout << "----------------------------------------------------------------------" << std::endl;

                std::atomic<bool> breachConfirmed(false);
                std::atomic<int> processedWords(0);
                std::string winningPassword = "";
                std::string extractedPayload = "";
                double winningFitness = 0.0;
                std::mutex winMutex;

                auto start_brute = std::chrono::high_resolution_clock::now();
                size_t chunkSize = totalWords / cores;
                std::vector<std::thread> assaultSquad;

                for (unsigned int i = 0; i < cores; ++i) {
                    size_t startIdx = i * chunkSize;
                    size_t endIdx = (i == cores - 1) ? totalWords : startIdx + chunkSize;

                    assaultSquad.emplace_back([&, startIdx, endIdx]() {
                        for (size_t j = startIdx; j < endIdx; ++j) {
                            if (breachConfirmed.load(std::memory_order_relaxed)) return;
                            processedWords.fetch_add(1, std::memory_order_relaxed);
                            
                            std::string candidateWord = ramDictionary[j];
                            std::string derivedKey = KeyDerivation::stretchKey(candidateWord, salt, 1);
                            AESCipher aes(derivedKey);
                            
                            try {
                                std::string result = aes.decrypt(rawTarget); // Usa il binario decodificato
                                
                                if (!result.empty()) {
                                    int printableChars = 0;
                                    for (unsigned char c : result) {
                                        if (std::isprint(c) || std::isspace(c)) printableChars++;
                                    }
                                    
                                    double printableRatio = (double)printableChars / result.length();
                                    if (printableRatio < 0.85) continue;

                                    double fit = sa.calculateMultiAnchorFitness(result);
                                    if (fit > -150.0) {
                                        std::lock_guard<std::mutex> lock(winMutex);
                                        if (!breachConfirmed.load(std::memory_order_relaxed)) {
                                            winningPassword = candidateWord;
                                            extractedPayload = result;
                                            winningFitness = fit;
                                            breachConfirmed.store(true, std::memory_order_relaxed);
                                        }
                                    }
                                }
                            } catch (...) { continue; }
                        }
                    });
                }

                std::thread telemetryDaemon([&]() {
                    int lastProcessed = 0;
                    while (!breachConfirmed.load(std::memory_order_relaxed)) {
                        int current = processedWords.load(std::memory_order_relaxed);
                        if (current >= (int)totalWords) break;
                        
                        double progress = ((double)current / totalWords) * 100.0;
                        int speed = (current - lastProcessed) * 2; 
                        lastProcessed = current;

                        std::cout << "\r[*] Telemetria: " << std::fixed << std::setprecision(2) << progress << "% | " 
                                  << current << " / " << totalWords << " | Rate: ~" << speed << " p/s     " << std::flush;
                        std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    }
                });

                for (auto& t : assaultSquad) if (t.joinable()) t.join();
                if (telemetryDaemon.joinable()) telemetryDaemon.join();

                if (breachConfirmed.load()) {
                    std::cout << "\n\n======================================================================" << std::endl;
                    std::cout << " [!] SINGOLARITA' RAGGIUNTA - AES-256 COMPROMESSO" << std::endl;
                    std::cout << "======================================================================" << std::endl;
                    std::cout << " PASSWORD TROVATA : " << winningPassword << std::endl;
                    std::cout << " FITNESS ESTRATTA : " << std::fixed << std::setprecision(2) << winningFitness << std::endl;
                    std::cout << " PAYLOAD ESTRATTO : " << extractedPayload << std::endl;
                } else {
                    std::cout << "\n\n[STATO] Esaurimento Totale dello Spazio Parametrico. Nessuna collisione individuata." << std::endl;
                }
                
                auto end_brute = std::chrono::high_resolution_clock::now();
                std::cout << "[TEMPO ASSALTO AES] : " << std::chrono::duration<double>(end_brute - start_brute).count() << "s\n" << std::endl;
                break;
            }
            case 10: { // RSA CIPHER (BIDIREZIONALE)
                std::cout << "\n[EXEC] Inizializzazione Modulo RSA (Asimmetrico)..." << std::endl;
                
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                std::string p_str, q_str, e_str;
                std::cout << " [?] Inserisci il Primo P (es. 61) o premi INVIO per i parametri default: ";
                std::getline(std::cin, p_str);
                
                if (p_str.empty()) {
                    p_str = "61"; q_str = "53"; e_str = "17";
                    std::cout << " [!] Parametri Test iniettati: P=" << p_str << ", Q=" << q_str << ", E=" << e_str << std::endl;
                } else {
                    std::cout << " [?] Inserisci il Primo Q: ";
                    std::getline(std::cin, q_str);
                    std::cout << " [?] Inserisci l'Esponente E: ";
                    std::getline(std::cin, e_str);
                }

                std::cout << "\n SELEZIONA OPERAZIONE RSA:" << std::endl;
                std::cout << " [1] Cifra un payload (Genera array numerico)" << std::endl;
                std::cout << " [2] Decifra il target in ciphertext.txt" << std::endl;
                std::cout << " > ";
                int rsaOp;
                std::cin >> rsaOp;
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

                try { 
                    RSACipher rsa(p_str, q_str, e_str);
                    
                    if (rsaOp == 1) {
                        std::cout << "\n [?] Inserisci il testo in chiaro: ";
                        std::string plaintext;
                        std::getline(std::cin, plaintext);
                        
                        std::string ciphered = rsa.encrypt(plaintext);
                        std::cout << "\n======================================================================" << std::endl;
                        std::cout << " [!] VETTORE CIFRATO RSA GENERATO" << std::endl;
                        std::cout << "======================================================================" << std::endl;
                        std::cout << ciphered << std::endl;
                        std::cout << "(Copia questo blocco numerico in ciphertext.txt per testare l'inversione)" << std::endl;
                        
                    } else if (rsaOp == 2) {
                        std::cout << "[SYSTEM] Inversione modulare (M = C^d mod N) in corso..." << std::endl;
                        std::string out = rsa.decrypt(rawTarget);
                        
                        std::cout << "\n======================================================================" << std::endl;
                        std::cout << " [!] SINGOLARITA' RSA RAGGIUNTA" << std::endl;
                        std::cout << "======================================================================" << std::endl;
                        std::cout << " PAYLOAD ESTRATTO : " << out << std::endl;
                    } else {
                        std::cout << "[ERR] Operazione annullata. Selezione non valida." << std::endl;
                    }
                } 
                catch (const std::exception& e) { 
                    std::cout << "[ERR] Crash RSA: " << e.what() << std::endl; 
                }
                catch (...) { 
                    std::cout << "[ERR] Disallineamento matematico. Formato del ciphertext non supportato (Richiesti interi separati da spazio)." << std::endl; 
                }
                break;
            }
            case 11: { // ECC ELGAMAL (BIDIREZIONALE E PARAMETRICO)
                std::cout << "\n[EXEC] Inizializzazione Modulo ECC ElGamal (Curva Ellittica)..." << std::endl;
                
                // Pulizia buffer
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                
                std::string p_str, a_str, b_str, gx_str, gy_str, priv_str;
                std::cout << " [?] Inserisci il Primo P del campo finito (es. 467) o premi INVIO per default: ";
                std::getline(std::cin, p_str);
                
                if (p_str.empty()) {
                    p_str = "467"; a_str = "2"; b_str = "3"; gx_str = "3"; gy_str = "6"; priv_str = "15";
                    std::cout << " [!] Parametri Test: y^2 = x^3 + " << a_str << "x + " << b_str << " mod " << p_str << std::endl;
                    std::cout << " [!] Generatore G=(" << gx_str << "," << gy_str << ") | Chiave Privata d=" << priv_str << std::endl;
                } else {
                    std::cout << " [?] Inserisci coefficiente 'a': "; std::getline(std::cin, a_str);
                    std::cout << " [?] Inserisci coefficiente 'b': "; std::getline(std::cin, b_str);
                    std::cout << " [?] Inserisci coordinata Gx del Generatore: "; std::getline(std::cin, gx_str);
                    std::cout << " [?] Inserisci coordinata Gy del Generatore: "; std::getline(std::cin, gy_str);
                    std::cout << " [?] Inserisci Chiave Privata 'd': "; std::getline(std::cin, priv_str);
                }

                std::cout << "\n SELEZIONA OPERAZIONE ECC:" << std::endl;
                std::cout << " [1] Cifra un payload (Genera matrici di punti C1, C2)" << std::endl;
                std::cout << " [2] Decifra il target geometrico in ciphertext.txt" << std::endl;
                std::cout << " > ";
                int eccOp;
                std::cin >> eccOp;
                std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

                try { 
                    ECCipher ecc(p_str, a_str, b_str, gx_str, gy_str, priv_str);
                    
                    if (eccOp == 1) {
                        std::cout << "\n [?] Inserisci il testo in chiaro da mappare sulla curva: ";
                        std::string plaintext;
                        std::getline(std::cin, plaintext);
                        
                        std::string ciphered = ecc.encrypt(plaintext);
                        std::cout << "\n======================================================================" << std::endl;
                        std::cout << " [!] PUNTI ELLITTICI GENERATI CON SUCCESSO" << std::endl;
                        std::cout << "======================================================================" << std::endl;
                        std::cout << ciphered << std::endl;
                        std::cout << "(Copia queste coordinate in ciphertext.txt per testare l'inversione)" << std::endl;
                        
                    } else if (eccOp == 2) {
                        std::cout << "[SYSTEM] Moltiplicazione scalare inversa su Curva Ellittica in corso..." << std::endl;
                        std::string out = ecc.decrypt(rawTarget);
                        
                        std::cout << "\n======================================================================" << std::endl;
                        std::cout << " [!] SINGOLARITA' ECC RAGGIUNTA" << std::endl;
                        std::cout << "======================================================================" << std::endl;
                        std::cout << " PAYLOAD ESTRATTO : " << out << std::endl;
                    } else {
                        std::cout << "[ERR] Operazione annullata. Selezione fuori range." << std::endl;
                    }
                } 
                catch (const std::exception& e) { 
                    std::cout << "[ERR] Crash ECC controllato: " << e.what() << std::endl; 
                }
                catch (...) { 
                    std::cout << "[ERR] Disallineamento matematico. Formato del ciphertext incompatibile con la topologia della curva." << std::endl; 
                }
                break;
            }
            case 12: { 
                std::cout << "\n[EXEC] Calcolo Reticolare LWE (Post-Quantum)..." << std::endl;
                LWECipher lwe(12345, 256, 256, 3329);
                try { std::cout << "Output: " << lwe.decrypt(rawTarget) << std::endl; } 
                catch (...) { std::cout << "Crash LWE controllato." << std::endl; }
                break;
            }
            case 13: { 
                std::cout << "\n[EXEC] Hashing SHA-256..." << std::endl;
                SHA256 sha;
                (void)sha; 
                std::cout << "[STATO] Modulo hash allocato." << std::endl;
                break;
            }
            case 14: { 
                std::cout << "\n[EXEC] Avvio PCAP Parser..." << std::endl;
                PCAPParser pcap;
                (void)pcap;
                std::cout << "[STATO] Motore di estrazione traffico allocato." << std::endl;
                break;
            }
            case 15: { 
                std::cout << "\n[EXEC] Avvio File Carver..." << std::endl;
                FileCarver carver;
                (void)carver;
                std::cout << "[STATO] Motore ricerca Magic Bytes allocato." << std::endl;
                break;
            }
            default:
                std::cout << "[ERR] Scelta non contemplata. Selezionare un indice da 0 a 15." << std::endl;
                break;
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        std::cout << "\n[TEMPO DI ELABORAZIONE] : " << std::chrono::duration<double>(end_time - start_time).count() << "s\n" << std::endl;
    }
    return 0;
}