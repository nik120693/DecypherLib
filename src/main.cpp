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
#include <unordered_set>
#include <cstring>

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
std::mutex coutMutex;

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
            case 3: { // MODULO VIGENERE (KASISKI + DICT + OMNI-SWEEP BRUTE FORCE)
            std::cout << "\n[EXEC] Inizializzazione Assedio Vigenere Dinamico..." << std::endl;
            
            std::ifstream f("ciphertext.txt");
            if (!f) { std::cout << "[ERR] File non trovato.\n"; break; }
            std::string cleanTarget = ""; char ch;
            while (f.get(ch)) { if (std::isalpha(ch)) cleanTarget += std::toupper(ch); }

            // 1. KASISKI ENGINE
            std::cout << "[SYSTEM] Analisi Kasiski/IC per l'identificazione delle armoniche..." << std::endl;
            std::vector<int> targetLengths;
            for (int L = 1; L <= 20; ++L) {
                double avgIC = 0;
                for (int i = 0; i < L; ++i) {
                    std::string col = "";
                    for (size_t j = i; j < cleanTarget.length(); j += L) col += cleanTarget[j];
                    if (col.length() > 1) avgIC += ke.calculateIC(col);
                }
                avgIC /= L;
                if (avgIC >= 0.058) {
                    targetLengths.push_back(L);
                    std::cout << " -> Tracciata armonica potenziale L=" << L << " (IC: " << std::fixed << std::setprecision(4) << avgIC << ")" << std::endl;
                }
            }
            if (targetLengths.empty()) {
                std::cout << "[WARN] Nessuna armonica rilevata. Fallback su spettro 1-10." << std::endl;
                for(int i=1; i<=10; i++) targetLengths.push_back(i);
            }

            std::unordered_set<std::string> uniqueKeys;

            // 2. DATA CLEANSING: Estrazione dal Dizionario
            std::cout << "[SYSTEM] Estrazione chiavi da book.txt per le geometrie rilevate..." << std::endl;
            std::ifstream dictFile("book.txt");
            if (dictFile) {
                std::string rawToken;
                while (dictFile >> rawToken) {
                    std::string cleanWord = "";
                    for (char c : rawToken) {
                        if (std::isalpha(c)) cleanWord += std::toupper(c);
                    }
                    bool validLength = false;
                    for (int l : targetLengths) {
                        if ((int)cleanWord.length() == l) { validLength = true; break; }
                    }
                    if (validLength) uniqueKeys.insert(cleanWord);
                }
            }

            // 2.5 OMNI-SWEEP BRUTE FORCE (Generazione esaustiva per L <= 4)
            std::cout << "[SYSTEM] Innesco Omni-Sweep Brute-Force per chiavi <= 4 caratteri..." << std::endl;
            for (int l : targetLengths) {
                if (l <= 4) {
                    std::vector<int> idx(l, 0);
                    bool done = false;
                    while (!done) {
                        std::string bKey = "";
                        for (int i = 0; i < l; ++i) bKey += (char)('A' + idx[i]);
                        uniqueKeys.insert(bKey); // Inserimento nel set (ignora i duplicati del libro)
                        
                        // Incremento vettoriale base-26
                        int pos = l - 1;
                        while (pos >= 0) {
                            idx[pos]++;
                            if (idx[pos] < 26) break;
                            idx[pos] = 0;
                            pos--;
                        }
                        if (pos < 0) done = true;
                    }
                }
            }

            std::vector<std::string> dictCandidates(uniqueKeys.begin(), uniqueKeys.end());
            std::cout << "[STATO] Vettori caricati. " << dictCandidates.size() << " chiavi totali in RAM. Innesco thread..." << std::endl;

            // 3. MULTI-THREADING OFFENSIVO
            double maxScore = -1e20;
            std::string winner = "None";
            std::string bestPlain = "";
            std::atomic<int> tested(0);

            int numThreads = std::thread::hardware_concurrency();
            if(numThreads == 0) numThreads = 1;
            std::vector<std::thread> workers;
            int chunkSize = dictCandidates.size() / numThreads;
            if(chunkSize == 0) { chunkSize = dictCandidates.size(); numThreads = 1; }
            
            auto start_time = std::chrono::high_resolution_clock::now();

            for (int t = 0; t < numThreads; ++t) {
                workers.emplace_back([&, t, chunkSize]() {
                    int startIdx = t * chunkSize;
                    int endIdx = (t == numThreads - 1) ? dictCandidates.size() : (t + 1) * chunkSize;

                    for (int i = startIdx; i < endIdx; ++i) {
                        tested++;
                        if (t == 0 && tested % 5000 == 0) {
                            std::cout << "\r[*] Scansione SMP... " << tested << "/" << dictCandidates.size() << std::flush;
                        }

                        VigenereCipher vc(dictCandidates[i]);
                        std::string p = vc.decrypt(cleanTarget);
                        double fit = sa.calculateMultiAnchorFitness(p);
                        
                        std::lock_guard<std::mutex> lockRes(resultMutex);
                        if (fit > maxScore) { 
                            maxScore = fit; 
                            winner = dictCandidates[i]; 
                            bestPlain = p; 
                        }
                    }
                });
            }
            for (auto& t : workers) if (t.joinable()) t.join();

            auto end_time = std::chrono::high_resolution_clock::now();
            std::cout << "\n\n======================================================================" << std::endl;
            std::cout << " [!] VIGENERE: DECIFRAZIONE COMPLETATA" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << " CHIAVE VINCITRICE : " << winner << " (Fitness: " << std::fixed << std::setprecision(2) << maxScore << ")" << std::endl;
            std::cout << " TESTO DECIFRATO   : " << bestPlain.substr(0, 150) << "..." << std::endl;
            std::cout << " [TEMPO] : " << std::chrono::duration<double>(end_time - start_time).count() << "s\n" << std::endl;
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
            case 7: { // MODULO ENIGMA M3 (EMULATORE KRIEGSMARINE)
                std::cout << "\n[EXEC] Inizializzazione Emulatore Enigma M3..." << std::endl;
                
                std::ifstream f("ciphertext.txt");
                if (!f) { std::cout << "[ERR] File non trovato.\n"; break; }
                std::string cleanTarget = ""; char ch;
                while (f.get(ch)) { if (std::isalpha(ch)) cleanTarget += std::toupper(ch); }

                // KERNEL ENIGMA M3 LOCALE
                struct LocalEnigma {
                    int rot[3], pos[3], ring[3], pb[26];
                    const std::string W[5] = {"EKMFLGDQVZNTOWYHXUSPAIBRCJ", "AJDKSIRUXBLHWTMCQGZNPYFVOE", 
                                              "BDFHJLCPRTXVZNYEIWGAKMUSQO", "ESOVPZJAYQUIRHXLNFTGKDCMWB", 
                                              "VZBRGITYUPSDNHLXAWMJQOFECK"};
                    const int notches[5] = {16, 4, 21, 9, 25}; // Q, E, V, J, Z
                    const std::string REF = "YRUHQSLDPXNGOKMIEBFZCWVJAT"; // Riflettore B

                    LocalEnigma(int r1, int r2, int r3, std::string p, std::string r) {
                        rot[0] = r1-1; rot[1] = r2-1; rot[2] = r3-1;
                        pos[0] = p[0]-'A'; pos[1] = p[1]-'A'; pos[2] = p[2]-'A';
                        ring[0] = r[0]-'A'; ring[1] = r[1]-'A'; ring[2] = r[2]-'A';
                        for(int i=0; i<26; i++) pb[i] = i;
                    }

                    char process(char c) {
                        int v = c - 'A'; v = pb[v];
                        bool stepM = (pos[2] == notches[rot[2]]);
                        bool stepL = (pos[1] == notches[rot[1]]);
                        if(stepL) stepM = true; // Anomalia Double Stepping
                        pos[2] = (pos[2]+1)%26;
                        if(stepM) pos[1] = (pos[1]+1)%26;
                        if(stepL) pos[0] = (pos[0]+1)%26;

                        for(int i=2; i>=0; i--) { // Forward
                            int shift = (pos[i] - ring[i] + 26) % 26;
                            v = (W[rot[i]][(v + shift) % 26] - 'A' - shift + 26) % 26;
                        }
                        v = REF[v] - 'A'; // Riflettore
                        for(int i=0; i<=2; i++) { // Backward
                            int shift = (pos[i] - ring[i] + 26) % 26;
                            v = (W[rot[i]].find((char)((v + shift) % 26 + 'A')) - shift + 26) % 26;
                        }
                        return (char)(pb[v] + 'A');
                    }
                };

                int r1, r2, r3;
                std::string p, r;
                std::cout << " [?] Inserisci i Rotori (Sinistra, Centro, Destra) [es. 1 2 3]: ";
                std::cin >> r1 >> r2 >> r3;
                std::cout << " [?] Inserisci la Posizione Iniziale (3 lettere) [es. ABC]: ";
                std::cin >> p;
                std::cout << " [?] Inserisci il Ringstellung (3 lettere) [es. AAA]: ";
                std::cin >> r;

                LocalEnigma m3(r1, r2, r3, p, r);
                std::string output = "";
                for(char c : cleanTarget) output += m3.process(c);

                std::cout << "\n======================================================================" << std::endl;
                std::cout << " [!] TRASMISSIONE ENIGMA ELABORATA" << std::endl;
                std::cout << "======================================================================" << std::endl;
                std::cout << " OUTPUT : " << output << "\n\n";
                break;
            }

            case 8: { // MODULO TURING BOMBE (KPA MULTI-THREAD)
                std::cout << "\n[EXEC] Inizializzazione Turing Bombe (Multi-Thread KPA)..." << std::endl;
                
                std::ifstream f("ciphertext.txt");
                if (!f) { std::cout << "[ERR] File non trovato.\n"; break; }
                std::string cleanTarget = ""; char ch;
                while (f.get(ch)) { if (std::isalpha(ch)) cleanTarget += std::toupper(ch); }

                std::cout << " [?] Inserisci il CRIB (Testo in chiaro noto da cercare): ";
                std::string crib; std::cin >> crib;
                for(char& c : crib) c = std::toupper(c);

                std::cout << "[SYSTEM] Generazione dei " << (5*4*3 * 26*26*26) << " stati termodinamici in RAM..." << std::endl;
                
                struct LocalEnigma {
                    int rot[3], pos[3], ring[3];
                    const std::string W[5] = {"EKMFLGDQVZNTOWYHXUSPAIBRCJ", "AJDKSIRUXBLHWTMCQGZNPYFVOE", "BDFHJLCPRTXVZNYEIWGAKMUSQO", "ESOVPZJAYQUIRHXLNFTGKDCMWB", "VZBRGITYUPSDNHLXAWMJQOFECK"};
                    const int notches[5] = {16, 4, 21, 9, 25};
                    const std::string REF = "YRUHQSLDPXNGOKMIEBFZCWVJAT";

                    LocalEnigma(int r1, int r2, int r3, int p1, int p2, int p3) {
                        rot[0] = r1; rot[1] = r2; rot[2] = r3;
                        pos[0] = p1; pos[1] = p2; pos[2] = p3;
                        ring[0] = 0; ring[1] = 0; ring[2] = 0; // KPA base ignora gli anelli (AAA)
                    }

                    char process(char c) {
                        int v = c - 'A';
                        bool stepM = (pos[2] == notches[rot[2]]);
                        bool stepL = (pos[1] == notches[rot[1]]);
                        if(stepL) stepM = true;
                        pos[2] = (pos[2]+1)%26;
                        if(stepM) pos[1] = (pos[1]+1)%26;
                        if(stepL) pos[0] = (pos[0]+1)%26;

                        for(int i=2; i>=0; i--) {
                            int shift = (pos[i] - ring[i] + 26) % 26;
                            v = (W[rot[i]][(v + shift) % 26] - 'A' - shift + 26) % 26;
                        }
                        v = REF[v] - 'A';
                        for(int i=0; i<=2; i++) {
                            int shift = (pos[i] - ring[i] + 26) % 26;
                            v = (W[rot[i]].find((char)((v + shift) % 26 + 'A')) - shift + 26) % 26;
                        }
                        return (char)(v + 'A');
                    }
                };

                // Generazione combinazioni dei rotori P(5,3) = 60
                std::vector<std::vector<int>> rotorPerms;
                for(int i=0; i<5; i++)
                    for(int j=0; j<5; j++)
                        for(int k=0; k<5; k++)
                            if(i!=j && i!=k && j!=k) rotorPerms.push_back({i, j, k});

                std::atomic<bool> found(false);
                std::atomic<int> processedStates(0);
                int numThreads = std::thread::hardware_concurrency();
                if(numThreads == 0) numThreads = 1;
                std::vector<std::thread> workers;

                auto start_time = std::chrono::high_resolution_clock::now();
                int totalStates = rotorPerms.size() * 17576;

                for (int t = 0; t < numThreads; ++t) {
                    workers.emplace_back([&, t]() {
                        for(size_t rIdx = t; rIdx < rotorPerms.size(); rIdx += numThreads) {
                            if(found) break;
                            auto rts = rotorPerms[rIdx];
                            
                            for(int p1=0; p1<26; p1++) {
                                for(int p2=0; p2<26; p2++) {
                                    for(int p3=0; p3<26; p3++) {
                                        if(found) return;
                                        processedStates++;
                                        if(t==0 && processedStates % 50000 == 0) {
                                            std::cout << "\r[*] Rotazioni elaborate... " << processedStates << "/" << totalStates << std::flush;
                                        }

                                        LocalEnigma m3(rts[0], rts[1], rts[2], p1, p2, p3);
                                        std::string attempt = "";
                                        for(char c : cleanTarget) attempt += m3.process(c);

                                        if(attempt.find(crib) != std::string::npos) {
                                            if(!found.exchange(true)) {
                                                std::lock_guard<std::mutex> lock(coutMutex);
                                                std::cout << "\n\n======================================================================" << std::endl;
                                                std::cout << " [!] TURING BOMBE: COLLISIONE LOGICA CONFERMATA" << std::endl;
                                                std::cout << "======================================================================" << std::endl;
                                                std::cout << " ROTORI (L-M-R)  : " << rts[0]+1 << " " << rts[1]+1 << " " << rts[2]+1 << std::endl;
                                                std::cout << " POSIZIONE (Grd) : " << (char)(p1+'A') << (char)(p2+'A') << (char)(p3+'A') << std::endl;
                                                std::cout << " PAYLOAD ESTRATTO: " << attempt << std::endl;
                                            }
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
                for (auto& w : workers) if (w.joinable()) w.join();

                auto end_time = std::chrono::high_resolution_clock::now();
                if(!found) std::cout << "\n\n[STATO] Esaurimento stati (" << processedStates << "). Crib non trovato." << std::endl;
                std::cout << " [TEMPO] : " << std::chrono::duration<double>(end_time - start_time).count() << "s\n" << std::endl;
                break;
            }
            case 9: { // MODULO AES-256 (MULTI-THREAD SMP + BIG DATA + HEX SANITIZATION)
            std::cout << "\n[EXEC] Inizializzazione Assedio Multi-Thread su AES-256..." << std::endl;
            
            // 1. SANITIZZAZIONE DEL TARGET (Prevenzione crash da spazi/newline di CyberChef)
            std::string hexTarget = "";
            for (char c : rawTarget) {
                if (std::isxdigit(c)) hexTarget += c;
            }
            if (hexTarget.empty() || hexTarget.length() % 2 != 0) {
                std::cout << "[ERR] Il ciphertext non contiene un esadecimale valido o e' dispari." << std::endl;
                break;
            }

            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::string salt;
            std::cout << " [?] Inserisci il SALT (premi INVIO per ometterlo o usare default): ";
            std::getline(std::cin, salt);
            if(salt.empty()) salt = "INVASION"; 
            std::cout << " [!] Parametro SALT iniettato: '" << salt << "'\n" << std::endl;

            // 2. DATA CLEANSING: Estrazione chiavi da book.txt
            std::cout << "[SYSTEM] Estrazione chiavi univoche da book.txt (Data Cleansing)..." << std::endl;
            std::unordered_set<std::string> aesUniqueKeys;
            std::ifstream dictFile("book.txt");
            if (dictFile) {
                std::string rawWord;
                while (dictFile >> rawWord) {
                    std::string cleanWord = "";
                    for (char c : rawWord) {
                        if (std::isalpha(c)) cleanWord += std::toupper(c);
                    }
                    if (cleanWord.length() >= 3 && cleanWord.length() <= 25) {
                        aesUniqueKeys.insert(cleanWord);
                    }
                }
            }

            std::vector<std::string> aesCandidates(aesUniqueKeys.begin(), aesUniqueKeys.end());
            std::cout << "[STATO] Vettori offensivi AES allocati in RAM: " << aesCandidates.size() << " chiavi uniche." << std::endl;
            
            std::atomic<bool> breachConfirmed(false);
            std::atomic<int> processedWords(0);
            
            int numThreads = std::thread::hardware_concurrency();
            if(numThreads == 0) numThreads = 1;
            std::vector<std::thread> workers;
            int chunkSize = aesCandidates.size() / numThreads;
            if(chunkSize == 0) { chunkSize = aesCandidates.size(); numThreads = 1; }
            
            std::cout << "[SYSTEM] Architettura SMP rilevata: " << numThreads << " core logici. Ingaggio." << std::endl;
            std::cout << "----------------------------------------------------------------------" << std::endl;
            
            auto start_brute = std::chrono::high_resolution_clock::now();

            for (int t = 0; t < numThreads; ++t) {
                workers.emplace_back([&, t, chunkSize, hexTarget]() {
                    int startIdx = t * chunkSize;
                    int endIdx = (t == numThreads - 1) ? aesCandidates.size() : (t + 1) * chunkSize;
                    
                    for (int i = startIdx; i < endIdx; ++i) {
                        if (breachConfirmed) break; // Termina istantaneamente gli altri thread in caso di vittoria
                        
                        int current = ++processedWords;
                        if (current % 1000 == 0) {
                            std::lock_guard<std::mutex> lock(coutMutex);
                            std::cout << "\r[*] Testate " << current << " / " << aesCandidates.size() 
                                      << " password..." << std::flush;
                        }
                        
                        // 1 iterazione per allineamento con i test ECB custom
                        std::string derivedKey = KeyDerivation::stretchKey(aesCandidates[i], salt, 1);
                        AESCipher aes(derivedKey);
                        
                        try {
                            // Usiamo hexTarget sanitizzato invece del rawTarget sporco
                            std::string result = aes.decrypt(hexTarget);
                            if (!result.empty()) {
                                int printableChars = 0;
                                for (unsigned char c : result) {
                                    if (std::isprint(c) || std::isspace(c)) printableChars++;
                                }
                                if ((double)printableChars / result.length() < 0.90) continue;

                                double fit = sa.calculateMultiAnchorFitness(result);
                                if (fit > 0.0) {
                                    if (!breachConfirmed.exchange(true)) {
                                        std::lock_guard<std::mutex> lock(coutMutex);
                                        std::cout << "\n\n======================================================================" << std::endl;
                                        std::cout << " [!] SINGOLARITA' RAGGIUNTA - AES-256 COMPROMESSO" << std::endl;
                                        std::cout << "======================================================================" << std::endl;
                                        std::cout << " PASSWORD TROVATA : " << aesCandidates[i] << std::endl;
                                        std::cout << " FITNESS ESTRATTA : " << std::fixed << std::setprecision(2) << fit << std::endl;
                                        std::cout << " PAYLOAD ESTRATTO : " << result << std::endl;
                                    }
                                }
                            }
                        } catch (...) { continue; }
                    }
                });
            }
            for (auto& t : workers) if (t.joinable()) t.join();

            if (!breachConfirmed) {
                std::cout << "\n\n[STATO] Esaurimento Dizionario (" << processedWords << " chiavi). Nessuna collisione." << std::endl;
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
            case 12: { // MODULO LWE (Post-Quantum)
            std::cout << "\n[EXEC] Inizializzazione Modulo LWE Lattice (Post-Quantum Crypto)..." << std::endl;
            std::cout << "[SYSTEM] Algoritmo di Regev attivato. Generazione del reticolo spaziale in corso..." << std::endl;
            
            std::cout << "\n SELEZIONA OPERAZIONE LWE:\n [1] Cifra un payload (Genera Vettori Rumorosi in Zq)\n [2] Decifra il target in ciphertext.txt\n > ";
            int op; 
            std::cin >> op; 
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

            try {
                LWECipher lwe(42, 8, 16, 251); 
                if (op == 1) {
                    std::cout << " [?] Inserisci il testo in chiaro da proiettare nel reticolo: ";
                    std::string pt; 
                    std::getline(std::cin, pt);
                    
                    std::string cypher = lwe.encrypt(pt);
                    std::cout << "\n======================================================================" << std::endl;
                    std::cout << " [!] SINGOLARITA' QUANTISTICA: VETTORI LWE GENERATI CON SUCCESSO" << std::endl;
                    std::cout << "======================================================================" << std::endl;
                    std::cout << cypher << std::endl;
                    std::cout << "\n(Usa 'echo \"<output>\" > ciphertext.txt' per testare l'inversione NP-Hard)" << std::endl;
                    
                } else if (op == 2) {
                    std::cout << "[SYSTEM] Calcolo della distanza vettoriale (Learning With Errors) in corso...\n";
                    std::string dec = lwe.decrypt(rawTarget);
                    
                    std::cout << "\n======================================================================" << std::endl;
                    std::cout << " [!] VETTORE QUANTISTICO COLLASSATO" << std::endl;
                    std::cout << "======================================================================" << std::endl;
                    std::cout << " PAYLOAD ESTRATTO : " << dec << std::endl;
                }
            } catch(const std::exception& e) { 
                std::cout << "[ERR] Disallineamento dimensionale nel reticolo: " << e.what() << "\n"; 
            }
            break;
        }
            case 13: { // MODULO SHA-256 (FILE HASHING FORENSE)
            std::cout << "\n[EXEC] Inizializzazione Motore di Hashing SHA-256..." << std::endl;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::string filename;
            std::cout << " [?] Inserisci il file per estrarre l'impronta digitale (es. dump.raw) o INVIO per 'ciphertext.txt': ";
            std::getline(std::cin, filename);
            if(filename.empty()) filename = "ciphertext.txt";

            std::ifstream file(filename, std::ios::binary);
            if (!file) {
                std::cout << "[ERR] Fallimento I/O: Impossibile accedere al tensore '" << filename << "'." << std::endl;
                break;
            }

            // KERNEL SHA-256 STANDALONE (Nessuna dipendenza esterna)
            struct LocalSHA256 {
                uint32_t state[8] = {
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
                };
                uint64_t bitlen = 0;
                uint8_t data[64];
                uint32_t datalen = 0;

                // Funzioni logiche primarie
                uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
                uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
                uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & (b | c)) | (b & c); }
                uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
                uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
                uint32_t ep0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
                uint32_t ep1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

                // Funzione di Compressione (Il cuore dell'entropia)
                void transform() {
                    const uint32_t k[64] = {
                        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
                        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
                        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
                        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
                        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
                        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
                        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
                        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
                    };
                    uint32_t m[64];
                    for (int i=0, j=0; i < 16; ++i, j += 4)
                        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
                    for (int i=16; i < 64; ++i)
                        m[i] = sig1(m[i-2]) + m[i-7] + sig0(m[i-15]) + m[i-16];

                    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
                    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

                    for (int i=0; i < 64; ++i) {
                        uint32_t t1 = h + ep1(e) + choose(e,f,g) + k[i] + m[i];
                        uint32_t t2 = ep0(a) + majority(a,b,c);
                        h = g; g = f; f = e; e = d + t1;
                        d = c; c = b; b = a; a = t1 + t2;
                    }
                    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
                    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
                }

                // Iniettore sequenziale
                void update(const uint8_t* p, size_t len) {
                    for (size_t i = 0; i < len; ++i) {
                        data[datalen] = p[i];
                        datalen++;
                        if (datalen == 64) {
                            transform();
                            bitlen += 512;
                            datalen = 0;
                        }
                    }
                }

                // Imbottitura finale (Padding) e serializzazione
                std::string finalize() {
                    uint32_t i = datalen;
                    if (datalen < 56) {
                        data[i++] = 0x80;
                        while (i < 56) data[i++] = 0x00;
                    } else {
                        data[i++] = 0x80;
                        while (i < 64) data[i++] = 0x00;
                        transform();
                        memset(data, 0, 56);
                    }
                    bitlen += datalen * 8;
                    data[63] = bitlen; data[62] = bitlen >> 8; data[61] = bitlen >> 16; data[60] = bitlen >> 24;
                    data[59] = bitlen >> 32; data[58] = bitlen >> 40; data[57] = bitlen >> 48; data[56] = bitlen >> 56;
                    transform();
                    
                    std::stringstream ss;
                    for(int idx=0; idx<8; idx++) {
                        ss << std::hex << std::setw(8) << std::setfill('0') << state[idx];
                    }
                    return ss.str();
                }
            };

            LocalSHA256 sha;
            char buffer[8192];
            auto start_time = std::chrono::high_resolution_clock::now();
            size_t totalBytes = 0;

            std::cout << "[SYSTEM] Innesco pipeline I/O bufferizzata (Chunk size: 8192 bytes)..." << std::endl;
            
            // Assorbimento continuo del file a blocchi per prevenire Memory Leak
            while (file.read(buffer, sizeof(buffer))) {
                sha.update(reinterpret_cast<uint8_t*>(buffer), file.gcount());
                totalBytes += file.gcount();
            }
            // Assorbimento del residuo finale
            if (file.gcount() > 0) {
                sha.update(reinterpret_cast<uint8_t*>(buffer), file.gcount());
                totalBytes += file.gcount();
            }

            std::string hashStr = sha.finalize();
            auto end_time = std::chrono::high_resolution_clock::now();

            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] DIGEST SHA-256 GENERATO CON SUCCESSO" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << " File Target    : " << filename << std::endl;
            std::cout << " Massa Elaborata: " << totalBytes << " bytes" << std::endl;
            std::cout << " SHA-256 HASH   : " << hashStr << std::endl;
            std::cout << " [TEMPO]        : " << std::chrono::duration<double>(end_time - start_time).count() << "s\n" << std::endl;
            
            break;
        }
            case 14: { // MODULO PCAP/PCAPNG PARSER (NETWORK FORENSICS & CARVING)
            std::cout << "\n[EXEC] Inizializzazione Network Forensics Parser (Compatibilita' PCAPNG)..." << std::endl;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::string filename;
            std::cout << " [?] Inserisci il nome del file di cattura (es. target.pcapng) o premi INVIO per default: ";
            std::getline(std::cin, filename);
            if(filename.empty()) filename = "target.pcapng";

            std::ifstream file(filename, std::ios::binary);
            if (!file) {
                std::cout << "[ERR] Disallineamento filesystem: Impossibile aprire '" << filename << "'." << std::endl;
                break;
            }

            // 1. SCANSIONE FORENSE DELL'INTESTAZIONE (MAGIC BYTES)
            uint32_t magic = 0;
            file.read(reinterpret_cast<char*>(&magic), 4);

            bool isPcapng = false;
            bool isPcap = false;
            bool swapEndian = false;

            if (magic == 0xa1b2c3d4 || magic == 0xa1b23c4d) { isPcap = true; swapEndian = false; }
            else if (magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1) { isPcap = true; swapEndian = true; }
            else if (magic == 0x0A0D0D0A) { isPcapng = true; }

            if (!isPcap && !isPcapng) {
                std::cout << "[ERR] Magic Bytes Sconosciuti (0x" << std::hex << magic << std::dec 
                          << "). Il tensore non e' un archivio PCAP/PCAPNG valido." << std::endl;
                break;
            }

            std::cout << "[SYSTEM] Risonanza strutturale confermata: Formato " 
                      << (isPcapng ? "PCAP-Next Generation (PCAPNG)" : "Classic PCAP") << std::endl;
            std::cout << "[SYSTEM] Innesco Deep Packet Inspection. Ricerca artefatti e payload in chiaro..." << std::endl;

            int packetCount = 0;
            std::vector<std::string> extractedPayloads;

            auto swap32 = [](uint32_t val) {
                return ((val << 24) & 0xFF000000) | ((val << 8) & 0x00FF0000) |
                       ((val >> 8) & 0x0000FF00) | ((val >> 24) & 0x000000FF);
            };

            // 2. DISSEZIONE BINARIA DIFFERENZIALE
            if (isPcap) {
                file.seekg(24, std::ios::beg);
                while (file) {
                    uint32_t pcapHdr[4]; 
                    file.read(reinterpret_cast<char*>(pcapHdr), 16);
                    if (!file) break; // FIX: Controllo di stato dello stream
                    
                    uint32_t incl_len = swapEndian ? swap32(pcapHdr[2]) : pcapHdr[2];
                    if (incl_len > 65535) { std::cout << "[WARN] Frammentazione anomala pacchetto. Salto." << std::endl; break; }

                    std::vector<char> pktData(incl_len);
                    file.read(pktData.data(), incl_len);
                    if (!file) break;
                    packetCount++;

                    std::string currentStr = "";
                    for (char c : pktData) {
                        if (std::isprint(static_cast<unsigned char>(c)) || c == '\t') {
                            currentStr += c;
                        } else {
                            if (currentStr.length() >= 8) extractedPayloads.push_back(currentStr);
                            currentStr = "";
                        }
                    }
                    if (currentStr.length() >= 8) extractedPayloads.push_back(currentStr);
                }
            } else if (isPcapng) {
                file.seekg(0, std::ios::beg);
                while (file) {
                    uint32_t blockType = 0, blockTotLength = 0;
                    
                    // FIX: Lettura asincrona sicura e bypass del gcount
                    file.read(reinterpret_cast<char*>(&blockType), 4);
                    if (!file) break; 
                    file.read(reinterpret_cast<char*>(&blockTotLength), 4);
                    if (!file || blockTotLength < 12) break; 
                    
                    uint32_t bodyLen = blockTotLength - 12; 
                    std::vector<char> blockBody(bodyLen);
                    file.read(blockBody.data(), bodyLen);
                    
                    uint32_t trailingLen = 0;
                    file.read(reinterpret_cast<char*>(&trailingLen), 4);

                    if (blockType == 6) { // Enhanced Packet Block
                        packetCount++;
                        if (bodyLen >= 20) {
                            uint32_t capLen = *reinterpret_cast<uint32_t*>(&blockBody[12]);
                            uint32_t dataOffset = 20;
                            
                            // Validazione della lunghezza per evitare segmentation fault
                            if (dataOffset + capLen <= bodyLen) {
                                std::string currentStr = "";
                                for (uint32_t i = 0; i < capLen; i++) {
                                    char c = blockBody[dataOffset + i];
                                    if (std::isprint(static_cast<unsigned char>(c)) || c == '\t') {
                                        currentStr += c;
                                    } else {
                                        if (currentStr.length() >= 8) extractedPayloads.push_back(currentStr);
                                        currentStr = "";
                                    }
                                }
                                if (currentStr.length() >= 8) extractedPayloads.push_back(currentStr);
                            }
                        }
                    }
                }
            }

            // 3. REPORTISTICA TATTICA E DATA CARVING
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] PARSING DI RETE COMPLETATO" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << " Volumetria Pacchetti : " << packetCount << std::endl;
            std::cout << " Artefatti Isolati    : " << extractedPayloads.size() << std::endl;
            
            if (!extractedPayloads.empty()) {
                std::cout << "\n[SYSTEM] Estrazione Frammenti ad Alta Entropia Semantica (Primi 15 rilevati):" << std::endl;
                int limit = std::min(static_cast<int>(extractedPayloads.size()), 15);
                for (int i = 0; i < limit; i++) {
                    std::cout << "  -> " << extractedPayloads[i] << std::endl;
                }
            } else {
                std::cout << "[STATO] Nessun payload in chiaro rilevato. Il traffico risulta crittografato (es. TLS/HTTPS)." << std::endl;
            }
            break;
        }
            case 15: { // MODULO FILE CARVER (ESTRAZIONE MAGIC BYTES)
            std::cout << "\n[EXEC] Inizializzazione File Carver Forense (Ricerca Firme Esadecimali)..." << std::endl;
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::string filename;
            std::cout << " [?] Inserisci il nome del file binario/dump da analizzare (es. dump.raw) o premi INVIO per 'ciphertext.txt': ";
            std::getline(std::cin, filename);
            if(filename.empty()) filename = "ciphertext.txt";

            // Apertura in modalita' binaria posizionando il puntatore alla fine (ate) per calcolare la massa del file
            std::ifstream file(filename, std::ios::binary | std::ios::ate);
            if (!file) {
                std::cout << "[ERR] Disallineamento filesystem: Impossibile aprire '" << filename << "'." << std::endl;
                break;
            }

            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::cout << "[SYSTEM] Allocazione buffer tensoriale per " << size << " bytes continui..." << std::endl;

            std::vector<unsigned char> buffer(size);
            if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
                std::cout << "[STATO] Lettura RAW completata. Innesco scansione lineare profonda su matrice contigua..." << std::endl;
            } else {
                std::cout << "[ERR] Fallimento irreversibile di lettura RAW. Allocazione abortita." << std::endl;
                break;
            }

            // 1. DEFINIZIONE DELLE FIRME GEOMETRICHE (MAGIC BYTES)
            // Header e Footer per il protocollo JPEG (Joint Photographic Experts Group)
            const std::vector<unsigned char> jpgHeader = {0xFF, 0xD8, 0xFF};
            const std::vector<unsigned char> jpgFooter = {0xFF, 0xD9};
            
            // Header e Footer per il protocollo PNG (Portable Network Graphics) incluse le ridondanze IEND
            const std::vector<unsigned char> pngHeader = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
            const std::vector<unsigned char> pngFooter = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};

            // Header e Footer per la struttura dati PDF (Portable Document Format)
            const std::vector<unsigned char> pdfHeader = {0x25, 0x50, 0x44, 0x46, 0x2D}; // "%PDF-"
            const std::vector<unsigned char> pdfFooter = {0x25, 0x25, 0x45, 0x4F, 0x46}; // "%%EOF"

            int carvedCount = 0;
            size_t i = 0;

            // Funzione Lambda anonima per il confronto balistico delle sequenze in RAM
            auto matchSequence = [&](size_t idx, const std::vector<unsigned char>& seq) {
                if (idx + seq.size() > buffer.size()) return false;
                for (size_t j = 0; j < seq.size(); ++j) {
                    if (buffer[idx + j] != seq[j]) return false;
                }
                return true;
            };

            // 2. DISSEZIONE VETTORIALE E DATA CARVING
            while (i < buffer.size()) {
                
                // [A] Intercettazione Anomalia Strutturale: JPEG
                if (matchSequence(i, jpgHeader)) {
                    std::cout << " [*] Trovata anomalia (Header JPEG) all'offset vettoriale: 0x" << std::hex << i << std::dec << std::endl;
                    
                    size_t endIdx = i + 2; // Avanza oltre il primo FF D8
                    int depth = 1;         // Inizializza il bilanciamento tensoriale
                    
                    while (endIdx < buffer.size() - 1 && depth > 0) {
                        if (buffer[endIdx] == 0xFF && buffer[endIdx+1] == 0xD8) {
                            depth++; // Trovato un sub-header (es. EXIF Thumbnail)
                            endIdx += 2;
                        } else if (buffer[endIdx] == 0xFF && buffer[endIdx+1] == 0xD9) {
                            depth--; // Trovato un sub-footer
                            if (depth == 0) break; // Singolarità raggiunta: vero End-Of-Image
                            endIdx += 2;
                        } else {
                            endIdx++;
                        }
                    }
                    
                    if (depth == 0 && endIdx < buffer.size() - 1) {
                        endIdx += 2; // Includi i due byte finali FF D9
                        std::string outName = "carved_artifact_" + std::to_string(++carvedCount) + ".jpg";
                        std::ofstream out(outName, std::ios::binary);
                        out.write(reinterpret_cast<char*>(&buffer[i]), endIdx - i);
                        std::cout << "  -> File intatto isolato ed estratto: " << outName << " (Massa: " << (endIdx - i) << " bytes)" << std::endl;
                        i = endIdx; continue; // Salta il segmento già processato
                    } else {
                        std::cout << "  -> [WARN] Footer JPEG mancante o sbilanciato (File troncato). Estrazione saltata." << std::endl;
                    }
                }
                
                // [B] Intercettazione Anomalia Strutturale: PNG
                else if (matchSequence(i, pngHeader)) {
                    std::cout << " [*] Trovata anomalia (Header PNG) all'offset vettoriale: 0x" << std::hex << i << std::dec << std::endl;
                    size_t endIdx = i + pngHeader.size();
                    while (endIdx < buffer.size() && !matchSequence(endIdx, pngFooter)) endIdx++;
                    
                    if (endIdx < buffer.size()) {
                        endIdx += pngFooter.size();
                        std::string outName = "carved_artifact_" + std::to_string(++carvedCount) + ".png";
                        std::ofstream out(outName, std::ios::binary);
                        out.write(reinterpret_cast<char*>(&buffer[i]), endIdx - i);
                        std::cout << "  -> File intatto isolato ed estratto: " << outName << " (Massa: " << (endIdx - i) << " bytes)" << std::endl;
                        i = endIdx; continue;
                    } else {
                        std::cout << "  -> [WARN] Footer PNG mancante (File troncato a fine dump). Estrazione saltata." << std::endl;
                    }
                }
                
                // [C] Intercettazione Anomalia Strutturale: PDF
                else if (matchSequence(i, pdfHeader)) {
                    std::cout << " [*] Trovata anomalia (Header PDF) all'offset vettoriale: 0x" << std::hex << i << std::dec << std::endl;
                    size_t endIdx = i + pdfHeader.size();
                    while (endIdx < buffer.size() && !matchSequence(endIdx, pdfFooter)) endIdx++;
                    
                    if (endIdx < buffer.size()) {
                        endIdx += pdfFooter.size(); 
                        // Assorbimento di eventuali newline terminali ereditati dall'EOF
                        while(endIdx < buffer.size() && (buffer[endIdx] == '\n' || buffer[endIdx] == '\r')) endIdx++;
                        
                        std::string outName = "carved_artifact_" + std::to_string(++carvedCount) + ".pdf";
                        std::ofstream out(outName, std::ios::binary);
                        out.write(reinterpret_cast<char*>(&buffer[i]), endIdx - i);
                        std::cout << "  -> Documento intatto isolato ed estratto: " << outName << " (Massa: " << (endIdx - i) << " bytes)" << std::endl;
                        i = endIdx; continue;
                    } else {
                        std::cout << "  -> [WARN] Footer PDF mancante (Documento troncato a fine dump). Estrazione saltata." << std::endl;
                    }
                }
                i++; // Avanzamento brutale byte per byte se nessuna firma corrisponde
            }

            // 3. REPORTISTICA FORENSE TERMINALE
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] OPERAZIONE DI ESTRAZIONE MAGIC BYTES COMPLETATA" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << " Bytes Analizzati   : " << buffer.size() << std::endl;
            std::cout << " File Estratti (RAW): " << carvedCount << std::endl;
            if (carvedCount == 0) {
                std::cout << "[STATO] Nessuna firma esadecimale (JPEG/PNG/PDF) rilevata all'interno del tensore." << std::endl;
            } else {
                std::cout << "[STATO] Gli artefatti sono stati materializzati fisicamente nella root directory." << std::endl;
            }
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