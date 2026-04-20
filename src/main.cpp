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