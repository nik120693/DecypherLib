#include "../include/ActionHandlers.h"
#include "../include/CoreUtils.h"
#include "../include/CaesarCipher.h"
#include "../include/AtbashCipher.h"
#include "../include/VigenereCipher.h"
#include "../include/RailFenceCipher.h"
#include "../include/AffineCipher.h"
#include "../include/BeaufortCipher.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <fstream>
#include <iomanip>
#include <unordered_set>
#include <numeric>

void handleCaesar(const std::string& rawTarget, StatisticalAnalyzer& sa) {
    std::cout << "\n[EXEC] Lancio Caesar Cipher..." << std::endl;
    for (int i = 1; i <= 25; ++i) {
        CaesarCipher cc(i);
        std::string p = cc.decrypt(rawTarget);
        double fit = sa.calculateMultiAnchorFitness(p);
        if (fit > 0.0) updateTopResults({"Shift " + std::to_string(i), p, fit});
    }
    printTopResults(sa);
}

void handleAtbash(const std::string& rawTarget, StatisticalAnalyzer& sa) {
    std::cout << "\n[EXEC] Lancio Atbash Cipher..." << std::endl;
    AtbashCipher ac;
    std::string p = ac.decrypt(rawTarget);
    double fit = sa.calculateMultiAnchorFitness(p);
    if (fit > 0.0) updateTopResults({"N/A", p, fit});
    printTopResults(sa);
}

void handleVigenere(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa, KasiskiEngine& ke) {
    std::cout << "\n[EXEC] Inizializzazione Assedio Vigenere Dinamico..." << std::endl;
    
    std::string cleanTarget = alphaTarget; // Usa alphaTarget passato

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
                uniqueKeys.insert(bKey); // Inserimento nel set
                
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
}

void handleRailFence(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa) {
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
}

void handleAffine(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa) {
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
            return;
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
}

void handleBeaufort(const std::string& rawTarget, const std::string& alphaTarget, StatisticalAnalyzer& sa) {
    std::cout << "\n[EXEC] Lancio Beaufort Cipher (Dictionary)..." << std::endl;
    std::ifstream dFile("lexicon.txt");
    std::string w;
    while (dFile >> w) {
        if (w.length() >= 3 && w.length() <= 10) {
            for(auto & ch : w) ch = std::toupper(ch);
            BeaufortCipher bc(w);
            // Uso rawTarget per mantenere gli spazi se presenti
            std::string p = bc.decrypt(rawTarget);
            double fit = sa.calculateMultiAnchorFitness(p);
            if (fit > 0.0) updateTopResults({w, p, fit});
        }
    }
    printTopResults(sa);
}
