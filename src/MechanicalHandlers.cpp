#include "../include/ActionHandlers.h"
#include "../include/CoreUtils.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>

void handleEnigma(const std::string& rawTarget, const std::string& alphaTarget) {
    std::cout << "\n[EXEC] Inizializzazione Emulatore Enigma M3..." << std::endl;
    
    std::string cleanTarget = alphaTarget;

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
}

void handleTuringBombe(const std::string& rawTarget, const std::string& alphaTarget) {
    std::cout << "\n[EXEC] Inizializzazione Turing Bombe (Multi-Thread KPA)..." << std::endl;
    
    std::string cleanTarget = alphaTarget;

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
}
