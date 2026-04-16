#include "../include/TuringBombe.h"
#include "../include/EnigmaCipher.h"
#include <thread>
#include <mutex>
#include <atomic>
#include <iostream>

std::vector<std::tuple<int, int, int, std::string>> TuringBombe::crackEnigma(const std::string& ciphertext, const std::string& crib) {
    std::vector<std::tuple<int, int, int, std::string>> successfulCracks;
    std::mutex resultsMutex; // Mutex per proteggere la scrittura sul vettore dei risultati

    // Rileva il numero di core della CPU disponibili per il parallelismo
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4; // Fallback di sicurezza

    std::vector<std::thread> workers;
    
    // Variabile atomica thread-safe per distribuire il lavoro (le posizioni del rotore 1)
    std::atomic<int> currentP1(0);

    // Definizione della funzione lambda (task) che eseguirà ogni singolo thread
    auto workerTask = [&]() {
        while (true) {
            // Un thread prende in carico un valore di P1 e incrementa il contatore in modo sicuro
            int p1 = currentP1.fetch_add(1);
            
            // Se abbiamo esplorato tutti i 26 scatti del primo rotore, il thread ha finito
            if (p1 > 25) break;

            // Cicli annidati per le restanti posizioni (26 * 26 = 676 tentativi per ogni step di P1)
            for (int p2 = 0; p2 < 26; ++p2) {
                for (int p3 = 0; p3 < 26; ++p3) {
                    // Instanziamo rapidamente la macchina virtuale
                    EnigmaCipher testMachine(p1, p2, p3);
                    std::string attemptText = testMachine.decrypt(ciphertext);

                    // Verifica Euristica: Il testo decifrato contiene il "Crib" noto?
                    if (attemptText.find(crib) != std::string::npos) {
                        // Trovato! Blocchiamo la memoria con un mutex per evitare Race Conditions
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        successfulCracks.push_back(std::make_tuple(p1, p2, p3, attemptText));
                    }
                }
            }
        }
    };

    // FASE 1: Avvio asincrono dello sciame di thread
    for (unsigned int i = 0; i < numThreads; ++i) {
        workers.push_back(std::thread(workerTask));
    }

    // FASE 2: Sincronizzazione (Join). Il programma principale attende che tutti i thread finiscano il calcolo
    for (auto& t : workers) {
        if (t.joinable()) {
            t.join();
        }
    }

    return successfulCracks;
}