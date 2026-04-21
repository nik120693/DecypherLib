#include "../include/ActionHandlers.h"
#include "../include/CoreUtils.h"
#include "../include/AESCipher.h"
#include "../include/KeyDerivation.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <unordered_set>
#include <cstring>
#include <limits>

void handleAES(const std::string& rawTarget, StatisticalAnalyzer& sa) {
    std::cout << "\n[EXEC] Inizializzazione Assedio Multi-Thread su AES-256..." << std::endl;
    
    // 1. SANITIZZAZIONE DEL TARGET
    std::string hexTarget = "";
    for (char c : rawTarget) {
        if (std::isxdigit(c)) hexTarget += c;
    }
    if (hexTarget.empty() || hexTarget.length() % 2 != 0) {
        std::cout << "[ERR] Il ciphertext non contiene un esadecimale valido o e' dispari." << std::endl;
        return;
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
                if (breachConfirmed) break;
                
                int current = ++processedWords;
                if (current % 1000 == 0) {
                    std::lock_guard<std::mutex> lock(coutMutex);
                    std::cout << "\r[*] Testate " << current << " / " << aesCandidates.size() 
                              << " password..." << std::flush;
                }
                
                std::string derivedKey = KeyDerivation::stretchKey(aesCandidates[i], salt, 1);
                AESCipher aes(derivedKey);
                
                try {
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
}

void handleSHA256(const std::string& /*rawTarget*/) {
    std::cout << "\n[EXEC] Inizializzazione Motore di Hashing SHA-256..." << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string filename;
    std::cout << " [?] Inserisci il file per estrarre l'impronta digitale (es. dump.raw) o INVIO per 'ciphertext.txt': ";
    std::getline(std::cin, filename);
    if(filename.empty()) filename = "ciphertext.txt";

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cout << "[ERR] Fallimento I/O: Impossibile accedere al tensore '" << filename << "'." << std::endl;
        return;
    }

    // KERNEL SHA-256 STANDALONE
    struct LocalSHA256 {
        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        uint64_t bitlen = 0;
        uint8_t data[64];
        uint32_t datalen = 0;

        uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
        uint32_t choose(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
        uint32_t majority(uint32_t a, uint32_t b, uint32_t c) { return (a & (b | c)) | (b & c); }
        uint32_t sig0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
        uint32_t sig1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
        uint32_t ep0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
        uint32_t ep1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

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
    
    while (file.read(buffer, sizeof(buffer))) {
        sha.update(reinterpret_cast<uint8_t*>(buffer), file.gcount());
        totalBytes += file.gcount();
    }
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
}
