#include "../include/ActionHandlers.h"
#include "../include/CoreUtils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <limits>
#include <algorithm>

void handlePCAP() {
    std::cout << "\n[EXEC] Inizializzazione Network Forensics Parser (Compatibilita' PCAPNG)..." << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string filename;
    std::cout << " [?] Inserisci il nome del file di cattura (es. target.pcapng) o premi INVIO per default: ";
    std::getline(std::cin, filename);
    if(filename.empty()) filename = "target.pcapng";

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cout << "[ERR] Disallineamento filesystem: Impossibile aprire '" << filename << "'." << std::endl;
        return;
    }

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
        return;
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

    if (isPcap) {
        file.seekg(24, std::ios::beg);
        while (file) {
            uint32_t pcapHdr[4]; 
            file.read(reinterpret_cast<char*>(pcapHdr), 16);
            if (!file) break; 
            
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
            
            file.read(reinterpret_cast<char*>(&blockType), 4);
            if (!file) break; 
            file.read(reinterpret_cast<char*>(&blockTotLength), 4);
            if (!file || blockTotLength < 12) break; 
            
            uint32_t bodyLen = blockTotLength - 12; 
            std::vector<char> blockBody(bodyLen);
            file.read(blockBody.data(), bodyLen);
            
            uint32_t trailingLen = 0;
            file.read(reinterpret_cast<char*>(&trailingLen), 4);

            if (blockType == 6) { 
                packetCount++;
                if (bodyLen >= 20) {
                    uint32_t capLen = *reinterpret_cast<uint32_t*>(&blockBody[12]);
                    uint32_t dataOffset = 20;
                    
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
}

void handleFileCarver() {
    std::cout << "\n[EXEC] Inizializzazione File Carver Forense (Ricerca Firme Esadecimali)..." << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::string filename;
    std::cout << " [?] Inserisci il nome del file binario/dump da analizzare (es. dump.raw) o premi INVIO per 'ciphertext.txt': ";
    std::getline(std::cin, filename);
    if(filename.empty()) filename = "ciphertext.txt";

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        std::cout << "[ERR] Disallineamento filesystem: Impossibile aprire '" << filename << "'." << std::endl;
        return;
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::cout << "[SYSTEM] Allocazione buffer tensoriale per " << size << " bytes continui..." << std::endl;

    std::vector<unsigned char> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        std::cout << "[STATO] Lettura RAW completata. Innesco scansione lineare profonda su matrice contigua..." << std::endl;
    } else {
        std::cout << "[ERR] Fallimento irreversibile di lettura RAW. Allocazione abortita." << std::endl;
        return;
    }

    const std::vector<unsigned char> jpgHeader = {0xFF, 0xD8, 0xFF};
    const std::vector<unsigned char> jpgFooter = {0xFF, 0xD9};
    const std::vector<unsigned char> pngHeader = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    const std::vector<unsigned char> pngFooter = {0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82};
    const std::vector<unsigned char> pdfHeader = {0x25, 0x50, 0x44, 0x46, 0x2D}; 
    const std::vector<unsigned char> pdfFooter = {0x25, 0x25, 0x45, 0x4F, 0x46}; 

    int carvedCount = 0;
    size_t i = 0;

    auto matchSequence = [&](size_t idx, const std::vector<unsigned char>& seq) {
        if (idx + seq.size() > buffer.size()) return false;
        for (size_t j = 0; j < seq.size(); ++j) {
            if (buffer[idx + j] != seq[j]) return false;
        }
        return true;
    };

    while (i < buffer.size()) {
        if (matchSequence(i, jpgHeader)) {
            std::cout << " [*] Trovata anomalia (Header JPEG) all'offset vettoriale: 0x" << std::hex << i << std::dec << std::endl;
            
            size_t endIdx = i + 2; 
            int depth = 1;         
            
            while (endIdx < buffer.size() - 1 && depth > 0) {
                if (buffer[endIdx] == 0xFF && buffer[endIdx+1] == 0xD8) {
                    depth++; 
                    endIdx += 2;
                } else if (buffer[endIdx] == 0xFF && buffer[endIdx+1] == 0xD9) {
                    depth--; 
                    if (depth == 0) break; 
                    endIdx += 2;
                } else {
                    endIdx++;
                }
            }
            
            if (depth == 0 && endIdx < buffer.size() - 1) {
                endIdx += 2; 
                std::string outName = "carved_artifact_" + std::to_string(++carvedCount) + ".jpg";
                std::ofstream out(outName, std::ios::binary);
                out.write(reinterpret_cast<char*>(&buffer[i]), endIdx - i);
                std::cout << "  -> File intatto isolato ed estratto: " << outName << " (Massa: " << (endIdx - i) << " bytes)" << std::endl;
                i = endIdx; continue; 
            } else {
                std::cout << "  -> [WARN] Footer JPEG mancante o sbilanciato (File troncato). Estrazione saltata." << std::endl;
            }
        }
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
        else if (matchSequence(i, pdfHeader)) {
            std::cout << " [*] Trovata anomalia (Header PDF) all'offset vettoriale: 0x" << std::hex << i << std::dec << std::endl;
            size_t endIdx = i + pdfHeader.size();
            while (endIdx < buffer.size() && !matchSequence(endIdx, pdfFooter)) endIdx++;
            
            if (endIdx < buffer.size()) {
                endIdx += pdfFooter.size(); 
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
        i++; 
    }

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
}
