#include "../include/PCAPParser.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

std::string PCAPParser::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::string PCAPParser::extractTCPPayload(const std::string& pcapFilename) {
    std::ifstream file(pcapFilename, std::ios::binary);
    if (!file.is_open()) return "";

    std::cout << "[*] PCAP Ingestion Module: Analisi del traffico di rete da " << pcapFilename << "..." << std::endl;

    // Salta l'Header Globale del file PCAP (24 byte)
    file.seekg(24, std::ios::beg);

    std::vector<uint8_t> totalPayload;

    // Struttura minima dell'Header del Pacchetto PCAP (16 byte)
    uint32_t ts_sec, ts_usec, incl_len, orig_len;

    while (file.read(reinterpret_cast<char*>(&ts_sec), 4)) {
        file.read(reinterpret_cast<char*>(&ts_usec), 4);
        file.read(reinterpret_cast<char*>(&incl_len), 4);
        file.read(reinterpret_cast<char*>(&orig_len), 4);

        if (incl_len == 0 || incl_len > 65535) break; // Prevenzione overflow

        std::vector<uint8_t> packetData(incl_len);
        file.read(reinterpret_cast<char*>(packetData.data()), incl_len);

        // --- DECAPSULAMENTO OSI ---
        // 1. ETHERNET HEADER (Fisso a 14 byte)
        if (incl_len < 14) continue; 
        uint16_t ethType = (packetData[12] << 8) | packetData[13];
        if (ethType != 0x0800) continue; // Procediamo solo se è IPv4 (0x0800)

        // 2. IPv4 HEADER (Lunghezza variabile, da estrarre)
        int ipOffset = 14;
        if (incl_len < static_cast<uint32_t>(ipOffset + 20)) continue;
        
        uint8_t ipHeaderLen = (packetData[ipOffset] & 0x0F) * 4;
        uint8_t protocol = packetData[ipOffset + 9];
        
        if (protocol != 0x06) continue; // Procediamo solo se è TCP (0x06)

        // 3. TCP HEADER (Lunghezza variabile, da estrarre)
        int tcpOffset = ipOffset + ipHeaderLen;
        if (incl_len < static_cast<uint32_t>(tcpOffset + 20)) continue;

        uint8_t tcpHeaderLen = ((packetData[tcpOffset + 12] >> 4) & 0x0F) * 4;

        // 4. ESTRAZIONE DEL PAYLOAD APPLICATIVO
        int payloadOffset = tcpOffset + tcpHeaderLen;
        int payloadLen = incl_len - payloadOffset;

        if (payloadLen > 0) {
            totalPayload.insert(totalPayload.end(), packetData.begin() + payloadOffset, packetData.end());
        }
    }

    file.close();

    if (totalPayload.empty()) {
        std::cout << "[-] Attenzione: Nessun payload TCP utile trovato nel traffico." << std::endl;
        return "";
    }

    std::cout << "[+] Estrazione Completata: " << totalPayload.size() << " byte di dati applicativi isolati." << std::endl;
    return bytesToHex(totalPayload);
}