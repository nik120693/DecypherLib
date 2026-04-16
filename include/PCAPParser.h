#ifndef PCAP_PARSER_H
#define PCAP_PARSER_H

#include <string>
#include <vector>
#include <cstdint>

class PCAPParser {
private:
    // Converte un vettore di byte crudi in una stringa esadecimale continua
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);

public:
    // Legge un file .pcap, estrae i payload TCP IPv4, e ritorna una stringa Hex
    static std::string extractTCPPayload(const std::string& pcapFilename);
};

#endif // PCAP_PARSER_H