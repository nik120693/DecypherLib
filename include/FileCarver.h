#ifndef FILE_CARVER_H
#define FILE_CARVER_H

#include <string>

class FileCarver {
public:
    // Analizza i primi 4 byte per rilevare Magic Numbers
    static std::string detectSignature(const std::string& rawData);
    
    // Scrive un flusso di byte crudi direttamente su disco
    static void dumpToFile(const std::string& rawData, const std::string& filename);
};

#endif // FILE_CARVER_H