#include "../include/FileCarver.h"
#include <fstream>

std::string FileCarver::detectSignature(const std::string& rawData) {
    if (rawData.size() < 4) return "UNKNOWN";
    
    // Lambda per convertire i char in unsigned byte per confronti esadecimali sicuri
    auto b = [](char c) { return static_cast<unsigned char>(c); };

    // Firme Esadecimali Standard (Magic Numbers)
    if (b(rawData[0]) == 0xFF && b(rawData[1]) == 0xD8 && b(rawData[2]) == 0xFF) return "JPEG";
    if (b(rawData[0]) == 0x89 && b(rawData[1]) == 0x50 && b(rawData[2]) == 0x4E && b(rawData[3]) == 0x47) return "PNG";
    if (b(rawData[0]) == 0x50 && b(rawData[1]) == 0x4B && b(rawData[2]) == 0x03 && b(rawData[3]) == 0x04) return "ZIP";
    if (b(rawData[0]) == 0x25 && b(rawData[1]) == 0x50 && b(rawData[2]) == 0x44 && b(rawData[3]) == 0x46) return "PDF";

    return "UNKNOWN";
}

void FileCarver::dumpToFile(const std::string& rawData, const std::string& filename) {
    // ios::binary disabilita la formattazione testuale, copiando i byte puri
    std::ofstream outFile(filename, std::ios::binary);
    if (outFile) {
        outFile.write(rawData.data(), rawData.size());
        outFile.close();
    }
}