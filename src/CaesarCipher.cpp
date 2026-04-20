#include "../include/CaesarCipher.h"
#include <cctype>

CaesarCipher::CaesarCipher(int k) : shift(k % 26) {}

std::string CaesarCipher::getName() const { 
    return "Caesar Cipher (Shift " + std::to_string(shift) + ")"; 
}

std::string CaesarCipher::encrypt(const std::string& p) const {
    std::string res = "";
    for (char c : p) {
        if (std::isalpha(c)) {
            char b = std::isupper(c) ? 'A' : 'a';
            res += (char)((c - b + shift) % 26 + b);
        } else res += c;
    }
    return res;
}

std::string CaesarCipher::decrypt(const std::string& c) const {
    std::string res = "";
    int inv = 26 - shift;
    for (char ch : c) {
        if (std::isalpha(ch)) {
            char b = std::isupper(ch) ? 'A' : 'a';
            res += (char)((ch - b + inv) % 26 + b);
        } else res += ch;
    }
    return res;
}