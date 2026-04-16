#include "../include/SHA256.h"
#include <iomanip>
#include <sstream>

const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256::SHA256() {
    // Lasciato vuoto intenzionalmente. L'inizializzazione ora avviene ad ogni chiamata hash()
}

uint32_t SHA256::rotr(uint32_t n, uint32_t x) const { return (x >> n) | (x << (32 - n)); }
uint32_t SHA256::shr(uint32_t n, uint32_t x) const { return (x >> n); }
uint32_t SHA256::ch(uint32_t x, uint32_t y, uint32_t z) const { return (x & y) ^ (~x & z); }
uint32_t SHA256::maj(uint32_t x, uint32_t y, uint32_t z) const { return (x & y) ^ (x & z) ^ (y & z); }
uint32_t SHA256::sigma0(uint32_t x) const { return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x); }
uint32_t SHA256::sigma1(uint32_t x) const { return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x); }
uint32_t SHA256::Gamma0(uint32_t x) const { return rotr(7, x) ^ rotr(18, x) ^ shr(3, x); }
uint32_t SHA256::Gamma1(uint32_t x) const { return rotr(17, x) ^ rotr(19, x) ^ shr(10, x); }

void SHA256::processChunk(const std::vector<uint8_t>& chunk) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (chunk[i*4] << 24) | (chunk[i*4+1] << 16) | (chunk[i*4+2] << 8) | (chunk[i*4+3]);
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = Gamma1(w[i-2]) + w[i-7] + Gamma0(w[i-15]) + w[i-16];
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], _h = h[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = _h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
        _h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += _h;
}

std::string SHA256::hash(const std::string& input) {
    // RESET DELLO STATO: Essenziale per poter riutilizzare lo stesso oggetto per più hash!
    h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
    h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;

    std::vector<uint8_t> data(input.begin(), input.end());
    uint64_t bitLength = data.size() * 8;

    data.push_back(0x80);

    while ((data.size() % 64) != 56) {
        data.push_back(0x00);
    }

    for (int i = 7; i >= 0; --i) {
        data.push_back((bitLength >> (i * 8)) & 0xFF);
    }

    for (size_t i = 0; i < data.size(); i += 64) {
        std::vector<uint8_t> chunk(data.begin() + i, data.begin() + i + 64);
        processChunk(chunk);
    }

    std::stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << std::setfill('0') << std::setw(8) << h[i];
    }
    return ss.str();
}