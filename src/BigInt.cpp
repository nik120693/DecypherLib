#include "../include/BigInt.h"
#include <algorithm>
#include <vector>

void BigInt::clean() {
    size_t nonZero = value.find_first_not_of('0');
    if (nonZero != std::string::npos) {
        value = value.substr(nonZero);
    } else {
        value = "0";
    }
}

BigInt::BigInt() : value("0") {}
BigInt::BigInt(std::string val) : value(val) { clean(); }
BigInt::BigInt(unsigned long long val) : value(std::to_string(val)) {}

std::string BigInt::getValue() const { return value; }

bool BigInt::operator==(const BigInt& other) const { return value == other.value; }
bool BigInt::operator!=(const BigInt& other) const { return value != other.value; }

bool BigInt::operator<(const BigInt& other) const {
    if (value.length() != other.value.length())
        return value.length() < other.value.length();
    return value < other.value;
}

bool BigInt::operator<=(const BigInt& other) const { return (*this < other) || (*this == other); }
bool BigInt::operator>(const BigInt& other) const { return !(*this <= other); }
bool BigInt::operator>=(const BigInt& other) const { return !(*this < other); }

BigInt BigInt::operator+(const BigInt& other) const {
    std::string res = "";
    int carry = 0, i = value.length() - 1, j = other.value.length() - 1;
    while (i >= 0 || j >= 0 || carry) {
        int sum = carry;
        if (i >= 0) sum += value[i--] - '0';
        if (j >= 0) sum += other.value[j--] - '0';
        res.push_back(sum % 10 + '0');
        carry = sum / 10;
    }
    std::reverse(res.begin(), res.end());
    return BigInt(res);
}

BigInt BigInt::operator-(const BigInt& other) const {
    if (*this < other) return BigInt("0"); // Protezione negativa
    std::string res = "";
    int borrow = 0, i = value.length() - 1, j = other.value.length() - 1;
    while (i >= 0) {
        int sub = (value[i--] - '0') - borrow;
        if (j >= 0) sub -= (other.value[j--] - '0');
        if (sub < 0) { sub += 10; borrow = 1; } 
        else { borrow = 0; }
        res.push_back(sub + '0');
    }
    std::reverse(res.begin(), res.end());
    return BigInt(res);
}

BigInt BigInt::operator*(const BigInt& other) const {
    if (*this == BigInt("0") || other == BigInt("0")) return BigInt("0");
    std::vector<int> res(value.length() + other.value.length(), 0);
    for (int i = value.length() - 1; i >= 0; i--) {
        for (int j = other.value.length() - 1; j >= 0; j--) {
            int mul = (value[i] - '0') * (other.value[j] - '0');
            int sum = mul + res[i + j + 1];
            res[i + j + 1] = sum % 10;
            res[i + j] += sum / 10;
        }
    }
    std::string resultStr = "";
    for (int num : res) resultStr += std::to_string(num);
    return BigInt(resultStr);
}

BigInt BigInt::operator/(const BigInt& other) const {
    if (other == BigInt("0")) throw std::runtime_error("Division by zero");
    if (*this < other) return BigInt("0");
    BigInt res("0"), current("0");
    for (char c : value) {
        current.value += c; current.clean();
        int count = 0;
        while (current >= other) { current = current - other; count++; }
        res.value += std::to_string(count);
    }
    res.clean();
    return res;
}

BigInt BigInt::operator%(const BigInt& other) const {
    if (other == BigInt("0")) throw std::runtime_error("Modulo by zero");
    if (*this < other) return *this;
    BigInt current("0");
    for (char c : value) {
        current.value += c; current.clean();
        while (current >= other) { current = current - other; }
    }
    return current;
}

// Algoritmo Esponenziale Veloce
BigInt BigInt::modExp(BigInt exp, BigInt mod) const {
    BigInt res("1"), base = (*this) % mod, zero("0"), two("2");
    while (exp > zero) {
        if (exp % two != zero) res = (res * base) % mod;
        exp = exp / two;
        base = (base * base) % mod;
    }
    return res;
}

// Algoritmo di Euclide Esteso integrato a livello di base-10
BigInt BigInt::modInverse(const BigInt& mod) const {
    BigInt zero("0"), one("1");
    BigInt t = zero, newt = one;
    BigInt r = mod, newr = *this;
    
    while (newr > zero) {
        BigInt quotient = r / newr;
        BigInt q_newt = (quotient * newt) % mod;
        BigInt temp_t;
        
        if (t >= q_newt) temp_t = t - q_newt;
        else temp_t = mod - (q_newt - t);
        
        t = newt; newt = temp_t;
        BigInt temp_r = r - (quotient * newr);
        r = newr; newr = temp_r;
    }
    if (r > one) throw std::runtime_error("Errore: Numero non invertibile");
    return t;
}

std::ostream& operator<<(std::ostream& os, const BigInt& num) {
    os << num.value;
    return os;
}