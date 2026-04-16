#ifndef BIGINT_H
#define BIGINT_H

#include <string>
#include <iostream>
#include <stdexcept>

class BigInt {
private:
    std::string value;
    void clean();

public:
    BigInt();
    BigInt(std::string val);
    BigInt(unsigned long long val);

    std::string getValue() const;

    bool operator==(const BigInt& other) const;
    bool operator!=(const BigInt& other) const;
    bool operator<(const BigInt& other) const;
    bool operator<=(const BigInt& other) const;
    bool operator>(const BigInt& other) const;
    bool operator>=(const BigInt& other) const;

    BigInt operator+(const BigInt& other) const;
    BigInt operator-(const BigInt& other) const; 
    BigInt operator*(const BigInt& other) const;
    BigInt operator/(const BigInt& other) const;
    BigInt operator%(const BigInt& other) const;

    // Nuove funzioni modulari avanzate centralizzate nel motore matematico
    BigInt modExp(BigInt exp, BigInt mod) const;
    BigInt modInverse(const BigInt& mod) const;

    friend std::ostream& operator<<(std::ostream& os, const BigInt& num);
};

#endif // BIGINT_H