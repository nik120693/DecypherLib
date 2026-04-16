#ifndef KASISKI_ENGINE_H
#define KASISKI_ENGINE_H

#include <string>
#include <vector>

class KasiskiEngine {
private:
    // Frequenze statiche dell'alfabeto inglese
    static const double englishFreqs[26];

    // Pulisce il testo (solo A-Z maiuscole)
    std::string cleanText(const std::string& text) const;

    // Calcola l'Indice di Coincidenza (IoC) per dedurre la lunghezza della chiave
    double calculateIoC(const std::string& text) const;

    // Estrae un "coseto" (es. ogni n-esima lettera del testo)
    std::string getCoset(const std::string& text, int keyLength, int offset) const;

    // Applica il test statistico Chi-Quadro per indovinare la singola lettera della chiave
    char guessKeyLetter(const std::string& coset) const;

public:
    KasiskiEngine() = default;

    // Tenta di indovinare l'esatta chiave di Vigenere usata per cifrare il testo
    std::string extractVigenereKey(const std::string& ciphertext) const;
};

#endif // KASISKI_ENGINE_H