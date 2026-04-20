#ifndef KASISKI_ENGINE_H
#define KASISKI_ENGINE_H

#include <string>
#include <vector>

class KasiskiEngine {
public:
    /**
     * @brief Identifica la lunghezza probabile della chiave (periodo) 
     * utilizzando l'analisi di Kasiski e l'Indice di Coincidenza.
     */
    int findKeyLength(const std::string& ciphertext);

    /**
     * @brief Calcola l'Indice di Coincidenza (IC) per una data stringa.
     * Valore target per l'inglese: ~0.0667.
     */
    double calculateIC(const std::string& text);
};

#endif