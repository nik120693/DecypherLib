#ifndef DICTIONARY_H
#define DICTIONARY_H

#include <string>
#include <unordered_set>
#include <vector>

class Dictionary {
private:
    std::unordered_set<std::string> validWords;

    // Metodi privati di utility per la normalizzazione del testo
    std::string toLower(const std::string& str) const;
    std::vector<std::string> tokenize(const std::string& text) const;

public:
    // Costruttore: accetta il percorso del file dizionario
    explicit Dictionary(const std::string& filepath);

    // Ritorna il numero di parole valide contenute nel testo passato
    int scoreText(const std::string& text) const;

    // Verifica se il dizionario è stato caricato correttamente
    bool isLoaded() const;
};

#endif // DICTIONARY_H