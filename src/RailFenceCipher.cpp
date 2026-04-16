#include "../include/RailFenceCipher.h"

RailFenceCipher::RailFenceCipher(int numRails) {
    // Validazione stringente: il Rail Fence non ha senso con meno di 2 binari
    this->rails = (numRails < 2) ? 2 : numRails;
}

std::string RailFenceCipher::encrypt(const std::string& plaintext) const {
    if (plaintext.empty()) return "";

    std::vector<std::string> fence(rails, "");
    int row = 0;
    bool goingDown = false;

    // Distribuzione dei caratteri sui binari
    for (char c : plaintext) {
        fence[row] += c;
        // Invertiamo la direzione quando tocchiamo il binario superiore o inferiore
        if (row == 0 || row == rails - 1) {
            goingDown = !goingDown;
        }
        row += goingDown ? 1 : -1;
    }

    // Ricostruzione della stringa cifrata leggendo i binari orizzontalmente
    std::string result = "";
    for (const std::string& rail : fence) {
        result += rail;
    }
    return result;
}

std::string RailFenceCipher::decrypt(const std::string& ciphertext) const {
    if (ciphertext.empty()) return "";

    int length = ciphertext.length();
    // Creiamo una matrice booleana per tracciare dove andranno inseriti i caratteri
    std::vector<std::vector<bool>> marker(rails, std::vector<bool>(length, false));
    
    int row = 0;
    bool goingDown = false;

    // Passo 1: "Disegniamo" il pattern a zig-zag segnando le posizioni con 'true'
    for (int i = 0; i < length; ++i) {
        marker[row][i] = true;
        if (row == 0 || row == rails - 1) {
            goingDown = !goingDown;
        }
        row += goingDown ? 1 : -1;
    }

    // Passo 2: Riempiamo la matrice riga per riga con i caratteri cifrati
    std::vector<std::string> fence(rails, std::string(length, '\n'));
    int index = 0;
    for (int i = 0; i < rails; ++i) {
        for (int j = 0; j < length; ++j) {
            if (marker[i][j] && index < length) {
                fence[i][j] = ciphertext[index++];
            }
        }
    }

    // Passo 3: Leggiamo a zig-zag per recuperare il testo in chiaro
    std::string result = "";
    row = 0;
    goingDown = false;
    for (int i = 0; i < length; ++i) {
        result += fence[row][i];
        if (row == 0 || row == rails - 1) {
            goingDown = !goingDown;
        }
        row += goingDown ? 1 : -1;
    }

    return result;
}

std::string RailFenceCipher::getName() const {
    return "Rail Fence Cipher";
}