#include "../include/ActionHandlers.h"
#include "../include/CoreUtils.h"
#include "../include/RSACipher.h"
#include "../include/ECCipher.h"
#include "../include/LWECipher.h"
#include <iostream>
#include <limits>
#include <string>

void handleRSA(const std::string& rawTarget) {
    std::cout << "\n[EXEC] Inizializzazione Modulo RSA (Asimmetrico)..." << std::endl;
    
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    std::string p_str, q_str, e_str;
    std::cout << " [?] Inserisci il Primo P (es. 61) o premi INVIO per i parametri default: ";
    std::getline(std::cin, p_str);
    
    if (p_str.empty()) {
        p_str = "61"; q_str = "53"; e_str = "17";
        std::cout << " [!] Parametri Test iniettati: P=" << p_str << ", Q=" << q_str << ", E=" << e_str << std::endl;
    } else {
        std::cout << " [?] Inserisci il Primo Q: ";
        std::getline(std::cin, q_str);
        std::cout << " [?] Inserisci l'Esponente E: ";
        std::getline(std::cin, e_str);
    }

    std::cout << "\n SELEZIONA OPERAZIONE RSA:" << std::endl;
    std::cout << " [1] Cifra un payload (Genera array numerico)" << std::endl;
    std::cout << " [2] Decifra il target in ciphertext.txt" << std::endl;
    std::cout << " > ";
    int rsaOp;
    std::cin >> rsaOp;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    try { 
        RSACipher rsa(p_str, q_str, e_str);
        
        if (rsaOp == 1) {
            std::cout << "\n [?] Inserisci il testo in chiaro: ";
            std::string plaintext;
            std::getline(std::cin, plaintext);
            
            std::string ciphered = rsa.encrypt(plaintext);
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] VETTORE CIFRATO RSA GENERATO" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << ciphered << std::endl;
            std::cout << "(Copia questo blocco numerico in ciphertext.txt per testare l'inversione)" << std::endl;
            
        } else if (rsaOp == 2) {
            std::cout << "[SYSTEM] Inversione modulare (M = C^d mod N) in corso..." << std::endl;
            std::string out = rsa.decrypt(rawTarget);
            
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] SINGOLARITA' RSA RAGGIUNTA" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << " PAYLOAD ESTRATTO : " << out << std::endl;
        } else {
            std::cout << "[ERR] Operazione annullata. Selezione non valida." << std::endl;
        }
    } 
    catch (const std::exception& e) { 
        std::cout << "[ERR] Crash RSA: " << e.what() << std::endl; 
    }
    catch (...) { 
        std::cout << "[ERR] Disallineamento matematico. Formato del ciphertext non supportato (Richiesti interi separati da spazio)." << std::endl; 
    }
}

void handleECC(const std::string& rawTarget) {
    std::cout << "\n[EXEC] Inizializzazione Modulo ECC ElGamal (Curva Ellittica)..." << std::endl;
    
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    
    std::string p_str, a_str, b_str, gx_str, gy_str, priv_str;
    std::cout << " [?] Inserisci il Primo P del campo finito (es. 467) o premi INVIO per default: ";
    std::getline(std::cin, p_str);
    
    if (p_str.empty()) {
        p_str = "467"; a_str = "2"; b_str = "3"; gx_str = "3"; gy_str = "6"; priv_str = "15";
        std::cout << " [!] Parametri Test: y^2 = x^3 + " << a_str << "x + " << b_str << " mod " << p_str << std::endl;
        std::cout << " [!] Generatore G=(" << gx_str << "," << gy_str << ") | Chiave Privata d=" << priv_str << std::endl;
    } else {
        std::cout << " [?] Inserisci coefficiente 'a': "; std::getline(std::cin, a_str);
        std::cout << " [?] Inserisci coefficiente 'b': "; std::getline(std::cin, b_str);
        std::cout << " [?] Inserisci coordinata Gx del Generatore: "; std::getline(std::cin, gx_str);
        std::cout << " [?] Inserisci coordinata Gy del Generatore: "; std::getline(std::cin, gy_str);
        std::cout << " [?] Inserisci Chiave Privata 'd': "; std::getline(std::cin, priv_str);
    }

    std::cout << "\n SELEZIONA OPERAZIONE ECC:" << std::endl;
    std::cout << " [1] Cifra un payload (Genera matrici di punti C1, C2)" << std::endl;
    std::cout << " [2] Decifra il target geometrico in ciphertext.txt" << std::endl;
    std::cout << " > ";
    int eccOp;
    std::cin >> eccOp;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    try { 
        ECCipher ecc(p_str, a_str, b_str, gx_str, gy_str, priv_str);
        
        if (eccOp == 1) {
            std::cout << "\n [?] Inserisci il testo in chiaro da mappare sulla curva: ";
            std::string plaintext;
            std::getline(std::cin, plaintext);
            
            std::string ciphered = ecc.encrypt(plaintext);
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] PUNTI ELLITTICI GENERATI CON SUCCESSO" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << ciphered << std::endl;
            std::cout << "(Copia queste coordinate in ciphertext.txt per testare l'inversione)" << std::endl;
            
        } else if (eccOp == 2) {
            std::cout << "[SYSTEM] Moltiplicazione scalare inversa su Curva Ellittica in corso..." << std::endl;
            std::string out = ecc.decrypt(rawTarget);
            
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] SINGOLARITA' ECC RAGGIUNTA" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << " PAYLOAD ESTRATTO : " << out << std::endl;
        } else {
            std::cout << "[ERR] Operazione annullata. Selezione fuori range." << std::endl;
        }
    } 
    catch (const std::exception& e) { 
        std::cout << "[ERR] Crash ECC controllato: " << e.what() << std::endl; 
    }
    catch (...) { 
        std::cout << "[ERR] Disallineamento matematico. Formato del ciphertext incompatibile con la topologia della curva." << std::endl; 
    }
}

void handleLWE(const std::string& rawTarget) {
    std::cout << "\n[EXEC] Inizializzazione Modulo LWE Lattice (Post-Quantum Crypto)..." << std::endl;
    std::cout << "[SYSTEM] Algoritmo di Regev attivato. Generazione del reticolo spaziale in corso..." << std::endl;
    
    std::cout << "\n SELEZIONA OPERAZIONE LWE:\n [1] Cifra un payload (Genera Vettori Rumorosi in Zq)\n [2] Decifra il target in ciphertext.txt\n > ";
    int op; 
    std::cin >> op; 
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

    try {
        LWECipher lwe(42, 8, 16, 251); 
        if (op == 1) {
            std::cout << " [?] Inserisci il testo in chiaro da proiettare nel reticolo: ";
            std::string pt; 
            std::getline(std::cin, pt);
            
            std::string cypher = lwe.encrypt(pt);
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] SINGOLARITA' QUANTISTICA: VETTORI LWE GENERATI CON SUCCESSO" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << cypher << std::endl;
            std::cout << "\n(Usa 'echo \"<output>\" > ciphertext.txt' per testare l'inversione NP-Hard)" << std::endl;
            
        } else if (op == 2) {
            std::cout << "[SYSTEM] Calcolo della distanza vettoriale (Learning With Errors) in corso...\n";
            std::string dec = lwe.decrypt(rawTarget);
            
            std::cout << "\n======================================================================" << std::endl;
            std::cout << " [!] VETTORE QUANTISTICO COLLASSATO" << std::endl;
            std::cout << "======================================================================" << std::endl;
            std::cout << " PAYLOAD ESTRATTO : " << dec << std::endl;
        }
    } catch(const std::exception& e) { 
        std::cout << "[ERR] Disallineamento dimensionale nel reticolo: " << e.what() << "\n"; 
    }
}
