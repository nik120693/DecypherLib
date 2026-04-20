# DecypherLib: Omni-Decoder & Cryptanalysis Suite

DecypherLib è una suite software modulare ad altissime prestazioni scritta in C++17, progettata per l'analisi forense, la crittanalisi statistica e l'ingegneria inversa dei cifrari. Sviluppato per operare sia su cifrari storici che su moderne primitive crittografiche, il sistema integra algoritmi di Machine Learning probabilistico (Viterbi), analisi spettrale (Indice di Coincidenza) e calcolo asimmetrico post-quantistico.

## 🚀 Caratteristiche Architetturali

Il sistema è orchestrato da una Command Line Interface (CLI) interattiva che espone cinque macro-moduli operativi:

1. **Crittanalisi Classica Estesa**: Attacco simultaneo multithread tramite Forza Bruta e Dictionary Attack su Caesar, Atbash, Vigenère, Affine, Beaufort e Rail Fence.
2. **Crittanalisi Meccanica (WWII)**: Emulazione di rotori Enigma e implementazione della Bomba di Turing per attacchi Known-Plaintext (Crib).
3. **Sicurezza Moderna**: Decrittazione simmetrica AES-256 (con Key Derivation PBKDF2 simulata) ed estrazione di impronte hash SHA-256.
4. **Forensica Asimmetrica & Post-Quantum**: Manipolazione di grandi interi per RSA, decrittazione su Curva Ellittica (ECC ElGamal) ed emulazione crittografica LWE (Learning With Errors) basata su reticoli.
5. **Data Extraction**: Parsing a basso livello di file PCAP (Network Forensics) e File Carving binario tramite Magic Numbers.

## 🛠️ Compilazione ed Esecuzione

Il progetto utilizza un Makefile ottimizzato per sistemi UNIX-like (Linux/macOS) con flag di massima ottimizzazione (`-O3`) e supporto al multithreading POSIX (`-pthread`).

```bash
# Compilazione totale e build dei test
make clean && make all && make test

# Esecuzione della suite interattiva
make run