# DecypherLib: The C++ Cryptographic Masterpiece

DecypherLib è un motore crittografico sviluppato in puro C++17, culminato nella sua Sesta e definitiva fase di ingegneria: la costruzione di un ecosistema di crittografia a **Curve Ellittiche (ECC)** supportato da un framework aritmetico a precisione arbitraria (`BigInt`).

## Nuova Architettura: Elliptic Curve Cryptography (ECC)
Il sistema processa coordinate geometriche e moltiplicazioni scalari utilizzando l'algoritmo Double-and-Add e addizioni in spazi cartesiani modulari.
* Risolve il problema del logaritmo discreto.
* Utilizza la variante ElGamal per oscurare e associare stringhe ASCII al "Segreto Condiviso" derivante dalla moltiplicazione delle chiavi.

## OMNI-DECODER (AI Heuristic Identifier)
Il cuore pulsante dell'applicativo `main.cpp` non si limita a decifrare. Agisce come un'IA di Pattern Recognition. Inserita una stringa esadecimale o un caotico blocco testuale, l'Omni-Decoder la lancia contro i 9 algoritmi conosciuti (Cesare, Vigenère, Atbash, RailFence, Affine, Beaufort, Enigma M3, RSA, ECC). Filtra il risultato nel modulo dizionario Hash-Based e **identifica automaticamente l'algoritmo matematico e il messaggio originale.**

## Costruzione
Lanciando `make test` è possibile verificare matematicamente l'integrità del motore Double-And-Add geometrico prima di lanciare il decoder in produzione. Eseguire in sequenza:
`make clean && make all && make test && make run`