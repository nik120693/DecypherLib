# User Manual: DecypherLib Omni-Decoder

This document illustrates in detail how each of the **15 attack vectors** provided by the DecypherLib interactive suite works.

To start the suite, type in the terminal:
```bash
make run
```
The program will load data from the `ciphertext.txt` file (if required by the selected module) and will perform a quick *heuristic profiling* of the file to give you a diagnostic suggestion on which algorithm to use. After that, you will be presented with the main menu.

---

## Module 1: Classical Cryptanalysis

These algorithms historically operate on text alphabets and logical substitutions.

### [1] Caesar Cipher (Shift 1-25 Scan)
*   **Behavior:** Executes an exhaustive brute force attack on all 25 possible shifts of the Caesar Cipher.
*   **How to use:** Just select option `1`. The system will take the content of `ciphertext.txt`, apply every possible rotation, calculate the linguistic fitness score (via the Statistical Analyzer) and show you the top 5 most coherent decodings. *Spaces and punctuation from the original text are preserved.*

### [2] Atbash Cipher
*   **Behavior:** The Atbash Cipher is a simple mirrored alphabet substitution (A becomes Z, B becomes Y, etc.).
*   **How to use:** Select option `2`. Since there is only one possible key, the system will apply it and immediately return the result with its corresponding fitness score.

### [3] Vigenère Cipher (Dynamic Omni-Sweep Brute + Dict)
*   **Behavior:** A ruthless attack on the Vigenère polyalphabetic cipher. It initially uses the *Kasiski Test* and the Index of Coincidence (IC) to guess the probable key length.
*   **How to use:** Type `3`. The engine will automatically extract all words of the estimated length from the dictionary file (`book.txt`) and, simultaneously, generate all possible combinations of short keys (up to 4 characters). It will then launch a massive Multi-Threaded attack, calculating the fitness of each candidate and returning the absolute winner.

### [4] Rail Fence Cipher (Depth 2-15 Scan)
*   **Behavior:** Deciphers the "Rail Fence" zigzag transposition algorithm by testing depths (number of rails) between 2 and 15.
*   **How to use:** Type `4`. The engine will attempt decoding for every single depth. It will show real-time analysis telemetry, discarding rails that produce noise (negative fitness) and saving only those that form logical words, presenting you with the best one.

### [5] Affine Cipher (A Coprimes, Shift B Scan)
*   **Behavior:** The Affine cipher uses the mathematical function `E(x) = (ax + b) mod 26`.
*   **How to use:** Type `5`. You will be presented with a sub-menu:
    *   `[1] Omni-Sweep`: Automatically tests all valid values for A (the 12 numbers coprime to 26) and all 26 values for B.
    *   `[2] Parametric Injection`: If you already know the mathematical key, you can manually type the values of A and B to decrypt the output.

### [6] Beaufort Cipher (Dictionary Attack)
*   **Behavior:** Similar to Vigenère but uses a reversed variant of the alphabet. 
*   **How to use:** Type `6`. This module performs a "Dictionary Attack". It will load the `lexicon.txt` vocabulary testing every single existing word as a potential encryption key, ultimately returning the best scores.

---

## Module 2: Mechanical Cryptanalysis (WWII)

### [7] Enigma Cipher (M3 Emulator)
*   **Behavior:** Emulates in RAM the electromechanical core of the legendary Enigma M3 machine used by the Wehrmacht, with its corresponding Reflector B (UKW-B).
*   **How to use:** Type `7`. The system will be interactive. You will need to input:
    1.  The **Rotor** numbers (E.g., `1 2 3` for I, II, III).
    2.  The **Initial Position** of the rotors (E.g., `ABC`).
    3.  The Ring settings, called **Ringstellung** (E.g., `AAA`).
    The emulator will process `ciphertext.txt` simulating the "Double Stepping" and mechanical rotations in real-time.

### [8] Turing Bombe (Known-Plaintext Attack)
*   **Behavior:** Conceptually simulates Alan Turing's "Bombe" used at Bletchley Park. If you know (or guess) a word present inside the Enigma ciphertext (called a "CRIB"), this module will find it and reveal the used rotors.
*   **How to use:** Type `8`. You will be asked to input the CRIB (e.g., `WETTER`). The Bombe will allocate 17,576 combinations in Multi-Thread across 60 different rotor permutations. The calculation will abruptly end (Logical Collision) as soon as the emulator generates text where the word you entered appears, revealing the Enigma configuration used.

---

## Module 3: Modern Security

### [9] AES-256 (Multi-Threaded Symmetric Decryption)
*   **Behavior:** Attacks an AES-256 dump (in hexadecimal format). Uses simulated PBKDF2 (Password-Based Key Derivation Function) to derive keys from a wordlist.
*   **How to use:** Ensure that `ciphertext.txt` contains the hex cipher. Type `9`. You will be asked for a cryptographic **SALT** (if you don't know it, press ENTER and "INVASION" will be used). The program will extract keys from `book.txt` and engage in a massively parallel attack on all your CPU cores, stopping as soon as it reaches a sensibly deciphered printable payload.

### [13] SHA-256 (File Hash Generation)
*   **Behavior:** Calculates the irreversible SHA-256 digital fingerprint (Digest) of an entire file for integrity verification.
*   **How to use:** Type `13`. You will be asked which file to operate on (press ENTER to analyze `ciphertext.txt`). The engine will read the file in optimized 8192-byte blocks and return the final hexadecimal cryptographic fingerprint.

---

## Module 4: Asymmetric & Post-Quantum Forensics

*Note: These modules support ciphers with asymmetric mathematical architecture, requiring specific configurations.*

### [10] RSA Cipher (Asymmetric)
*   **Behavior:** Handles the basic modular arithmetic of RSA encryption (modular inversion).
*   **How to use:** Type `10`. You will be asked for the mathematical parameters `P`, `Q`, and `E` (you can press ENTER for default diagnostic keys). At this point you can choose:
    *   `[1] Encrypt`: Input text to see it converted into its encrypted numerical matrix.
    *   `[2] Decrypt`: Decrypt the numerical array currently present in `ciphertext.txt` via derived private key.

### [11] ECC ElGamal (Elliptic Curve)
*   **Behavior:** Simulates point translation in an Elliptic Curve Space over Finite Fields `y^2 = x^3 + ax + b mod p`.
*   **How to use:** Type `11`. The system will ask for various geometric coefficients and the Generator G parameters (or ENTER for the test curve `P=467`). Like RSA, you can generate ciphertexts (coordinate matrices `C1, C2`) or decrypt the geometric tensor present in `ciphertext.txt` via scalar inversion.

### [12] LWE Lattice (Post-Quantum Crypto)
*   **Behavior:** Simulates Quantum-resistant cryptography (Regev's Algorithm on lattices, or *Lattice Based*).
*   **How to use:** Type `12`. The mathematical lattice initializes itself using a static seed, spatial dimension, and preconfigured Gaussian error factor. It offers the choice to input text to "project and smudge into the lattice" (Encrypt) or to collapse the noisy vector present in `ciphertext.txt` to retrieve the original plaintext data (Decrypt).

---

## Module 5: Digital Forensics & Carving

### [14] PCAP Parser (Network Forensics)
*   **Behavior:** A miniature *Deep Packet Inspector* (DPI). Analyzes files captured by network analyzers (like Wireshark) looking for "plaintext" conversations, bypassing encrypted TLS protocols where possible.
*   **How to use:** Type `14`. Provide the name of a file in `.pcap` or `.pcapng` format. The algorithm will verify the network format's "Magic Bytes", scan the entire packet volume, and extract all those "Sensitive Artifacts" or "Payloads" (printable character strings at least 8 bytes long), showing you the first isolated anomalies it deems most suspicious.

### [15] File Carver (Magic Bytes Extraction)
*   **Behavior:** "Carving" is the forensic technique used to recover deleted or altered files hidden inside corrupted hexadecimal dumps (RAW), ignoring the native File System logic.
*   **How to use:** Type `15`. You will be asked for the target dump file. The system will allocate the entire file in RAM as a RAW matrix. Then it will perform a deep byte-by-byte scan to find headers and footers of known files:
    *   **JPEG** (`FF D8 FF` -> `FF D9`)
    *   **PNG** (`89 50 4E 47` -> `IEND`)
    *   **PDF** (`%PDF-` -> `%%EOF`)
    If one of these signatures is found intact, the image or document will be physically extracted from the shapeless dump and saved in the main folder (e.g., `carved_artifact_1.jpg`).
