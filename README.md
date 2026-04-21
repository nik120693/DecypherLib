# DecypherLib: Omni-Decoder & Cryptanalysis Suite

DecypherLib is a high-performance modular software suite written in C++17, designed for forensics analysis, statistical cryptanalysis, and cipher reverse engineering. Developed to operate on both historical ciphers and modern cryptographic primitives, the system integrates probabilistic Machine Learning algorithms (Viterbi), spectral analysis (Index of Coincidence), and post-quantum asymmetric computation.

## Architectural Features

The system is orchestrated by an interactive Command Line Interface (CLI) that exposes five operational macro-modules:

1. **Extended Classical Cryptanalysis**: Simultaneous multithreaded attacks via Brute Force and Dictionary Attacks on Caesar, Atbash, Vigenère, Affine, Beaufort, and Rail Fence.
2. **Mechanical Cryptanalysis (WWII)**: Emulation of Enigma rotors and implementation of the Turing Bombe for Known-Plaintext Attacks (Cribs).
3. **Modern Security**: Symmetric AES-256 decryption (with simulated PBKDF2 Key Derivation) and SHA-256 hash fingerprint extraction.
4. **Asymmetric & Post-Quantum Forensics**: Large integer manipulation for RSA, Elliptic Curve decryption (ECC ElGamal), and lattice-based LWE (Learning With Errors) cryptographic emulation.
5. **Data Extraction**: Low-level parsing of PCAP files (Network Forensics) and binary File Carving via Magic Numbers.

## Compilation and Execution

The project uses an optimized Makefile for UNIX-like systems (Linux/macOS) with maximum optimization flags (`-O3`) and POSIX multithreading support (`-pthread`).

```bash
# Full compilation and test build
make clean && make all && make test

# Execute the interactive suite
make run
```

## Documentation

For a step-by-step explanation of every single module, its parameters, and the algorithms, consult our [Detailed Usage Guide (USAGE_GUIDE.md)](USAGE_GUIDE.md).
For the mathematical foundations of the integrated engines, visit [DECYPHER_MATEMATICS.md](DECYPHER_MATEMATICS.md).
