## 1. The Semantic Engine: Viterbi and Markov Chains

The heart of our cryptanalysis is not simple decoding, but the machine's ability to "understand" if a deciphered string makes sense in human language. This problem was solved by modeling the English language as a Hidden Markov Model (HMM) solved via the **Viterbi Algorithm**.

  

### The Mathematics

Let $W = w_1, w_2, ..., w_n$ be a sequence of candidate words. The total probability that this sequence is a valid sentence is the product of the marginal probabilities of the individual words extracted from the lexicon:

$$P(W) = \prod_{i=1}^{n} P(w_i)$$

  

However, calculating the product of thousands of infinitesimal probabilities (e.g., $10^{-6}$) in a CPU invariably causes an **Arithmetic Underflow** (the number becomes so small that the `double` type collapses to zero). Because of this, we apply the logarithm, transforming the product into a sum:

$$\log P(W) = \sum_{i=1}^{n} \log P(w_i)$$

  

### The Computational Implementation (C++)

In the `StatisticalAnalyzer.cpp` file, the `segmentWords()` function uses **Dynamic Programming** to implement this formula in $O(N \cdot M)$ time.

We initialize a dynamic array `std::vector<double> chart(n + 1, -1e18)` where `-1e18` represents negative infinity (logarithmic probability zero). The iterative vector calculates the maximum of the submatrix for each node:

`chart[i] = std::max(chart[j] + prob_word)`

A separate array, `backpointer`, stores the optimal path to reconstruct the string once the end of the text is reached (Backtracking).

  

---

  

## 2. The Singularity: Exponential Semantic Gravity

The problem with the standard Viterbi algorithm is **Cryptographic Overfitting**: a wrong key can generate random fragments of 1 or 2 letters which, added together, produce a higher score than a real sentence but are less "probable" according to the dictionary.

  

### The Mathematics

We altered the probability space by introducing a non-linear attractor: **Exponential Semantic Gravity**. The global Fitness function $F$ of a decoding is defined as the sum of the N-Gram Entropy $E$ (calculated with quadgrams) plus the cubic sum of the lengths $L_i$ of the valid words extracted:

$$F = E + \alpha \sum_{i=1}^{k} (L_i)^3$$

Where $\alpha$ is a scalar balancing constant. Cubing alters the scoring topology: 10 words of 1 letter are worth $10 \times 1^3 = 10$, while 1 word of 10 letters is worth $1 \times 10^3 = 1000$.

  

### The Computational Implementation

In C++, this logic is injected into `calculateMultiAnchorFitness()`. We use `std::pow(len, 3.0)` on `double` variables. This literally annihilates statistical noise. Any Brute Force thread that births a real, meaningful word will see its fitness variable skyrocket, imposing itself on the `resultMutex` during the global leaderboard update phase.

  

---

  

## 3. Spectral Analysis: Index of Coincidence (IC) and $\chi^2$

To destroy the Vigenère cipher (which masks the frequencies of individual letters using multiple key-dependent alphabets), we use William F. Friedman's 1922 equations.

  

### Index of Coincidence (IC)

The IC measures the probability that two letters randomly chosen from a text are identical. In a purely random text (or perfect polyalphabetic cipher), $IC \approx 0.038$. In natural English, due to the high frequency of "E" and "T", $IC \approx 0.066$.

The formula used by our `KasiskiEngine` is:

$$IC = \frac{\sum_{i=A}^{Z} f_i(f_i - 1)}{N(N-1)}$$

Where $f_i$ is the absolute frequency of the i-th letter and $N$ is the total length of the analyzed column. The program divides the text into $L$ columns and calculates the average IC. When the average exceeds the $0.058$ threshold, the system deduces it has correctly "aligned" the text under the same letter of the key, thus revealing the length of the period $L$.

  

### Chi-Square Statistical Test ($\chi^2$)

Once the column is isolated, we must find the applied Caesar *shift*. We use Pearson's goodness-of-fit test ($\chi^2$) to compare the observed frequencies $O_i$ with the expected frequencies $E_i$ of the English language:

$$\chi^2 = \sum_{i=A}^{Z} \frac{(O_i - E_i)^2}{E_i}$$

In `main.cpp`, for each column and for each possible shift (from 0 to 25), we calculate the $\chi^2$ value. The shift that minimizes the function (meaning it makes the derived distribution as similar as possible to `ENG_FREQ`) is selected as the key letter.

  

---

  

## 4. Elliptic Curve Mathematics (ECC ElGamal)

Cryptanalysis doesn't stop at the classical world. The infrastructure supports Elliptic Curve Cryptography mathematics over finite fields $\mathbb{F}_p$.

  

### The Mathematics

An elliptic curve is defined by the restricted Weierstrass equation:

$$y^2 \equiv x^3 + ax + b \pmod p$$

The ElGamal encryption algorithm mapped onto a curve requires a generator $G$. The public key is $Q = k_{priv}G$. To encrypt a message $M$ (mapped as point $P_m$), the sender chooses a random $k$ and generates a cryptogram composed of two points:

$$C_1 = kG$$

$$C_2 = P_m + kQ$$

To decrypt, the receiver (in our `ECCipher.cpp` module) multiplies their private key by $C_1$ and performs point subtraction on the curve:

$$P_m = C_2 - k_{priv}C_1$$

  

### The Computational Implementation

Handling point mathematics (Addition and Doubling on a curve) in C++ requires careful type manipulation. In our `ECCipher.cpp`, to avoid 64-bit overflows during the resolution of the modular multiplicative inverse (extended Euclidean algorithm), we isolated the linear algebra within strings parsed by `std::stoll()` or relied on custom `BigInt` classes. Cryptographic blocks are managed using `std::stringstream` to split the $(X, Y, M)$ tensors.

  

---

  

## 5. Post-Quantum: Learning With Errors (LWE)

The unified oracle integrates an LWE prototype, the foundation of modern NIST schemes to resist Grover's attack on quantum computers.

  

### The Mathematics

Instead of relying on prime number factorization (RSA) or the discrete logarithm (ECC), LWE relies on the difficulty of solving systems of linear equations perturbed by Gaussian "noise".

The public key is a matrix of equations $(A, b)$ such that:

$$b \equiv As + e \pmod q$$

Where $s$ is the secret vector (private key) and $e$ is a small random error vector. Without $e$, the system would be solvable in polynomial time via Gaussian Elimination. The addition of $e$ transforms the problem into an N-dimensional lattice classified as NP-Hard.

  

### The Computational Implementation

In `LWECipher.cpp`, we no longer work with text strings or isolated large integers, but with matrix operations. We use `std::vector<std::vector<int>>` to represent the mathematical lattices. Error extraction (decapsulation) involves rounding the extracted bit based on algebraic submission: if the residue modulo $q$ is closer to $q/2$, the bit is 1, otherwise it is 0. This error tolerance mechanism was implemented with *bit-shifting* logic to ensure execution speed at the L1 cache level.

  

---