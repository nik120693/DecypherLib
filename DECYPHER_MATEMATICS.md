---

### 2. Il File `DECYPHER_MATHEMATICS.md` (Il Trattato Architetturale)

Crea questo file. È la spiegazione matematica e informatica, portata al livello di verbosità massima richiesto, che lega le equazioni del mondo reale all'implementazione in C++.

```markdown
# THE MATHEMATICS OF DECYPHERLIB: A Deep Dive

Questo documento sviscera l'infrastruttura matematica e le scelte ingegneristiche alla base della suite `DecypherLib`. Ogni algoritmo è il riflesso di un'equazione crittografica o probabilistica, tradotta in C++17 per massimizzare l'efficienza della CPU, parallelizzare il calcolo e prevenire l'overflow aritmetico.

---

## 1. Il Motore Semantico: Viterbi e Catene di Markov
Il cuore della nostra crittanalisi non è la semplice decodifica, ma la capacità della macchina di "comprendere" se una stringa decifrata ha senso nel linguaggio umano. Questo problema è stato risolto modellando la lingua inglese come una Catena di Markov Nascosta (HMM) risolta tramite l'**Algoritmo di Viterbi**.



### La Matematica
Sia $W = w_1, w_2, ..., w_n$ una sequenza di parole candidate. La probabilità totale che questa sequenza sia una frase valida è il prodotto delle probabilità marginali delle singole parole estratte dal lessico:
$$P(W) = \prod_{i=1}^{n} P(w_i)$$

Tuttavia, calcolare il prodotto di migliaia di probabilità infinitesime (es. $10^{-6}$) in una CPU causa invariabilmente un **Arithmetic Underflow** (il numero diventa così piccolo che il tipo `double` collassa a zero). Per questo, applichiamo il logaritmo, trasformando la produttoria in una sommatoria:
$$\log P(W) = \sum_{i=1}^{n} \log P(w_i)$$

### L'Implementazione Informatica (C++)
Nel file `StatisticalAnalyzer.cpp`, la funzione `segmentWords()` utilizza la **Programmazione Dinamica** (Dynamic Programming) per implementare questa formula in tempo $O(N \cdot M)$. 
Inizializziamo un array dinamico `std::vector<double> chart(n + 1, -1e18)` dove `-1e18` rappresenta l'infinito negativo (probabilità logaritmica zero). Il vettore iterativo calcola il massimo della sottomatrice per ogni nodo:
`chart[i] = std::max(chart[j] + prob_word)`
Un array separato, `backpointer`, memorizza il cammino ottimo per ricostruire la stringa una volta raggiunta la fine del testo (Backtracking).

---

## 2. La Singolarità: Gravità Semantica Esponenziale
Il problema dell'algoritmo di Viterbi standard è l'**Overfitting Crittografico**: una chiave errata può generare frammenti casuali di 1 o 2 lettere che, sommati, producono un punteggio superiore a una frase reale ma meno "probabile" secondo il dizionario.

### La Matematica
Abbiamo alterato lo spazio delle probabilità introducendo un attrattore non lineare: la **Gravità Semantica Esponenziale**. La funzione di Fitness globale $F$ di una decodifica è definita come la somma dell'Entropia N-Grammatica $E$ (calcolata con i quadgrammi) più la sommatoria cubica delle lunghezze $L_i$ delle parole valide estratte:
$$F = E + \alpha \sum_{i=1}^{k} (L_i)^3$$
Dove $\alpha$ è una costante di bilanciamento scalare. L'elevamento al cubo altera la topologia dei punteggi: 10 parole da 1 lettera valgono $10 \times 1^3 = 10$, mentre 1 parola da 10 lettere vale $1 \times 10^3 = 1000$.

### L'Implementazione Informatica
In C++, questa logica è iniettata in `calculateMultiAnchorFitness()`. Usiamo `std::pow(len, 3.0)` su variabili `double`. Questo annichilisce letteralmente il rumore statistico. Qualsiasi thread di Forza Bruta che partorisca una parola reale di senso compiuto vedrà la sua variabile di fitness esplodere verso l'alto, imponendosi sul mutex `resultMutex` durante la fase di aggiornamento della classifica globale.

---

## 3. Analisi Spettrale: Indice di Coincidenza (IC) e $\chi^2$
Per distruggere il cifrario di Vigenère (che maschera le frequenze delle singole lettere usando alfabeti multipli dipendenti dalla chiave), utilizziamo le equazioni di William F. Friedman del 1922.



### Indice di Coincidenza (IC)
L'IC misura la probabilità che due lettere scelte a caso da un testo siano identiche. In un testo puramente casuale (o cifrato polialfabetico perfetto), $IC \approx 0.038$. Nell'inglese naturale, a causa dell'alta frequenza della "E" e della "T", $IC \approx 0.066$.
La formula utilizzata dal nostro `KasiskiEngine` è:
$$IC = \frac{\sum_{i=A}^{Z} f_i(f_i - 1)}{N(N-1)}$$
Dove $f_i$ è la frequenza assoluta dell'i-esima lettera e $N$ è la lunghezza totale della colonna analizzata. Il programma suddivide il testo in $L$ colonne e calcola la media degli IC. Quando la media supera la soglia di $0.058$, il sistema deduce di aver "incolonnato" correttamente il testo sotto la stessa lettera della chiave, rivelando così la lunghezza del periodo $L$.

### Test Statistico del Chi-Quadrato ($\chi^2$)
Una volta isolata la colonna, dobbiamo trovare lo *shift* di Cesare applicato. Usiamo il test di bontà dell'adattamento di Pearson ($\chi^2$) per comparare le frequenze osservate $O_i$ con le frequenze attese $E_i$ della lingua inglese:
$$\chi^2 = \sum_{i=A}^{Z} \frac{(O_i - E_i)^2}{E_i}$$
In `main.cpp`, per ogni colonna e per ogni possibile shift (da 0 a 25), calcoliamo il valore di $\chi^2$. Lo shift che minimizza la funzione (ovvero che rende la distribuzione derivata il più simile possibile a `ENG_FREQ`) viene selezionato come lettera della chiave.

---

## 4. Matematica delle Curve Ellittiche (ECC ElGamal)
La crittanalisi non si ferma al mondo classico. L'infrastruttura supporta la matematica dell'Elliptic Curve Cryptography sui campi finiti $\mathbb{F}_p$.



### La Matematica
Una curva ellittica è definita dall'equazione di Weierstrass ristretta:
$$y^2 \equiv x^3 + ax + b \pmod p$$
L'algoritmo di cifratura ElGamal mappato su curva richiede un generatore $G$. La chiave pubblica è $Q = k_{priv}G$. Per cifrare un messaggio $M$ (mappato come punto $P_m$), il mittente sceglie un k casuale e genera un crittogramma composto da due punti:
$$C_1 = kG$$
$$C_2 = P_m + kQ$$
Per decifrare, il ricevente (nel nostro modulo `ECCipher.cpp`) moltiplica la sua chiave privata per $C_1$ ed esegue una sottrazione di punti sulla curva:
$$P_m = C_2 - k_{priv}C_1$$

### L'Implementazione Informatica
Trattare la matematica dei punti (Addizione e Raddoppio su curva) in C++ richiede un'attenta manipolazione dei tipi. Nel nostro `ECCipher.cpp`, per evitare overflow a 64-bit durante la risoluzione del modulo inverso moltiplicativo (algoritmo di Euclide esteso), abbiamo isolato l'algebra lineare all'interno di stringhe parzate da `std::stoll()` o appoggiandoci a classi `BigInt` custom. I blocchi crittografici sono gestiti usando `std::stringstream` per splittare i tensori $(X, Y, M)$.

---

## 5. Post-Quantum: Learning With Errors (LWE)
L'oracolo unificato integra un prototipo LWE, il fondamento dei moderni schemi NIST per resistere all'attacco di Grover su computer quantistici.



### La Matematica
Invece di basarsi sulla fattorizzazione di numeri primi (RSA) o sul logaritmo discreto (ECC), LWE si basa sulla difficoltà di risolvere sistemi di equazioni lineari perturbati da un "rumore" gaussiano.
La chiave pubblica è una matrice di equazioni $(A, b)$ tali che:
$$b \equiv As + e \pmod q$$
Dove $s$ è il vettore segreto (chiave privata) ed $e$ è un vettore di piccolo errore casuale. Senza $e$, il sistema sarebbe risolvibile in tempo polinomiale tramite Eliminazione di Gauss. L'aggiunta di $e$ trasforma il problema in un reticolo N-dimensionale classificato come NP-Difficile (NP-Hard).

### L'Implementazione Informatica
In `LWECipher.cpp`, lavoriamo non più con stringhe di testo o grandi interi isolati, ma con operazioni matriciali. Utilizziamo `std::vector<std::vector<int>>` per rappresentare i reticoli matematici. L'estrazione dell'errore (decapsulation) comporta l'arrotondamento del bit estratto basato sulla sottomissione algebrica: se il residuo modulo $q$ è più vicino a $q/2$, il bit è 1, altrimenti è 0. Questo meccanismo di tolleranza all'errore è stato implementato con logiche di *bit-shifting* per garantire velocità di esecuzione a livello L1 cache.

---


THE INVASION WILL COMMENCE AT DAWN PROCEED WITH OPERATION OVERLORD AND MAINTAIN STRICT RADIO SILENCE UNTIL FURTHER NOTICE