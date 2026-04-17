import re
import math
from collections import Counter
import sys

def clean_text(text):
    """Rimuove tutto ciò che non è una lettera e converte in maiuscolo."""
    return re.sub(r'[^A-Z]', '', text.upper())

def generate_datasets(input_file):
    print(f"[*] Inizio Ingestion e Analisi Statistica del file: {input_file}")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            raw_text = f.read()
    except FileNotFoundError:
        print(f"[-] ERRORE CRITICO: Il file {input_file} non esiste.")
        sys.exit(1)

    # 1. ESTREMA PULIZIA DEL TESTO
    words = re.findall(r'\b[a-zA-Z]+\b', raw_text)
    words = [w.upper() for w in words]
    continuous_text = "".join(words)

    if not continuous_text:
        print("[-] ERRORE: Il file non contiene testo valido.")
        sys.exit(1)

    print(f"[*] Testo caricato: {len(words)} parole, {len(continuous_text)} caratteri.")

    # 2. CONTEGGIO FREQUENZE
    print("[*] Calcolo distribuzioni di probabilità in corso...")
    word_counts = Counter(words)
    
    ngrams_counts = Counter()
    # Estrazione Trigrammi
    for i in range(len(continuous_text) - 2):
        ngrams_counts[continuous_text[i:i+3]] += 1
    # Estrazione Quadgrammi
    for i in range(len(continuous_text) - 3):
        ngrams_counts[continuous_text[i:i+4]] += 1

    # 3. NORMALIZZAZIONE LOGARITMICA (Scala 1.0 - 15.0)
    # L'Omni-Decoder in C++ si aspetta punteggi positivi. 
    # Usiamo il logaritmo per appiattire le curve esponenziali della Legge di Zipf.
    
    def normalize_to_scale(counter_dict, max_score=15.0, min_score=1.0):
        if not counter_dict:
            return {}
        max_count = counter_dict.most_common(1)[0][1]
        normalized = {}
        for item, count in counter_dict.items():
            if count > 1: # Ignoriamo i rumori statistici che appaiono una sola volta
                # Trasformazione logaritmica proporzionale
                score = (math.log(count) / math.log(max_count)) * max_score
                normalized[item] = max(min_score, round(score, 2))
        return normalized

    print("[*] Normalizzazione pesi logaritmici...")
    lexicon_scored = normalize_to_scale(word_counts, max_score=15.0)
    ngrams_scored = normalize_to_scale(ngrams_counts, max_score=15.0)

    # 4. MATERIALIZZAZIONE DEI DATABASE PER IL C++
    print("[*] Scrittura dei database tattici su disco...")
    
    with open('lexicon.txt', 'w', encoding='utf-8') as f:
        f.write("# OMNI-DECODER LEXICON DATABASE (AUTOGENERATO)\n")
        # Ordiniamo dal peso più alto al più basso
        for word, score in sorted(lexicon_scored.items(), key=lambda item: item[1], reverse=True):
            f.write(f"{word} {score:.1f}\n")

    with open('ngrams.txt', 'w', encoding='utf-8') as f:
        f.write("# OMNI-DECODER N-GRAMS DATABASE (AUTOGENERATO)\n")
        for ngram, score in sorted(ngrams_scored.items(), key=lambda item: item[1], reverse=True):
            f.write(f"{ngram} {score:.1f}\n")

    print("[+] OPERAZIONE COMPLETATA CON SUCCESSO.")
    print(f"    - Voci Lessicali estratte: {len(lexicon_scored)}")
    print(f"    - N-Grammi (3/4) estratti: {len(ngrams_scored)}")
    print("[!] Sostituisci i file generati nella root della DecypherLib.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 dataset_forge.py <file_testo_gigante.txt>")
    else:
        generate_datasets(sys.argv[1])