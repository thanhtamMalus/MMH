"""
ContextualScorer: improve cryptanalysis by scoring candidate plaintexts
based on context, meaning and syntax heuristics.

This file provides:
 - ContextualScorer: combines word-match coverage (max-match greedy),
   common-word weighting, character n-gram (tri/quad) score approximation,
   punctuation/sentence heuristics and word-length statistics.
 - integration helper: `hillclimb_substitution_with_scorer` which accepts a
   scorer instance and uses it inside the hill-climbing search.

The goal: prefer candidate plaintexts that "look like English" beyond
simple letter frequency.

This is intentionally self-contained (no external data files). For best
accuracy you can optionally load a larger word frequency list into
`ContextualScorer.word_freq`.
"""

import math
import random
import string
from collections import Counter

ALPHABET = string.ascii_uppercase
COMMON_WORDS = ["THE","BE","TO","OF","AND","A","IN","THAT","HAVE","I","IT","FOR","NOT","ON","WITH","AS","YOU","DO","AT"]

# A small built-in word frequency (unigram) approximated for common words.
# You can replace / extend this with a larger frequency dictionary for better results.
BUILTIN_WORD_FREQ = {
    'THE': 50000, 'BE':25000, 'TO':48000, 'OF':47000, 'AND':44000, 'A':30000,
    'IN':30000, 'THAT':15000, 'HAVE':14000, 'I':30000, 'IT':28000, 'FOR':20000,
    'NOT':18000, 'ON':17000, 'WITH':15000, 'AS':16000, 'YOU':20000, 'DO':12000,
    'AT':11000, 'THIS':13000, 'BUT':12000, 'FROM':10000, 'BY':9000
}

class ContextualScorer:
    """Score plaintext candidates by contextual heuristics.

    score(text) -> float (higher = better)

    Components used (weighted sum):
     - word_coverage_score: proportion of text tokens that match known dictionary words (greedy max-match)
     - common_word_bonus: extra points for presence of common function words (THE, AND, TO...)
     - char_ngram_score: log-probability approx using character trigrams (simple model built from english-ish samples)
     - sentence_heuristics: penalties/bonuses for punctuation at sentence boundaries, capitalization pattern
     - word_length_score: penalty for extremely short/long average word lengths

    You can pass a custom word_freq dict into the constructor for better results.
    """
    def __init__(self, word_freq=None):
        # word frequency dictionary (upper-case words -> frequency)
        if word_freq is None:
            self.word_freq = {k:v for k,v in BUILTIN_WORD_FREQ.items()}
        else:
            self.word_freq = {k.upper():v for k,v in word_freq.items()}
        # build small char trigram model from an English-like sample text
        sample = ("THIS IS A SMALL SAMPLE OF ENGLISH TEXT TO BUILD A SIMPLE CHARACTER NGRAM MODEL "
                  "IT IS NOT COMPREHENSIVE BUT IMPROVES SCORING OF CANDIDATES")
        self.tri_counts = Counter()
        s = ''.join(ch for ch in sample.upper() if ch.isalpha() or ch==' ')
        s = s.replace('  ',' ')
        s = ' ' + s + ' '
        for i in range(len(s)-2):
            self.tri_counts[s[i:i+3]] += 1
        self.total_trigrams = sum(self.tri_counts.values())

    # ---------- utility: greedy max-match tokenizer ----------
    def max_match_tokens(self, text: str):
        """Greedy longest-first max-match tokenization using word_freq keys.
        Returns list of tokens (uppercase). Non-matching substrings are returned as single-char tokens.
        """
        text = ''.join(ch for ch in text.upper() if ch.isalpha() or ch==' ')
        text = text.strip()
        # collapse multiple spaces
        while '  ' in text:
            text = text.replace('  ',' ')
        words = []
        i = 0
        raw = text
        n = len(raw)
        while i < n:
            if raw[i] == ' ':
                i += 1
                continue
            # try longest match up to remaining length
            matched = None
            for L in range(min(n-i, 20), 0, -1):
                cand = raw[i:i+L]
                if cand in self.word_freq:
                    matched = cand
                    break
            if matched:
                words.append(matched)
                i += len(matched)
            else:
                # fallback: if char sequence until next space, capture that as token
                j = raw.find(' ', i)
                if j == -1:
                    words.append(raw[i:])
                    break
                else:
                    words.append(raw[i:j])
                    i = j
        return words

    # ---------- scoring components ----------
    def word_coverage_score(self, text: str) -> float:
        tokens = self.max_match_tokens(text)
        if not tokens:
            return 0.0
        matches = sum(1 for t in tokens if t in self.word_freq)
        return matches / len(tokens)  # proportion matched

    def common_word_bonus(self, text: str) -> float:
        t = text.upper()
        bonus = 0.0
        for w in COMMON_WORDS:
            bonus += t.count(' ' + w + ' ') * 0.5
            # also consider start of string
            if t.startswith(w + ' '):
                bonus += 0.2
        return bonus

    def char_trigram_logprob(self, text: str) -> float:
        s = ' ' + ''.join(ch for ch in text.upper() if ch.isalpha() or ch==' ') + ' '
        score = 0.0
        for i in range(len(s)-2):
            tri = s[i:i+3]
            cnt = self.tri_counts.get(tri, 0) + 0.1  # add small smoothing
            score += math.log(cnt / (self.total_trigrams + 1e-9))
        # normalize by length
        return score / max(1, (len(s)-2))

    def avg_word_length_penalty(self, text: str) -> float:
        tokens = [t for t in ''.join(ch if ch.isalpha() or ch==' ' else ' ' for ch in text.upper()).split()]
        if not tokens:
            return 0.0
        avg = sum(len(t) for t in tokens) / len(tokens)
        # ideal english avg word length ~ 4.5; penalize if too short (<2.5) or too long (>8)
        if avg < 2.5:
            return - (2.5 - avg)
        if avg > 8:
            return - (avg - 8) * 0.5
        return 0.0

    def punctuation_sentence_heuristics(self, text: str) -> float:
        # reward presence of spaces and common punctuation placement (ends with period/question), etc.
        s = text.strip()
        score = 0.0
        # proportion of spaces between words
        spaces = s.count(' ')
        score += min(spaces / max(1, len(s)/5), 1.0) * 0.5
        if s.endswith('.') or s.endswith('?') or s.endswith('!'):
            score += 0.5
        return score

    # ---------- final composite scoring ----------
    def score(self, text: str) -> float:
        # combine components with weights (tunable)
        w_cov = 5.0
        w_common = 1.5
        w_tri = 2.0
        w_len = 1.0
        w_sent = 1.0

        cov = self.word_coverage_score(text)
        common = self.common_word_bonus(text)
        tri = self.char_trigram_logprob(text)
        length_pen = self.avg_word_length_penalty(text)
        sent = self.punctuation_sentence_heuristics(text)

        # tri is negative logprob per trigram; convert to positive by negation
        tri_pos = -tri

        total = w_cov * cov + w_common * common + w_tri * tri_pos + w_len * length_pen + w_sent * sent
        return total

# ---------- integration: hillclimb that accepts a scorer ----------

def hillclimb_substitution_with_scorer(cipher: str, scorer: ContextualScorer, restarts=20, iters=2000):
    """Hill-climbing substitution solver that uses scorer.score(plaintext) as objective.

    Returns (best_key, best_plain, best_score).
    """
    def random_key():
        lst = list(ALPHABET)
        random.shuffle(lst)
        return ''.join(lst)
    def swap_key(k):
        a = list(k)
        i,j = random.sample(range(26),2)
        a[i],a[j] = a[j],a[i]
        return ''.join(a)
    def decode_with_key(k):
        inv = {k[i]: ALPHABET[i] for i in range(26)}
        return ''.join(inv.get(ch, ch) for ch in cipher.upper())

    best_overall = (None, '', -1e9)
    for r in range(restarts):
        key = random_key()
        plain = decode_with_key(key)
        best_local = (key, plain, scorer.score(plain))
        no_improve = 0
        for it in range(iters):
            cand_key = swap_key(best_local[0])
            cand_plain = decode_with_key(cand_key)
            s = scorer.score(cand_plain)
            if s > best_local[2]:
                best_local = (cand_key, cand_plain, s)
                no_improve = 0
            else:
                no_improve += 1
            if no_improve > 400:
                break
        if best_local[2] > best_overall[2]:
            best_overall = best_local
    return best_overall

# ---------- example usage ----------
if __name__ == '__main__':
    # small demo: use the scorer inside hillclimb to attack a substitution cipher
    sample_cipher = "GSRH RH Z HVXIVG NVHHZTV"
    scorer = ContextualScorer()
    k, p, sc = hillclimb_substitution_with_scorer(sample_cipher, scorer, restarts=30, iters=1500)
    print('BEST SCORE:', sc)
    print('PLAINTEXT:', p)
    print('KEY:', k)
