"""Offline multinomial Naive Bayes baseline; JSON artifacts, never pickle.

The bundled baseline learns only from development families. Its posterior is
uncalibrated and must not be advertised as a real-world phishing probability.
"""
import argparse
from collections import Counter
from functools import lru_cache
import hashlib
import json
import math
import os
from pathlib import Path
import re
from evaluation_cases import build_cases


def tokens(text):
    words = re.findall(r'[^\W_]+', text.lower(), re.UNICODE)[:4000]
    return words + [' '.join(pair) for pair in zip(words, words[1:])]


def train(cases):
    counts = [Counter(), Counter()]
    documents = [0, 0]
    for row in cases:
        if row.get('label') not in {'phishing', 'legitimate'} or not isinstance(row.get('text'), str):
            raise ValueError('Each training row requires text and phishing/legitimate label.')
        if row.get('split') == 'heldout':
            raise ValueError('Held-out cases cannot be used for training.')
        label = int(row['label'] == 'phishing')
        documents[label] += 1
        counts[label].update(tokens(row['text']))
    if not all(documents):
        raise ValueError('Training requires both classes.')
    digest = hashlib.sha256(json.dumps(cases, sort_keys=True).encode()).hexdigest()[:12]
    return dict(version='nb-1-' + digest, counts=[dict(c) for c in counts], documents=documents,
                training_samples=sum(documents), calibrated=False)


@lru_cache(maxsize=1)
def load_model():
    path = os.environ.get('PHISHLENS_MODEL')
    if path:
        model = json.loads(Path(path).read_text(encoding='utf-8'))
        if (len(model.get('counts', [])) != 2 or len(model.get('documents', [])) != 2
                or not all(type(x) is int and x > 0 for x in model['documents'])
                or any(not isinstance(c, dict) or any(type(v) is not int or v < 0 for v in c.values()) for c in model['counts'])):
            raise ValueError('Invalid model artifact.')
        return model
    rows = [r for r in build_cases('dev') if r['id'].endswith('-0')]
    return {**train(rows), 'source': '28 synthetic development families'}


def predict(text):
    model = load_model()
    counts, docs = model['counts'], model['documents']
    vocab = set(counts[0]) | set(counts[1])
    totals = [sum(c.values()) + len(vocab) for c in counts]
    log_odds = math.log(docs[1] / docs[0])
    contributions = []
    for token, count in Counter(tokens(text)).items():
        if token not in vocab:
            continue
        weight = count * math.log(((counts[1].get(token, 0) + 1) / totals[1]) /
                                  ((counts[0].get(token, 0) + 1) / totals[0]))
        log_odds += weight
        contributions.append(dict(term=token, weight=round(weight, 3)))
    score = 1 / (1 + math.exp(-max(-40, min(40, log_odds))))
    return dict(version=model['version'], source=model.get('source', 'manually trained JSON artifact'),
                training_samples=model['training_samples'], score=round(score, 4),
                label='phishing' if score >= .5 else 'legitimate', assessed=bool(contributions),
                calibrated=False, evidence=sorted(contributions, key=lambda r: abs(r['weight']), reverse=True)[:8],
                warning='Experimental language classifier. Score is uncalibrated, not a verified phishing probability.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Manually train from reviewed JSON rows; never trains from feedback automatically.')
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    rows = json.loads(args.input.read_text(encoding='utf-8'))
    args.output.write_text(json.dumps(train(rows), ensure_ascii=False, indent=2), encoding='utf-8')
