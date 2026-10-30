"""Run reproducible evaluations, including visible errors and category metrics."""
import argparse
import json
from pathlib import Path
from evaluation_cases import build_cases
from rules import run_analysis, RULESET_VERSION


def metrics(rows):
    tp = sum(r['actual'] and r['predicted'] for r in rows)
    tn = sum(not r['actual'] and not r['predicted'] for r in rows)
    fp = sum(not r['actual'] and r['predicted'] for r in rows)
    fn = sum(r['actual'] and not r['predicted'] for r in rows)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    return dict(samples=len(rows), true_positive=tp, true_negative=tn,
                false_positive=fp, false_negative=fn,
                precision=precision, recall=recall,
                false_positive_rate=fp / (fp + tn) if fp + tn else 0,
                f1=2 * precision * recall / (precision + recall) if precision + recall else 0,
                accuracy=(tp + tn) / len(rows) if rows else 0)


def evaluate(cases):
    rows = []
    for case in cases:
        result = run_analysis(case['text'], case['url'])
        rows.append({**case, 'actual': case['label'] == 'phishing',
                     'predicted': result['risk'] in {'medium', 'high'},
                     'score': result['score'], 'risk': result['risk']})
    return dict(ruleset_version=RULESET_VERSION,
                limitation='Synthetic surface variants of 40 scenario families; not independent real-world evidence. Labels assume the described sender context, which the analyzer cannot verify.',
                families=len({r['family'] for r in rows}), **metrics(rows),
                categories={category: metrics([r for r in rows if r['category'] == category])
                            for category in sorted({r['category'] for r in rows})},
                errors=[r for r in rows if r['actual'] != r['predicted']])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--split', choices=['dev', 'heldout', 'all'], default='dev')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = evaluate(build_cases(args.split))
    report['split'] = args.split
    payload = json.dumps(report, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(payload + '\n', encoding='utf-8')
    print(payload)
