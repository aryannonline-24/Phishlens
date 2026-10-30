from rules import run_analysis

# label: your ground truth ("phishing" or "legitimate") — YOU decide this,
# since you're writing these examples yourself.
TEST_SET = [
    {"text": "Dear Customer, verify your OTP immediately or your account will be suspended!!!",
     "url": "http://192.168.1.5/login", "label": "phishing"},
    {"text": "Hi Aditi, your order has shipped and will arrive Thursday.",
     "url": "https://www.amazon.com/orders/123", "label": "legitimate"},
    {"text": "URGENT: Your bank account has been locked. Confirm your password now.",
     "url": "http://paypa1.com/verify", "label": "phishing"},
    {"text": "Your monthly newsletter is here — check out this month's top articles.",
     "url": "https://www.medium.com/newsletter", "label": "legitimate"},
    {"text": "Congratulations! You have won a free gift. Claim your prize now!!!",
     "url": "https://bit.ly/claim123", "label": "phishing"},
    {"text": "Hi, this is Priya from HR. Could you quickly confirm your employee ID on this portal before end of day?",
    "url": "http://hr-portal-verify.com/login", "label": "phishing"},
    {"text": "URGENT: Your flight departs in 3 hours, please complete online check-in immediately.",
    "url": "https://www.airindia.com/checkin", "label": "legitimate"},
    # keep adding more here — aim for 25-30 total, roughly half phishing, half legitimate
]

def evaluate(cases=TEST_SET):
    """Small developer sample, not an independent benchmark."""
    tp = tn = fp = fn = 0
    for case in cases:
        result = run_analysis(case['text'], case['url'])
        positive = result['risk'] in ('medium', 'high')
        actual = case['label'] == 'phishing'
        tp += positive and actual
        tn += not positive and not actual
        fp += positive and not actual
        fn += not positive and actual
        print(f"{case['label']:12} score={result['score']:3} risk={result['risk']:6} {'OK' if positive == actual else 'MISS'}")
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    metrics = {'samples': total, 'true_positive': tp, 'true_negative': tn,
        'false_positive': fp, 'false_negative': fn,
        'accuracy': (tp + tn) / total if total else 0,
        'precision': precision, 'recall': recall,
        'f1': 2 * precision * recall / (precision + recall) if precision + recall else 0}
    return metrics


if __name__ == '__main__':
    import json
    print(json.dumps(evaluate(), indent=2))
    print('This small development sample does not establish real-world accuracy.')
