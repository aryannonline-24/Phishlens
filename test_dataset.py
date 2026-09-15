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

correct = 0
for case in TEST_SET:
    result = run_analysis(case["text"], case["url"])
    predicted = "phishing" if result["risk"] in ("medium", "high") else "legitimate"
    is_correct = predicted == case["label"]
    correct += is_correct
    print(f'{case["label"]:12} -> predicted {predicted:12} (score={result["score"]})  {"OK" if is_correct else "MISS"}')

print(f"\nAccuracy: {correct}/{len(TEST_SET)} = {correct/len(TEST_SET)*100:.1f}%")