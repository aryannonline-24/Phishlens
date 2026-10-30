"""Synthetic, scenario-labelled cases; NOT collected messages or a benchmark.

Each family stays in one split. Eight surface variants exercise normalization;
the effective semantic diversity is 40 families, not 320 independent examples.
Held-out families are evaluation-only: do not tune rules against their scores.
"""
FAMILIES = [
    # split, category, label, message, URL
    ('dev', 'credentials', 'phishing', 'Please send your password to restore access.', ''),
    ('dev', 'credentials', 'phishing', 'Share your OTP with our support agent.', ''),
    ('dev', 'identity', 'phishing', 'HR asks you to confirm your employee ID on this portal.', 'http://hr-portal-verify.com/login'),
    ('dev', 'identity', 'phishing', 'Upload your Aadhaar to receive this unexpected refund.', ''),
    ('dev', 'payment', 'phishing', 'Please transfer the invoice payment to our new bank account.', ''),
    ('dev', 'payment', 'phishing', 'Pay the supplier using the updated bank details.', ''),
    ('dev', 'kyc', 'phishing', 'Update KYC immediately or your account will be blocked.', ''),
    ('dev', 'kyc', 'phishing', 'Complete KYC today to prevent suspension.', ''),
    ('dev', 'hinglish', 'phishing', 'Apna OTP abhi bhejo.', ''),
    ('dev', 'hindi', 'phishing', 'अपना पासवर्ड तुरंत भेजें।', ''),
    ('dev', 'domain', 'phishing', 'Review your account notice.', 'https://paypa1.com/login'),
    ('dev', 'domain', 'phishing', 'Open this banking notice.', 'https://paypal.com.attacker-example.com'),
    ('dev', 'obfuscation', 'phishing', 'Sign in at hxxps://paypa1[.]com/login', ''),
    ('dev', 'reward', 'phishing', 'You have won a free gift! Claim your prize now!!', 'https://bit.ly/prize'),
    ('dev', 'warning', 'legitimate', 'Your OTP is 246810. Do not share this OTP with anyone.', ''),
    ('dev', 'warning', 'legitimate', 'Never send your password to a support agent.', ''),
    ('dev', 'identity', 'legitimate', 'Your employee ID has been updated in our records.', ''),
    ('dev', 'identity', 'legitimate', 'Do not upload your Aadhaar in response to unsolicited messages.', ''),
    ('dev', 'payment', 'legitimate', 'Your payment reached our existing account successfully.', ''),
    ('dev', 'payment', 'legitimate', 'Do not transfer funds to a new account without verification.', ''),
    ('dev', 'kyc', 'legitimate', 'Your KYC review is complete. No action is required.', ''),
    ('dev', 'kyc', 'legitimate', 'Read the KYC policy in the banking app when convenient.', ''),
    ('dev', 'hinglish', 'legitimate', 'Apna OTP kisi ko mat bhejo.', ''),
    ('dev', 'hindi', 'legitimate', 'अपना पासवर्ड किसी से साझा न करें।', ''),
    ('dev', 'domain', 'legitimate', 'Your order has shipped.', 'https://www.amazon.com/orders'),
    ('dev', 'domain', 'legitimate', 'Your statement is available in the official app.', 'https://retail.sbi.co.in'),
    ('dev', 'urgency', 'legitimate', 'URGENT: Your flight departs in 3 hours, check in immediately.', 'https://www.airindia.com'),
    ('dev', 'bare_link', 'legitimate', 'Our documentation is at example.com/help', ''),
    ('heldout', 'identity', 'phishing', 'Recruitment needs you to submit your passport for a fake job offer.', ''),
    ('heldout', 'payment', 'phishing', 'Remit the outstanding balance to the replacement beneficiary account.', ''),
    ('heldout', 'hindi', 'phishing', 'केवाईसी आज अपडेट करें वरना खाता बंद होगा।', ''),
    ('heldout', 'hinglish', 'phishing', 'Naye UPI account par payment karo.', ''),
    ('heldout', 'indirect_request', 'phishing', 'The six digits you just received are needed by our agent to finish your refund.', ''),
    ('heldout', 'attachment', 'phishing', 'The attached payroll viewer must be installed to see your salary.', ''),
    ('heldout', 'identity', 'legitimate', 'Please enter your employee ID at the reception desk for your scheduled appointment.', ''),
    ('heldout', 'credentials', 'legitimate', 'Enter your password in the official app you opened to finish signing in.', ''),
    ('heldout', 'hindi', 'legitimate', 'बैंक कभी आपका ओटीपी नहीं मांगता।', ''),
    ('heldout', 'payment', 'legitimate', 'We received your request to add a new beneficiary account.', ''),
    ('heldout', 'obfuscation', 'legitimate', 'Training example: hxxps://example[.]com/help is a defanged documentation link.', ''),
    ('heldout', 'newsletter', 'legitimate', 'Our newsletter explains how fraudsters redirect payments.', ''),
]


def build_cases(split='all'):
    cases = []
    for index, (partition, category, label, text, url) in enumerate(FAMILIES):
        if split != 'all' and partition != split:
            continue
        variants = [text, 'notification: ' + text.lower(), 'NOTICE: ' + text.upper(), '  ' + text + '  ',
                    'Notice: ' + text, 'Message:\n' + text, text + '\nThank you.',
                    text + '\nReference: CASE-' + str(index + 1)]
        for variant, message in enumerate(variants):
            cases.append(dict(id=f'{index + 1:02}-{variant}', family=f'family-{index + 1:02}',
                              split=partition, category=category, label=label,
                              text=message, url=url, source='synthetic scenario'))
    return cases
