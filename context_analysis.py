"""Conversation observations; user-supplied context is never proof of trust."""
import re
from email.utils import parseaddr


def analyze_context(message, previous='', sender='', previous_sender='', initiated=False):
    findings = []
    if sender and previous_sender:
        current = parseaddr(sender)[1].lower()
        prior = parseaddr(previous_sender)[1].lower()
        if current and prior and current != prior:
            findings.append(dict(label='Sender changed', evidence=f'{prior} → {current}',
                                 tip='Verify the new sender through a known contact.'))
    # Compare explicit payment identifiers rather than arbitrary digit changes.
    pattern = r'\b(?:account|iban|upi)\s*(?:number|id)?\s*[:#=-]?\s*([A-Z0-9][A-Z0-9@._-]{5,33})'
    old = set(re.findall(pattern, previous, re.I))
    new = set(re.findall(pattern, message, re.I))
    if old and new and {x.lower() for x in old} != {x.lower() for x in new}:
        findings.append(dict(label='Payment identifier changed', evidence=f'{", ".join(sorted(old))} → {", ".join(sorted(new))}',
                             tip='Call the payee on a previously verified number before paying.'))
    if previous and re.search(r'\b(?:new|changed|updated|replacement)\b.*\b(?:account|bank details|beneficiary)\b', message, re.I):
        findings.append(dict(label='Change of payment instructions in conversation', evidence=message[:300],
                             tip='Confirm changed instructions independently.'))
    return dict(findings=findings, supplied=bool(previous or sender or previous_sender or initiated),
                initiated_by_user=initiated,
                note='You initiated the interaction; this does not establish trust and does not lower the rule score.' if initiated else
                     'Context is supplied by you. Sender identity has not been authenticated.')
