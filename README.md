# PhishLens 3.0

Offline phishing indicator analyzer with evidence, practical next steps, private-by-default scans and optional local history. Normal scans remain offline. Explicit online actions can query reputation/registration services or inspect a website in a restricted Docker worker. The interface uses local assets.

See [Advanced workflows and setup](ADVANCED.md) for hybrid detection, email import, conversation checks, OCR/QR, online services, isolated inspection, feedback/evaluation and the browser extension.

## Run on Windows

From this folder (containing `app.py`):

```powershell
py -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt -r requirements-advanced.txt
.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000 and keep the terminal running. Stop with Ctrl+C. Installation requires internet. The Public Suffix List ships with tldextract; network updates are disabled. On macOS/Linux use `python3` and `.venv/bin/python`.

## What is new

- Nine message rules and eight URL rules, with added employee/identity information requests, payment redirection and pressured KYC checks.
- Selected Hindi and Hinglish credential, identity, payment and KYC phrases. Explicit warning clauses are excluded from the new contextual checks. This is limited phrase coverage, not general multilingual understanding.
- Bare domains, `hxxp(s)://`, `[.]` and `(.)` defanging are recognized alongside HTTP(S) links. Bare domains require a recognized public suffix; email addresses are not treated as links. Reports preserve original URL text and show normalization in URL details. Paths and query strings are not rewritten.
- Result cards lead with the strongest indicator, its evidence, actual destination/registered domain, and a recommended next step. Low results say “Few warning signs detected”. Scores and all individual checks remain available, including JSON downloads.
- New demonstrations cover HR requests, Hinglish KYC and obfuscated links.

## Privacy and history

Saving is **off by default**, both in the interface and when the API omits `save_history`. Enabling it stores full message text, links and results unencrypted in local SQLite. Choose 7, 30 (default), or 90 days, or keep until manually deleted. Expired scans are deleted when the app next handles a page, analysis or history request; no cleanup runs while the app is closed. Database deletion is not a secure erase of backups or filesystem remnants.

Existing history migrates without deletion and has no expiry unless it already had one. The default database is `phishlens.db` beside `database.py`, regardless of working directory. `PHISHLENS_DB` overrides the path. Back up this file before replacing a project. History supports search, risk filters, pagination, report details and deletion. Legacy scans without stored findings must be rescanned to get a report.

## Scores and limits

Low: below 20; Medium: 20–49; High: 50+. New identity and KYC rules contribute 20 each; payment redirection contributes 25. Credential requests contribute 25. URL indicators count once each across all links; per-link scores remain visible. Maximum aggregate score is 245. These are uncalibrated indicator totals, not probabilities.

Up to ten unique extracted links, 20,000 message characters and 2,048 characters per URL are supported. Missing schemes remain unknown. Invalid embedded URLs mark analysis incomplete; invalid separately supplied URLs reject the scan. Defanging alone does not add risk: legitimate security training can use defanged URLs.

The analyzer cannot establish sender identity, intent or domain ownership. Legitimate identity/password entry instructions may trigger warnings; indirect requests and attachment lures can be missed. Normal scans do not open attachments, expand shorteners or query live reputation. Image text/QR extraction and explicit online checks are separate workflows described in ADVANCED.md. A low score, HTTPS or familiar branding cannot establish trust.

## Validation and evaluation

```powershell
.venv\Scripts\python.exe -m unittest discover -s . -p "test_*.py" -v
.venv\Scripts\python.exe test_dataset.py
.venv\Scripts\python.exe evaluate.py --split dev --output evaluation-dev.json
.venv\Scripts\python.exe evaluate.py --split heldout --output evaluation-heldout.json
```

Regression tests use temporary databases and cover original behavior, disguised links, paired legitimate/request examples, split isolation, default privacy, retention validation, expiry and legacy migration. JavaScript can be checked with `node --check static/app.js`.

`evaluation_cases.py` defines **320 synthetic surface variants of 40 labelled scenario families**. The development split contains 224 cases/28 families; the evaluation-only split contains 96 cases/12 different families. Variants of a family never cross splits. Labels describe intended scenarios and may rely on context unavailable to the analyzer. These are not 320 independent real-world messages. The evaluation-only families were scored after implementation and were not used to tune rules; future tuning against their failures requires a fresh unseen evaluation set.

Reports include precision, recall, F1, accuracy, false-positive rate, confusion counts, category metrics and every error. Current results:

| Set | True positives | True negatives | False positives | False negatives |
| --- | ---: | ---: | ---: | ---: |
| Original seven examples | 4 | 3 | 0 | 0 |
| Synthetic development | 112 | 112 | 0 | 0 |
| Synthetic evaluation-only | 32 | 32 | 16 | 16 |

Evaluation-only precision/recall are both 66.7%; repeated variants are correlated. Misses include indirect requests and attachment lures; false alarms include legitimate identity/password entry instructions. The original HR lure now triggers a warning. **None of these results establishes real-world accuracy.** Before performance claims, collect independently labelled, consented/de-identified real messages, separate near-duplicate families, reserve unseen cases, and calibrate thresholds only on development data.

## Local API and deployment

This is a single-user local app, not an authenticated public service. Debug is off unless `PHISHLENS_DEBUG=1`. `PHISHLENS_SECRET` can supply a stable random session secret; otherwise restarting invalidates sessions.

API clients GET `/`, retain the cookie, and send its meta-tag token in `X-CSRF-Token` for POST/DELETE requests. POST `/analyze` accepts `message`, `url`, `save_history` (boolean, default false) and `retention_days` (0/7/30/90, default 30; 0 means no expiry). Reports are rendered as text, and database operations are parameterized.

Browser validation passed in headless Edge at desktop and 390px mobile widths: private defaults, HR results, normalization disclosure, saved expiry/history, no horizontal overflow and no JavaScript errors. All 53 Python regression tests passed on 30 October 2026. JavaScript syntax validation passed in the earlier local validation.
