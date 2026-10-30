# PhishLens 3.0 advanced workflows

## Start

The project-local `.venv` contains the core and image packages on this machine. From the workspace root:

```powershell
.\phishlens\.venv\Scripts\python.exe .\phishlens\app.py
```

Open http://127.0.0.1:5000. Alternatively run `phishlens/start.ps1`. For a fresh installation, create `.venv` inside `phishlens` and install both `requirements.txt` and `requirements-advanced.txt`.

## 1. Hybrid detection

Each analysis includes the existing rule report, a local Naive Bayes text classifier, and a separate hybrid review decision. The classifier uses word/bigram evidence and exposes its version, training size and strongest contributing terms. Its bundled training data consists of one example from each of 28 synthetic development families; evaluation-only families are excluded. It is an experimental baseline, not a pretrained language model or calibrated detector.

Hybrid triage requests review when rules reach Medium/High, the model score reaches 0.85, or context/email discrepancies exist. Model output never reduces a rule score. A classifier's legitimate label does not verify safety. The 0.85 threshold is a design choice, not statistically calibrated confidence.

Manual training is supported from reviewed JSON records containing `text` and `label` (`phishing` or `legitimate`), with both classes represented:

```powershell
.venv\Scripts\python.exe model.py reviewed-labels.json model-custom.json
$env:PHISHLENS_MODEL = (Resolve-Path model-custom.json).Path
.venv\Scripts\python.exe app.py
```

No automatic learning occurs. Use a separate validation set and fresh held-out families before adopting a custom model. Training refuses rows explicitly marked `split: heldout`; users must still prevent semantic duplicates/leakage. Artifacts are JSON, not executable pickle files. Restart the app to switch models.

## 2. Email analysis

Expand **Import email, screenshot or QR image**, select an `.eml` file, and choose **Extract for review**. The parser extracts subject/body/HTML destinations, compares visible link domains with actual destinations, checks From/Reply-To differences and brand display names against sender domains, and lists attachments without opening them. HTML is converted to text and never injected into the page.

Uploaded `Authentication-Results` headers are displayed as unverified evidence. They are not used to claim SPF/DKIM/DMARC validation: a forged uploaded header is indistinguishable from a trusted mail-server result without trusted ingestion infrastructure. Sender discrepancies are review cues, not proof of impersonation.

Extraction metadata is signed for 30 minutes, bound to the server's session secret and included in a report only when the returned token validates. If extracted text is edited, reports label source findings as describing the original file. Files themselves are not persisted. Saving a resulting report does persist its extracted content and metadata under the selected history retention.

## 3. Conversation context

Add previous messages, current/previous sender addresses and whether you initiated the interaction. Checks compare sender addresses and explicit account/IBAN/UPI identifiers, and flag changed payment instructions. This does not authenticate senders or understand arbitrary conversations. Initiating an interaction never suppresses a warning. Previous messages are analyzed locally; reports retain matched context evidence only when saving is enabled.

## 4. OCR and QR scanning

PNG, JPEG and WebP are supported up to 5 MB and 12 megapixels. OpenCV decodes QR payloads. Tesseract supplies OCR when installed/configured; on Windows the app falls back to the operating system's offline OCR engine and installed recognition languages. Windows OCR does not expose a confidence number, so `null` is shown rather than invented confidence.

Tesseract configuration for other environments or additional languages:

```powershell
$env:PHISHLENS_TESSERACT = 'C:\Program Files\Tesseract-OCR\tesseract.exe'
$env:PHISHLENS_OCR_LANG = 'eng+hin'
```

The named language data must be installed separately. OCR has a timeout; temporary Windows OCR files are deleted after use. QR decoding still runs when OCR is unavailable. Review extracted text before clicking Analyze. QR payloads are text only: they are never opened automatically.

## 5. Optional reputation and domain information

**Optional online checks** has a separate URL field and explicit sharing checkbox. A reputation check sends the full normalized URL to URLhaus (if configured) and the registered domain to RDAP lookup services. These actions are never part of a normal offline scan. URLhaus covers known malware URLs and is not comprehensive phishing detection. `not_listed`, `unavailable`, and `listed` are separate states; absence never establishes safety.

Configure a user-owned [URLhaus Auth-Key](https://urlhaus.abuse.ch/api/) in the server environment, never in browser code:

```powershell
$env:URLHAUS_AUTH_KEY = 'your-key'
```

RDAP lookup needs no app API key but registration data may be unavailable. Results use a bounded 15-minute in-memory cache keyed by URL digest, with no persistent cache. Provider errors do not alter offline results. Online reports can be downloaded separately and are not silently added to scan history.

## 6. Isolated website inspection

Install Docker with Linux containers and a running daemon, then from `phishlens`:

```powershell
docker build -f inspector.Dockerfile -t phishlens-inspector:1 .
$env:PHISHLENS_ENABLE_INSPECTION = '1'
.venv\Scripts\python.exe app.py
```

The `.dockerignore` includes only the Dockerfile and two worker source files; history, keys, models and environment directories never enter the build context. Building requires network access to obtain the Python base image. Run-time workers use `--pull=never`, no host mounts, a read-only filesystem, a non-root UID, dropped capabilities, no-new-privileges, 128 MB RAM, half a CPU, 32-process limit, and a 30-second wall deadline. Only one inspection runs at a time. The app never falls back to executing website inspection on the host.

The worker fetches static HTML only. It validates all DNS answers at each redirect, rejects private/local/reserved/multicast addresses and userinfo/unsupported ports, pins the connection to a validated address, verifies TLS, and follows at most three HTTP redirects. It rejects attachments, unsupported content types, compressed responses and bodies over 512 KB. It reports redirect paths, page title, password fields and cross-host form destinations. It does not execute JavaScript, follow meta-refresh, submit forms, download attachments, or use browser sessions/cookies. This is a restricted static inspector, not a full browser detonation system. Containers are a defense layer, not an absolute security boundary.

## 7. Feedback and evaluation dashboard

Explicitly save a scan, suggest a label from its result, then open **Evaluation & feedback**. Reviewers approve phishing/legitimate labels or reject submissions. Only reviewed labels are exported. Deleting/expiring the associated scan also deletes its feedback. Notes and labels are local plaintext data.

The dashboard compares rule, model and hybrid precision/recall, missed phishing and false alarms, with category breakdowns and versioned evaluation runs. It also evaluates the latest 100 reviewed scans using their text and URL; source/context signals are excluded from that comparison. User-selected feedback is not an independent benchmark. At most 20 evaluation runs and 100 feedback entries are displayed; the newest reviewed label per scan is used in exports and comparisons.

The supplied 96-case reserved synthetic split remains correlated variants of only 12 families and has already been inspected during development. Current hybrid results on it: 43 true positives, 32 true negatives, 16 false positives and 5 false negatives (precision 72.9%, recall 89.6%). These are diagnostic results, not evidence of real-world accuracy. Rule-only results remain 32/32/16/16. The dashboard keeps the older rule report for comparison; future tuning requires new unseen cases.

## 8. Browser extension

In Chrome or Edge, open the extensions manager, enable developer mode and **Load unpacked**, selecting the `phishlens/extension` folder. Start the local app separately.

The popup's **Read selection and URL** uses temporary `activeTab` and `scripting` permissions. It has no persistent host permissions, background scanner or remote service. Review/edit the content, then click **Open in local PhishLens**. Content travels in a URL fragment to the local app, never as a query string; the app clears the fragment immediately and waits for explicit analysis. Saving remains off. Restricted browser pages cannot be read.

## Verification and setup status

```powershell
.venv\Scripts\python.exe -m unittest discover -s . -p "test_*.py" -v
node test_extension.cjs
node --check static/advanced.js
```

Automated tests cover CSRF, upload bounds, signed source metadata, forged authentication headers, context changes, feedback review/export/cascade deletion, model training boundaries, QR decoding, consent, blocked network addresses, DNS-pinned connections, redirects and Docker isolation arguments. Generated OCR and QR fixtures live in `fixtures/`.

`browser_check.cjs` uses Playwright and Edge against a running server. **Use a separate `PHISHLENS_DB`**, because it creates scans and feedback. Set `NODE_PATH` to an installed Playwright package directory if necessary. Browser validation covers OCR, email import, context, feedback approval/export, evaluation tables, network consent, disabled inspection, extension handoff, mobile overflow and JavaScript errors. Extension API behavior is unit-tested with mocked Chrome APIs; the extension has not been installed into your personal browser profile.

On this machine, OCR/QR, core workflows and the browser tests passed. Docker is not installed/configured and a URLhaus key has not been supplied, so live container inspection and authenticated reputation responses have not been verified here. Those paths fail explicitly until configured; no substitute success result is fabricated.

References: [Python email parsing](https://docs.python.org/3/library/email.parser.html), [Chrome activeTab permissions](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab), [Docker runtime restrictions](https://docs.docker.com/engine/containers/run/), [URLhaus client example](https://github.com/abusech/URLhaus/blob/master/lookup_url.py).

Validation summary: 53 Python tests passed, extension unit checks passed, and the final browser workflow test passed at desktop and 390px mobile widths. Newly imported or edited content clears stale reports; extension handoff also clears online consent. The temporary test server and its separate database were cleaned up. Your existing phishlens.db was not used by these tests.
