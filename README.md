# SmartShield AI — Professional Cyber Defense Dashboard

A polished, local-first cybersecurity demonstration platform with a Flask backend, SQLite storage, explainable URL/message scanning, optional screenshot OCR, interactive analytics, a reproducible machine-learning training pipeline, email-file inspection, QR decoding, optional live URL reputation lookup and PDF reports.

## Run on Windows / VS Code

1. Extract the ZIP.
2. Open the `SmartShield_Pro` folder in VS Code.
3. Select **Terminal → New Terminal**.
4. Run:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

5. (Recommended) Download the dataset and train the ML model:

```powershell
python train_model.py
```

The script fetches UCI dataset ID 967 using `ucimlrepo` if the CSV is not already in `data/raw/`. It trains a Random Forest model using URL-string features extracted from the URL column only, with a stratified 80/20 split. It saves `models/url_model.joblib` and evaluation metrics under `reports/`.

6. Start the web app:

```powershell
python app.py
```

7. Open **http://127.0.0.1:5000**

If PowerShell blocks activation, run:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`
Then activate the venv again. You can also run the app using `python app.py` from the activated environment.

## Features

- Professional responsive dark dashboard with light/dark setting.
- URL scanner: trained model after training; transparent lexical fallback before training.
- Message/email scanner: social-engineering indicator checks.
- Screenshot OCR: optional; requires Pillow, pytesseract and the separate Tesseract OCR engine.
- Scan history, detail records and CSV export.
- Dataset and model analytics with Chart.js charts.
- Model evaluation metrics and confusion matrix values after training.
- Security center, privacy policy, FAQ, feedback and preferences.
- Email file scanner for `.eml` messages (headers, reply-to, readable body and attachment names; attachments are not opened).
- QR-code image decoding and embedded URL screening (OpenCV).
- Optional Google Safe Browsing v4 reputation lookup. Requires your own API key and sends the submitted URL to Google only when you click Check reputation.
- Downloadable PDF reports from Scan History.
- Local read-only Admin Overview for scan counts, scan modes, recent activity and feedback totals. It is not production authentication or user management.
- SQLite-backed settings, feedback and scan history.
- Local-only URL inspection: the app never opens submitted destinations.

## Dataset and evaluation

Dataset: **PhiUSIIL Phishing URL (Website)**, UCI Machine Learning Repository, dataset 967. It contains 235,795 records (134,850 legitimate and 100,945 phishing) and 54 features. UCI label 1 is legitimate; label 0 is phishing. Dataset license: CC BY 4.0. See `data/dataset_info.json` for citation and metadata.

The trainer intentionally uses the URL text and its label to build lexical features, instead of relying on webpage-source features that are unavailable when a user only submits a URL. Metrics in `reports/metrics.json` are generated on a held-out random split and should not be represented as a guarantee of real-world performance. Dataset temporal drift, domain overlap and collection bias may affect results.

## API endpoints

- `GET /api/health`
- `POST /api/scan` with `{ "mode": "url"|"message", "content": "..." }`
- `POST /api/ocr` multipart image upload
- `GET /api/history`, `DELETE /api/history`
- `GET /api/history/export`
- `GET /api/analytics`
- `GET /api/settings`, `POST /api/settings`
- `POST /api/feedback`
- `GET /api/report/<id>` and `GET /api/report/<id>/pdf`
- `POST /api/scan/email-file` (multipart `email_file`)
- `POST /api/scan/qr` (multipart `qr_image`)
- `POST /api/threat-intel` with `{ "url": "https://example.com" }` (optional API key)
- `GET /api/admin/summary` (local-only summary)

## Optional live threat-intelligence setup

1. Create/enable a Google Safe Browsing API key in your Google Cloud project.
2. In the same PowerShell terminal used to start Flask, set it for the current terminal session:

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="YOUR_OWN_API_KEY"
python app.py
```

Do not paste your API key into chat, commit it to GitHub, or put it in frontend JavaScript. Without the key, all local scanning features still work and the reputation lookup explains that it is not configured. Google Safe Browsing checks are optional and disclose the URL to Google.

## Important safety / deployment note

This is an educational prototype, not a production SOC, antivirus, browser reputation service or guarantee of safety. Do not submit real credentials, OTPs, PINs, CVVs or confidential data. Before public deployment, add authentication/authorization, CSRF protection, rate limiting, secure session management, HTTPS, hardened server configuration, dependency scanning, audit logging, privacy/legal review and security testing. Keep the app bound to localhost unless you deliberately configure and secure a deployment.

## Language support (prototype)

The Settings page includes English, Hindi, Kannada, Urdu, Tamil and Telugu interface choices. The current localization translates key navigation and common actions; some detailed explanations, technical terms, report content and system-generated messages remain in English. The message scanner includes a starter set of common phishing indicators in the five additional languages. This is keyword/rule-based screening, not a fully trained multilingual NLP model. Test with representative local-language examples and expand the phrase lists before making accuracy claims.

## Beginner-friendly feature guide

- **URL scanner:** paste a website address to inspect suspicious URL patterns. It does not open the site.
- **Message scanner:** paste an SMS, chat or email body to look for pressure, password/OTP requests and payment lures.
- **Screenshot scan:** upload an image; OCR requires the separately installed Tesseract engine.
- **Email file check:** upload an `.eml` file to inspect its headers and readable text. Attachments are not executed or malware-scanned.
- **QR check:** upload a QR image to decode its link and inspect the URL without visiting it.
- **Website reputation:** optional Google Safe Browsing lookup; requires your own API key and sends the URL to Google only when requested.
- **PDF report:** download the report from a saved scan in Scan History.
- **Admin overview:** local read-only activity summary, not a secure multi-user administration system.

Risk scores are screening signals, not guarantees or calibrated probabilities. Multilingual rules are an initial prototype and can miss new or nuanced scams.
