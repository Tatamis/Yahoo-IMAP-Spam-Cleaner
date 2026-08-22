# 🛡️ Bulletproof IMAP Spam Filter

**Automated IMAP spam, phishing & spoofing protection with VirusTotal integration.**

A resilient Python-based email filtering script designed for **Yahoo Mail and other IMAP providers**. It combines fast local heuristics with VirusTotal URL analysis to detect and safely quarantine unwanted emails while handling **network drops, IMAP rate limits, reconnects, and API quotas**.

> ⚠️ **Designed for safety first:** suspicious messages are moved to **Trash** instead of being permanently deleted, and a **dry-run mode** is available for testing.

---

## ✨ Features

| Feature                       | Description                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------- |
| ⚡ **Cascade Filtering**       | Runs cheap local checks first and uses VirusTotal only when necessary.                      |
| 🕵️ **Anti-Spoofing**         | Detects emails impersonating your own address and checks authentication headers.            |
| 🔐 **SPF / DMARC Validation** | Flags messages that fail key email authentication checks.                                   |
| 🦠 **VirusTotal Integration** | Extracts URLs from emails and checks suspicious links for malware/phishing.                 |
| 🛡️ **Rate-Limit Protection** | Uses exponential backoff and controlled reconnects to reduce the risk of provider/API bans. |
| 🔄 **UID-Based Processing**   | Uses IMAP UIDs so the script can resume safely after connection failures.                   |
| 🗑️ **Safe Quarantine**       | Moves suspicious messages to `Trash` instead of permanently deleting them.                  |
| 🧪 **Dry-Run Mode**           | Test filtering rules without modifying your mailbox.                                        |
| 🚀 **Long-Running Execution** | Built to process large inboxes without failing on temporary network issues.                 |

---

## 🧠 How It Works

The filter uses a **short-circuit cascade**. Each message is evaluated from the fastest and safest checks to the more expensive ones.

```text
                    ┌───────────────────────┐
                    │      Incoming Mail     │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  1. Self-Sent Check   │
                    └───────────┬───────────┘
                                │
                        Legitimate sender?
                         ┌──────┴──────┐
                         │             │
                        YES            NO
                         │             │
                         ▼             ▼
                      KEEP       ┌───────────────┐
                                 │ 2. Spoofing   │
                                 │    Check      │
                                 └───────┬───────┘
                                         │
                                         ▼
                                 ┌───────────────┐
                                 │ 3. Domain     │
                                 │    Blocklist  │
                                 └───────┬───────┘
                                         │
                                         ▼
                                 ┌───────────────┐
                                 │ 4. SPF/DMARC  │
                                 └───────┬───────┘
                                         │
                                         ▼
                                 ┌───────────────┐
                                 │ 5. Empty      │
                                 │    Subject    │
                                 └───────┬───────┘
                                         │
                                         ▼
                                 ┌───────────────┐
                                 │ 6. Spam Regex │
                                 │    Keywords   │
                                 └───────┬───────┘
                                         │
                                         ▼
                                 ┌───────────────┐
                                 │ 7. VirusTotal │
                                 │    URL Scan   │
                                 └───────┬───────┘
                                         │
                              Malicious URL found?
                                ┌────────┴────────┐
                                │                 │
                               YES                NO
                                │                 │
                                ▼                 ▼
                           🗑️ TRASH            ✅ KEEP
```

### Filtering Order

1. **Self-Sent Failsafe**
   Messages genuinely sent from your own address are preserved.

2. **Spoofing Detection**
   Detects messages that imitate your display name or sender identity while using a different address.

3. **Blocked Domains**
   Known spam, scam, casino, or otherwise unwanted domains are immediately quarantined.

4. **SPF / DMARC Authentication**
   Messages failing configured authentication checks are flagged.

5. **Empty Subject Detection**
   Emails with completely empty subjects can be quarantined.

6. **Regex Spam Detection**
   Searches the subject/body for configurable spam and phishing keywords.

7. **VirusTotal URL Analysis**
   URLs from messages that survive the previous checks are extracted and suspicious links are analyzed using VirusTotal.

---

## 🛡️ Resilience & Reliability

The script is designed for environments where an IMAP connection cannot be assumed to remain stable.

### 🔄 UID-Based Resume

Instead of relying on volatile IMAP sequence numbers, messages are processed using **UIDs**.

This means that after a connection failure, the script can reconnect and continue processing without unnecessarily restarting or skipping messages.

### ⏳ Exponential Backoff

Temporary failures such as:

* network interruptions
* IMAP timeouts
* API rate limits
* temporary server errors

are handled using **exponential backoff**, reducing repeated connection attempts.

### 🔌 Connection Cycling

Long-running sessions can periodically reconnect to avoid accumulating stale connections or triggering provider-side limits.

For example, the script can safely cycle the IMAP connection after a configured number of processed emails.

---

## 🚀 Installation

### Requirements

* **Python 3.7+**
* An IMAP-enabled mailbox
* Yahoo Mail App Password or equivalent provider credential
* VirusTotal API key

### 1. Clone the Repository

```bash
git clone https://github.com/YourUsername/Bulletproof-IMAP-Spam-Filter.git
cd Bulletproof-IMAP-Spam-Filter
```

### 2. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

If the project does not include a `requirements.txt` file and only requires `requests`:

```bash
pip install requests
```

---

## ⚙️ Configuration

Open the main Python script and configure your mailbox and VirusTotal credentials:

```python
EMAIL = "your_email@yahoo.com"
APP_PASSWORD = "your_app_password"
IMAP_SERVER = "imap.mail.yahoo.com"

VT_API_KEY = "your_virustotal_api_key"
```

### 🔐 Important

Use an **App Password** instead of your normal mailbox password whenever your provider supports it.

Never commit secrets directly to GitHub.

A better production setup is to load credentials from environment variables:

```bash
export EMAIL="your_email@yahoo.com"
export APP_PASSWORD="your_app_password"
export VT_API_KEY="your_virustotal_api_key"
```

---

## 🎯 Customize the Filtering Rules

The filtering engine is intentionally configurable.

### 🚫 `BLOCKED_DOMAINS`

Add domains that should be immediately quarantined:

```python
BLOCKED_DOMAINS = {
    "example-spam.com",
    "example-casino.com",
}
```

### 🔎 `SPAM_KEYWORDS`

Customize the regex patterns according to the type of spam you receive:

```python
SPAM_KEYWORDS = [
    r"\bcasino\b",
    r"\bfree money\b",
    r"\bbitcoin giveaway\b",
]
```

This can be extended with localized scam patterns, fake dating alerts, cryptocurrency scams, phishing messages, and other recurring spam themes.

### ✅ `SAFE_DOMAINS`

Trusted domains can bypass VirusTotal URL scanning:

```python
SAFE_DOMAINS = {
    "google.com",
    "apple.com",
    "microsoft.com",
}
```

This helps reduce unnecessary VirusTotal API usage.

---

## 🧪 Dry-Run Mode

**Always test new filtering rules before enabling automatic quarantine.**

Enable:

```python
DRY_RUN = True
```

Then run:

```bash
python spam_filter.py
```

In dry-run mode, the script evaluates messages and reports what it *would* do without moving emails.

Once you're confident there are no false positives:

```python
DRY_RUN = False
```

Run the script again:

```bash
python spam_filter.py
```

---

## 📂 Recommended Project Structure

```text
Bulletproof-IMAP-Spam-Filter/
│
├── spam_filter.py
├── requirements.txt
├── README.md
├── .gitignore
└── LICENSE
```

Recommended `.gitignore`:

```gitignore
__pycache__/
*.pyc
.env
.venv/
venv/
```

---

## 🔒 Security Considerations

This project handles highly sensitive information, including email credentials and message contents.

### Never commit:

```text
APP_PASSWORD
VT_API_KEY
.env
credentials.json
```

Use environment variables or a secrets manager where possible.

Also remember that **VirusTotal submissions may have privacy implications** depending on the service/API tier and how URLs are submitted. Review VirusTotal's current terms and privacy documentation before using the scanner with sensitive links.

---

## ⚠️ Limitations

No spam filter is perfect.

False positives can occur, particularly when:

* aggressive regex rules are used
* legitimate emails fail SPF/DMARC
* a trusted sender uses a suspicious URL
* a legitimate domain is mistakenly added to a blocklist

For this reason, **Dry-Run mode should be used before deploying new rules.**

---

## 📊 Processing Strategy

The core design principle is:

```text
Cheap local checks
        ↓
More expensive local checks
        ↓
External reputation analysis
```

This minimizes:

* VirusTotal API calls
* unnecessary network traffic
* processing time
* exposure to API rate limits

The result is a more efficient filtering pipeline for large mailboxes.

---

## 🤝 Contributing

Contributions, improvements, and additional filtering techniques are welcome.

Typical areas for improvement include:

* additional authentication checks
* improved phishing detection
* HTML analysis
* attachment scanning
* machine-learning based classification
* better provider compatibility
* richer logging and metrics
* asynchronous processing

---

## 📜 Disclaimer

This project is provided **as-is** and without guarantees.

Always use:

```python
DRY_RUN = True
```

when introducing or modifying filtering rules.

The author is **not responsible for lost, quarantined, or incorrectly classified emails** resulting from the use of this software.

---

## ⭐ If You Find It Useful

Consider giving the repository a ⭐ on GitHub and contributing improvements back to the project.
