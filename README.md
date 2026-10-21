# Upwind Email Scorer

**An explainable phishing-risk assessment Gmail Add-on**

## 1. Overview and User Experience

Upwind Email Scorer is a Gmail Add-on that helps users assess the risk of an email without leaving their inbox. It combines deterministic, rule-based checks with community-reported sender reputation and returns three things:

- **Risk score:** a value between 0 and 100.
- **Verdict:** `Safe`, `Suspicious`, or `Malicious`.
- **Explanations:** the signals that contributed to the assessment.

The user opens a message in Gmail, launches the Add-on, and selects **Scan Email**. The result appears in a Gmail card, alongside an option to **Report as Phishing**. New users first complete a short inbox-history verification flow; the Add-on displays the requirements and their progress.

The design prioritizes **explainability**, **modularity**, and **security awareness**. A score is a heuristic risk indicator, **not** a calibrated probability or a guarantee that an email is safe or malicious.

## 2. Detection Capabilities

I chose complementary signals rather than relying on a single indicator: sender identity, social-engineering language, attachments, URLs, and community experience. Each signal is independently explainable, and the rules can evolve without replacing the scoring engine.

### 2.1 Sender Identity Analysis

Checks the sender's address and display name for suspicious patterns: free email providers, unrecognized domains, brand names used with mismatching domains, and authority-related names such as `admin`, `support`, or `security` used with free providers.

**Rationale and trade-off:** A free mailbox is common and receives only a small penalty; apparent brand impersonation is a stronger signal. These checks are inexpensive and easy to explain, but domain recognition is **not sender authentication**. The Add-on does not validate SPF, DKIM, or DMARC, and sophisticated spoofing may go undetected.

### 2.2 Content and Urgency Analysis

Examines the subject and plain-text body for urgency expressions and requests for sensitive actions (passwords, verification codes, payment details, or account verification). The current rules include English and Hebrew patterns, and apply an additional penalty when urgency and a sensitive request appear together.

**Rationale and trade-off:** Matching action-oriented phrases instead of isolated words such as `password` reduces some false positives. However, predefined expressions cannot fully interpret context, new wording, or nuanced social engineering.

### 2.3 Attachment Analysis

Classifies attachment **filenames by extension**, including executables/scripts (for example, `.exe` and `.js`), macro-enabled Office documents (for example, `.docm` and `.xlsm`), and common documents (for example, `.pdf` and `.docx`).

**Rationale and trade-off:** All recognized attachments receive explanations, but only the **highest attachment risk** contributes points. This avoids inflating the score merely because an email has several files. No attachment content is uploaded for analysis, opened, executed, or malware-scanned; an extension is only an indicator.

### 2.4 URL Analysis

Inspects URLs found in the subject and plain-text body for suspicious brand-domain structures, direct IPv4 hosts, known URL shorteners, and unencrypted `http://` links.

**Rationale and trade-off:** URLs are parsed locally without visiting the destination, reducing the complexity and risks of interacting with untrusted sites. The rule reports the links it can parse but applies only the **highest URL penalty**. It does not inspect landing pages, resolve shortened destinations, detect every lookalike domain, or extract all links hidden in HTML.

### 2.5 Community Reputation

Allows verified users to report suspicious senders. Reports are associated with a **normalized sender email address**, and each verified Google account can contribute only one report per sender.

| Distinct reports | Scoring effect |
| --- | --- |
| 0 | No reputation penalty |
| 1–2 | +15 points |
| 3 or more | Sender considered blacklisted; +60 points |

**Rationale and trade-off:** Community feedback can flag senders whose messages lack obvious technical indicators. However, it introduces a new attack surface: coordinated or inaccurate reports can damage a legitimate sender's reputation. Reports therefore contribute to the score rather than independently proving maliciousness; verification and deduplication provide partial abuse resistance.

*Implementation note:* The five capabilities are implemented through **four `EmailScannerRule` classes**. Community reputation is consulted within `SenderIdentityRule`.

## 3. Community Verification: Security vs. Friction

Community-driven scoring is useful only if attackers cannot trivially amplify their votes. To raise the barrier to mass-created reporting accounts, the Add-on combines **Google identity authentication** with a lightweight **Proof of Inbox History** challenge.

Before scanning or reporting, the user submits metadata for **two emails** that:

- Are each at least **90 days old**.
- Come from **different senders**.
- Are separated by at least **3 days**.

Verification progress and requirements are returned by the backend and displayed in the Add-on.

**Product trade-off:** A stronger challenge could reduce low-effort abuse but would also increase onboarding friction and discourage legitimate users. The current two-email flow favors usability while adding some friction in the normal UI. Requiring verification even for **scanning** is an additional usability cost; a future version could allow scanning immediately and restrict only reputation-changing reports.

**Important security boundary:** A verified Google identity does **not** make client-supplied email metadata trustworthy. The backend currently checks the submitted dates and senders but does **not** independently query Gmail to prove that those messages exist. A caller making direct API requests can forge this metadata. Consequently, this mechanism is **not a robust Sybil-attack defense**; it is a proof-of-concept friction mechanism.

## 4. Architecture and Engineering Decisions

### Frontend / Backend Split

The **Gmail Add-on** is implemented in **Google Apps Script (V8)**. It uses Gmail's current-message context and `GmailApp` to read the sender, subject, plain-text body, and attachment names. `CardService` renders the interface; `UrlFetchApp` sends authenticated JSON requests.

The **Java / Spring Boot backend** owns identity verification, authorization, input validation, the scoring engine, verification state, and community reputation. This prevents the frontend from being the authority for security decisions and keeps the detection logic independent of the Gmail UI.

```text
Opened Gmail message
       |
       v
Google Apps Script + CardService
       |  Google ID token + selected email data
       v
HTTPS / ngrok (local development)
       |
       v
Spring Boot REST API -> ScanController
       |                    |
       |             Authentication / validation
       v
EmailScoringService -> ScannerRuleFactory
       |
       v
EmailScannerRule implementations
       |
       v
Score + verdict + reasons -> Gmail card
```

During local development, **Spring Boot listens on port 8080** and **ngrok** provides a public HTTPS endpoint accessible to Apps Script. ngrok is a development/demo tunnel, not a production deployment. Separating the two components makes the backend easier to extend, at the cost of requiring a reachable service and network communication.

### Code Organization and Patterns

| Package | Responsibility |
| --- | --- |
| `controller` | REST endpoints, request validation, authentication and authorization orchestration |
| `dto` | Request and response data transfer objects |
| `service` | Scoring orchestration, Google authentication, verification state, and reputation |
| `rules` | Detection rules, shared rule interface, results, and rule factory |

- **Strategy:** `EmailScannerRule` defines a common `analyze` contract. Each rule encapsulates an independent detection strategy and produces a `RuleResult` (points plus explanations).
- **Simple Factory:** `ScannerRuleFactory` assembles the active rules and their dependencies. Adding a rule requires implementing the interface and registering it with the factory, without rewriting `EmailScoringService`.
- **Dependency Injection:** Spring-managed services use constructor injection, keeping responsibilities and dependencies explicit.

### Data Structures, Shared State, and Concurrency

`Set` and `Map` support efficient membership checks and mappings such as brand name to expected domain. A `List<EmailScannerRule>` defines the active scoring pipeline.

Community reputation is stored as `ConcurrentHashMap<String, Set<String>>`: a normalized sender address maps to a concurrent set of distinct reporting users (`ConcurrentHashMap.newKeySet()`). This prevents duplicate reports even when requests arrive concurrently. User verification states are also held in a `ConcurrentHashMap`; a `synchronized` block on each user's state makes the history checks and state update atomic **for that user**.

**Shared state is per backend process.** Reports from one user affect future scans by other users connected to the same running instance, but there is **no database, persistence across restarts, or synchronization between separate backend instances**. In-memory storage keeps the proof of concept small and easy to run, at the cost of durability and scalability.

## 5. Security and Trust Boundaries

**Google authentication.** Apps Script obtains a Google ID token using `ScriptApp.getIdentityToken()` and sends it as `Authorization: Bearer <token>`. The backend uses the Google API Client to validate the token and its configured OAuth audience, checks the verified-email claim, and derives the current user's email from the verified token. It does not trust client-submitted `userEmail` or `reporter` values as identities.

**Authorization.** All four API endpoints require a valid Google identity. The `/api/scan` and `/api/report` operations additionally require completed inbox-history verification, enforced on the backend rather than only in the UI.

**Untrusted input.** Incoming email text, sender names, links, attachment filenames, and request payloads are treated as untrusted. The controller validates required fields and bounds field lengths, attachment counts, and verification dates. Text inserted into Gmail cards is HTML-escaped. URL analysis does not fetch destinations, and attachment analysis does not execute files.

**Sensitive data.** Scanning explicitly sends the selected message's sender, subject, plain-text body, and attachment **names** to the backend over HTTPS; attachment contents are not sent in the scan payload. The implementation does not intentionally persist scanned message bodies in a database. It stores verification metadata and community reports in memory. Processing email content on a separate backend is itself a privacy and trust consideration, even in a prototype.

**Configuration.** The Google OAuth client ID is configured through the `GOOGLE_OAUTH_CLIENT_ID` environment variable instead of being embedded in Java source. An OAuth client ID is an identifier, not a secret; tokens and other credentials should never be committed to the repository.

## 6. Scoring and Explainability

Each rule returns its points and reasons. `EmailScoringService` aggregates the results, caps the total at **100**, and assigns the verdict:

| Score | Verdict |
| --- | --- |
| 0–20 | `Safe` |
| 21–60 | `Suspicious` |
| 61–100 | `Malicious` |

The weights reflect qualitative judgments about the severity of each signal, rather than statistical calibration on a labeled dataset. Some observations can be shown with **zero additional points** to make the analysis more transparent. The result is deterministic and explainable, but false positives and false negatives are expected. In particular, `Safe` must not be read as a security guarantee.

## 7. Running the Project

**1. Prerequisites.** Java 17+, Maven, a Google account with Gmail, Google Apps Script, and ngrok. The Apps Script project must be configured as a Gmail Add-on and have an OAuth client ID compatible with the ID token issued to the Add-on.

**2. Backend.** From the directory containing `pom.xml`, set the OAuth client ID and start Spring Boot (PowerShell example):

```powershell
$env:GOOGLE_OAUTH_CLIENT_ID="YOUR_GOOGLE_OAUTH_CLIENT_ID"
mvn spring-boot:run
```

The backend reads this value through `auth.google.client-id=${GOOGLE_OAUTH_CLIENT_ID}` in `application.properties` and runs on port **8080** by default.

**3. ngrok.** In a separate terminal, expose the local backend and update the frontend's `BASE_URL` with the assigned HTTPS address:

```bash
ngrok http 8080
```

```javascript
var BASE_URL = "https://YOUR_NGROK_DOMAIN/api";
```

**4. Gmail Add-on.** Add the Apps Script frontend and `appsscript.json` to a Google Apps Script project, configure and authorize the required Gmail, external-request, and `openid` OAuth scopes, and ensure the ID token's `aud` matches `GOOGLE_OAUTH_CLIENT_ID`. Install the Add-on using **Apps Script Test Deployments**.

**5. Usage.** Open an email in Gmail and launch the Add-on. Complete **Proof of Inbox History** verification if prompted, click **Scan Email** to view the score, verdict, and explanations, and use **Report as Phishing** to submit a community report. Keep Spring Boot and ngrok running during the demonstration.

## 8. Limitations and Next Steps

This project is a **proof of concept**, not a production-ready phishing filter. Its scope deliberately favors a working, understandable Gmail experience and explicit engineering trade-offs over a large detection stack.

- **Detection coverage:** No SPF/DKIM/DMARC validation, attachment content scanning, destination-site analysis, comprehensive HTML-link extraction, or external threat-intelligence feed. Rule-based detection can miss new techniques and produce false positives.
- **Verification integrity:** Historical-message metadata is supplied by the client and can be forged in direct API calls. In the current implementation, sender uniqueness in the history check compares normalized *From strings*, not canonical extracted email addresses; different display names can therefore cause the same address to count as different senders.
- **Community abuse:** A unique verified reporter is counted only once per sender, but account creation, collusion, and false reporting remain possible. The blacklist threshold is a scoring heuristic, not proof of wrongdoing.
- **Storage and deployment:** State is in memory and disappears on restart. It is not shared across processes. ngrok provides development connectivity, not managed hosting.
- **Operational security and privacy:** Production use would require stronger controls for rate limiting, logging, privacy and retention, secret handling, and access to sensitive email data.

**With more time, I would prioritize:** server-side verification of inbox history via appropriately authorized Gmail APIs; separating scan access from the privilege to submit reputation-changing reports; persistent storage and abuse monitoring; stronger sender authentication and threat-intelligence signals; evaluating the rules against labeled examples to calibrate scoring; and deployment to managed infrastructure with explicit data-handling controls.
