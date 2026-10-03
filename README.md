# Sentrys

Sentrys is a terminal-based reconnaissance toolkit written in Python. It probes
a target URL or domain, inspects TLS, fingerprints the technology stack,
checks every standard security header, scans for leaked secrets, resolves DNS
records, fetches robots.txt, sitemap.xml and security.txt, performs username
OSINT across twenty public platforms, and produces a weighted risk score.

Sentrys only uses passive and light-active techniques against public
endpoints. It performs read-only requests. It does not log in, does not modify
anything, does not bypass access controls, and does not attempt exploitation.

---

## Table of contents

1. Overview
2. Features
3. Project structure
4. Requirements
5. Installation
6. Commands
7. Command-line options
8. Interactive mode
9. What each scanner does
10. Secret scanning reference
11. Technology signatures reference
12. Username OSINT platforms
13. Risk scoring
14. Output layout
15. Example session
16. Troubleshooting
17. What Sentrys does not do
18. Legal and ethical notice
19. License

---

## 1. Overview

Sentrys is designed for developers, security researchers, bug bounty hunters
and sysadmins who need a quick, structured view of a web target from the
terminal.

You give it a URL or a domain. Sentrys performs a sequence of independent
probes, collects the results, correlates them, and writes a JSON report plus a
human-readable text report under `reports/`.

It works out of the box with no configuration, no API key, no account and no
browser. Everything happens from the command line.

---

## 2. Features

- Direct HTTP probe with status, redirect chain, headers, body sample, content
  length, server and powered-by.
- TLS inspection: subject, issuer, SAN, validity dates, remaining days, TLS
  version and cipher, all extracted natively with Python's `ssl` module.
- Technology fingerprinting across headers, cookies and body: server software,
  CDN, WAF, CMS, frameworks, analytics and more.
- Security header audit: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy,
  Cross-Origin-Resource-Policy. Missing and weak headers are flagged and
  graded.
- Secret scanner with around thirty regex families: cloud keys, API tokens,
  JWTs, private keys, database URIs, webhooks, bot tokens, generic credential
  assignments, and more.
- robots.txt, sitemap.xml and `.well-known/security.txt` retrieval with
  structured parsing of disallow rules and sitemap URLs.
- DNS resolution for A, AAAA, MX, TXT, NS, CNAME, SOA and CAA records.
- Username OSINT across twenty public platforms, concurrently, with status
  code and body checks.
- Weighted risk score with explicit reasons and letter grade.
- JSON and plain-text reports written automatically under a timestamped name.
- Optional proxy support, TLS verification toggle, redirect control, custom
  timeouts, retries and concurrency.
- Verbose logging mode.

---

## 3. Project structure

```
sentrys/
├── sentrys.py
├── requirements.txt
├── LICENSE
├── README.md
└── sentrys/
    ├── __init__.py
    ├── cli.py
    ├── core/
    │   ├── __init__.py
    │   ├── config.py
    │   ├── logger.py
    │   ├── http.py
    │   └── utils.py
    ├── scanners/
    │   ├── __init__.py
    │   ├── http_probe.py
    │   ├── tech_fingerprint.py
    │   ├── secret_scanner.py
    │   ├── security_headers.py
    │   ├── robots_sitemap.py
    │   ├── dns_lookup.py
    │   ├── tls_info.py
    │   └── username_osint.py
    ├── analyzers/
    │   ├── __init__.py
    │   └── risk_score.py
    ├── reporters/
    │   ├── __init__.py
    │   ├── json_report.py
    │   └── text_report.py
    └── data/
        ├── __init__.py
        ├── secret_patterns.py
        ├── tech_signatures.py
        └── username_platforms.py
```

Module responsibilities:

- `sentrys.py`: top-level entry point.
- `sentrys/cli.py`: argument parsing, prompt, orchestration, calling every
  scanner and analyzer, writing the reports.
- `sentrys/core/config.py`: runtime configuration (timeout, retries, proxy,
  TLS verification, output directory, concurrency).
- `sentrys/core/logger.py`: logging setup.
- `sentrys/core/http.py`: HTTP client with retries, headers and proxy.
- `sentrys/core/utils.py`: URL normalization, host extraction, filename
  sanitization, secret masking, deduplication.
- `sentrys/scanners/*`: individual probes.
- `sentrys/analyzers/risk_score.py`: weighted risk scoring.
- `sentrys/reporters/*`: JSON and plain-text writers.
- `sentrys/data/*`: regex and platform definitions.

---

## 4. Requirements

- Python 3.8 or newer.
- Internet access to reach the target and the username platforms.
- The following Python packages:
  - `requests`
  - `dnspython` (optional but recommended; if missing, the DNS scanner is
    skipped and this is reported in the output)

No API key, no cookie, no authentication token is required.

---

## 5. Installation

Step 1. Create a folder for the project, for example:

```
C:\Users\<you>\Downloads\sentrys
```

Step 2. Place `sentrys.py`, `requirements.txt`, `LICENSE`, `README.md` and the
`sentrys/` package folder in that directory. The final layout must match the
tree shown in section 3.

Step 3. Open a terminal in that folder:

```powershell
cd C:\Users\<you>\Downloads\sentrys
```

Step 4. Install the dependencies:

```bash
pip install -r requirements.txt
```

If you do not have `requirements.txt`, install directly:

```bash
pip install requests dnspython
```

Step 5. Verify the install:

```powershell
python -c "import sentrys, sentrys.cli; print('ok')"
```

Expected output: `ok`.

---

## 6. Commands

All commands must be run from the project folder, the one that contains
`sentrys.py`.

| Goal                                             | Command                                                          |
|--------------------------------------------------|------------------------------------------------------------------|
| Scan a URL                                       | `python sentrys.py https://example.com`                          |
| Scan a bare domain                               | `python sentrys.py example.com`                                  |
| Prompt for the target                            | `python sentrys.py`                                              |
| Scan a URL and run username OSINT together       | `python sentrys.py https://example.com -u someuser`              |
| Username OSINT only                              | `python sentrys.py --username-only -u someuser`                  |
| Write reports to a custom folder                 | `python sentrys.py https://example.com -o out`                   |
| Verbose logging                                  | `python sentrys.py https://example.com -v`                       |
| Do not follow redirects on the main probe        | `python sentrys.py https://example.com --no-redirects`           |
| Disable TLS certificate verification             | `python sentrys.py https://example.com --no-tls-verify`          |
| Use a proxy                                      | `python sentrys.py https://example.com --proxy http://127.0.0.1:8080` |
| Only emit JSON                                   | `python sentrys.py https://example.com --json-only`              |
| Only emit text                                   | `python sentrys.py https://example.com --text-only`              |
| Increase timeout and retries                     | `python sentrys.py https://example.com --timeout 30 --retries 5` |
| Increase concurrency for username OSINT          | `python sentrys.py -u someuser --concurrency 16`                 |
| Print version                                    | `python sentrys.py -V`                                           |
| Show help                                        | `python sentrys.py -h`                                           |

Equivalent on macOS and Linux: replace `python` with `python3`.

### 6.1 Walkthrough of the most common command

```bash
python sentrys.py https://example.com
```

Step by step:

1. Normalizes the target.
2. Runs the HTTP probe: status, headers, redirect chain, body sample.
3. Inspects TLS: subject, issuer, validity, cipher.
4. Fingerprints technologies from headers, cookies and body.
5. Audits security headers and produces a grade.
6. Fetches robots.txt, sitemap.xml and security.txt.
7. Scans the page, headers, robots.txt and security.txt for secrets.
8. Resolves DNS records for the host.
9. Computes the weighted risk score.
10. Writes the JSON and text reports under `reports/`.

### 6.2 Walkthrough of the interactive command

```bash
python sentrys.py
```

Output:

```
Target:
```

Type the URL or domain and press Enter. Everything else is identical to the
non-interactive run.

### 6.3 Walkthrough of the username-only command

```bash
python sentrys.py --username-only -u someuser
```

Skips the URL scan entirely and only checks `someuser` across the twenty
public platforms listed in section 12.

### 6.4 Walkthrough of the combined command

```bash
python sentrys.py https://example.com -u someuser -v
```

Runs the full URL scan and, in the same pass, the username OSINT. Verbose
logging shows each phase as it happens.

### 6.5 What to do after a run

| Step | Action                                                                    |
|------|---------------------------------------------------------------------------|
| 1    | Open `reports/` and locate the two files with the newest timestamp.      |
| 2    | Open the `.txt` file for the human-readable summary.                     |
| 3    | Open the `.json` file to process the data programmatically.              |
| 4    | Read the "Risk reasons" section at the bottom of the text report.        |
| 5    | Check the "Secrets" section for anything that needs immediate rotation.  |
| 6    | Check the "Security headers" section to see what should be added.        |

---

## 7. Command-line options

| Option               | Default      | Description                                                      |
|----------------------|--------------|------------------------------------------------------------------|
| `target`             | none         | URL or domain to scan. Prompted if omitted.                      |
| `-u`, `--username`   | none         | Username to run OSINT on.                                        |
| `--username-only`    | off          | Only run username OSINT. Requires `--username`.                  |
| `-o`, `--output`     | `reports`    | Output directory.                                                |
| `--timeout`          | `15`         | HTTP timeout per request in seconds.                             |
| `--retries`          | `3`          | Max retries per request.                                         |
| `--no-redirects`     | off          | Do not follow redirects on the main probe.                       |
| `--no-tls-verify`    | off          | Disable TLS certificate verification.                            |
| `--proxy`            | empty        | HTTP/HTTPS proxy URL.                                            |
| `--concurrency`      | `8`          | Concurrent workers for username checks.                          |
| `--json-only`        | off          | Only emit JSON report.                                           |
| `--text-only`        | off          | Only emit text report.                                           |
| `-v`, `--verbose`    | off          | Verbose logging.                                                 |
| `-V`, `--version`    | off          | Print version and exit.                                          |
| `-h`, `--help`       | off          | Show usage.                                                      |

---

## 8. Interactive mode

When you run Sentrys without a positional argument and without `--username`,
it prompts:

```
Target:
```

Enter a URL or domain and press Enter. An empty value aborts the run.

You can also run username-only interactively by passing `--username-only -u`
with the handle on the command line, or run both by passing the URL on the
command line and only the username interactively via `-u`.

---

## 9. What each scanner does

### http_probe

Sends one GET request to the target, does not follow redirects on the first
hop, then walks the redirect chain manually up to ten hops. Records status
code, reason, final URL, full header dictionary, redirect chain, content type,
content length, server and `X-Powered-By`, plus a 4 KB body sample used by
other scanners.

### tech_fingerprint

Matches a curated signature list against headers, cookies and body. Produces:
the sorted list of detected technologies, per-technology evidence markers,
detected WAFs (Cloudflare, Akamai, Fastly, Sucuri, Imperva Incapsula,
F5 BIG-IP, Barracuda, Amazon CloudFront) and detected CDNs.

### security_headers

For each header in the reference list, records whether it is present, missing
or weak. Weak means HSTS without `max-age` or CSP containing `unsafe-inline`
or `unsafe-eval`. Produces a letter grade from A to F based on the number of
missing and weak headers.

### secret_scanner

Runs every regex in `sentrys/data/secret_patterns.py` against the page body,
every response header, robots.txt disallow rules and security.txt content.
Findings are deduplicated by type, masked value and source, sorted by severity
and reported with type, severity, source, masked value and 200-character
context.

### robots_sitemap

Fetches `/robots.txt`, `/sitemap.xml` and `/.well-known/security.txt`. Parses
disallow rules from robots and up to 200 URLs from the sitemap. Reports
whether each file exists, its URL and, for robots, the number of disallow
rules.

### dns_lookup

Uses `dnspython` to resolve A, AAAA, MX, TXT, NS, CNAME, SOA and CAA records
for the host. Each record type is a separate query. Timeout is five seconds
per query. If `dnspython` is not installed, the scanner returns an explicit
error and the rest of the run continues.

### tls_info

Opens a raw TLS connection to the host on port 443 using Python's `ssl`
module. Reads the peer certificate and extracts common name, issuer, validity
dates, SAN DNS entries, remaining validity in days, negotiated TLS version and
cipher. Never uses an external binary.

### username_osint

Checks the given username against twenty public platforms concurrently, using
a thread pool. Each platform is checked either by status code or by a body
marker. Findings are grouped into found, not found and unknown, and returned
with URL and status.

---

## 10. Secret scanning reference

The following patterns are shipped by default. Each finding carries a
severity from `critical`, `high`, `medium` to `low`.

| Category                 | Examples                                                         | Severity |
|--------------------------|------------------------------------------------------------------|----------|
| AWS Access Key ID        | `AKIA...`, `ASIA...`                                             | critical |
| AWS Secret Access Key    | any 40-char base64 near "aws secret"                             | critical |
| Google API Key           | `AIza...`                                                        | high     |
| Google OAuth Client ID   | `*.apps.googleusercontent.com`                                   | medium   |
| Slack Token              | `xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`                      | critical |
| Slack Webhook            | `hooks.slack.com/services/...`                                   | high     |
| GitHub Token             | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`                           | critical |
| GitLab Token             | `glpat-...`                                                      | critical |
| Stripe Secret Key        | `sk_live_...`                                                    | critical |
| Stripe Publishable Key   | `pk_live_...`                                                    | medium   |
| SendGrid API Key         | `SG.xxx.yyy`                                                     | high     |
| Twilio Account SID       | `AC` + 32 hex                                                    | medium   |
| Mailgun API Key          | `key-...`                                                        | high     |
| Heroku API Key           | UUID near "heroku"                                               | high     |
| JWT                      | three dot-separated base64url segments starting with `eyJ`       | high     |
| Bearer Token             | `Bearer xxx`                                                     | medium   |
| Basic Auth               | `Authorization: Basic ...`                                       | high     |
| Private Key Block        | `-----BEGIN ... PRIVATE KEY-----`                                | critical |
| Generic API Key          | `api_key=`, `secret_key=`, `access_token=`                       | medium   |
| Generic Password         | `password=`, `passwd=`, `pwd=`                                   | medium   |
| Database URI             | `mongodb://`, `postgres://`, `mysql://`, `redis://`, `amqp://`   | high     |
| Firebase URL             | `https://<project>.firebaseio.com`                               | medium   |
| Firebase Config Key      | `apiKey: "AIza..."`                                              | high     |
| Cloudinary URL           | `cloudinary://...`                                               | high     |
| Discord Webhook          | `discord.com/api/webhooks/...`                                   | medium   |
| Telegram Bot Token       | `<digits>:<35-char>`                                             | high     |
| Shopify Access Token     | `shpat_...`                                                      | high     |
| Shopify Shared Secret    | `shpss_...`                                                      | high     |
| Square Access Token      | `sq0atp-...`                                                     | high     |
| Square OAuth Secret      | `sq0csp-...`                                                     | high     |
| NPM Token                | `npm_...`                                                        | high     |
| PyPI Token               | `pypi-AgEIcHlwaS5vcmc...`                                        | high     |
| OpenAI API Key           | `sk-...T3BlbkFJ...`                                              | critical |
| Anthropic API Key        | `sk-ant-...`                                                     | critical |
| Hugging Face Token       | `hf_...`                                                         | high     |

Add new patterns in `sentrys/data/secret_patterns.py`. Each entry is a
dictionary with `name`, `regex` and `severity`.

---

## 11. Technology signatures reference

Signatures are defined in `sentrys/data/tech_signatures.py`. Each entry has
`name`, `where` (`header`, `body` or `cookie`), `key` and `contains`.

Ships with signatures for:

- Servers and proxies: Nginx, Apache, IIS, LiteSpeed, Caddy.
- CDNs and platforms: Cloudflare, Akamai, Fastly, Amazon CloudFront, Amazon S3,
  Vercel, Netlify, GitHub Pages, Heroku.
- WAFs: Cloudflare, Akamai, Sucuri, Imperva Incapsula, F5 BIG-IP, Barracuda.
- CMS: WordPress, Drupal, Joomla, Shopify, Wix, Squarespace.
- Frameworks: React, Vue, Angular, Next.js, Nuxt, Svelte, jQuery, Bootstrap.
- Analytics: Google Analytics, Google Tag Manager, Facebook Pixel.
- Cookie markers: `PHPSESSID`, `ASP.NET_SessionId`, `JSESSIONID`,
  `csrftoken`, `laravel_session`, `__cfduid`, `cf_clearance`.

Add new signatures by extending `SERVER_SIGNATURES`.

---

## 12. Username OSINT platforms

Defined in `sentrys/data/username_platforms.py`. Each platform entry has
`name`, `url` template, `check` mode (`status` or `body`), and detection
rules.

Ships with these twenty platforms:

| Platform      | URL pattern                                     | Detection |
|---------------|-------------------------------------------------|-----------|
| GitHub        | `https://github.com/{u}`                        | status    |
| GitLab        | `https://gitlab.com/{u}`                        | status    |
| Reddit        | `https://www.reddit.com/user/{u}`               | status    |
| Instagram     | `https://www.instagram.com/{u}/`                | status    |
| TikTok        | `https://www.tiktok.com/@{u}`                   | status    |
| Twitter/X     | `https://x.com/{u}`                             | status    |
| YouTube       | `https://www.youtube.com/@{u}`                  | status    |
| Twitch        | `https://www.twitch.tv/{u}`                     | status    |
| Pinterest     | `https://www.pinterest.com/{u}/`                | status    |
| Telegram      | `https://t.me/{u}`                              | status    |
| Mastodon      | `https://mastodon.social/@{u}`                  | status    |
| Medium        | `https://medium.com/@{u}`                       | status    |
| Dev.to        | `https://dev.to/{u}`                            | status    |
| Keybase       | `https://keybase.io/{u}`                        | status    |
| Steam         | `https://steamcommunity.com/id/{u}`             | status    |
| Spotify       | `https://open.spotify.com/user/{u}`             | status    |
| Roblox        | `https://www.roblox.com/users/profile?username={u}` | status |
| HackerNews    | `https://news.ycombinator.com/user?id={u}`      | body      |
| SoundCloud    | `https://soundcloud.com/{u}`                    | status    |
| Behance       | `https://www.behance.net/{u}`                   | status    |

To add a platform, extend `PLATFORMS` in that file.

---

## 13. Risk scoring

The risk score starts at 100 and loses points for concrete issues, producing a
letter grade.

Deductions:

| Condition                                              | Points |
|--------------------------------------------------------|--------|
| HTTPS not enabled                                      | -20    |
| TLS error                                              | -15    |
| TLS certificate expires in less than 14 days           | -10    |
| Missing `Content-Security-Policy`                      | -8     |
| Missing `Strict-Transport-Security`                    | -4     |
| Missing `X-Frame-Options`                              | -4     |
| Missing `X-Content-Type-Options`                       | -2     |
| Missing `Referrer-Policy`                              | -2     |
| Missing `Permissions-Policy`                           | -2     |
| Missing `Cross-Origin-Opener-Policy`                   | -2     |
| Missing `Cross-Origin-Resource-Policy`                 | -2     |
| Weak HSTS or weak CSP                                  | -3 each|
| Critical secret                                        | -25 each|
| High severity secret                                   | -12 each|
| Medium severity secret                                 | -5 each|
| Low severity secret                                    | -2 each|
| No WAF detected                                        | -5     |
| No HTTP response                                       | -15    |

Final score is clamped between 0 and 100.

Letter grade:

| Score range | Grade |
|-------------|-------|
| 90 - 100    | A     |
| 80 - 89     | B     |
| 70 - 79     | C     |
| 60 - 69     | D     |
| 0 - 59      | F     |

Every deduction is listed in the "Risk reasons" section of the text report
and in `risk.reasons` in the JSON report.

---

## 14. Output layout

All files are written under the output directory (default `reports/`), one
pair per run:

```
reports/
├── example.com_20260403_120102.json
└── example.com_20260403_120102.txt
```

The filename is derived from the host (or from the username when running in
username-only mode) and a UTC timestamp.

### JSON structure

Top-level keys:

- `meta`: tool name, version, timestamp.
- `target`: input, normalized URL, host.
- `http_probe`: status, headers, redirects, body sample, and metadata.
- `tls`: certificate and TLS details.
- `tech`: technologies, evidence, WAFs, CDNs.
- `security_headers`: present, missing, weak, grade.
- `secrets`: count, breakdown by severity, list of findings.
- `robots_sitemap`: robots, sitemap, security.txt.
- `dns`: record types and values.
- `username_osint`: found, not found, unknown.
- `risk`: score, grade, reasons.

### Text report structure

Sections, in order:

- Header with target, host, scan timestamp, version, risk score.
- Username OSINT (if run).
- HTTP probe.
- TLS.
- Technologies.
- Security headers.
- Secrets.
- Robots / sitemap / security.txt.
- DNS.
- Risk reasons.
- End marker.

---

## 15. Example session

Command:

```bash
python sentrys.py https://example.com -u someuser -v
```

Console output (abridged):

```
[12:00:01] HTTP probe: https://example.com
[12:00:02] TLS information
[12:00:02] Technology fingerprinting
[12:00:02] Security headers
[12:00:03] Secret scanning
[12:00:03] DNS lookup
[12:00:04] Username OSINT: someuser
[12:00:06] Risk analysis
[12:00:06] JSON report: reports/example.com_20260403_120006.json
[12:00:06] Text report: reports/example.com_20260403_120006.txt
```

Excerpt from the text report:

```
========================================================================
SENTRYS REPORT
========================================================================
Target        : https://example.com
URL           : https://example.com
Host          : example.com
Scanned at    : 2026-04-03T12:00:01.123456+00:00
Version       : 1.0.0
Risk score    : 82 (B)

========================================================================
TLS
========================================================================
Subject       : example.com
Issuer        : DigiCert Inc
Not before    : Jan  1 00:00:00 2026 GMT
Not after     : Apr  1 00:00:00 2026 GMT
Expires in    : 27 days
TLS version   : TLSv1.3
Cipher        : TLS_AES_256_GCM_SHA384

========================================================================
TECHNOLOGIES
========================================================================
WAF           : Cloudflare
CDN           : Cloudflare
Detected      :
  - Cloudflare
  - Next.js
  - Google Analytics

========================================================================
SECURITY HEADERS
========================================================================
Grade         : B
Present       :
  [+] Strict-Transport-Security: max-age=63072000
  [+] X-Content-Type-Options: nosniff
Missing       :
  [-] Content-Security-Policy (high)
  [-] Permissions-Policy (low)
```

What you do next:

- Read the "Risk reasons" section.
- Inspect the "Secrets" section, if present.
- Feed the JSON report into your own tooling if needed.

---

## 16. Troubleshooting

| Error                                                                 | Cause                                                     | Fix                                                                   |
|-----------------------------------------------------------------------|-----------------------------------------------------------|-----------------------------------------------------------------------|
| `ImportError: cannot import name 'get_logger' from 'sentrys.core.logger'` | The `logger.py` on disk is an older version.             | Replace it with the exact file shown in the installation section.      |
| `ImportError: cannot import name 'Correlator' from 'roxint'`           | Roxint leftovers. Sentrys must live in its own folder.    | Move Sentrys to a separate directory.                                  |
| `ModuleNotFoundError: No module named 'sentrys'`                       | Running from the wrong directory.                         | `cd` into the folder that contains `sentrys.py`.                       |
| `No module named 'dns'`                                                | `dnspython` not installed.                                | `pip install dnspython`. DNS section will otherwise be skipped.        |
| `Target not found` or empty output                                     | URL wrong or host unreachable.                            | Verify the URL in a browser.                                           |
| Username OSINT returns many `unknown`                                  | Platform requires JavaScript or blocks the User-Agent.    | This is expected. Change the User-Agent or accept the unknown status.  |
| Very slow run                                                          | Many concurrent requests, slow target.                    | Lower `--concurrency`.                                                 |
| Proxy errors                                                           | Malformed proxy URL.                                      | Use the format `http://host:port` or `http://user:pass@host:port`.     |
| `Reports directory not found`                                          | Custom output path does not exist.                        | Sentrys creates it automatically. Check write permissions.             |

---

## 17. What Sentrys does not do

- No authentication, no login, no session cookies, no credential use.
- No write requests.
- No exploitation, no fuzzing, no brute force.
- No attempts to bypass WAF, rate limits or access controls.
- No access to private data.
- No traffic estimation for third-party sites.
- No JavaScript execution, so dynamic content may be missed.

Sentrys is a reconnaissance assistant, not a vulnerability scanner. It
gathers publicly available information and flags obvious issues. It does not
replace a professional audit.

---

## 18. Legal and ethical notice

Sentrys is intended for educational and research use, and for inspecting
targets you own or are explicitly authorized to test.

- Only public endpoints are used.
- No authentication, no cookies, no tokens.
- No write operations, no mutations, no bypass of access controls.
- The tool must be used in compliance with the target's Terms of Service and
  with all applicable laws, including data protection and computer misuse
  regulations.

Running any kind of scan against systems you do not own or have written
permission to test may be illegal in your jurisdiction. You are solely
responsible for how you use this tool and for any consequences that follow.

The author assumes no responsibility for misuse.

---

## 19. License

MIT License

Copyright (c) 2026 Qustylex

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
