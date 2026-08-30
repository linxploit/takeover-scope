<div align="center">

```
 _____  _    _  _______ _____     _______ ____  ____   ____ ___  ____  _____
|_   _|/ \  | |/ / ____/ _ \ \   / / ____|  _ \/ ___| / ___/ _ \|  _ \| ____|
 | | / _ \ | ' /|  _|| | | \ \ / /|  _| | |_) \___ \| |  | | | | |_) |  _|
  | |/ ___ \| . \| |__| |_| |\ V / | |___|  _ < ___) | |__| |_| |  __/| |___
   |_/_/   \_\_|\_\_____\___/  \_/  |_____|_| \_\____/ \____\___/|_|   |_____|
```

### ✦ Subdomain Takeover & Dangling CNAME Detector ✦

**Detection only. Never claims or registers anything.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Made by Mindless](https://img.shields.io/badge/Made%20by-Mindless-ff69b4.svg)](https://linxploit.com/founder)
[![Linxploit](https://img.shields.io/badge/Linxploit-linxploit.com-black.svg)](https://linxploit.com)

**Made by [Mindless](https://linxploit.com/founder) — Founder & CEO of [Linxploit](https://linxploit.com)**

</div>

---

## 🧠 What is TakeoverScope?

**TakeoverScope** checks a list of subdomains for the classic **dangling CNAME** pattern that leads to subdomain takeover: a DNS record still points at a third-party hosting service (GitHub Pages, Heroku, Shopify, S3, Surge, and 15+ others), but the resource on that service was deleted, renamed, or never claimed — leaving the subdomain wide open for anyone to register the same resource name and serve their own content under your domain.

It works exactly the way every public subdomain-takeover checklist describes: resolve the CNAME chain, check whether it points at a known vulnerable service, and — where it does — make one ordinary HTTP request to see if that service is still showing an "unclaimed" page. It never attempts to actually claim, register, or take over anything.

---

## ✨ Features

- 🎨 **Clean, color-coded terminal output** — per-host verdicts, the full CNAME chain, and a scan summary with a dedicated "verify these manually" list for anything flagged vulnerable.
- 🕵️ **20 built-in service fingerprints** covering GitHub Pages, Heroku, AWS S3, Shopify, Fastly, Surge.sh, Bitbucket, Tumblr, Unbounce, WordPress.com, Zendesk, Webflow, Ghost, Pantheon, Cargo Collective, Help Scout, UserVoice, Intercom, Netlify, and Azure.
- 🔗 **Full CNAME chain resolution** — follows multi-hop CNAME chains (up to 8 levels) rather than assuming a single hop.
- 🧭 **Five-way classification**, not just yes/no:
  - **VULNERABLE** — known service + dangling target (NXDOMAIN) or a matched "unclaimed resource" fingerprint in the response body.
  - **SUSPICIOUS** — CNAME target is dangling (NXDOMAIN) but isn't in the fingerprint database — still worth a manual look.
  - **UNKNOWN_SERVICE** — CNAME points somewhere outside the known-service list; out of this tool's coverage.
  - **NOT_VULNERABLE** — CNAME target resolves and responds normally; the resource is claimed and active.
  - **NOT_APPLICABLE** — no CNAME record at all (direct A/AAAA, or doesn't resolve).
- 🧩 **User-extensible fingerprint database** — pass `--fingerprints custom.json` to add or override services, since providers change their error pages over time and any static list will eventually go stale.
- ⚡ **Concurrent scanning** of an entire subdomain list — feed it straight from the output of your passive-recon step (crt.sh, Amass, Sublist3r, etc.).
- 🌐 **Custom DNS resolver support** (`--resolver`) and a DNS-only fast mode (`--skip-http`) for large lists.
- 📊 **Exportable reports** — full **JSON** (every field) or flat **CSV**.
- 🛡️ **Authorization gate** — confirms you're allowed to assess a target before making a single request (skippable with `--yes`).

---

## 📸 Preview

```
✦ Subdomain Takeover & Dangling CNAME Detector ✦
v1.0.0 · Detection only. Never claims or registers anything.

[ VULNERABLE      ] blog.example.com
          🔗 CNAME: blog.example.com → ghost-blog.surge.sh
          service: Surge.sh
          › CNAME points to Surge.sh, and the response body matches its
            'unclaimed resource' fingerprint ('project not found').

[ SUSPICIOUS      ] old.example.com
          🔗 CNAME: old.example.com → legacy.some-random-startup.io
          › CNAME points to 'legacy.some-random-startup.io', which doesn't
            resolve (NXDOMAIN) — not in the known service fingerprint list.

[ NOT_VULNERABLE  ] shop.example.com
          🔗 CNAME: shop.example.com → realstore.myshopify.com
          service: Shopify

[ SCAN SUMMARY ]
────────────────────────────────────────────────────────────
  VULNERABLE       :   1  •
  SUSPICIOUS       :   1  •
  NOT_VULNERABLE   :   1  •

  ⚠ 1 likely-vulnerable subdomain(s) — verify manually before disclosure:
    • blog.example.com → ghost-blog.surge.sh (Surge.sh)
```

---

## 📦 Installation

```bash
git clone https://github.com/linxploit/takeover-scope.git
cd takeover-scope
pip install -r requirements.txt
```

Requires **Python 3.8+**.

---

## 🚀 Usage

### Check a single subdomain

```bash
python3 takeoverscope.py -d blog.example.com
```

### Check a list of subdomains (typical passive-recon output)

```bash
python3 takeoverscope.py -l examples/subdomains.txt --threads 10
```

### Faster, DNS-only pass (no HTTP requests)

```bash
python3 takeoverscope.py -l examples/subdomains.txt --skip-http
```

### Use your own / extended fingerprint database

```bash
python3 takeoverscope.py -l examples/subdomains.txt --fingerprints examples/custom_fingerprints.json
```

### Use a specific DNS resolver

```bash
python3 takeoverscope.py -l examples/subdomains.txt --resolver 1.1.1.1 --resolver 8.8.8.8
```

### Save a report

```bash
python3 takeoverscope.py -l examples/subdomains.txt -o report.json
python3 takeoverscope.py -l examples/subdomains.txt -o report.csv
```

### Skip the authorization prompt (for your own automated pipelines)

```bash
python3 takeoverscope.py -l examples/subdomains.txt --yes
```

### Full option reference

```bash
python3 takeoverscope.py --help
```

| Flag | Description |
|---|---|
| `-d`, `--domain` | Single subdomain/hostname to check |
| `-l`, `--list` | File with one subdomain per line |
| `--fingerprints` | Path to a custom JSON fingerprint file |
| `-t`, `--timeout` | DNS/HTTP timeout in seconds (default: `8`) |
| `--threads` | Concurrent hostnames checked in parallel (default: `10`) |
| `--resolver` | Custom DNS resolver IP, repeatable |
| `--skip-http` | Skip the HTTP fingerprint check — DNS/NXDOMAIN signals only |
| `-o`, `--output` | Save report to `.json` or `.csv` |
| `-v`, `--verbose` | Show the reasoning note for every result |
| `--yes` | Skip the authorization confirmation prompt |
| `--no-banner` | Suppress the ASCII banner |
| `--version` | Print version info and exit |

---

## 🧩 Writing a custom fingerprint file

```json
[
  {
    "service": "My Internal Platform",
    "cname": ["staging.internal-platform.com"],
    "http": ["No deployment found for this subdomain"],
    "nxdomain_confirms": false
  }
]
```

- `cname` — substrings matched (case-insensitively) against the final CNAME target.
- `http` — substrings that indicate an *unclaimed* resource when found in the response body.
- `nxdomain_confirms` — whether a bare NXDOMAIN on the target is enough by itself to call it vulnerable for this service (`true` for most), or whether the HTTP fingerprint is required (`false` — used for services like S3 and Azure where a resolving-but-empty state is more common than outright NXDOMAIN).

See `examples/custom_fingerprints.json` for a working example.

---

## ⚠️ A note on fingerprint freshness

Hosting providers update their error pages. A fingerprint that worked last year may not match today, and a service not yet in the default list might be exactly the one that matters for your target. Treat the built-in database as a solid starting point, not a permanent source of truth — cross-reference against actively maintained community lists (such as EdOverflow's `can-i-take-over-xyz` project) periodically, and extend `--fingerprints` as needed.

> ⚠️ **A VULNERABLE verdict is strong evidence, not proof.** Always confirm manually — attempt to view the actual unclaimed-resource page yourself, check the service's current registration flow — before reporting or acting on a finding.

---

## ⚖️ Responsible use

TakeoverScope performs ordinary DNS queries and, for matched services, a single ordinary HTTP GET per subdomain — the same kind of traffic any browser or DNS-aware tool generates. It never registers, claims, or configures anything on any third-party service. Still:

- Only run TakeoverScope against domains you **own** or have **explicit permission** to assess.
- TakeoverScope will ask you to confirm authorization before scanning, every time, unless you pass `--yes`.
- If you do confirm a real takeover opportunity, follow responsible disclosure — don't claim the resource yourself without authorization, even to "prove" the finding.
- You are solely responsible for how you use this tool and for complying with all applicable laws and the terms of any authorization you've been granted.

---

## 🛠️ Project structure

```
takeover-scope/
├── takeoverscope.py              # Main executable — the tool itself
├── requirements.txt                 # Python dependencies
├── examples/
│   ├── subdomains.txt                  # Example target list for -l/--list
│   └── custom_fingerprints.json        # Example custom fingerprint file
├── tests/
│   └── test_takeoverscope.py           # Unit tests (plus a live DNS integration test)
├── LICENSE                          # MIT License
└── README.md                         # You are here
```

---

## 🤝 Contributing

Issues and pull requests are welcome — updated/additional service fingerprints are especially valuable, since this category of tool only stays useful if the database stays current.

---

## 📜 License

Released under the [MIT License](LICENSE).

---

<div align="center">

### Made by **Mindless**
**Founder & CEO of [Linxploit](https://linxploit.com)**

🌐 [linxploit.com](https://linxploit.com) &nbsp;·&nbsp; 👤 [linxploit.com/founder](https://linxploit.com/founder)

</div>
