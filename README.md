# AETHERIS — IPsec VPN Security Analyzer

It parses classic PCAP v2.4 captures, identifies observable IKE/ESP/AH headers, applies a small explicit ruleset, stores results in SQLite, and generates a PDF report.

## Run on Windows

Requirements: Python 3.10+ and Node.js 18+.

For the easiest one-command startup, open PowerShell in this folder and run:

```powershell
python run.py
```

The launcher creates the Python virtual environment, installs missing Python/Node dependencies on first run, starts the API and frontend, waits until both are ready, and opens the dashboard in your browser. Leave that PowerShell window open while using the app; press **Ctrl+C** there to stop both servers. If ports 8000 or 5173 are already occupied, close the other application using the port and try again.

Alternatively, run both servers manually:

```powershell
cd C:\Users\KiTE\Downloads\CYB\CYBER
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
cd frontend
npm install
cd ..
```

In **PowerShell window 1**:

```powershell
cd C:\Users\KiTE\Downloads\CYB\CYBER
.\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

In **PowerShell window 2**:

```powershell
cd C:\Users\KiTE\Downloads\CYB\CYBER\frontend
npm run dev
```

Open <http://127.0.0.1:5173>. To serve a production frontend through FastAPI instead, run `npm run build` in `frontend`, stop the dev server, then start Uvicorn and open <http://127.0.0.1:8000>.

## Demonstration workflow

1. Create a local account with an email and a password of at least 10 characters, then sign in. Account passwords are stored as salted PBKDF2 hashes; the browser receives a 12-hour HTTP-only session cookie.
2. Select **Analyze demo data**. This creates a deterministic, synthetic four-frame PCAP in memory and sends it through the same parser, rules, database, and reporting paths as uploaded captures.
3. Verify packet counts and header details against the result. Demo traffic uses documentation-only IP addresses and is labelled **SYNTHETIC DEMO DATA**.
4. Inspect the rule findings and unknown parameters; the UI labels the ML classifier **NOT IMPLEMENTED** and presents no prediction or confidence.
5. Download the generated PDF report or download the synthetic `.pcap` and upload it.
6. To exercise error handling, upload an empty `.pcap`, a non-PCAP file named `.pcap`, or a `.pcapng` file. A useful error is shown; invalid analyses are not stored.

Authentication is intended only for this local PoC. Password recovery and email verification are not implemented. Do not expose the development server to the public internet or reuse a sensitive password.

## API

| Endpoint | Function |
|---|---|
| `GET /api/health` | Local service status |
| `POST /api/auth/signup` | Create a local account and start a session |
| `POST /api/auth/login` | Sign in and start a session |
| `GET /api/auth/me` | Return the signed-in account |
| `POST /api/auth/logout` | Revoke the current session |
| `GET /api/sample` | Download generated synthetic PCAP bytes |
| `POST /api/analyze/demo` | Analyze the synthetic capture with the real parser |
| `POST /api/analyze?filename=<name>.pcap` | Analyze classic PCAP bytes sent in the request body |
| `GET /api/analysis/{analysis_id}` | Retrieve a stored result |
| `GET /api/analysis/history` | List stored analyses |
| `GET /api/analysis/{analysis_id}/report` | Download the analysis PDF |
| `GET /api/dashboard/statistics` | Aggregates from saved SQLite results |
| `GET /api/ml/status` | Explicitly reports ML as not implemented |

## Supported input and analysis

- Classic PCAP v2.4, microsecond or nanosecond timestamps, Ethernet (including VLAN tags) or raw-IP link types; IPv4 and IPv6 packet headers.
- IKE on UDP/500 and UDP/4500 with structural IKE header validation. Selected IKEv2 SA_INIT transforms are parsed from SA proposals and explicitly reported as **offered, not negotiated**.
- ESP (IP protocol 50 and observable UDP/4500 non-ESP-marker distinction) and AH (IP protocol 51) SPI and sequence metadata.
- A 20 MiB capture limit and 200,000 packet processing limit.
- Rule-based checks on the transforms observed. Score = `min(100, 30 × FAIL + 15 × WARNING)`. PASS and UNKNOWN contribute zero. Categories: LOW 0–14, MEDIUM 15–39, HIGH 40–69, CRITICAL 70–100.
- Reports state the PoC's limitations and include the actual analysis result. The rules are not a compliance certification.

## Standards references

Header parsing and protocol terminology follow the relevant protocol specifications: [RFC 7296 (IKEv2)](https://www.rfc-editor.org/rfc/rfc7296), [RFC 4303 (ESP)](https://www.rfc-editor.org/rfc/rfc4303), and [RFC 4302 (AH)](https://www.rfc-editor.org/rfc/rfc4302). The deliberately small transform review is informed by [RFC 8247 (IKEv2 algorithm implementation recommendations)](https://www.rfc-editor.org/rfc/rfc8247) and [NIST SP 800-77 Rev. 1](https://csrc.nist.gov/pubs/sp/800/77/r1/final). It does not implement a full standards or NIST compliance assessment; operators must verify current policy, proposal context, and negotiated settings.

## Explicitly not implemented

No trained or demo ML classifier, labelled traffic dataset, ML predictions, confidence scores, ESP decryption, live capture, PCAPNG support, PostgreSQL, or blockchain feature is implemented. No claim is made that packets were captured from a real VPN. PFS, IKE authentication, and key lifetimes remain UNKNOWN unless the capture actually exposes relevant evidence; this PoC does not infer them from encrypted payloads.

## Tests

Run the built-in tests (no test-runner installation required):

```powershell
cd C:\Users\KiTE\Downloads\CYB\CYBER
python -m unittest discover -s tests -v
```

The test suite checks the generated PCAP, IKE/ESP/AH parsing, transforms, security scoring, empty/invalid/unsupported inputs, API failure handling, SQLite persistence, and report generation.

## PPTX version

The workspace includes multiple SIH26160 PPTX files. This implementation was not matched to a specific submitted PPTX revision because the authoritative version was not identified. Review the project claims against the **Explicitly not implemented** section before submission.
