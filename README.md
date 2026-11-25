# Day 1 – Web Server Log Analysis: Directory Enumeration Detection

|||
|-|-|
|**Candidate Name**|Abhishek Gulati|
|**Track**|Blue Team |
|**Time Spent**|1 hour |
|**Date**|25 November 2026|

\---

## 1\. Objective

Generate a synthetic Nginx access log containing a hidden directory-enumeration attack, detect it using both command-line tools and a custom Python script, extract the attacker's IP address and User-Agent, and summarize the findings with defensive recommendations.



## 2\. Scope \& Environment

|Item|Detail|
|-|-|
|OS / Shell|Ubuntu (Linux), bash|
|Tools|Python 3 (`re`, `collections`, `datetime`), `grep`, `awk`, `sort`, `uniq`, `wc`, `md5sum`|
|Log format|Nginx / Apache **combined** log format|
|Data source|**100% synthetic**, created by my own script `evidence/generate\_log.py` (fixed random seed → reproducible; MD5 `196f12a8fc75e16f49417395e956c4f1`)|
|IP addresses|RFC 5737 documentation ranges only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) – not routable, not real hosts|
|Domain|`shop.example.test` (reserved, non-existent)|
|Network activity|**None.** No scanning of any real system. The "attack" is only lines of text written to a file.|

**Confirmation:** all data is self-generated synthetic data. No real company data, PII, leaked databases, or live infrastructure were used.



## 3\. Methodology

1. **Created the lab dataset** – wrote `generate\_log.py` to produce 4,570 log lines for a day (24 Nov 2026, 09:00–18:00 UTC) containing:

   * \~4,200 normal requests from 66 benign IPs (including \~3% natural 404s from stale links and `robots.txt`/favicon requests)
   * a **decoy** benign crawler (`192.0.2.50`, `ExampleBot/2.1`) with a few 404s, to test for false positives
   * an **attacker** (`198.51.100.77`) running a gobuster-style wordlist scan, then following up on discoveries

```bash
   cd evidence \&\& python3 generate\_log.py     # -> access.log (4570 lines)
   md5sum access.log
   ```

2. **Baseline the traffic** – count lines and status code distribution:

```bash
   wc -l access.log
   awk '{print $9}' access.log | sort | uniq -c | sort -rn
   ```

3. **Find the 404 spike by source IP** – the key hunting query:

```bash
   awk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head
   ```

4. **Profile the suspect IP** – User-Agents, paths, timing:

```bash
   grep "^198.51.100.77" access.log | awk -F\\" '{print $6}' | sort | uniq -c
   grep "^198.51.100.77" access.log | awk '$9==404{print $7}' | head -10
   grep "^198.51.100.77" access.log | awk '{print substr($4,2,17)}' | uniq -c
   ```

5. **Look for what the attacker FOUND** (non-404 responses from that IP):

```bash
   grep "^198.51.100.77" access.log | awk '$9!=404 {print $4,$9,$10,$7}'
   ```

6. **Automate and validate with Python** – `analyze\_log.py` parses every line with a regex, flags any IP with **≥ 50 404s inside a 5-minute window**, and prints a profile. Run:

```bash
   python3 analyze\_log.py access.log | tee analysis\_output.txt
   ```

7. **Cross-check for false positives** – confirmed the decoy crawler `192.0.2.50` (11 × 404, 9% of its traffic) did **not** trip the detector.
8. **Mapped to MITRE ATT\&CK and wrote defensive controls** (`fail2ban\_nginx\_scanner.conf`, `nginx\_hardening\_snippet.conf`).

## 4\. Findings / Analysis

### 4.1 Detection summary

|Metric|Value|
|-|-|
|Total requests analysed|4,570|
|Total 404 responses|344|
|404s from attacker IP|**205 (60% of all 404s in the log)** from one IP|
|Attacker's 404 ratio|82% (normal users: \~5–9%)|
|Unique non-existent paths probed|205|
|Enumeration speed|216 requests in 16 seconds ≈ **13.5 req/s** (14:32:05 → 14:32:21 UTC)|

The next-highest 404 source had only 11 – a clear outlier.

### 4.2 Indicators of Compromise (IOCs)

|Type|Value|
|-|-|
|**Attacker IP**|`198.51.100.77`|
|**User-Agent #1 (scanner)**|`gobuster/3.6` (216 requests)|
|**User-Agent #2 (spoofed browser)**|`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36` (34 requests)|
|Attack window|2026-11-24 14:32:05 – 14:36:57 UTC|
|Targeted paths|`/admin`, `/backup.sql`, `/config.php.bak`, `/.git/HEAD`, `/.env`, `/wp-admin`, `/phpmyadmin`, `/server-status` …|
|Follow-up target|`POST /admin/login`|

### 4.3 Attack timeline

|Time (UTC)|Event|
|-|-|
|14:32:05 – 14:32:21|**Phase 1 – Enumeration.** gobuster fires 216 GETs. 205 return 404.|
|14:32:09 – 14:32:20|Discoveries: `/.git/HEAD` (200), `/backup.sql` (200, 2.4 MB), `/config.php.bak` (200), `/admin` (301), `/uploads` (301), `/api` (301); `/backup`, `/server-status`, `/.env` return 403 (exist but forbidden).|
|14:32 – 14:35|\~3 min pause (operator reviews results).|
|14:35:27 – 14:36:02|**Phase 2 – Exploitation of exposed files.** UA switched to a Chrome string; attacker browses `/admin/`, downloads `/backup.sql` (200, 2,483,921 B) and `/config.php.bak`.|
|14:36:04 – 14:36:57|**Phase 3 – Credential guessing.** 30 × `POST /admin/login`: 29 × **401**, then 1 × **302** (redirect – likely **successful login**).|

### 4.4 Key analytical points

* **Why it is enumeration, not a broken link:** hundreds of *distinct* paths from one IP in seconds, all dictionary-style names (`admin`, `backup`, `.git`, `wp-login.php`), with a gobuster User-Agent.
* **User-Agent is not reliable alone:** the attacker switched to a spoofed Chrome UA in phase 2. **Pivoting on the IP** exposed the full kill chain – a UA-only rule would have missed phase 2.
* **403 ≠ safe:** a 403 confirms the resource exists (information leak).
* **The 2.4 MB `backup.sql` returned 200 with full byte count** → treat as a confirmed data exposure.
* **False positive handled:** `ExampleBot/2.1` produced some 404s but at a slow, steady pace – not flagged.

### 4.5 MITRE ATT\&CK mapping

|Technique|ID|Evidence|
|-|-|-|
|Active Scanning: Wordlist Scanning|T1595.003|gobuster, 205 unique 404 paths|
|Unsecured Credentials: Credentials in Files|T1552.001|`config.php.bak` served|
|Brute Force: Password Guessing|T1110.001|30 POSTs to `/admin/login`|
|Exploit Public-Facing Application (exposed admin/backup)|T1190|Sensitive files reachable from the internet|

## 5\. Recommendation / Remediation

### Immediate (contain)

1. **Block** `198.51.100.77` at the WAF/firewall (and watch for related infrastructure).
2. **Assume the admin account is compromised** (the 302 after 29 failures): force password reset, invalidate all sessions, check admin audit logs for actions after 14:36:57.
3. **Rotate every secret** inside `config.php.bak` (DB passwords, API keys) and treat the data in `backup.sql` as breached.
4. **Remove** `backup.sql`, `config.php.bak`, and the `.git` directory from the web root.

### Short term (harden) – see `evidence/nginx\_hardening\_snippet.conf`

5. Deny dotfiles and backup extensions (`.git`, `.env`, `.sql`, `.bak`, `.old`, `.zip`).
6. Rate-limit per IP (`limit\_req`) and auto-ban 404 floods (`fail2ban` – see `evidence/fail2ban\_nginx\_scanner.conf`).
7. Restrict `/admin/` to VPN / allow-listed IPs; enforce **MFA** and account lockout on login.
8. Deploy a WAF with scanner/bot rules.

### Detection engineering

9. SIEM alert: **≥ 50 404s from one IP in 5 minutes**; second alert on **many 401s followed by a 302/200** on the same login URL.
10. Alert on known scanner UAs, but **correlate by IP** since UAs are spoofable. Behind a CDN/proxy, log `X-Forwarded-For` so the real client IP is analysed.

### Business impact

|Area|Impact|
|-|-|
|Confidentiality|Database backup and config secrets exposed → customer data leak risk|
|Integrity / Availability|Possible admin takeover → defacement, data tampering, further pivoting|
|Legal / Compliance|Likely breach notification duties (e.g. GDPR / India's DPDP Act) and fines|
|Reputation / Cost|Incident response, customer trust loss, possible regulatory penalties|

## 6\. Repository Structure

```
day1-yourname-blue/
├── README.md
└── evidence/
    ├── generate\_log.py              # synthetic log generator (seeded)
    ├── access.log                   # generated log (4,570 lines)
    ├── analyze\_log.py               # detection script
    ├── analysis\_output.txt          # script output
    ├── commands\_output.txt          # grep/awk command output
    ├── fail2ban\_nginx\_scanner.conf  # defensive control
    └── nginx\_hardening\_snippet.conf # defensive control
```

## 7\. Self-Attestation

I self-sourced all materials, used only public/synthetic/self-owned resources, and performed non-destructive work.

