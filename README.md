<div align="center">

# 🔍 Footprinting & Network Scanning Report

**Reconnaissance and Local Network Discovery — Week 2, Cybersecurity Internship**

![Status](https://img.shields.io/badge/status-completed-brightgreen)
![Phase](https://img.shields.io/badge/phase-recon%20%26%20scanning-blue)
![Tools](https://img.shields.io/badge/tools-WHOIS%20%7C%20WhatWeb%20%7C%20Nslookup%20%7C%20Curl%20%7C%20Wafw00f%20%7C%20DNSRecon%20%7C%20Zenmap-informational)

</div>

---

## 📋 Table of Contents

- [Disclaimer](#-disclaimer)
- [Overview](#-overview)
- [Environment](#-environment)
- [Toolkit](#-toolkit)
- [Part 1 — Domain Footprinting](#-part-1--domain-footprinting)
- [Part 2 — Local Network Scanning](#-part-2--local-network-scanning)
- [Findings & Risk Summary](#-findings--risk-summary)
- [Recommendations](#-recommendations)
- [Evidence](#-evidence)
- [Lessons Learned](#-lessons-learned)
- [About](#-about)

---

## ⚠️ Disclaimer

> All activity documented here was carried out only against systems and networks I own or was explicitly authorized to test, as part of a supervised training program. This report is for educational purposes only.

---

## 🧭 Overview

| | |
|---|---|
| **Trainee** | Saud Ur Rehman Abbasi |
| **Program / Batch** | NetworkWalks-B083 |
| **Date** | 17 September 2026 |
| **Target(s)** | networkwalks.com (written permission obtained) · own local LAN |
| **Modules** | Footprinting (multi-tool) · Zenmap network scan |


This report walks through two linked exercises: gathering public information about a target domain, and then discovering live devices on a local network. Together they illustrate the two earliest stages of a real-world attack path — open-source intelligence gathering, followed by internal reconnaissance.

Every step below lists the **command run**, the **result observed**, and **why it matters** from an attacker's perspective.

---

## 🖥️ Environment

- Domain footprinting performed from **Kali Linux**
- Network scanning performed from a **Windows host** running **Zenmap** (Nmap GUI)

---

## 🧰 Toolkit

| Tool | Role |
|---|---|
| `whois` | Pulls domain registration data — registrant, dates, name servers |
| `whatweb` | Fingerprints the web stack — CMS, plugins, server software |
| `nslookup` | Resolves the domain to its hosting IP address |
| `curl -I` | Reads raw HTTP response headers |
| `wafw00f` | Detects the presence/vendor of a Web Application Firewall |
| `dnsrecon` | Enumerates DNS records — NS, MX, TXT/SPF, SRV |
| `Zenmap` | GUI front-end for Nmap; used for host discovery + topology mapping |
| `ipconfig` | Confirms local IP/subnet before scanning |

---

## 🌐 Part 1 — Domain Footprinting

<details open>
<summary><strong>1. WHOIS lookup</strong></summary>

**Command:** `whois networkwalks.com`

**Observed:**
| Field | Value |
|---|---|
| Registrar | GoDaddy.com, LLC (IANA ID 146) |
| Creation Date | 2019-11-06 |
| Expiry Date | 2027-11-06 |
| Last Updated | 2025-11-12 |
| Name Servers | NS6135.HOSTGATOR.COM, NS6136.HOSTGATOR.COM |
| Domain Status | clientDeleteProhibited, clientRenewProhibited, clientTransferProhibited, clientUpdateProhibited |
| DNSSEC | unsigned |

**Why it matters:** The registrar and name-server records show the domain is registered through GoDaddy but hosted/resolved via HostGator name servers — a mismatch worth noting when profiling infrastructure. DNSSEC being unsigned also means DNS responses for this domain aren't cryptographically verifiable.

</details>

<details>
<summary><strong>2. WhatWeb fingerprinting</strong></summary>

**Command:** `whatweb networkwalks.com`

**Observed:**
- Server: **Apache**, IP **192.232.216.135**
- CMS: **WordPress 7.1**, with **WP Download Manager 3.3.58** plugin active
- Contact email exposed in page metadata: `info@networkwalks.com`
- Uses Bootstrap, jQuery 3.7.1, Google Tag Manager
- Page title: "NetworkWalks Academy"
- HTTP → HTTPS redirect in place (301 → 200)

**Why it matters:** The exposed CMS and plugin *versions* are the most actionable finding here — they let an attacker check directly against known WordPress/plugin CVEs rather than guessing at the stack.

</details>

<details>
<summary><strong>3. DNS resolution</strong></summary>

**Command:** `nslookup networkwalks.com`

**Observed:** Resolved to **192.232.216.135** (via local resolver 192.168.1.1)

**Why it matters:** Confirms the hosting IP, useful for pivoting into IP-based reconnaissance (reverse DNS, shared-hosting checks, ASN lookups, etc.).

</details>

<details>
<summary><strong>4. HTTP header inspection</strong></summary>

**Command:** `curl -I https://networkwalks.com`

**Observed:**
- `HTTP/2 200`
- `server: Apache`
- `x-nginx-cache: WordPress` (caching layer identified)
- `link:` header exposes the WordPress REST API root at `/wp-json/` and `api.w.org`, plus a `rel="shortlink"`
- `set-cookie: __qpde_client...` and a fairly permissive `permissions-policy` referencing Google, reCAPTCHA, Cloudflare and hCaptcha domains
- `referrer-policy: no-referrer-when-downgrade`

**Why it matters:** The `/wp-json/` REST endpoint and cache header confirm WordPress hosting details beyond what WhatWeb alone showed, and give another route for enumeration (e.g. querying `/wp-json/wp/v2/users`).

</details>

<details>
<summary><strong>5. WAF detection</strong></summary>

**Command:** `wafw00f networkwalks.com`

**Observed:** Site is behind **ModSecurity (SpiderLabs)** — identified after 2 requests.

**Why it matters:** Confirms a WAF is actively protecting the site, which shapes how an attacker would need to approach evasion versus a completely unprotected target.

</details>

<details>
<summary><strong>6. DNS record enumeration</strong></summary>

**Command:** `dnsrecon -d networkwalks.com`

**Observed:** 8 records found, including:
| Type | Value |
|---|---|
| SOA | ns6135.hostgator.com, 50.87.144.87 |
| NS | ns6135.hostgator.com, ns6136.hostgator.com |
| MX | mail.networkwalks.com → 192.232.216.135 |
| A | networkwalks.com → 192.232.216.135 |
| TXT (SPF) | `v=spf1 -a +mx +ip4:50.87.144.87 +include:websitewelcome.com ~all` |
| TXT | Google site-verification token |
| SRV (×6) | `_autodiscover._tcp` records pointing to `cpanelemaildiscovery.cpanel.net` across several `184.94.20x.x` hosts |

No answer received for a **DNSSEC** query, consistent with the "unsigned" status seen in WHOIS.

**Why it matters:** The SPF record and autodiscover SRV records confirm cPanel-based email hosting alongside the web hosting, rounding out the infrastructure picture built from the previous steps.

</details>

---

## 📡 Part 2 — Local Network Scanning

**Goal:** identify the local subnet, discover live hosts, and produce a topology map.

1. **Identify local subnet** — confirmed local subnet as **192.168.108.0/24**
2. **Ping scan** — ran `nmap -sn 192.168.108.0/24` (Zenmap's "Ping scan" profile)
3. **Hosts discovered:** 2 hosts up, scanned in 8.19 seconds

   | # | IP Address | MAC Address | Notes |
   |---|---|---|---|
   | 1 | 192.168.108.1 | — | Host is up (latency 0.00089s) |
   | 2 | 192.168.108.254 | 00:50:56:85:d3:9c | Vendor: VMware |

4. **Topology** — generated the network topology view in Zenmap, enabled the legend, exported to PDF (see [Evidence](#-evidence))

> Only two hosts responded on this subnet, and the second is a VMware virtual adapter/host rather than a physical device — consistent with running Zenmap from inside a VM-based lab environment.

---

## 🚦 Findings & Risk Summary

| # | Finding | Source | Impact | Risk |
|---|---|---|---|:---:|
| 1 | WordPress 7.1 + WP Download Manager 3.3.58 version exposed | WhatWeb | Enables targeted CVE lookups against known plugin/core versions | 🟡 Medium |
| 2 | Hosting IP (192.232.216.135) identifiable | Nslookup / WhatWeb | Reveals network location of the web service | 🟢 Low |
| 3 | `/wp-json/` REST API + cache header exposed | Curl | Aids fingerprinting & supports further WP REST enumeration | 🟢 Low |
| 4 | ModSecurity (SpiderLabs) WAF identifiable | Wafw00f | Reveals security architecture detail | 🟢 Low |
| 5 | Full DNS/mail infrastructure (cPanel, SPF, MX) exposed | DNSRecon | Helps build a broader hosting/email infra profile | 🟡 Medium |
| 6 | 2 live hosts identified on local subnet | Zenmap | Confirms scope of reachable devices; VMware host warrants review if unexpected | 🟢 Low |

> These are **observations from information-gathering activities**, not confirmed vulnerabilities. No exploitation or validation was performed — a discovered version number or open service does not by itself prove exploitability. Further authorized testing would be needed to confirm real risk.

---

## 🛡️ Recommendations

- [ ] Regularly audit what technology/version information is publicly exposed
- [ ] Keep CMS, plugins, and server software patched against current advisories
- [ ] Review HTTP response headers for unnecessary information disclosure
- [ ] Periodically review DNS records for stale or unintended entries
- [ ] Keep the WAF properly configured, tuned, and monitored
- [ ] Run internal network discovery scans on a regular cadence
- [ ] Investigate any unrecognized device found on the network
- [ ] Maintain up-to-date network topology documentation
- [ ] Always scope and authorize testing in writing before scanning

---

## 🖼️ Evidence

<details>
<summary>Click to expand screenshots</summary>

- `![WHOIS output](./screenshots/whois.png)`
- `![WhatWeb output](./screenshots/whatweb.png)`
- `![Nslookup output](./screenshots/nslookup.png)`
- `![Curl headers](./screenshots/curl.png)`
- `![Wafw00f output](./screenshots/wafw00f.png)`
- `![DNSRecon output](./screenshots/dnsrecon.png)`
- `![Zenmap host discovery](./screenshots/zenmap-hosts.png)`
- `![Network topology](./screenshots/topology.pdf)` — *not yet captured, add once exported*

*(Drop the corresponding screenshots into a `/screenshots` folder in this repo — the six command-output images are ready to go; the topology export is still outstanding.)*

</details>

---

## 🎓 Lessons Learned

- A surprising amount can be learned about a target **before** any exploitation is attempted, just from public records and response headers.
- Good reporting explains four things clearly for every finding: what was done, what was found, what it means, and what to do about it.
- Reconnaissance and scanning — even "just discovery" — should always happen inside an authorized, documented scope.

---

## 👤 About

**`<Your Name>`** — Cybersecurity Trainee
`<Program name>` · Week 2
[LinkedIn](<your-linkedin-url>)

</div>
