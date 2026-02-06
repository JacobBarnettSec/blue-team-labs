# Browser-Based Threat Hunting Investigation

## Introduction
This investigation simulates a SOC analyst performing browser-based threat hunting and indicator enrichment following suspicious activity observed in the environment. The objective is to assess the risk of identified indicators using open-source intelligence (OSINT) tools and determine appropriate security actions.

---

## Scope
The investigation focuses on analyzing a set of indicators of compromise (IOCs), including domains, IP addresses, and URLs, using publicly available threat intelligence platforms.

---

## Indicators Investigated
| # | Indicator | Type | Source | Risk Level |
|---|-----------|------|--------|------------|
| 1 | 185.220.101.1 | IP Address | Observed in network logs | High |
| 2 | testphp.vulnweb.com | Domain | Observed in browser logs | Low |
| 3 | http://free-giftcards-example.net/redeem | URL | Suspicious link in phishing email | Low / Monitor |

---

## Investigation Methodology
Each indicator was analyzed using multiple OSINT tools to assess reputation, activity history, and associations with known malicious campaigns.

**Tools used:**
- VirusTotal  
- AbuseIPDB  
- URLScan  
- WHOIS / DNS lookup tools  

---

## Findings

### Indicator 1
**Indicator:** 185.220.101.1  
**Type:** IP Address  
**Risk Level:** High

**Analysis:**
- **VirusTotal:** 14/93 security vendors flagged this IP as malicious. Activity suggests association with anonymization or spam. ASN indicates a Tor exit node. No direct malware samples linked.  
- **AbuseIPDB:** 6,504 reports; Abuse Confidence Score 100%. Categories: anonymized proxy, potential hacking attempts. ASN AS60729 / ISP Artikel10 e.V. confirms Tor exit node usage.  
- **URLScan:** Not applicable; IP does not host web services.  
- **WHOIS / DNS:** ASN AS60729, hostname berlin01.tor-exit.artikel10.org, Berlin, Germany.

**Assessment:** High-risk. Consider blocking or alerting if observed in sensitive network traffic.

---

### Indicator 2
**Indicator:** `testphp.vulnweb.com`  
**Type:** Domain  
**Risk Level:** Low

**Analysis:**
- **VirusTotal:** 1/93 vendors flagged across historical IPs; minimal detections.  
- **AbuseIPDB:** No abuse reports. ISP: Amazon.com, Inc.; AWS hosting; no prior abuse.  
- **URLScan:** One IP contacted in one country; no malicious activity observed.  
- **WHOIS / DNS:** A record: 44.228.249.3 (AS16509 - AMAZON-02, US). Registrar: GANDI SAS. Domain created June 13, 2010. Google Safe Browsing: No classification.

**Assessment:** Benign / Low-risk. Appears to be a legitimate test environment.

---

### Indicator 3
**Indicator:** `http://free-giftcards-example.net/redeem`  
**Type:** URL  
**Risk Level:** Low / Monitor

**Analysis:**
- **VirusTotal:** 0/94 vendors flagged. URL contains “free gift” wording, often used in phishing, but no current detections.  
- **AbuseIPDB / IP Analysis:** Domain did not resolve; no reports. Likely inactive or recently registered.  
- **URLScan.io:** Scan failed (HTTP 400 / DNS error). Domain currently inactive.

**Assessment:** Low-risk. Monitor for potential future activity if observed in alerts or emails.

---

## Conclusions
Based on OSINT enrichment and correlation:

- **Indicator 1:** High-risk; associated with Tor exit node traffic and multiple abuse reports.  
- **Indicator 2:** Low-risk; legitimate test environment with no malicious activity.  
- **Indicator 3:** Low-risk; currently inactive, but may require monitoring.

This investigation demonstrates OSINT enrichment, threat intelligence analysis, and proactive risk assessment in a browser-only environment.

---

## Recommended Actions
- Block confirmed malicious indicators at network or email gateways (e.g., Indicator 1).  
- Monitor suspicious or inactive indicators for future activity (e.g., Indicator 3).  
- No action required for confirmed benign indicators (e.g., Indicator 2).  
- Document all findings for reference, trend analysis, and detection tuning.  
- Update threat-hunting procedures based on observations, including monitoring newly registered or dormant domains.

---

## Sources / References
- VirusTotal  
- AbuseIPDB  
- URLScan  
- WHOIS / DNS lookup tools
