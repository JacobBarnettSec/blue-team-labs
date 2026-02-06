# Browser-Based Threat Hunting Investigation

## Introduction
This investigation simulates a SOC analyst performing browser-based threat hunting and indicator enrichment following suspicious activity observed in the environment. The objective is to assess the risk of identified indicators using open-source intelligence (OSINT) tools and determine appropriate security actions.

---

## Scope
The investigation focuses on analyzing a set of indicators of compromise (IOCs), including domains, IP addresses, and URLs, using publicly available threat intelligence platforms.

---

## Indicators Investigated
| # | Indicator | Type | Source |
|---|-----------|------|--------|
| 1 | 185.220.101.1 | IP Address | Observed in network logs |
| 2 | testphp.vulnweb.com | Domain | Observed in browser logs |
| 3 | http://free-giftcards-example.net/redeem | URL | Suspicious link in phishing email |

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

**Analysis:**
- **VirusTotal:** 14/93 security vendors flagged this IP as malicious. Observed activity suggests association with anonymization or spam-related activity. ASN indicates it belongs to a Tor network exit node. No direct malware samples are linked, but the IP has been involved in suspicious traffic.
- **AbuseIPDB:** Reported 6,504 times with an Abuse Confidence Score of 100%. Categories include anonymized proxy usage and potential hacking attempts. ASN AS60729 / ISP Artikel10 e.V., confirming Tor exit node usage. High volume of reports and maximum confidence indicate high-risk activity.
- **URLScan:** Not applicable; IP is a Tor exit node without a directly hosted web service.
- **WHOIS / DNS:** ASN AS60729, operated by Artikel10 e.V., confirms Tor exit node status. Hostname is berlin01.tor-exit.artikel10.org, located in Berlin, Germany. This supports findings from VirusTotal and AbuseIPDB, indicating the IP is high-risk.

**Assessment:** Suspicious / High-risk. Monitor closely, and consider blocking or generating alerts if observed in sensitive network traffic.

---

### Indicator 2
**Indicator:** `testphp.vulnweb.com`  
**Type:** Domain  

**Analysis:**
- **VirusTotal:** 1/93 security vendors flagged this domain as malicious. Domain resolved to the following IPs over time:  
  - 44.228.249.3 (2021-10-29, 1/93 detections)  
  - 18.192.172.30 (2020-11-21, 0/93 detections)  
  - 176.28.50.165 (2019-12-13, 0/93 detections)  
Minimal detections suggest low observed malicious activity, but monitoring is recommended.  

- **AbuseIPDB:** 44.228.249.3 was not found in the database. ISP: Amazon.com, Inc.; Usage Type: Data Center / Web Hosting / Transit; ASN: unknown. Hostname: ec2-44-228-249-3.us-west-2.compute.amazonaws.com, located in Boardman, Oregon, USA. No prior reports of abuse; low risk based on historical activity.  

- **URLScan:** The website contacted 1 IP in 1 country across 1 domain to perform 4 HTTP transactions. Main IP: 44.228.249.3 (Boardman, United States, Amazon.com, Inc.). No external connections flagged as malicious. Verdict: No classification. Page appears benign, consistent with a lab/hosted test environment.  

- **WHOIS / DNS:**  
  - Current A record: 44.228.249.3 (AS16509 - AMAZON-02 - Amazon.com, Inc., US)  
  - Domain registrar: GANDI SAS  
  - Domain creation date: June 13th, 2010  
  - No suspicious registration patterns or recent changes detected  
  - Google Safe Browsing: No classification  

**Assessment:** Benign / Low-risk. The domain appears to be a legitimate test environment hosted on Amazon AWS. No signs of compromise, malicious hosting, or abuse were observed during OSINT enrichment.

---

### Indicator 3
**Indicator:** `http://free-giftcards-example.net/redeem`  
**Type:** URL  

**Analysis:**
- **VirusTotal:** 0/94 security vendors flagged this URL as malicious.  
  - **History:** First submission, last submission, and last analysis all on 2026-02-06 00:39:15 UTC.  
  - **HTTP Response / Final URL:** `http://free-giftcards-example.net/redeem`  
  - No category classification or community comments suggesting malicious activity.  
  - Although no detections were reported, URLs with promotional or “free gift” wording can often be associated with phishing campaigns in real-world investigations, so further enrichment is recommended.

- **AbuseIPDB / IP Analysis:**  
  - No IP address was returned for `free-giftcards-example.net` during DNS resolution.  
  - Without a resolved IP, no AbuseIPDB history or reports could be found.  
  - This behavior is consistent with recently registered, inactive, or intentionally dormant domains often used in phishing campaigns.  

- **URLScan.io:**  
  - Attempted scan returned an **HTTP 400 / DNS Error**.  
  - Domain could not be resolved to an IPv4/IPv6 address; URLScan did not attempt to load the page.  
  - This is consistent with a non-resolving, inactive, or placeholder domain.  

**Assessment (overall):**  
- Current evidence suggests the URL is **inactive**.  
- No active hosting IP, no malicious detections, and no resolved page.  
- Risk remains **low at this time**, but the domain should be **monitored** for future resolution or suspicious activity if observed in alerts or emails.

---

## Conclusions
Based on OSINT enrichment and correlation, the investigated indicators were assessed for maliciousness and risk to the environment.  

- **Indicator 1 (185.220.101.1):** High-risk. Associated with Tor exit node traffic and numerous abuse reports.  
- **Indicator 2 (testphp.vulnweb.com):** Benign / Low-risk. Legitimate test environment hosted on Amazon AWS, no signs of compromise.  
- **Indicator 3 (http://free-giftcards-example.net/redeem):** Low-risk. Domain is currently inactive with no resolved IP or malicious detections, but should be monitored for potential future activity.

Overall, this investigation demonstrates effective OSINT enrichment, threat intelligence analysis, and proactive risk assessment in a browser-only environment.

---

## Recommended Actions
- **Block confirmed malicious indicators** at network and email gateways (e.g., Indicator 1).  
- **Monitor suspicious or inactive indicators** for future activity or resolution (e.g., Indicator 3).  
- **No action required** for confirmed benign indicators (e.g., Indicator 2).  
- **Document all findings** for future reference, trend analysis, and detection tuning.  
- **Update threat-hunting procedures** based on observations, including monitoring of newly registered or dormant domains that may later become active threats.

---

## Sources / References
- VirusTotal  
- AbuseIPDB  
- URLScan  
- WHOIS / DNS lookup tools
