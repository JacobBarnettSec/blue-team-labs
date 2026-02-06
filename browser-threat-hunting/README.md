# Browser-Based Threat Hunting Lab

## Overview
This lab demonstrates proactive, browser-only threat hunting using open-source intelligence (OSINT) tools. The investigation focuses on analyzing suspicious domains, IP addresses, and URLs to assess risk and determine potential malicious activity.

This project is part of the **blue-team-labs** repository and is designed to showcase SOC investigative techniques in a browser-only environment.

---

## Objectives
- Analyze and enrich indicators of compromise (IOCs) including domains, IP addresses, and URLs.  
- Evaluate maliciousness and risk to the environment using OSINT sources.  
- Document findings and recommended security actions.

---

## Tools Used
- VirusTotal  
- AbuseIPDB  
- URLScan  
- WHOIS / DNS lookup tools  
- Google and OSINT search techniques

---

## Case File
The full investigation is documented in [threat-hunt-case.md](./threat-hunt-case.md), including:  
- Indicators analyzed  
- Step-by-step OSINT enrichment  
- Risk assessment for each indicator  
- Recommended security actions

---

## Recommended Actions
- Block confirmed malicious indicators at network or email gateways.  
- Monitor suspicious or inactive indicators for future activity.  
- Document all findings for reference and trend analysis.

