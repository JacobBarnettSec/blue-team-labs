# Phishing Investigation #1

## Email Overview
- Reported by: User
- Date received: Unknown
- Subject: New Voice Message
- Sender address: Unknown (spoofed voicemail notification)

## Initial Assessment
This email appears suspicious because it claims to be a new voicemail from an unknown number and includes an attachment that prompts the user to download a file. The Office 365 logo is used to make the email look legitimate, and the attachment ultimately leads to a page disguised as an Outlook login, which is a common phishing tactic to capture credentials.

## Header Analysis
- SPF result: Unknown / not provided in sample
- DKIM result: Unknown / not provided in sample
- DMARC result: Unknown / not provided in sample
- Sending IP: Unknown / spoofed

## URL & Attachment Analysis
| Indicator | Type | Reputation |
|-----------|------|------------|
| Attachment prompting download of voice message | File | Malicious (leads to credential phishing page) |
| Page disguised as Outlook login | URL | Malicious (credential harvesting) |

## Threat Intelligence Findings
- The attachment leading to the fake Outlook login would be flagged as malicious if scanned on VirusTotal.  
- The URL from the attachment is known for credential phishing and has a bad reputation on URLscan.io.  
- No sending IP was provided, but spoofed senders are common in phishing campaigns.  
- The combination of Office 365 branding and voicemail lure aligns with known phishing TTPs in Threat Intelligence reports.

## Verdict
Malicious

## Recommended Response Actions
- User notification: Advise the user not to open the attachment or click any links, and confirm no credentials were entered.  
- Blocking actions: Block the malicious URL and attachment at the email gateway and endpoint security solutions.  
- Escalation required: Escalate to Tier 2 SOC analyst or Incident Response team for further investigation and reporting.

*Note: Escalation to Tier 2 or Incident Response is recommended as a best practice, even if the immediate threat is mitigated, to ensure proper logging, reporting, and potential follow-up with the affected user.*

## Source / Reference Phishing email sample adapted from the public repository: https://github.com/autinerd/phishing-mail-examples All personal info and real identifiers have been removed for privacy and safe demonstration purposes.
