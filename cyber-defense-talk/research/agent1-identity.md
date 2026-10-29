# Primary-source grounding for five detection agents

Verification notes up front (things I could NOT confirm, so you don't quote them):
- RedLock's original Tesla post (blog.redlock.io/cryptojacking-tesla, Feb 20 2018) now 301s to paloaltonetworks.com and web.archive.org is blocked from this environment; only secondary coverage was reachable.
- The DOJ complaint PDF against Paige Thompson (justice.gov) returned an empty body here; the SSRF/IMDSv1 mechanism therefore rests on the AWS IMDSv2 blog plus Capital One's own facts page, not the complaint text.
- attack.mitre.org/techniques/T1562/007/ returned a 67-byte body (bot-blocked); name taken from the Stratus page's AWS Threat Technique Catalog cross-reference.
- Neither Mandiant's UNC5537 report nor CISA AA23-320A publishes a dwell-time or time-to-exfil figure. See "Headline stats" for what is available.
- Stratus Red Team has no "create admission controller" / mutating-webhook technique, no Okta, and no GitHub techniques (list fetched 2026-10-29: 103 techniques across AWS/Azure/EKS/Entra ID/GCP/Kubernetes). Atomic Red Team has NO atomics folder for T1621, T1550.001, T1550.004, T1556.006, T1562.007 (verified 404 on raw.githubusercontent.com).

---

## Agent 1 — Identity Provider (Okta System Log / Entra ID)

**Incident sources**
- CISA/FBI AA23-320A "Scattered Spider", pub. Nov 16 2023, rev. Jul 29 2025 — https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a. Logs/TTPs: help-desk-driven password resets and MFA transfers, push bombing ("MFA fatigue"), SIM swap, historical addition of a federated IdP with automatic account linking (advisory says this IdP TTP is "not currently observed").
- Okta Security, "Cross-Tenant Impersonation: Prevention and Detection", Aug 31 2023 (activity Jul 29–Aug 19 2023) — https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection/. Logs showed: service-desk resets of all MFA factors on Super Admins, sign-ins via anonymizing proxies, a second attacker IdP configured as inbound-federation source, username attribute rewritten to impersonate a target user.
- Okta, "Unauthorized Access to Okta's Support Case Management System: Root Cause", Nov 3 2023 — https://sec.okta.com/articles/2023/11/unauthorized-access-oktas-support-case-management-system-root-cause/. Service-account credential saved in an employee's personal Google profile; HAR files with session tokens downloaded Sep 28–Oct 17 2023; 134 customers' files, 5 session hijacks; the "Files tab" download path generated an event type Okta's monitoring did not flag (14-day blind spot).
- Mandiant/Google, "UNC5537 Targets Snowflake Customer Instances", Jun 10 2024 — https://cloud.google.com/blog/topics/threat-intelligence/unc5537-snowflake-data-theft-extortion. No MFA, infostealer credentials (some from Nov 2020, ~4 years stale), no network allow-lists; ~165 orgs notified; ≥79.7% of used accounts had prior credential exposure.
- ReliaQuest, "Scattered Spider Attack Analysis", Nov 21 2023 — https://reliaquest.com/blog/scattered-spider-attack-analysis-account-compromise/. Okta logs: four MFA challenges in two minutes then new-device enrollment; eight bulk MFA prompts tripping an Okta rate-limit violation; HIGH-risk sign-in with `threatSuspected=false`; IdP activation/lifecycle events for a rogue secondary IdP; "Unable to match transformed username" failure.
- Caesars Entertainment Form 8-K (event date Sep 7 2023): "social engineering attack on an outsourced IT support vendor" — https://www.sec.gov/Archives/edgar/data/1590895/000119312523235015/d537840d8k.htm. MGM's 8-K pointed to a press release only; help-desk attribution for MGM is press reporting, not filing text.

**ATT&CK (verified on attack.mitre.org)**: T1621 Multi-Factor Authentication Request Generation; T1566.004 Phishing: Spearphishing Voice; T1539 Steal Web Session Cookie; T1550.004 Use Alternate Authentication Material: Web Session Cookie; T1556.006 Modify Authentication Process: Multi-Factor Authentication; T1484.002 Domain or Tenant Policy Modification: Trust Modification; T1098.003 Account Manipulation: Additional Cloud Roles; T1078.004 Valid Accounts: Cloud Accounts; T1110.004 Credential Stuffing.

**D3FEND (verified https://d3fend.mitre.org/tactic/d3f:Detect/)**: D3-ANET Authentication Event Thresholding; D3-CCSA Credential Compromise Scope Analysis; D3-UGLPA User Geolocation Logon Pattern Analysis; D3-DAM Domain Account Monitoring; D3-SDA Session Duration Analysis.

**Validation tests**
- Stratus: none for Okta. For the Entra side: `entra-id.persistence.new-application` (creates app + Global Administrator role → "Add member to role"), `entra-id.persistence.guest-user`, `entra-id.persistence.hidden-au`.
- Atomic: `T1098.003` test #1 "Azure AD - Add Company Administrator Role to a user", #2 "Simulate - Post BEC persistence via user password reset followed by user added to company administrator role"; `T1484.002` test #1 "Add Federation to Azure AD" (AADInternals); `T1110.003` test #4 "Password spray all Azure AD users with a single password", #7 "MSOLSpray". T1539 atomics are end