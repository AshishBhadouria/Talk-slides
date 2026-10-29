# Research grounding, part 2: Agents 2–5 and headline stats

Verification key: everything below was fetched from the cited URL on 2026-10-29 unless marked **[U]** (unverified / secondary only). Atomic Red Team folder existence was verified by HTTP status on raw.githubusercontent.com. Stratus Red Team IDs were verified on https://stratus-red-team.cloud/attack-techniques/list/ (103 techniques; NO Okta, NO GitHub, NO admission-webhook technique). ATT&CK names verified on attack.mitre.org (T1562.007 page was bot-blocked; name taken from Stratus's AWS catalog cross-reference, marked [U]).

---

## Agent 2 — SOURCE CONTROL + CI/CD (GitHub Enterprise audit log + Actions)

### Primary incident sources
| Incident | Org / date | URL | What the logs showed |
|---|---|---|---|
| tj-actions/changed-files, CVE-2025-30066 | Wiz, 2025-03-15 (upd. 03-17) | https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066 | Existing version tags retroactively repointed to a malicious commit; payload dumped Runner.Worker memory and printed secrets into workflow logs as double-base64; no external exfil; `reviewdog/action-setup` implicated as precursor; maintainers attributed it to a compromised PAT of `@tj-actions-bot`. Wiz notes audit-log signals such as workflow-log deletion and merges by an unusual bot user. |
| same | StepSecurity, 2025-03-14 | https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised | Detected via Harden-Runner anomaly: unexpected outbound to gist.githubusercontent.com; >23,000 repos used the action; all tags force-moved to commit `0e58ed8671d6b60d0890c21b07f8835ace038e67`. |
| Shai-Hulud npm worm | CISA alert, 2025-09-23 | https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem | >500 npm packages; malware scanned for GitHub PATs and AWS/GCP/Azure keys, exfiltrated to an actor endpoint and to a public repo named `Shai-Hulud`; self-propagated by publishing as the compromised maintainer. CISA: audit GitHub Apps/OAuth apps, webhooks, secrets; block webhook.site. |
| same | GitHub blog, 2025-09-22 | https://github.blog/security/supply-chain-security/our-plan-for-a-more-secure-npm-supply-chain/ | GitHub notified Sep 14 2025; >500 packages removed; response: trusted publishing, deprecate classic tokens, 2FA for local publish, 7-day granular tokens. |
| Shai-Hulud 2.0 (Nov wave) | Unit 42, 2025-11-25 (upd. 12-03) | https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ | >25,000 malicious repos / ~350 users; pre-install execution; `discussion.yaml` workflow registers victim as self-hosted runner; TruffleHog abused for secret discovery; Sept wave's workflow referenced as `shai-hulud-workflow.yml` in detection query. |
| GhostAction | GitGuardian, 2025-09-05 | https://blog.gitguardian.com/ghostaction-campaign-3-325-secrets-stolen/ | Malicious workflow `.github/workflows/github_actions_security.yml` ("Github Actions Security"), triggers `push` + `workflow_dispatch`; secret names copied from legitimate workflows then POSTed via curl; 327 users, 817 repos, 3,325 secrets; first commit 2025-09-02. |
| CircleCI breach | CircleCI, 2023-01-12 | https://circleci.com/blog/jan-4-2023-incident-report/ | Malware on an engineer's laptop stole a 2FA-backed SSO session cookie; Dec 16 2022 compromise, Dec 19 recon, Dec 22 exfil; GitHub audit-log IOC `repo.download_zip`. |
| Codecov Bash Uploader | Codecov, 2021-04-15 | https://about.codecov.io/security-update/ | Docker-image build error leaked the uploader credential; modified script sent `git remote -v` and `env` to a third-party server; Jan 31 2021 → Apr 1 2021 window. |

### ATT&CK (verified)
- T1195.002 Supply Chain Compromise: Compromise Software Supply Chain
- T1213.003 Data from Information Repositories: Code Repositories
- T1552 Unsecured Credentials (secrets leaked into build logs / env)
- T1078.004 Valid Accounts: Cloud Accounts (stolen PAT / SSO cookie reuse)
- T1098.001 Account Manipulation: Additional Cloud Credentials (new PAT / deploy key / app credential)
- T1550.004 Use Alternate Authentication Material: Web Session Cookie (CircleCI)

### D3FEND (verified on https://d3fend.mitre.org/tactic/d3f:Detect/)
D3-FCR File Content Rules (workflow-file diffing); D3-UDTA User Data Transfer Analysis (secret egress from runners); D3-DAM Domain Account Monitoring (new members, outside collaborators, PATs); D3-RAPA Resource Access Pattern Analysis.

### Validation tests
- **Stratus:** none (no GitHub platform).
- **Atomic:** no GitHub audit-log test. Adjacent only: `T1195.002` test #1 "Simulate npm package installation on a Linux system" (containers/Linux); `T1552.007` #1 "List All Secrets" is Kubernetes, not GitHub.
- **No off-the-shelf test → custom injection (3 lines):**
  1. From a test account, create a fine-grained PAT, then `gh api -X PUT /repos/ORG/REPO/actions/secrets/CANARY` to add a secret.
  2. Push a commit to the default branch adding `.github/workflows/canary.yml` with a step that references `${{ secrets.CANARY }}` and `curl`s an external host.
  3. Assert the agent fires on `personal_access_token.access_granted` + `repo.create_actions_secret` + `workflows.created_workflow_run` on a just-modified default-branch workflow.

### Exact audit-log action names (verified)
Docs: https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization and https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise
- Tokens / keys / apps: `personal_access_token.access_granted`, `personal_access_token.request_created`, `personal_access_token.access_revoked`, `personal_access_token.auto_approve_grant_requests_enabled`; `public_key.create`, `public_key.delete` (deploy keys); `integration_installation.create`, `integration_installation.repositories_added`, `integration.create`, `oauth_application.create`, `org.oauth_app_access_approved`, `hook.create`
- Workflows: `workflows.created_workflow_run`, `workflows.completed_workflow_run`, `workflows.approve_workflow_job`, `workflows.disable_workflow`, `workflows.delete_workflow_run`, `workflows.actions_policy_violation`, `workflows.debugger_session_started`
- Membership: `org.add_member`, `org.invite_member`, `org.update_member`, `org.add_outside_collaborator`, `repo.add_member`, `repo.remove_member`
- Repo state: `repo.access` (visibility change), `repo.create`, `repo.transfer`, `repo.destroy`, `repo.archived`, `repo.download_zip`
- Secrets / Actions settings: `repo.create_actions_secret`, `repo.update_actions_secret`, `repo.remove_actions_secret`, `org.create_actions_secret`, `org.update_actions_secret`, `repo.update_actions_settings`, `repo.update_actions_access_settings`, `org.update_actions_settings`, `org.set_actions_fork_pr_approvals_policy`, `environment.create_actions_secret`
- Protections: `protected_branch.policy_override`, `protected_branch.update_pull_request_reviews_enforcement_level`, `protected_branch.destroy`, `repository_secret_scanning_push_protection.disable`, `repository_secret_scanning.disable`
- Git (GHE Cloud enterprise log): `git.clone`, `git.fetch`, `git.push`
- Note: "secret read inside a workflow" has no audit event; it must be inferred from workflow-file diffs (`${{ secrets.* }}` references) plus `workflows.created_workflow_run`. Action-pinning changes are a diff signal (tag vs 40-char SHA in `uses:`), not an audit event.

### Daily volume (estimate)
~50k–150k audit events/day for a 500-engineer org when `git.*` events are enabled, dominated by `git.*`, `workflows.*`, `pull_request.*`. The agent's sensitive subset (new PATs/apps/deploy keys, default-branch workflow changes, visibility changes, outside collaborators, secret-scanning toggles) is typically tens/day. No GitHub per-seat figure is published.

---

## Agent 3 — EXTERNAL EXPOSURE / attack surface

### Primary incident sources
| Incident | Org / date | URL | What was shown |
|---|---|---|---|
| Capital One 2019 | Capital One, 2019 (facts page) | https://www.capitalone.com/digital/facts2019/ | Access Mar 22–23 2019; discovered Jul 19 2019 after a Jul 17 responsible-disclosure tip; ~106M people; ~140k US SSNs, ~80k bank accounts, ~1M Canadian SINs; described as a "configuration vulnerability". SSRF/WAF/IMDSv1 mechanism and S3 sync are from the DOJ complaint, which could not be fetched here **[U]**. |
| IMDSv2 (mitigation for the SSRF→IMDS class) | AWS Security Blog, 2019-11-19 | https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/ | Session PUT token, TTL hop limit 1, refuses requests carrying X-Forwarded-For; explicitly motivated by SSRF via misconfigured WAFs/reverse proxies. |
| Public RDS snapshots | Mitiga, Nov 2022 (via Dark Reading) | https://www.darkreading.com/cloud/thousands-amazon-rds-snapshots-leaking-corporate-pii | 2,783 snapshots observed in one month, 810 public the whole period, 1,859 public 1–2 days; PII incl. passwords and card data; no CloudTrail event when a third party copies or restores from a public snapshot. **[U: primary Mitiga blog not fetched; figures from Dark Reading/SiliconANGLE coverage]** |
| 2025 open bucket with company acknowledgment | UpGuard (Nupay, India), Aug–Sep 2025 | https://www.upguard.com/breaches/india-bank-transfers-data-leak.md | Public S3 bucket with >273k bank-transfer documents; company acknowledged a misconfigured bucket of "test data". **[U: not fetched; from search summary]** |

### ATT&CK (verified unless marked)
- T1190 Exploit Public-Facing Application
- T1552.005 Unsecured Credentials: Cloud Instance Metadata API
- T1530 Data from Cloud Storage
- T1537 Transfer Data to Cloud Account (shared snapshots / AMIs)
- T1580 Cloud Infrastructure Discovery
- T1595 Active Scanning
- T1562.007 Impair Defenses: Disable or Modify Cloud Firewall **[U: MITRE page bot-blocked; name via Stratus/AWS catalog cross-ref]**

### D3FEND (verified https://d3fend.mitre.org/tactic/d3f:Model/ and Detect)
D3-AI Asset Inventory; D3-CI Configuration Inventory; D3-NM Network Mapping; D3-NNI Network Node Inventory; D3-OAM Operational Activity Mapping (IaC-intent vs observed state).

### Validation tests (Stratus, all verified on list + technique pages)
| Stratus ID | Name | CloudTrail event / detection field |
|---|---|---|
| `aws.exfiltration.ec2-share-ebs-snapshot` | Exfiltrate EBS Snapshot by Sharing It | `ModifySnapshotAttribute`; alert when `requestParameters.createVolumePermission` adds an unknown account or `groups=all`; follow-ons `SharedSnapshotCopyInitiated`, `SharedSnapshotVolumeCreated` (recipient = `userIdentity.accountId`) |
| `aws.exfiltration.s3-backdoor-bucket-policy` | Backdoor an S3 Bucket via its Bucket Policy | `PutBucketPolicy` granting s3:GetObject/GetBucketLocation/ListBucket to external account; GuardDuty `Policy:S3/BucketAnonymousAccessGranted` only if public |
| `aws.exfiltration.ec2-security-group-open-port-22-ingress` | Open Ingress Port 22 on a Security Group | `AuthorizeSecurityGroupIngress` with `requestParameters.cidrIp=0.0.0.0/0`, filter on admin ports |
| `aws.exfiltration.rds-share-snapshot` | Exfiltrate RDS Snapshot by Sharing | `ModifyDBSnapshotAttribute` where `attributeName=restore`; `valuesToAdd` contains unknown account or `all` |
| also | `aws.exfiltration.ec2-share-ami`, `aws.exfiltration.ec2-share-ebs-volume`, `azure.exfiltration.storage-public-access`, `gcp.exfiltration.share-compute-snapshot` | |
- **Atomic (verified):** `T1530` #1 "AWS - Scan for Anonymous Access to S3"; `T1552.005` #3 "AWS - Retrieve EC2 IAM Role Credentials via IMDSv2", #2 "Azure - Dump Azure Instance Metadata from Virtual Machines".
- **No off-the-shelf test for "new DNS record" / "new Censys hit" → custom injection:** (1) `aws route53 change-resource-record-sets` adding an A record for `canary.corp.example` to a fresh public IP; (2) attach an SG allowing 0.0.0.0/0:8443 to that instance; (3) assert the next daily diff reports the record + port as *not present in Terraform state* and that Censys/Shodan shows the host within 24–72h.

### Exact log fields (verified)
- CloudTrail `eventName`: `ModifySnapshotAttribute`, `ModifyDBSnapshotAttribute`, `PutBucketPolicy`, `PutBucketAcl`, `AuthorizeSecurityGroupIngress`, `ModifyImageAttribute`, `SharedSnapshotCopyInitiated`, `SharedSnapshotVolumeCreated`; key on `requestParameters.createVolumePermission`, `requestParameters.valuesToAdd`, `requestParameters.cidrIp`.
- Route 53: `ChangeResourceRecordSets`, `CreateHostedZone`, `DeleteHostedZone` logged by CloudTrail with `eventSource=route53.amazonaws.com`, `awsRegion=us-east-1` — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/logging-using-cloudtrail.html
- Gap: copy/restore of a *public* snapshot by a third party is not logged (Mitiga), so the exposure agent must diff `describe-snapshots --restorable-by-user-ids all` / `describe-db-snapshots` state daily rather than rely on CloudTrail.

### Daily volume (estimate)
Management-event CloudTrail for a mid-size multi-account estate: ~100k–500k events/day; the exposure-mutating event names above are tens to low hundreds/day; the daily asset diff normally yields single-digit net-new public exposures/day. No vendor per-seat figure.

---

## Agent 4 — KUBERNETES CONTROL PLANE (kube-apiserver audit)

### Primary incident sources
| Incident | Org / date | URL | What was shown |
|---|---|---|---|
| Tesla cryptojacking | RedLock, Feb 2018 | Original blog.redlock.io/cryptojacking-tesla now redirects **[U]**; coverage: https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/tesla-and-jenkins-servers-fall-victim-to-cryptominers ,