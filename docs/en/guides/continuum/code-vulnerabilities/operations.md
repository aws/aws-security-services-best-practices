---
title: Operate and troubleshoot
---

# Operate and troubleshoot

## Maintain a useful assessment

Review the environment when repositories, build dependencies, deployment accounts, or access roles change. Check that its selected source and associated collectors still represent the application.

Start with **Manual only** while correcting setup problems, then choose a [recurring schedule](https://docs.aws.amazon.com/continuum/latest/userguide/cv-triggering-scan.html) appropriate to the application's change frequency. Check scan history before starting another manual run.

Track integration credentials and permissions. For GitLab, follow the documented [token rotation and revocation procedures](https://docs.aws.amazon.com/continuum/latest/userguide/gitlab-integration-security.html). For Amazon Simple Storage Service (Amazon S3) and collectors, check access again after changes to identity permissions in AWS Identity and Access Management (IAM), encryption-key permissions in AWS Key Management Service (AWS KMS), bucket policies, or organization policies.

## Troubleshoot from the failing operation

| Symptom | Check | Action |
|---|---|---|
| GitHub authorization remains pending | Installation account, app repository access, and the separate authorization flow | Cancel and restart authorization as described in [GitHub setup](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html#cv-getting-started-github). |
| A GitLab project is missing or rejected | Private visibility, token scope and role, expiry, and self-managed server reachability | Correct the relevant [GitLab prerequisite](https://docs.aws.amazon.com/continuum/latest/userguide/gitlab-integration-security.html), then recheck project selection. |
| An S3 integration cannot validate or read source | Account and Region, role path, external identifier (ID), bucket listing, object prefix, and any KMS authorization | Compare the setup with the [S3 role and integration procedure](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html#cv-getting-started-s3-role). |
| Source selection is rejected | Case-sensitive extensions and excluded directories | Check the [supported source rules](https://docs.aws.amazon.com/continuum/latest/userguide/cv-supported-languages.html) and inspect the actual selected repository or ZIP archive. |
| A scan fails during build | Scan failure stage/message, manifests, toolchain inputs, dependency hosts, and authentication requirements | Reproduce the normal build from a clean checkout, correct its inputs or the environment settings, and start a new scan. |
| An issue is inconclusive | The issue's evidence and the scan result | Use the stated limitation to choose the next check. Do not infer a build failure from issue status alone. |
| A successful scan shows few or no issues | Issue processing, active filters, and loaded pages | Refresh and load additional issues following [viewing issues](https://docs.aws.amazon.com/continuum/latest/userguide/cv-viewing-issues.html). |
| Collector association is denied | Caller permissions, role trust and identity policy, member-account resource policy, Region, and any explicit deny | Follow [cross-account troubleshooting](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html#cv-adding-context-cross-account-troubleshooting). Check the failed operation and principal in CloudTrail. |
| A collector is associated but expected context is missing | Current environment role, permissions for every collector, collector state, and relevant workload inventory | Check authorization again and inspect the issue's contributing context. Association readback alone is not proof of inventory use. |
| Amazon Elastic Kubernetes Service (Amazon EKS) context is missing | Cluster onboarding, access entry, and read-only Kubernetes role-based access control (RBAC) | Repeat the [EKS verification steps](https://docs.aws.amazon.com/continuum/latest/userguide/cv-onboard-eks-cluster.html#cv-onboard-eks-cluster-verify) for the affected cluster. |
| A patch is available but was not delivered | Patch delivery state, configured destination, integration permissions, and automatic patch setting | Correct the delivery prerequisite or download the patch from [View patch](https://docs.aws.amazon.com/continuum/latest/userguide/cv-viewing-patches.html). Review and test it before deployment. |

## Quotas and recurring work

Check [current quotas](https://docs.aws.amazon.com/continuum/latest/userguide/quotas.html) before expanding the deployment. Documented defaults include 20 integrations and 50 environments per account and Region, 10 repositories per environment, one collector per account and Region, and 100 collectors per environment.

Avoid duplicate environments that assess the same source without a clear purpose. Retire abandoned trials and reduce recurring scans for inactive applications. Confirm the applicable service pricing and any supporting AWS resource costs before expanding scan frequency or coverage.

## Protect source, evidence, and patches

Review [Continuum data protection](https://docs.aws.amazon.com/continuum/latest/userguide/data-protection.html) and [encryption at rest](https://docs.aws.amazon.com/continuum/latest/userguide/encryption-at-rest.html) before connecting sensitive source.

Limit access to code, findings, issue artifacts, and downloaded patches. Keep credentials and sensitive customer information out of resource names, tags, and uniform resource locators (URLs). Apply your normal retention and access controls to exported evidence and source archives.

Distinguish storage location from inference processing location. The data protection documentation states that data remains stored in the request's originating Region, while inference can be processed in another Region within the documented geographic area. Review that behavior against your data residency requirements.

If using an AWS Organizations [artificial intelligence (AI) services opt-out policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html), review the current Continuum data usage statement and apply the policy through your organization's process. Do not infer one capability's data handling from the penetration-testing documentation; the Continuum data protection page states that it does not cover penetration testing.

## Retire an environment

Before removing a trial or application:

1. Retain any findings, artifacts, patches, and source-revision details required by your records policy.
2. Set the schedule to Manual only if you need to stop future scheduled scans while finishing the review. This does not cancel a running scan.
3. Check whether its integrations, collectors, roles, buckets, and keys serve other environments.
4. Delete the unused environment using the console or the documented [`DeleteEnvironment` operation](https://docs.aws.amazon.com/boto3/latest/reference/services/continuum/client/delete_environment.html).
5. Remove an integration and its access role only after no environment needs them. Follow the [S3 integration cleanup order](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html#cv-getting-started-s3-role) and the provider's credential revocation procedure where applicable.
6. Remove task-owned source archives and patch objects according to your retention policy. Check other consumers before changing shared collectors or encryption keys.

Verify the remaining configuration after cleanup. Preserve resources that still support another application or environment.
