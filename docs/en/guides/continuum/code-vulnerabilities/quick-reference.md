---
title: Quick reference
---

# Best practices quick reference

The highest-impact recommendations from this guide, without the reasoning behind them. Each one links to the section that explains why.

## Source and setup

| Do this | Why it matters | Details |
|---|---|---|
| Start with one application you know well | The first scan of a large codebase can produce hundreds of issues and pull requests. | [Prepare and connect source code](setup.md) |
| Connect source, not compiled output | A ZIP with only binaries failed at the scan stage. | [Check source eligibility](setup.md#2-check-source-eligibility) |
| Keep Amazon Inspector for packages and binaries | Continuum flags a library only when its flaw is reachable from application code. | [Where Continuum fits](index.md#where-continuum-fits) |
| Use private repositories | Each fix opens a pull request that describes a vulnerability. | [Connect the source](setup.md#3-connect-the-source) |
| Include deploy workflows and infrastructure-as-code in the scanned source | They let Continuum relate a flaw to a running workload. | [Prepare the build inputs](setup.md#4-prepare-the-build-inputs) |

## AWS context

| Do this | Why it matters | Details |
|---|---|---|
| Create environments in one central account and put a collector in each workload account | One place for issues and patches, and each account owner keeps control of its inventory. | [Use one central environment](aws-context.md#use-one-central-environment-and-a-collector-in-each-workload-account) |
| Give the environment's data access role access to every associated collector | Associating a collector with a new role replaces the stored role. | [Configure the data access role](aws-context.md#3-configure-the-environments-data-access-role) |
| Read likelihood and impact factors, not only severity | They show whether a rating reflects your deployment or only the code. | [Add EKS and deployment context](aws-context.md#6-add-eks-and-deployment-context-where-applicable) |
| Write a short business-context document for S3 sources | It is where your judgment about sensitive data enters a rating. | [Identify your crown jewels](aws-context.md#7-identify-your-crown-jewels) |

## Scans, issues, and patches

| Do this | Why it matters | Details |
|---|---|---|
| Scan when code changes, and triage by flaw | Rescans of unchanged code can add new issues with new IDs. | [Scan and remediate](scans-and-remediation.md) |
| Wait for issue processing before concluding anything | A scan can succeed while issues and patches are still arriving. | [Follow issue processing](scans-and-remediation.md#2-follow-issue-processing) |
| Describe traced issues as traced | Every issue in our runs was proved by source analysis. | [Read the evidence](index.md#read-the-evidence-before-acting) |
| Treat every patch as a draft | A patch is a proposal, and delivery is not deployment. | [Review a patch](scans-and-remediation.md#4-review-and-validate-a-patch) |
| Use custom findings to check another tool, and keep that tool | Continuum confirmed and re-rated most findings but added little new detection. | [Submit findings from another source](scans-and-remediation.md#optional-submit-findings-from-another-source) |

## Cost

| Do this | Why it matters | Details |
|---|---|---|
| Set an issues-per-scan limit and a focus mode that fit your budget | Findings that are not pursued are not validated, rated, or patched, so a cap makes the bill predictable. | [Limit what Continuum works on](cost-considerations.md#limit-what-continuum-works-on) |
| Set a budget alert before the first scan | The first scan starts at creation and spend is not capped. | [Cost considerations](cost-considerations.md) |
| Match the schedule to how often you can triage | Issue count drives inference charges. | [Control cost](cost-considerations.md#control-cost) |
