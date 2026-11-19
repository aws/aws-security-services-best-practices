---
title: Cost considerations
---

# Cost considerations

Continuum charges for the code it protects and for the issues it works. See the [Continuum pricing page](https://aws.amazon.com/continuum/pricing/) for current rates, and use it for estimates. This page covers what drives the charges in practice and how to control them.

## What drives charges

Pricing has two dimensions: a context charge based on the lines of code in your environments, and inference charges for the issues Continuum validates, rates, and patches. In Cost Explorer the usage types appear as `ContinuumContext-Code` and `ContinuumInference`. The pricing page assumes about one inference unit per vulnerability. In our testing, charges tracked the number of issues worked, at somewhat less than one unit per issue on average.

The practical consequence is that **issue count is the number to manage**, and three things raise it:

- A large or very vulnerable codebase. The first scan is usually your largest.
- Rescans of code that has not changed, which can add a second set of issues. See [rescanning](scans-and-remediation.md#2-follow-issue-processing).
- More repositories, environments, or scan frequency than you can triage.

!!! warning "The first scan starts at creation"

    Creating an environment starts its first scan at once, **including when Manual only is selected**. Settings you edit afterward apply only to later scans, so set the focus mode and issue limit when you create the environment if the console offers them, and otherwise expect the first scan to run without a cap. Get cost approval and set an alert before you create an environment on a large repository.

## Limit what Continuum works on

Two environment settings control how much Continuum validates, rates, and patches in each scan. Find them under **Edit environment settings**. Continuum still finds every vulnerability, and the settings decide how many it pursues.

| Setting | What it does |
|---|---|
| **Focus mode** | **Comprehensive** pursues every finding at any severity. **Focused** pursues higher-severity findings and does not pursue lower-severity ones. |
| **Issues to pursue per scan** (optional) | Caps how many findings Continuum pursues in one scan. When a scan finds more, it pursues the highest-severity findings first and does not pursue the rest. Leave it empty for no limit. |

Both settings reduce inference charges, because findings that are not pursued are not validated, rated, or patched. A change to focus mode applies only to findings created after you save, so existing findings keep their status. A change to the issue limit applies to scans started after it.

!!! tip "Best practice"

    Set a per-scan issue limit that matches your budget for one scan. The pricing page assumes about one inference unit per vulnerability, so a limit of 10 issues is about 10 units per scan. A daily scan at that limit costs about 30 times a single scan in a month. Use **Focused** mode when your team can act only on the most serious issues, and use **Comprehensive** when you need a complete record, such as for a baseline or a compliance review.

Plan for what a limit hides. Lower-severity findings that Continuum does not pursue have no validation, rating, or patch, so a cap trades coverage for a predictable bill. Review the cap after the first few scans, and raise it if serious issues are being left out.

## Control cost

!!! tip "Best practice"

    Set an AWS Budgets alert or a Cost Anomaly Detection monitor on Continuum usage before your first scan.

- **Cap each scan.** Set the issue limit and choose a focus mode that fits your budget, as described above.
- **Start with one application.** Prove value and estimate cost on a small repository, then scale.
- **Scan on change, not on a clock.** Choose **Manual only** or a long interval for applications that rarely change, and scan after meaningful changes.
- **Keep generated and vendored code out.** Source under the [excluded folders](setup.md#2-check-source-eligibility) is skipped. Keep third-party and generated code outside the scanned source where you can.
- **Avoid duplicate environments** that assess the same source without a clear purpose.
- **Retire what you no longer need.** Delete trial environments and reduce recurring scans for inactive applications. See [retire an environment](operations.md#retire-an-environment).

## Estimate before you commit

Estimate the first scan as lines of code (for the context charge) plus a range of issue counts (for inference), using the pricing page rates. Use a high case that covers a codebase with many findings, because the issue count is unknown until the scan runs.

Continue to the [quick reference](quick-reference.md).
