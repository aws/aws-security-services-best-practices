---
title: Code vulnerabilities
---

# Code vulnerabilities best practices

[Continuum for code vulnerabilities](https://docs.aws.amazon.com/continuum/latest/userguide/code-vulnerabilities.html) analyzes application source code, validates potential vulnerabilities, prioritizes issues using available context, and proposes remediation. Connect repositories or upload code through Amazon Simple Storage Service (Amazon S3), then review the resulting issues and patches.

Start with one application whose source, dependencies, build, and deployment you understand. Establish a successful scan and review its evidence before expanding the repository selection or scan schedule.

## How to use this guide

The guide follows the order of a first deployment, but each page can be read on its own. Prescriptive guidance is called out in green **Best practice** boxes, and cautions in yellow boxes, so you can skim a page and act on those alone. If you only want the recommendations, see the [Best practices quick reference](quick-reference.md). Each one links to the section that explains why.

## Where Continuum fits

Continuum for code vulnerabilities is a good fit when:

- You own first-party source code in a [supported language](https://docs.aws.amazon.com/continuum/latest/userguide/cv-supported-languages.html) that you can connect from GitHub, GitLab, or Amazon S3.
- You want issues validated, ranked using where the code runs, and paired with a patch to review.
- Other scanners already produce findings that your team has to triage, and you want a second look at them.

Use another tool when the need is different:

| If you need | Use |
|---|---|
| Vulnerabilities in compiled binaries, container images, or the full list of vulnerable packages | [Amazon Inspector](../../inspector/index.md) |
| Proof of exploitability against a running application | [On-demand penetration testing](../../security-agent/index.md) |
| Detection of active threats in your accounts | [Amazon GuardDuty](../../guardduty/index.md) |

## Setup and use

| Step | What to do | Check before moving on |
|---|---|---|
| [1. Prepare and connect source code](setup.md) | Check source eligibility, choose an integration, and create an environment. | The selected source contains the application and its build inputs. The first scan can build it. |
| [2. Add AWS context](aws-context.md) | Enable collectors where the application runs and associate them with the environment. | The intended collectors and access role appear on the environment. |
| [3. Scan and remediate](scans-and-remediation.md) | Run a scan, inspect issue evidence, and review available patches. | You can distinguish scan completion, issue processing, patch availability, and patch delivery. |
| [4. Operate the environment](operations.md) | Maintain access, troubleshoot failures, control recurring work, and retire unused resources. | Integrations remain usable and scan results still represent the application you intend to assess. |
| [Cost considerations](cost-considerations.md) | Understand what drives charges and how to control them. | You have a budget alert and a plan for the first scan. |
| [Quick reference](quick-reference.md) | The highest-impact recommendations without the reasoning. | |

## Terms used in this guide

An **integration** connects Continuum to a code source. An **environment** selects the code and settings to assess. A **collector** gathers AWS workload context in its account and Region.

The **primary account** is the AWS account containing the environment. A **member account** is another account containing workloads whose context you want to associate with that environment. These labels describe the setup in this guide; they do not assign AWS Organizations administrator roles. A single-account setup uses the primary account for both the environment and the workloads.

## Read the evidence before acting

Validation evidence can include [source analysis or executed proof](https://docs.aws.amazon.com/continuum/latest/APIReference/API_ValidationEvidenceBody.html). Source analysis does not mean that code was built or run for that proof. Executed proof is optional. Review the evidence attached to each issue before describing it as a demonstrated exploit. In our runs every issue's proof was source analysis, so describe those issues as traced, not as demonstrated exploits. For proof against a running application, use [on-demand penetration testing](../../security-agent/index.md).

Treat a proposed patch as a code change to review and test. A downloadable patch, a delivered pull request, and a deployed fix are separate outcomes.
