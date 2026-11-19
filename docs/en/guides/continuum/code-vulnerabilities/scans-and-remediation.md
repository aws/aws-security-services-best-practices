---
title: Scan and remediate
---

# Scan and remediate

## 1. Run a scan

Creating an environment triggers its first scan. For later runs, use the console's scan action or [`CreateCodeScan`](https://docs.aws.amazon.com/continuum/latest/APIReference/API_CreateCodeScan.html).

The [documented schedules](https://docs.aws.amazon.com/continuum/latest/userguide/cv-triggering-scan.html) are every day, every 2 days, every 7 days, or Manual only. Choose a recurring schedule after the source and build setup work reliably.

```bash
aws continuum create-code-scan \
  --profile "<PRIMARY-PROFILE>" --region "<REGION>" \
  --environment-id "<ENVIRONMENT-ID>" \
  --client-token "<UNIQUE-SCAN-REQUEST-TOKEN>" \
  --output json --no-cli-pager

aws continuum get-code-scan \
  --profile "<PRIMARY-PROFILE>" --region "<REGION>" \
  --environment-id "<ENVIRONMENT-ID>" \
  --scan-run-id "<SCAN-RUN-ID>" \
  --output json --no-cli-pager
```

Use the returned `scan.scanRunId` in the second command. Use a new client token for a new requested scan and retain it when retrying the same request. If a request times out, check the scan history before submitting another request; the application programming interface (API) documentation describes concurrency and partial-failure caveats for token handling.

Repeat `get-code-scan` to inspect the run's status. If it fails, use its failure stage and message to decide whether to correct source access, build inputs, or another prerequisite. Record the run identifier (ID) and source revision with your review.

Continuum currently does not support canceling a scan after it starts. **Manual only** prevents future scheduled scans; it does not cancel a running scan.

!!! warning "Rescanning unchanged code adds issues"

    In our testing, a second scan of the same code produced a second set of issues with new IDs and reworded titles, and none was marked as a duplicate. One missing-ownership flaw in a training application kept reappearing as separate issues across weekly scans, each with its own pull request. Scan when the code changes or on a schedule that matches how often you can triage. Triage by flaw and not by issue count, and decide how you will retire duplicate pull requests before you turn on a recurring schedule.

## 2. Follow issue processing

Open the environment's **Scans**, **Findings**, and **Issues** views as the run progresses. A scan can reach `SUCCEEDED` while downstream issue or patch processing is still in progress. In our runs a scan of a small application took about 25 minutes, and issues and patches kept arriving for another 20 minutes to an hour. Do not read an empty list right after a scan succeeds as a clean result.

In **Issues**, search and counts apply to the issues currently loaded. Use **Load more**, clear filters, and refresh before concluding that no issue exists. See [viewing issues](https://docs.aws.amazon.com/continuum/latest/userguide/cv-viewing-issues.html).

For each issue, review:

- The affected code, contributing findings, and explanation of the risk.
- The severity and the workload context used to prioritize it.
- The proof or source analysis, including its assumptions and limitations.
- The remediation guidance and any available patch.

An inconclusive issue alone does not establish that the application failed to build. Use the scan's failure information and the issue's own evidence to identify the next action.

## 3. Retrieve issue evidence

Use issue and artifact IDs returned by Continuum. Obtain the issue ID from the environment's issue list or [`ListCodeIssues`](https://docs.aws.amazon.com/continuum/latest/APIReference/API_ListCodeIssues.html), then list its artifacts before fetching one.

```bash
aws continuum get-code-issue \
  --profile "<PRIMARY-PROFILE>" --region "<REGION>" \
  --environment-id "<ENVIRONMENT-ID>" --issue-id "<ISSUE-ID>" \
  --output json --no-cli-pager

aws continuum list-code-issue-artifacts \
  --profile "<PRIMARY-PROFILE>" --region "<REGION>" \
  --environment-id "<ENVIRONMENT-ID>" --issue-id "<ISSUE-ID>" \
  --output json --no-cli-pager

aws continuum get-code-issue-artifact \
  --profile "<PRIMARY-PROFILE>" --region "<REGION>" \
  --environment-id "<ENVIRONMENT-ID>" --issue-id "<ISSUE-ID>" \
  --artifact-id "<ARTIFACT-ID>" \
  --output json --no-cli-pager > issue-artifact.json
```

`issue-artifact.json` contains the API response; it is not automatically a patch file. The [artifact API](https://docs.aws.amazon.com/continuum/latest/APIReference/API_GetCodeIssueArtifact.html) describes the returned body.

Validation artifacts can contain `body.validationEvidence.sourceAnalysis` or `body.validationEvidence.executedProof`. [Source analysis](https://docs.aws.amazon.com/continuum/latest/APIReference/API_ValidationEvidenceBody.html) is evidence derived without building or running the proof. Executed proof is evidence from execution against the repository under test. Inspect the returned artifact instead of assuming that every issue includes an executable demonstration.

If no artifact is listed yet, check issue processing and refresh later.

### Interpret crown-jewel signals

Scoring artifacts can include a [`SignalExploitability`](https://docs.aws.amazon.com/continuum/latest/APIReference/API_SignalExploitability.html) object. Its [`reachedCrownJewels`](https://docs.aws.amazon.com/sdk-for-kotlin/api/latest/continuum/aws.sdk.kotlin.services.continuum.model/-signal-exploitability/reached-crown-jewels.html) field reports whether validation reached the high-value sink described by the attack path.

Read that result with `confidenceTier` and inspect the validation artifact identified by `sourceValidationArtifactId`. A `true` result with `SOURCE_READ` confidence reflects source analysis; it does not demonstrate that the path was executed against a deployed workload.

A `false` result means validation did not reach that sink. An omitted `reachedCrownJewels` field means the result is unknown. Do not treat an omitted field as `false`, or use this Boolean to confirm that a particular AWS resource tag was read. Compare the supporting evidence with your [crown-jewel inventory](aws-context.md#7-identify-your-crown-jewels) before deciding the issue's business impact.

## 4. Review and validate a patch

Open an issue and choose **View patch** when available. Review the diff, its assumptions, and the code paths it changes. Use the [patch view](https://docs.aws.amazon.com/continuum/latest/userguide/cv-viewing-patches.html) to download the patch and inspect delivery information.

Keep these outcomes separate:

| Outcome | What to check |
|---|---|
| A patch was generated | A patch artifact is available to inspect or download. |
| Delivery was attempted | The patch delivery state identifies a result or failure. For an API artifact, inspect `body.patch.delivery.status`. |
| A pull request or object was delivered | The reported destination exists and contains the expected change. |
| The fix is ready to deploy | Code review and the application's build, tests, and security checks pass. |
| The deployed application is fixed | The reviewed change reached the intended workload and the affected behavior was checked. |

Automatic patch settings control delivery behavior. Review the setting explicitly when creating an environment; do not assume console and API defaults are identical. A delivery failure or `SKIPPED` state does not by itself mean no patch was generated. A patch can remain available to download even when delivery fails.

For GitHub, review the generated pull request. For Amazon Simple Storage Service (Amazon S3), check the reported destination under `continuum-patches/` and the integration role's write permissions. For GitLab, review the [integration's merge request and pipeline behavior](https://docs.aws.amazon.com/continuum/latest/userguide/gitlab-integration-security.html) before relying on automatic continuous integration (CI) execution.

After downloading or receiving a patch:

1. Apply it to a review branch for the source revision it was generated against.
2. Review the diff for unintended behavior changes.
3. Run the application's build and tests, including a regression test for the affected path.
4. Complete your normal security review and deployment checks.
5. Run a new Continuum scan when appropriate and compare its source revision and evidence with the prior run.

Do not treat issue processing completion or patch delivery as confirmation that a fix has been deployed. If an older patch was skipped, check its delivery state or download it; changing a setting is not evidence that the earlier patch was sent.

## Optional: submit findings from another source

[`CreateCodeFinding`](https://docs.aws.amazon.com/continuum/latest/APIReference/API_CreateCodeFinding.html) accepts a finding from another tool in the Open Cybersecurity Schema Framework (OCSF), a common format for security data, encoded as JavaScript Object Notation (JSON). Continuum validates the document when you submit it and rejects an invalid one with a `ValidationException`.

### Accepted classes and required fields

Continuum accepts two OCSF classes, up to 256 kilobytes (KB) per document:

| Class | `class_uid` |
|---|---|
| Vulnerability Finding | `2002` |
| Application Security Posture Finding | `2007` |

Other classes, such as Detection Finding (`2004`), are rejected with `unsupported finding class_uid`. Besides the fields OCSF itself requires, Continuum requires:

| Field | Requirement |
|---|---|
| `finding_info.uid` | A unique identifier for the finding. |
| `vulnerabilities[0].affected_code[0].file` | The affected file, using `path` or `name`. With several repositories in the environment, the path must start with the repository name. |
| `metadata.product.name` or `metadata.product.vendor_name` | The tool that produced the finding. |

A document missing any of these is rejected. The following shows the shape. Replace each placeholder with your own value:

```json
{
  "activity_id": 1,
  "category_uid": 2,
  "class_uid": 2002,
  "type_uid": 200201,
  "severity_id": 4,
  "time": 1700000000000,
  "metadata": {
    "version": "1.9.0",
    "product": { "name": "<TOOL-NAME>", "vendor_name": "<VENDOR-NAME>" }
  },
  "finding_info": {
    "uid": "<UNIQUE-FINDING-ID>",
    "title": "<SHORT-TITLE>",
    "desc": "<DESCRIPTION-OF-THE-WEAKNESS>"
  },
  "vulnerabilities": [
    {
      "title": "<SHORT-TITLE>",
      "cwe": { "uid": "<CWE-NUMBER>" },
      "affected_code": [
        {
          "file": { "path": "<REPOSITORY>/<PATH-TO-FILE>", "name": "<FILE-NAME>", "type_id": 1 },
          "start_line": 10,
          "end_line": 10
        }
      ]
    }
  ]
}
```

!!! tip "Best practice"

    Use custom findings to check another tool's output, and keep that tool in place. In a test of about 250 findings from several scanners, findings that pointed at a real file and line were mostly confirmed, and many came back with a lower severity than the sender gave. Package vulnerabilities reported at line 1 of a manifest were nearly all discarded, while those pointing at the line that declares the package were nearly all confirmed, so map each package finding to its declaring line before you send it. Continuum added little detection beyond its own scan. The value was in checking and re-rating existing findings.

### What happens after you submit

A submitted finding stays `SUBMITTED` until a successful build includes its repository. If the next successful build does not include it, Continuum discards it with the reason `SOURCE_REPO_NOT_FOUND`. Check the file path against the repositories in the environment, and wait for a scan to finish before expecting an issue.

Continuum validates the claim itself. A confirmed finding becomes an issue and can carry a different severity than the one you sent. A discarded finding keeps a reason you can read in the **Findings** view. Import a small sample first and compare the results with your tool's own before automating a larger feed. This contract does not establish compatibility with every scanner's native export format.

Continue to [ongoing operations](operations.md).
