---
title: Add AWS context
---

# Add AWS context

Continuum can use [AWS workload context](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html) to relate code to deployed resources and assess the conditions under which an issue matters. Start with the accounts and Regions where the selected application runs.

Collectors gather supported resource configuration and relationships. The documentation lists the [supported inventory](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html), including compute, networking, AWS Identity and Access Management (IAM), storage, and Kubernetes context. Use the current list when deciding which application resources to include.

## 1. Place the resources in the correct account

| Resource or action | Location |
|---|---|
| Source integration and code environment | Primary account |
| Collector data access role used by that environment | Primary account |
| AWS collector | Each workload account, in the environment's Region |
| Collector resource policy for cross-account access | On the collector in the member account |
| Collector association | On the environment in the primary account |
| Amazon Elastic Kubernetes Service (Amazon EKS) cluster access and Kubernetes role-based access control (RBAC) | Each cluster being onboarded |

For a single-account application, the collector is also in the primary account. You still configure its data access role and association. For applications spanning several accounts, repeat collector setup and authorization for each account. The environment and its associated collectors must be in the **same Region**.

## 2. Enable the collector

In each workload account, open **Collectors**, choose **AWS collector**, and follow the [enablement procedure](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html). Complete the permission setup and confirm that the collector is **Active**.

Record its Amazon Resource Name (ARN), which identifies the collector. Use the actual collector ARN throughout the policy and association steps; an AWS account identifier (ID) alone does not identify the collector.

## 3. Configure the environment's data access role

In the primary account, create the role described in [authorizing collector access](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html#cv-adding-context-cross-account):

- Its trust policy allows `continuum.amazonaws.com` to assume it, restricted by the primary account's `aws:SourceAccount` and the environment's exact `aws:SourceArn`.
- Its identity policy allows `continuum:GetCollectorDataAccessAuthorization` on every collector the environment will use.
- The caller creating the association can use `continuum:AssociateCollector` on the environment and pass this role with `iam:PassRole`.

Use a dedicated collector data access role. It has a different purpose from the role used to read source archives from Amazon Simple Storage Service (Amazon S3).

!!! warning "The role applies to the whole environment"

    Associating a collector with a different data access role replaces the environment's stored role. Ensure the replacement role can access **all** associated collectors, including collectors added earlier.

## 4. Authorize a member-account collector

For cross-account access, the member account must also grant access in the collector's resource policy. The following example grants one primary-account role access to one collector, using an [IAM role principal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html). The [public authorization walkthrough](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html#cv-adding-context-cross-account) explains the role and resource-policy requirements.

For a same-account collector, skip this cross-account grant and continue to association.

### Read the current policy

Read the collector's current policy before adding the grant. If its `Statement` array is empty, the statement below becomes its first entry. Otherwise, keep every existing statement and append the new grant. Follow the [cross-account procedure](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html#cv-adding-context-cross-account) for the role and policy prerequisites.

Run the following in Bash with the AWS Command Line Interface (AWS CLI) and `jq` available to call AWS services and process their responses. These examples use the commercial AWS partition, `arn:aws`. Preserve the role's full path when replacing its placeholder.

```bash
set -euo pipefail
MEMBER_PROFILE='<MEMBER-PROFILE>'
PRIMARY_PROFILE='<PRIMARY-PROFILE>'
REGION='<REGION>'
COLLECTOR_ARN='arn:aws:continuum:<REGION>:<MEMBER-ACCOUNT-ID>:collectors/<COLLECTOR-ID>'
DATA_ROLE_ARN='arn:aws:iam::<PRIMARY-ACCOUNT-ID>:role/<ROLE-PATH-AND-NAME>'
ENVIRONMENT_ID='<ENVIRONMENT-ID>'
```

```bash
aws continuum get-resource-policy \
  --arn "$COLLECTOR_ARN" \
  --profile "$MEMBER_PROFILE" --region "$REGION" \
  --output json --no-cli-pager > collector-policy-before.json

jq -r '.policy' collector-policy-before.json > collector-policy.json
```

The member-account caller needs `continuum:GetResourcePolicy` and `continuum:PutResourcePolicy` on the collector.

### Add the grant to the existing policy

Edit `collector-policy.json`. Append the statement below to its existing `Statement` array, using the same role and collector ARNs as above. Keep every existing statement and use a unique `Sid`; if the array is empty, this becomes its first entry.

```json
{
  "Sid": "AuthorizeEnvironmentRole",
  "Effect": "Allow",
  "Principal": {
    "AWS": "arn:aws:iam::<PRIMARY-ACCOUNT-ID>:role/<ROLE-PATH-AND-NAME>"
  },
  "Action": "continuum:GetCollectorDataAccessAuthorization",
  "Resource": "arn:aws:continuum:<REGION>:<MEMBER-ACCOUNT-ID>:collectors/<COLLECTOR-ID>"
}
```

The JavaScript Object Notation (JSON) example above contains **one statement**, not the complete policy to submit. The application programming interface (API) replaces the entire stored policy. Submitting only this grant would remove other statements.

### Apply and read it back

```bash
REVISION_ID=$(jq -er '.revisionId' collector-policy-before.json)
jq -e . collector-policy.json > /dev/null

aws continuum put-resource-policy \
  --arn "$COLLECTOR_ARN" \
  --policy file://collector-policy.json \
  --expected-revision-id "$REVISION_ID" \
  --profile "$MEMBER_PROFILE" --region "$REGION" \
  --output json --no-cli-pager

aws continuum get-resource-policy \
  --arn "$COLLECTOR_ARN" \
  --profile "$MEMBER_PROFILE" --region "$REGION" \
  --output json --no-cli-pager > collector-policy-after.json

jq -s -e '.[0] == (.[1].policy | fromjson)' \
  collector-policy.json collector-policy-after.json
```

The final command returns `true` when the stored policy matches the submitted policy. If the revision changed, read the latest policy and reapply your edit to it before retrying. Do not combine an old policy document with a fresh revision ID.

## 5. Associate the collector from the primary account

Continue in the same shell after setting the variables above. For a same-account setup, use those variable definitions with the primary account's collector ARN, and skip the member-account policy commands.

```bash
aws continuum associate-collector \
  --environment-id "$ENVIRONMENT_ID" \
  --collector-arn "$COLLECTOR_ARN" \
  --collector-data-access-role-arn "$DATA_ROLE_ARN" \
  --profile "$PRIMARY_PROFILE" --region "$REGION" \
  --output json --no-cli-pager

aws continuum list-associated-collectors \
  --environment-id "$ENVIRONMENT_ID" \
  --profile "$PRIMARY_PROFILE" --region "$REGION" \
  --output json --no-cli-pager

aws continuum get-environment \
  --environment-id "$ENVIRONMENT_ID" \
  --profile "$PRIMARY_PROFILE" --region "$REGION" \
  --query 'configuration.codeConfiguration.collectorDetails.collectorDataAccessRoleArn' \
  --output text --no-cli-pager
```

Check that the intended collector appears and that the stored role is correct. Keep CLI automatic pagination enabled when listing associations. If calling the API directly, continue until there is no next token, even if a page is empty.

Association confirms the configured relationship. It does not by itself prove that a particular finding used the inventory. Continuum checks authorization again when retrieving context. After a scan, inspect the issue's contributing context and use [collector troubleshooting](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html#cv-adding-context-cross-account-troubleshooting) if the expected resources are missing.

## 6. Add EKS and deployment context where applicable

For EKS applications, follow [onboarding an EKS cluster](https://docs.aws.amazon.com/continuum/latest/userguide/cv-onboard-eks-cluster.html). AWS collector enablement does not complete cluster onboarding: the documented procedure also configures the collection role, an EKS access entry, and Kubernetes read-only RBAC. Repeat those steps and verification for each cluster. The procedure does not require making the Kubernetes API endpoint public.

Access entries require the cluster's authentication mode to be `API` or `API_AND_CONFIG_MAP`. Before changing a cluster that uses `CONFIG_MAP`, review the [one-way authentication-mode transition](https://docs.aws.amazon.com/continuum/latest/userguide/cv-onboard-eks-cluster.html#cv-onboard-eks-cluster-enable-access-entries).

For GitHub-backed applications, Continuum can collect [continuous integration and continuous delivery (CI/CD) context](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html#cv-adding-context-cicd) from workflows to help relate source to builds and deployments. Keep deployment definitions current and check the mappings shown in issue evidence.

When assessing severity, compare the issue's resource and deployment context with the application you actually run. The service's reachability assessment reasons over configuration; treat it as a prioritization signal, not a formal network reachability proof.

## 7. Identify your crown jewels

Identify resources whose compromise would have serious business impact, such as a database holding customer records or a bucket containing payment exports. Record each resource's ARN, account, Region, application, and business impact. Use this inventory when reviewing the resources and attack paths in an issue.

For example, use the resource tag `crown_jewel=true` to maintain this inventory for your own issue review. Apply it in the account that owns the resource, whether that is the primary account or a member account. Confirm the saved tag on the resource and remove it when the resource no longer meets your criteria.

Follow the [AWS guidance on classification tags](https://docs.aws.amazon.com/whitepapers/latest/tagging-best-practices/data-security-and-risk-management.html), and keep [sensitive information out of tag keys and values](https://docs.aws.amazon.com/prescriptive-guidance/latest/tagging-best-practices/tagging-practices-to-avoid.html#incorrect-sensitive). A tag records your classification; check the issue evidence to establish which resource and attack path the analysis considered. The [`reachedCrownJewels` signal](scans-and-remediation.md#interpret-crown-jewel-signals) describes a validation result and does not serve as tag readback.

Continue to [scanning and remediation](scans-and-remediation.md).
