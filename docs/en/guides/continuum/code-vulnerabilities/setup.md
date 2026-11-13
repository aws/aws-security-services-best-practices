---
title: Prepare and connect source code
---

# Prepare and connect source code

## 1. Choose the account, Region, and application

Create the environment in the **primary account**. Use the same Region for any collectors you will associate with it. For an Amazon Simple Storage Service (Amazon S3) integration, the source bucket must also be in the primary account and that Region. See [getting started](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html) and [collector setup](https://docs.aws.amazon.com/continuum/latest/userguide/cv-adding-context.html).

Before connecting source, identify:

- The repositories and projects that make up the application, including shared code needed to build it.
- The source revision you want to assess and the languages and file extensions it uses.
- The build command, runtime and toolchain versions, manifests, lockfiles, and generated inputs.
- The dependency hosts required during a clean build.
- The AWS accounts and Regions where this source is deployed.

Keep the first environment small enough to troubleshoot as one application. The documented default is **10 repositories per environment across all integrations**. Check [current quotas](https://docs.aws.amazon.com/continuum/latest/userguide/quotas.html) before selecting a larger application.

The command examples require a version of the AWS Command Line Interface (AWS CLI) that includes `aws continuum`. The collector policy example also uses Bash and `jq`. Replace every `<PLACEHOLDER>` with your own value.

Choose encryption settings before creating integrations and environments. Continuum uses AWS owned keys by default. Where [customer managed keys are supported](https://docs.aws.amazon.com/continuum/latest/userguide/encryption-at-rest.html), select an enabled symmetric encryption key in the same Region at creation; the resource's key cannot be changed later. Follow the documented key-policy prerequisites for the caller and service.

## 2. Check source eligibility

Use [Supported languages and source files](https://docs.aws.amazon.com/continuum/latest/userguide/cv-supported-languages.html) as the source of truth for eligible extensions and excluded folders. Check the actual extensions in each selected repository against that page; support for a language alone does not make every file type used by that language eligible.

Extensions are case-sensitive. At least one supported file must exist outside excluded folders across the selected repositories.

Extension eligibility does not establish that the entire application builds or that every framework feature can be validated. In a repository with several projects, check the source and build inputs for each project you intend to assess.

### Preview excluded directories

Run this command in **Bash from the repository root**. It prints directory paths whose names match the [documented exclusions](https://docs.aws.amazon.com/continuum/latest/userguide/cv-supported-languages.html), at any depth, and skips their contents.

```bash
set -o pipefail

find . -type d \( \
  -name .git -o -name .hg -o -name .svn -o \
  -name node_modules -o -name .venv -o -name venv -o \
  -name __pycache__ -o -name .mypy_cache -o -name .pytest_cache -o -name .tox -o \
  -name build -o -name dist -o -name target -o -name .next -o -name .nuxt \
\) -prune -print0 |
  while IFS= read -r -d '' excluded_dir; do
    printf '%q\n' "$excluded_dir"
  done
```

Illustrative output:

```text
./node_modules
./packages/api/build
./.venv
```

This previews the local working tree, including local directories that might not be committed. Paths are shell-escaped and symbolic links are not followed. No output with exit status `0` means no matching directory names were found; it does not check file extensions or prove that the selected source will build. Investigate any application source stored under an excluded directory before scanning.

## 3. Connect the source

Choose the integration that matches where the code is maintained.

| Source | Setup requirements | Check |
|---|---|---|
| GitHub | Install the Continuum GitHub App in the account or organization that owns the repositories, grant the intended repository access, and complete the separate authorization step in Continuum. | The integration lists the repositories you expect. Organization approval may be required. |
| GitLab | Use GitLab.com or a supported self-managed instance with a token that can access the selected private projects. | The token's scope, role, project visibility, expiry, and server reachability satisfy the requirements below. |
| Amazon S3 | Upload source as a ZIP archive and grant Continuum access through a dedicated integration role. | The bucket, role, source prefix, and external identifier (ID) match the integration configuration. |

### GitHub

Follow [getting started through GitHub](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html#cv-getting-started-github). Installation and authorization are separate steps. Select the account or organization that owns the code during installation, then return to Continuum to authorize and create the integration.

If the console remains at **Waiting for GitHub**, use **Cancel authorization** and restart the authorization flow. Check the installed app's repository access if a repository is missing.

### GitLab

Follow the [GitLab integration security guidance](https://docs.aws.amazon.com/continuum/latest/userguide/gitlab-integration-security.html). Continuum currently supports **Private** GitLab projects. Public and Internal project visibility are not supported for this integration.

Use a dedicated project or group access token where possible, with the documented `api` scope and at least the Developer role for the selected projects. Personal access tokens are also supported. Keep the token's access limited to the projects intended for Continuum.

With the optional `self_rotate` scope, Continuum can rotate the token automatically, with a 90-day lifetime for the replacement token. Otherwise, track its expiration and replacement. A self-managed GitLab instance must be publicly reachable on port 443 using Hypertext Transfer Protocol Secure (HTTPS); check that requirement before choosing it as a source.

### Amazon S3

Follow [getting started through Amazon S3](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html#cv-getting-started-s3).

1. Use a bucket in the primary account and the same Region as the integration.
2. Create a ZIP archive of the intended source and build inputs. Inspect the archive before uploading it.
3. Upload the archive under the source prefix you will select, such as `code/`.
4. Create the dedicated AWS Identity and Access Management (IAM) role using the [documented trust and permissions policies](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html#cv-getting-started-s3-role). The role must use the `/continuum/integrations/` path.
5. In **Integrations**, choose **Add integration**, select **S3**, and supply the Amazon Resource Names (ARNs) that identify the bucket and role, and the matching external ID.

The documented role permits bucket listing, source and context reads, and patch reads and writes under `continuum-patches/`. Scope object access to the prefixes in use. Keep the documented `ListBucket` permission usable for integration validation; a prefix condition on that permission can prevent validation.

If source objects use server-side encryption with AWS Key Management Service (AWS KMS) keys (SSE-KMS), check the role's KMS authorization and the key policy as well as its S3 access. See [accessing KMS-encrypted S3 objects](https://repost.aws/knowledge-center/decrypt-kms-encrypted-objects-s3). This is separate from [encryption of the Continuum resource](https://docs.aws.amazon.com/continuum/latest/userguide/encryption-at-rest.html).

## 4. Prepare the build inputs

Use a clean checkout to confirm the application's normal build command, toolchain versions, and dependency sources. Include the manifests and lockfiles that define that build. Check whether generated code, shared projects, or external build inputs are required.

In the environment's **Advanced settings**, configure any additional dependency domains required by the build. The [network policy configuration](https://docs.aws.amazon.com/cli/latest/reference/continuum/update-environment.html) accepts up to 50 hostname entries. Enter hostnames without uniform resource locator (URL) schemes, paths, ports, or wildcards.

Allowing a dependency host does not provide credentials for its registry. If a build depends on a private registry, verify how it can authenticate before relying on that build in Continuum. Do not put registry tokens or other secrets into source files to make a scan work.

When updating the network policy through the application programming interface (API) or CLI, submit the complete intended domain list: the update replaces the policy. Builds accepted before the change keep the domains they were accepted with.

## 5. Create the environment and follow its first scan

Follow [creating an environment](https://docs.aws.amazon.com/continuum/latest/userguide/cv-getting-started.html#cv-getting-started-s3-environment).

1. Open **Environments**, choose **Create environment**, and enter a name that identifies the application.
2. Select the integration and repositories. For S3, set **Source code base path** to the uploaded prefix, such as `code/`. Use a prefix, not an `s3://` uniform resource identifier (URI) or a ZIP object name.
3. For S3, if you uploaded optional context documents, set **Knowledge documents base path** to their prefix, such as `context/`. The path is configured here, when creating the environment.
4. Choose a scan schedule. **Manual only** is useful while qualifying the initial setup.
5. Review **Advanced settings**, including automatic patch settings and dependency domains, before creating the environment.

Creating an environment starts its first build and scan, **including when Manual only is selected**. That schedule controls subsequent automatic scans. Open the environment's **Scans** tab and follow the run. A successful scan can precede completion of issue and patch processing; refresh those views as processing continues.

For a useful first-run check, confirm the selected source, inspect any scan failure reason, and open available issues to review their evidence. Then [add the application's AWS context](aws-context.md).
