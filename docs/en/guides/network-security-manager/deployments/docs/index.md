<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# Deployments

## Overview

An NSM deployment puts NSM policies into effect. It connects one or more NSM policies to exactly one scope, and creating it is the step that rolls out those NSM policies. NSM then evaluates every resource in the scope, and each resource receives every deployed NSM policy whose scope includes it. Where a required firewall is missing, NSM creates it, and where one already exists, NSM synchronizes it with your NSM policies. NSM does the same for resources that teams create later.

A deployment decides where NSM policies apply, not how they combine. Priority belongs to each NSM policy, so NSM orders NSM rules and resolves conflicts in the same way no matter which NSM deployments the NSM policies are in. For how priority works, see [Policy Priority](../../policy-priority/docs/index.md). For how deployments relate to the other NSM resources, see [Relationships between NSM resources](../../prerequisites/docs/index.md#relationships-between-nsm-resources).

## Best practices

**Put NSM policies that share a scope and an owner in one NSM deployment**

An NSM deployment can connect more than one NSM policy, but only one scope. When NSM policies apply to the same scope and the same team owns them, put them in one NSM deployment. For example, a central team's **AMR deployment** can connect two NSM policies to [**All Public Facing Resources**](../../scopes/docs/index.md#all-public-facing-resources):

* [**AMRs-in-Count**](../../firewall-types/aws-waf/recommended-design/docs/index.md#policy-amrs-in-count) at priority 100, which labels requests that match the AMRs without blocking them.
* [**AMR block with exceptions**](../../firewall-types/aws-waf/recommended-design/docs/index.md#policy-amr-block-with-exceptions) at priority 9500, which blocks those labeled requests unless an application has an exception.

These two NSM policies belong together, because the block NSM policy enforces the AMRs that the count NSM policy adds, and both must reach the same resources.

**Group NSM policies into NSM deployments by what logically belongs together**

You don't need to split NSM deployments by priority, or by what the NSM policies contain, such as NSM rules for the AWS WAF pre-process or post-process rule groups, or NSM firewall configuration rules. NSM policies can share an NSM deployment whenever it logically makes sense for them to be deployed together. Each NSM policy's priority, not the NSM deployment that it's in, places its NSM rules in the firewall's rule order. In the previous example, **AMRs-in-Count** at 100 still runs before the application exceptions, and **AMR block with exceptions** at 9500 still runs after them, even though both NSM policies are in one NSM deployment.

**Combine firewall types in one NSM deployment**

One NSM deployment can connect NSM policies for different firewall types, such as an AWS WAF NSM policy and an AWS Shield Advanced NSM policy. For example, a central team can deploy a WAF NSM policy and a **Shield Advanced** NSM policy to the same **All Public Facing Resources** scope in one NSM deployment. NSM tracks priority separately for each firewall type, so NSM policies for different firewall types in one NSM deployment never compete on priority.

**Use separate NSM deployments when different teams own the NSM policies**

We recommend a separate NSM deployment for each team, even when the teams' NSM policies use the same scope. For example, we recommend that threat analysts own their own **Threat intelligence deployment**, instead of sharing an NSM deployment with the central team or with an application team. Each team can then roll out and roll back its own changes without changing another team's NSM deployment.


**Deploy to shared scopes**

Deploy organization-wide NSM policies to shared scopes, such as **All Public Facing Resources**, instead of creating a new scope for each NSM deployment. When the shared scope changes, every NSM deployment that uses it picks up the change. For more information, see [Scopes](../../scopes/docs/index.md).

**Plan for one NSM deployment for each scope**

Each NSM deployment has exactly one scope. CloudFront distributions and regional resources need separate scopes, so an NSM policy that applies to both needs one NSM deployment for each scope. For more information, see [How a scope selects resources](../../scopes/docs/index.md#how-a-scope-selects-resources).

**Give each application its own NSM deployment**

For application controls, create one NSM deployment for each application that connects the application's NSM policy to the application's scope. Adding a control to the application then means adding an NSM rule to its existing NSM policy, not creating another NSM deployment.

**Review what a scope matches before you deploy**

Each scope matches exactly what its conditions describe, and an NSM deployment applies its NSM policies to every resource that the scope matches. Before you deploy, review which resources the scope matches, so that NSM policies reach only the resources that need them.

**Promote changes from non-production to production**

Changes to a deployed NSM policy take effect right away. Use separate NSM deployments for non-production and production, test a new version in non-production, and then promote the same version to production. For more information, see [Versioning and Drafts](../../prerequisites/docs/index.md#versioning-and-drafts).

**Decide who needs to see synchronization status**

An NSM deployment can make the aggregate synchronization status of the resources that it covers visible across accounts. This setting is off by default. Turn it on when account owners, such as application teams, need to see whether NSM has synchronized their resources. For how to resolve synchronization issues, see [Troubleshooting Synchronization](../../troubleshooting-synchronization/docs/index.md).

**Name NSM deployments for what they connect**

Name each NSM deployment for the NSM policies and scope that it connects, such as **AMR deployment** or **App1 exception deployment**, so that operators can tell what each NSM deployment rolls out without opening it.

## Deployment example

The following example is a request body for the NSM `CreateDeployment` API. It connects the **AMRs-in-Count** and **AMR block with exceptions** NSM policies to the **All Public Facing Resources - CloudFront** scope. Account IDs and ARNs are placeholders.

```json
{
  "deploymentName": "AMR deployment",
  "deploymentConfiguration": {
    "enableCrossAccountVisibility": false
  },
  "associatedPolicyList": [
    { "policyIdentifier": "arn:aws:network-security-manager:us-east-1:111111111111:policy:amrs-in-count-EXAMPLE" },
    { "policyIdentifier": "arn:aws:network-security-manager:us-east-1:111111111111:policy:amr-block-with-exceptions-EXAMPLE" }
  ],
  "associatedScopeList": [
    { "scopeIdentifier": "arn:aws:network-security-manager:us-east-1:111111111111:scope:all-public-facing-cloudfront-EXAMPLE" }
  ]
}
```

<!-- TODO -->
