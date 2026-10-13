<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# Rules

!!! info "Looking for rule examples?"
    Each firewall type has a page of NSM rule examples, with the configuration of each NSM rule in its recommended NSM policies.

    **[AWS WAF Rule Examples →](../../firewall-types/aws-waf/rule-examples/docs/index.md)**

## Overview

An NSM rule defines what a network security control is, independent of where it applies. Each NSM rule is one of two types:

* **NSM traffic inspection rule** – Inspection logic that matches traffic and takes an action on it. The logic can be a managed rule group that a provider maintains and versions, such as AWS or an AWS Marketplace seller, or inspection logic that you define.
* **NSM firewall configuration rule** – A setting for the firewall itself rather than for the traffic, such as logging.

An NSM rule has no effect on its own. You add it to an NSM template or directly to an NSM policy, and the position of the NSM rule in the NSM policy and the priority of the NSM policy determine the order in which it's evaluated. Because an NSM rule doesn't carry a scope, you can reuse the same NSM rule in any number of NSM policies.

Each firewall type defines what an NSM rule can contain. For example, in AWS WAF, an NSM traffic inspection rule contains a rule group, such as an AWS Managed Rules (AMR) rule group or a custom rule group with WAF rules such as an IP block list or a rate limit, and an NSM firewall configuration rule contains one web ACL setting, such as a logging configuration.

## Best practices

<a id="use-nsm-rule-versions-to-test-changes-before-production"></a>
**Use NSM rule versions to test changes before production**

When you change an NSM rule that production uses, test the change in non-production before production picks it up. Pin production to a versioned snapshot of the NSM rule, and use separate NSM policies and NSM scopes for production and non-production, so that only non-production picks up the change until you move production to a new snapshot. For how drafts, changes going live, and versioned snapshots work, see [Versioning and Drafts](../../prerequisites/docs/index.md#versioning-and-drafts).

For example, to move an AWS WAF AMR rule group from version 1.0 to version 1.1:

1. Your NSM rule references version 1.0 of the AMR rule group. Create a versioned snapshot of the NSM rule. Your production NSM policy references that snapshot explicitly, instead of the latest version, and you deploy it to a production scope.
2. Your non-production NSM policy references the latest version of the NSM rule, and you deploy it to a non-production scope.
3. Edit the NSM rule to reference version 1.1 of the AMR rule group, and save it. The non-production NSM policy picks up version 1.1, and production stays on the snapshot that references version 1.0. Then create a new versioned snapshot of the NSM rule, which captures the configuration that you just saved.
4. Test version 1.1 on your non-production resources.
5. When you're satisfied with the results, update the production NSM policy to reference the snapshot from step 3. The NSM rule snapshot from step 3 contains the configuration that you tested, so production receives that configuration as long as no one changed the NSM rule again while you tested it.
