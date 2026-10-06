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

An NSM rule defines what a network security control is, independent of where it applies. Each NSM rule is one of the following:

* **Managed rule group** – A set of inspection logic that a provider maintains and versions, such as AWS or an AWS Marketplace seller.
* **FW inspection** – Inspection logic that you define, which matches traffic and takes an action on it.
* **FW configuration** – A setting for the firewall itself rather than for the traffic, such as logging.

An NSM rule has no effect on its own. You add it to an NSM template or directly to an NSM policy, and the position of the NSM rule in the NSM policy and the priority of the NSM policy determine the order in which it's evaluated. Because an NSM rule doesn't carry a scope, you can reuse the same NSM rule in any number of NSM policies.

Each firewall type defines what an NSM rule can contain. For example, in AWS WAF, a managed rule group is an AWS Managed Rules (AMR) rule group, an FW inspection is a WAF rule such as an IP block list or a rate limit, and an FW configuration is a logging configuration.

## Best practices

<a id="use-nsm-rule-versions-to-test-changes-before-production"></a>
**Use NSM rule versions to test changes before production**

When you change an NSM rule, create a new version of the NSM rule instead of editing the version that production uses. Then use separate NSM policies and NSM scopes for production and non-production, so you can test the new NSM rule version before you switch production to it.

For example, to move an AWS WAF AMR rule group from version 1.0 to version 1.1:

1. Version 1 of your NSM rule references version 1.0 of the AMR rule group. Your production NSM policy references version 1 of the NSM rule explicitly, instead of the latest version, and you deploy it to a production scope.
2. Create version 2 of the NSM rule that references version 1.1 of the AMR rule group.
3. Add version 2 of the NSM rule to a non-production NSM policy, and deploy that NSM policy to a non-production scope.
4. Test version 1.1 on your non-production resources.
5. When you're satisfied with the results, update the production NSM policy to use version 2 of the NSM rule. Only the NSM rule version changes, so production receives the same configuration that you tested.
