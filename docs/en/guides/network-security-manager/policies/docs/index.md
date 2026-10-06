<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# Policies

**Group NSM rules that share a priority and a scope into one NSM policy**

An NSM policy has one priority, so group NSM rules that need to run at the same priority into one NSM policy, and give each NSM policy one need. You can then read your NSM policies in priority order and know what each firewall contains and why.

The trade-off is that every NSM rule in an NSM policy applies to every scope that you deploy the NSM policy to. Where you need customizations or unique scoping, use separate NSM policies.

Common reasons to make NSM rules a separate NSM policy include the following:

| Reason | Example NSM policy | When it applies |
|---|---|---|
| Placed early in the firewall's rule order | **Threat intelligence/block lists** | The NSM traffic inspection rules must be evaluated on each firewall before the rules from most other NSM policies, such as block lists that need to stop traffic before any other inspection. |
| Placed late in the firewall's rule order | **Baseline enforcement** | The NSM traffic inspection rules must be evaluated on each firewall after the rules from most other NSM policies, such as enforcement that acts on the results of earlier inspection. |
| Wins or yields on configuration settings | **Mandatory firewall settings**, **Firewall defaults** | The NSM firewall configuration rules set a property that other NSM policies also set. When two NSM policies set the same property, the NSM policy with the higher priority (lower number) wins. For example, **Mandatory firewall settings** at a high priority sets logging that no other NSM policy can override, and **Firewall defaults** at a low priority sets fallback values that any more specific NSM policy can override. |
| Broad scope | **Baseline managed rules** | The NSM rules apply to a large part of your organization, such as every resource in **All Public Facing Resources**. |
| Specific scope | **Technology-specific managed rules** | The NSM rules apply only to resources that share a technology, resource type, or network role, such as a **Technology apps** scope. |
| Application or business unit scope | **Application exceptions**, **Business unit baseline** | The NSM rules apply only to one **Application** scope or one business unit's OU, and are often owned by that team. |

For how this applies to each firewall type, see the recommended NSM policies for [AWS WAF](../../firewall-types/aws-waf/recommended-design/docs/index.md) and [AWS Network Firewall](../../firewall-types/network-firewall/recommended-design/docs/index.md).

<!-- TODO -->

**Use separate NSM policies when different teams own the NSM rules**

We recommend a separate NSM policy for each team, even when the teams' NSM rules use the same priority range and scope. For example, we recommend that threat analysts own their own **Threat intelligence/block lists** NSM policy, instead of adding their NSM rules to an NSM policy that the central team owns. Each team can then version, test, and roll back its own NSM rules without changing another team's NSM policy.

The exception is an NSM rule that's specific to one application. For example, if a threat intelligence NSM rule applies only to App1, it can go in one of App1's NSM policies.

**Inspect with low priority numbers and enforce with high priority numbers**

We recommend low priority numbers for NSM policies that count or inspect, so they run first, and high priority numbers for NSM policies that enforce, where enforcing makes sense, so they run last. NSM policies between the two, such as exceptions, can then act on the results of inspection before enforcement.

Because each NSM policy has its own priority and scope, a central team can own the inspect and enforce NSM policies across the organization, while application teams add NSM policies between them for only their own applications. Application teams don't need to change the central team's NSM policies, and the central team doesn't need a different NSM policy for each application. For how this applies to AWS WAF, see [Label-Based Exceptions](../../firewall-types/aws-waf/label-based-exceptions/docs/index.md).

**Set priority deliberately**

For priority recommendations and strategies, see [Policy Priority](../../policy-priority/docs/index.md).

**Choose remediation options**

<!-- TODO: recommended remediation settings -->

<!-- TODO: when to use nonstandard remediation settings -->
