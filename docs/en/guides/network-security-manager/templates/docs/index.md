<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# Templates

An NSM template is a reusable, ordered set of NSM rules. You add an NSM template to an NSM policy in the same way that you add an NSM rule. NSM templates are optional, because an NSM policy can contain NSM rules directly.

**Use NSM templates when multiple operators manage parts of your organization**

NSM templates make the most sense when you have multiple business units, or multiple operators that each independently manage a large part of your organization. The most common example is an organization with multiple business units, where the larger organization has a baseline that it requires or suggests each business unit follows. The larger organization publishes the baseline as an NSM template, and each business unit adds that NSM template to its own NSM policies.

If one team manages NSM for your entire organization, add NSM rules to NSM policies directly instead.

<!-- TODO -->
