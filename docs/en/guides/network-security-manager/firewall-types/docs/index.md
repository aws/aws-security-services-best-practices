<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# NSM by Firewall Type

## Overview

NSM manages AWS WAF and AWS Shield Advanced today, and support for AWS Network Firewall is coming soon. The same model of NSM rules, NSM policies, NSM scopes, and NSM deployments applies to each firewall type that NSM manages.

Each firewall type has its own recommended NSM policies, and NSM tracks priority separately for each firewall type.

## Firewall types

* [AWS WAF](../aws-waf/docs/index.md)
* [AWS Shield Advanced](../shield-advanced/docs/index.md)
* [AWS Network Firewall](../network-firewall/docs/index.md)
