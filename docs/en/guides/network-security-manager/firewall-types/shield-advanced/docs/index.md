<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# AWS Shield Advanced

## Overview

An AWS Shield Advanced NSM policy turns on Shield Advanced protection for each resource in its scope. It doesn't contain NSM rules, and it doesn't configure Shield Advanced itself. For the recommended Shield Advanced NSM policy, its priority, and its scope, see [Shield Advanced](../../aws-waf/recommended-design/docs/index.md#policy-shield-advanced) in the AWS WAF Recommended Design.

## Configure Shield Advanced outside NSM

Before NSM can turn on protection, each account must subscribe to Shield Advanced. Configure the subscription and account-level settings, such as Shield Response Team (SRT) access and proactive engagement, outside NSM. The [AWS Shield Advanced One-Click Deployment](https://github.com/aws-samples/aws-shield-advanced-one-click-deployment) repository has code examples that show how to automatically configure the parts of Shield Advanced beyond resource protection, such as the subscription and SRT access.

## Configure layer 7 DDoS protection with an AWS WAF NSM rule

Configure layer 7 DDoS protection with the Anti-DDoS AMR rule group in an AWS WAF NSM rule, not with the Shield Advanced NSM policy. For the NSM rule, see [Anti-DDoS](../../aws-waf/rule-examples/docs/index.md#anti-ddos) in the AWS WAF Rule Examples. For the NSM policy that contains it, see [Anti-DDoS](../../aws-waf/recommended-design/docs/index.md#policy-anti-ddos) in the AWS WAF Recommended Design.

<!-- TODO -->
