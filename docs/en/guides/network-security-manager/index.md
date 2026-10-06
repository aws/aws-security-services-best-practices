<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# AWS Network Security Manager Best Practices

## Introduction

Welcome to the AWS Network Security Manager (NSM) Best Practices Guide. The purpose of this guide is to provide prescriptive guidance for using NSM to centrally manage AWS WAF and AWS Shield Advanced network security controls across your AWS accounts and resources. Publishing this guidance via GitHub will allow for quick iterations to enable timely recommendations that include service enhancements, as well as feedback from the user community.

## What is AWS Network Security Manager?

NSM gives every team that contributes to network security one shared place to manage those controls. NSM manages AWS WAF and AWS Shield Advanced today, and support for AWS Network Firewall is coming soon.

You define which traffic inspection and firewall configurations apply where, and in what order of precedence, through five NSM resources. The same model applies to each firewall type that NSM manages:

1. **NSM rules** define a traffic inspection or firewall configuration.
2. **NSM templates** (optional) capture a set of NSM rules that you use in more than one NSM policy.
3. **NSM policies** set the order of precedence in which NSM rules are inspected.
4. **NSM scopes** select the resources that an NSM policy targets.
5. **NSM deployments** put NSM policies into effect.

Every resource supports versioning, rollback, and drafts, so you can test version 2 of an NSM rule in development and then promote that same version to production.

If you use AWS Firewall Manager today, you no longer need to bundle every WAF rule and configuration into one Firewall Manager policy for each scope, or duplicate a Firewall Manager policy to give one business unit something different. Going forward, NSM is the recommended service for managing AWS WAF and AWS Shield.

## How to use this guide

This guide is geared towards cloud architects, central security and operations teams, application teams, and threat analysts who contribute to an organization's network security posture. The first sections cover each NSM resource in depth. Later sections cover each firewall type that NSM manages and how to troubleshoot synchronization issues:

* [Prerequisites and Fundamentals](./prerequisites/docs/index.md) – Prerequisites, NSM resources, versioning, and drafts
* [Rules](./rules/docs/index.md) – NSM rules
* [Templates](./templates/docs/index.md) – NSM templates
* [Policies](./policies/docs/index.md) – NSM policies, including priority principles that apply to every firewall type
* [Scopes](./scopes/docs/index.md) – How NSM scopes select resources, with example scopes
* [Deployments](./deployments/docs/index.md) – NSM deployment best practices and an example
* [NSM by Firewall Type](./firewall-types/docs/index.md) – The recommended design, rule examples, and firewall-specific topics for each firewall type that NSM manages
* [Troubleshooting Synchronization](./troubleshooting-synchronization/docs/index.md) – Diagnose and resolve synchronization issues (coming soon)

## Prerequisites

To use NSM across an organization, you need AWS Organizations with a delegated administrator account for NSM, and AWS Resource Access Manager (AWS RAM). To use NSM in a single account, you don't need to set anything up. In both cases, NSM creates and manages an AWS Config service-linked recorder for you, at no customer-facing cost.
