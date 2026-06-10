# AWS WAF Best Practices
> As of July 2025, AWS WAF released a new console experience which renamed web ACls to [protection packs](https://aws.amazon.com/blogs/security/introducing-the-new-console-experience-for-aws-waf/). APIs, ARNs, and CLI commands still use the term web_acl/webacl, as does the legacy console. This was a UI and documentation change only — the terms are interchangeable. The only distinction is that the new console introduces concepts that are exclusive to the new UI and only refer to protection packs.

!!! warning "Future Content Updates in progress"
    We are actively working to revamp the AWS WAF best practices.  Most of the content has been updated but we are still working on several sections.  Content that is incomplete or not yet updated has been marked as such

## Introduction

Welcome to the AWS WAF Best Practices Guide. The purpose of this guide is to provide prescriptive guidance for deploying, configuring, and managing AWS WAF to protect your web applications and APIs. Publishing this guidance via GitHub will allow for quick iterations to enable timely recommendations that include service enhancements, as well as, the feedback of the user community. This guide is designed to provide value whether you are deploying AWS WAF for the first time on a single resource, or looking for ways to optimize AWS WAF in an existing multi-account deployment managed by AWS Firewall Manager.



## How to use this guide

This guide is geared towards security practitioners, solutions architects, and application teams who are responsible for protecting web applications and APIs from common web exploits, bot traffic, and Layer 7 DDoS. The best practices are organized into focused sections for easier consumption. Each section includes a set of corresponding best practices that begin with a brief overview, followed by detailed guidance for implementing the recommendations. The topics do not need to be read in a particular order:

* [Prerequisites and Fundamentals](#prerequisites-and-fundamentals) — Fundamental concepts and planning for a new or updating an AWS WAF deployment
* [Recommended HTTP Architecture on AWS](#recommended-http-architecture-on-aws) — Architect HTTP workloads with CloudFront for maximum WAF effectiveness
* [Operationalizing](#operationalizing) — Operational guidance for managing AWS WAF at scale
* [AWS Managed Rules](#aws-managed-rules) — Baseline and use-case specific Amazon Manged Rule Groups
* [Custom Rules](#custom-rules) — Custom rules for application-specific threats
* [Recommended WAF Rule Order](#recommended-waf-rule-order) — Arrange rules in your protection pack for optimal protection and cost efficiency
* [Bot Management](#bot-management) — Detect and control bot traffic with Bot Control
* [Fraud Prevention](#fraud-prevention) — Detect fraudulent sign up and sign in attempts
* [CAPTCHA and Challenge](#captcha-and-challenge) — Use token-based mitigation actions effectively
* [Deployment Strategy](#deployment-strategy) — Safely deploy WAF for the first time and update managed rule versions
* [WAF Costs](#waf-cost) — Understand AWS WAF pricing, WCU capacity, and Shield Advanced cost protection
* [Logging Approaches](#waf-logging) — Configure log destinations, filtering, and cost optimization for AWS WAF logs
* [Monitoring WAF Rules](#monitoring-waf-rules) — Observe rule behavior with CloudWatch metrics and WAF log analysis
* [Using WAF with Other AWS Services](#using-waf-with-other-aws-services) — Integrate with Firewall Manager and Shield Advanced
* [Additional References](#additional-references) — Supplementary topics including known differences from WAF Classic

## What is AWS WAF?

AWS WAF is a web application firewall that lets you monitor and control the HTTP(S) requests that are forwarded to your protected web application resources. You can protect Amazon CloudFront distributions, Amazon API Gateway REST APIs, Application Load Balancers, AWS AppSync GraphQL APIs, Amazon Cognito user pools, AWS App Runner services, AWS Verified Access instances, and AWS Amplify applications. AWS WAF lets you create rules that can block, allow, count, or apply CAPTCHA and Challenge actions to web requests based on conditions that you specify, such as IP addresses, HTTP headers, HTTP body, URI strings, SQL injection, and cross-site scripting. For more information, see [What is AWS WAF?](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html) in the AWS WAF Developer Guide.

## What are the benefits of enabling AWS WAF?

AWS WAF gives you control over how traffic reaches your applications by enabling you to create security rules that block common attack patterns and filter out specific traffic patterns you define. Key benefits include:

* Protection against common web exploits such as SQL injection and cross-site scripting (XSS) using [AWS Managed Rules](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html) maintained AWS without needing to write and maintain rules yourself.
* Flexible [custom rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rules.html) that let you define application-specific conditions to allow, block, count, or challenge requests based on IP addresses, HTTP headers, request body, URI paths, geographic origin, and more.
* [Rule labels](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html) that let you use signals from AWS Managed Rules and other rule groups to customize how protection is applied — for example, switching a managed rule to Count mode and writing a custom rule that uses the label to block with additional conditions, enabling fine-grained false positive handling without losing protection.
* Rate-based rules that automatically block request floods from individual clients, protecting against volumetric attacks and reducing the impact of DDoS events.
* Application layer DDoS protection through the [Anti-DDoS managed rule group](https://docs.aws.amazon.com/waf/latest/developerguide/waf-anti-ddos-rg-using.html) (`AWSManagedRulesAntiDDoSRuleSet`) that automatically detects and mitigates layer 7 DDoS attacks within seconds using machine learning-based anomaly detection. This is available to all AWS WAF customers, with an advanced tier included for [AWS Shield Advanced](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary.html) subscribers.
* Bot management capabilities through [Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html) that detect and manage bot traffic ranging from self-identifying crawlers to sophisticated automated threats, including AI bots and Web Bot Authentication (WBA) for detecting headless browsers and automation frameworks.
* Fraud prevention through [Account Takeover Prevention (ATP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-atp.html) and [Account Creation Fraud Prevention (ACFP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-acfp.html) managed rule groups that detect and block credential stuffing, stolen credential usage, and fraudulent account creation attempts.
* Guided setup and preconfigured protection packs that reduce configuration complexity, with continuous security recommendations based on real-time traffic analysis.
* Centralized WAF policy management across your AWS Organization using [AWS Firewall Manager](https://docs.aws.amazon.com/waf/latest/developerguide/fms-chapter.html).
* Real-time visibility into web traffic through CloudWatch metrics and detailed WAF logs that can be analyzed with CloudWatch Logs Insights, Amazon Athena, or Amazon QuickSight.
* Pay only for what you use with no upfront commitments. Pricing is based on the number of protection packs, rules, and requests inspected. See [AWS WAF Pricing](https://aws.amazon.com/waf/pricing/) for details.

## Guide Sections

* [Prerequisites and Fundamentals](./prerequisites/docs/index.md)
* [Recommended HTTP Architecture on AWS](./recommended-http-architecture/docs/index.md)
* [Operationalizing](./operationalizing/docs/index.md)
* [AWS Managed Rules](./aws-managed-rules/docs/index.md)
* [Custom Rules](./custom-rules/docs/index.md)
* [Bot Management](./bot-management/docs/index.md)
* [Fraud Prevention](./fraud-prevention/docs/index.md)
* [Recommended WAF Rule Order](./recommended-waf-rule-order/docs/index.md)
* [CAPTCHA and Challenge](./captcha-and-challenge/docs/index.md)
* [WAF Costs](./waf-cost/docs/index.md)
* [Logging Approaches](./waf-logging/docs/index.md)
* [Monitoring WAF Rules](./monitoring-waf-rules/docs/index.md)
* [Using WAF with Other AWS Services](./using-waf-with-other-services/docs/index.md)
* [Additional References](./additional-references/docs/index.md)

## Related Guides

* [AWS WAF User Guide](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
* [Best practices for intelligent threat mitigation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-protections-best-practices.html)
* [Best practices for using the CAPTCHA and Challenge actions](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-best-practices.html)
* [Discover the benefits of AWS WAF advanced rate-based rules](https://aws.amazon.com/blogs/security/discover-the-benefits-of-aws-waf-advanced-rate-based-rules/)
* [How to configure block duration for IP addresses rate limited by AWS WAF](https://aws.amazon.com/blogs/networking-and-content-delivery/configure-block-duration-for-ips-rate-limited-by-aws-waf/)
