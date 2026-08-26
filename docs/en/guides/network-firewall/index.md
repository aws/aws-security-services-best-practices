---
title: Introduction
---

# AWS Network Firewall Best Practices

This guide provides opinionated, prescriptive guidance for deploying and operating AWS Network Firewall effectively. It is written for security practitioners, network engineers, and solutions architects. If you are evaluating which firewall approach to use, start with the [AWS Network Security Fundamentals](../firewall-overview/index.md) guide instead.

## How to use this guide

The guide is organized from foundational concepts through deployment decisions, rule configuration, and ongoing operations. First-time deployers benefit from reading in order, starting with prerequisites and working through deployment architecture before configuring rules. If you are looking for guidance on a specific topic, each page is self-contained and can be read independently.

If you just want to know what to do without reading the reasoning behind it, see the [Best practices quick reference](./quick-reference/docs/index.md). Every recommendation in it links to the section that explains why. Throughout the rest of the guide, the prescriptive guidance is called out in green "Best practice" boxes, so you can skim a page and act on those alone.

## Guide sections

| Section | What you will learn |
|---------|-------------------|
| [Prerequisites and fundamentals](./prerequisites/docs/index.md) | How the Suricata engine processes traffic, what Network Firewall inspects and does not inspect, the relationship between Network Firewall and DNS Firewall, and traffic symmetry requirements |
| [Deployment architecture](./deployment-architecture/docs/index.md) | Centralized and distributed deployment models, native Transit Gateway integration, multi-endpoint patterns, and multi-account management with AWS Firewall Manager and AWS RAM |
| [Firewall policy configuration](./firewall-policy-configuration/docs/index.md) | Rule evaluation ordering, default actions, stream exception policy, HOME_NET variable configuration, and TCP idle timeout tuning |
| [Customer managed rules](./customer-managed-rules/docs/index.md) | Best practices for writing custom Suricata rules, the `flow:` keyword and Suricata rule types, rule group capacity calculation, domain filtering, container attribute referencing, and protocol enforcement. Covers what you need to know before writing custom rules, and what experienced operators should be aware of. |
| [Sample Suricata rules](./sample-suricata-rules/docs/index.md) | Common Suricata rules typically deployed with Network Firewall, with explanations for each. Includes a getting-started rule template for the domain allowlist architecture use case. Helps you get up and running without needing deep Suricata expertise. |
| [AWS Managed Rules](./aws-managed-rules/docs/index.md) | Taking advantage of AWS-managed threat intelligence, Active Threat Defense, domain and IP reputation lists, URL/domain category filtering, and partner managed rules. You do not have to write all your rules from scratch. |
| [TLS inspection](./tls-inspection/docs/index.md) | Inbound and outbound TLS decryption configuration, CA certificate requirements, scope configurations, and guidance to help you decide whether TLS inspection is appropriate for your workloads |
| [Logging and monitoring](./logging-and-monitoring/docs/index.md) | Alert and flow log types, logging destinations, log analysis patterns, CloudWatch dashboards, and operational alarms |
| [Cost considerations](./cost-considerations/docs/index.md) | Pricing dimensions, NAT gateway bundled pricing, data processing cost optimization, and strategies for reducing per-GB costs |
| [Additional references](./additional-references/docs/index.md) | Workshops, videos, blog posts, and sample code for hands-on learning |

## What is AWS Network Firewall?

AWS Network Firewall is a managed stateful network firewall service that uses the Suricata engine to inspect VPC traffic at layers 3 through 7. Network Firewall is a regional service: you deploy firewall endpoints into the Availability Zones where your workloads run, and route traffic to those endpoints via route tables. AWS manages the underlying compute, patching, scaling, and availability of each firewall endpoint, supporting up to 100 Gbps of throughput per endpoint without capacity planning or autoscaling configuration on your part.

Network Firewall eliminates the operational overhead of running firewall appliance VMs on EC2, fronting them with Gateway Load Balancer, managing instance uptime, and handling capacity provisioning and scaling. You deploy firewall endpoints, configure rules, and route traffic. AWS handles everything else, including ensuring high availability within each Availability Zone. For security and networking teams, this means you can focus on writing effective security policy rather than maintaining firewall infrastructure reliability.

## Where Network Firewall fits

Network Firewall is most commonly deployed for **egress traffic filtering**, followed by east-west (inter-VPC) inspection, and then ingress. For egress, the most popular use case is restricting outbound traffic to a strict allowlist of known-good domains. For east-west, Network Firewall inspects lateral traffic between VPCs routed through Transit Gateway. For ingress, Network Firewall is appropriate for non-HTTP/HTTPS traffic (protocols like SMTP, custom TCP, or database connections); web application ingress traffic is better served by AWS WAF at the application layer. See the [AWS Network Security Fundamentals](../firewall-overview/index.md) guide for detailed guidance on which firewall service to use for each traffic pattern.

## Key capabilities

These are the primary reasons to deploy Network Firewall. Each links to the section of this guide covering configuration and best practices.

| Capability | What it does | Guide section |
|-----------|-------------|---------------|
| Domain-based filtering | Allow or deny outbound traffic by domain name using TLS SNI and HTTP host header inspection. This works without TLS decryption for any traffic where the SNI or host header is visible, making it the most common starting point for egress security. | [Domain filtering](./customer-managed-rules/docs/index.md#domain-filtering) |
| Managed threat detection | AWS-maintained threat signature rule groups that detect malware, exploits, botnets, and credential phishing. Active Threat Defense uses intelligence from AWS threat sensors to block communication with known malicious destinations. Partner managed rules provide additional threat intelligence from third-party security vendors. | [AWS Managed Rules](./aws-managed-rules/docs/index.md) |
| URL and domain category filtering | Block or allow traffic by AWS-maintained content categories such as social networking, gambling, command and control, and malware domains. | [URL and domain category filtering](./sample-suricata-rules/docs/index.md#domain-category-blocking) |
| Protocol detection | Identify application-layer protocols regardless of port number, allowing you to enforce that only HTTP runs on port 80 or block SSH on non-standard ports. | [Customer managed rules](./customer-managed-rules/docs/index.md) |
| Container attribute referencing | Dynamically reference Amazon ECS and Amazon EKS container IP addresses in firewall rules without maintaining static IP lists. Network Firewall subscribes to container lifecycle events and maintains an up-to-date IP set that you reference in Suricata rules. | [Container associations](https://docs.aws.amazon.com/network-firewall/latest/developerguide/container-associations.html) |
| Custom Suricata rules | Write stateful inspection rules using the Suricata rule language tailored to your environment, including IP reputation lists, GeoIP filtering, and protocol-specific matching. The sample rules in this guide are vetted and confirmed to work with the Network Firewall Suricata implementation. | [Customer managed rules](./customer-managed-rules/docs/index.md) |
| Logging and monitoring | Rich, detailed alert logs and flow logs for all traffic passing through firewall endpoints. Supports streaming to S3, CloudWatch Logs, and Kinesis Data Firehose for analysis of network traffic patterns. | [Logging and monitoring](./logging-and-monitoring/docs/index.md) |
| High availability and scaling | AWS manages firewall endpoint availability, scaling, and patching. Each endpoint supports up to 100 Gbps without capacity planning. No risk of network downtime due to firewall VM failures, missed patches, or scaling misconfigurations. | [Deployment architecture](./deployment-architecture/docs/index.md) |
| JA3/JA4 fingerprinting | Identify TLS clients by their cryptographic handshake fingerprint for filtering or forensic logging without decrypting traffic. | [JA3/JA4 hash logging](./sample-suricata-rules/docs/index.md#ja3ja4-hash-logging) |
| TLS inspection | Decrypt, inspect, and re-encrypt TLS traffic for deeper content inspection beyond domain-level filtering (for example, filtering on URL paths like `github.com/specific-repo` rather than just `github.com`). Usually adopted for a subset of workloads where this level of visibility is needed. | [TLS inspection](./tls-inspection/docs/index.md) |

## Related guides

- [AWS Network Firewall Developer Guide](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html)
- [AWS Networking Best Practices - Security](https://aws.github.io/aws-networking-best-practices/security/)
- [AWS Network Security Fundamentals](../firewall-overview/index.md)
