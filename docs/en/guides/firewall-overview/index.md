# AWS Network Security Fundamentals

## Introduction

AWS provides network security controls at every layer, from DNS resolution through to the application layer. Customers frequently ask "Which control should I use?" and the answer is almost always "several, working together," because each layer catches what the others miss. The combination of all layers is what delivers defense in depth.

This guide covers how AWS network security controls work, which services to choose for which use cases, and how they combine into a layered security architecture. It is organized around four use cases: protecting inbound traffic, controlling outbound traffic, isolating workloads, and centralizing policy. It links to the individual service best practices guides for implementation detail.

!!! info "Before you start"
    This guide assumes familiarity with core AWS networking concepts (VPCs, subnets, route tables, internet gateways). If you are new to AWS networking, start with the [AWS Networking Best Practices Guide](https://aws.github.io/aws-networking-best-practices/) for foundational context on VPC design, subnet tiers, and connectivity patterns. For internet ingress and egress architectural patterns specifically, see their [Internet Connectivity](https://aws.github.io/aws-networking-best-practices/connectivity/internet/) page.

---

## Guide contents

- [**Core concepts**](fundamentals/docs/index.md): How cloud networking differs from on-premises, and an overview of all AWS network security services and VPC security controls.

- [**Ingress patterns**](ingress-patterns/docs/index.md): Recommended architectures for protecting inbound traffic, covering both web (HTTP/HTTPS) and non-web (TCP/UDP) workloads.

- [**Egress patterns**](egress-patterns/docs/index.md): VPC endpoints as step zero, layered egress defense strategy, centralized vs. decentralized egress inspection, and cost considerations for outbound traffic.

- [**East-west traffic and segmentation**](segmentation/docs/index.md): Security groups for micro-segmentation, AWS Network Firewall for advanced east-west inspection, account-level isolation, and Amazon VPC Lattice.

- [**Cost considerations and reference**](cost-and-reference/docs/index.md): Layered defense summary, cost comparison across services, frequently asked questions, and topics not covered in this guide.

---

## Related guides

Dive deeper into individual service best practices:

- [AWS WAF Best Practices](../waf/index.md)
- [AWS Network Firewall Best Practices](../network-firewall/index.md)
- [Amazon Route 53 Resolver DNS Firewall Best Practices](../dns-firewall/index.md)

For security-specific networking guidance:

- [AWS Network Security](https://aws.github.io/aws-networking-best-practices/security/) in the AWS Networking Best Practices Guide

For the full networking context:

- [AWS Networking Best Practices Guide](https://aws.github.io/aws-networking-best-practices/)
