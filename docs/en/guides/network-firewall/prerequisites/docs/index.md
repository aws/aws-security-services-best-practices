# Prerequisites and fundamentals

AWS Network Firewall uses the [Suricata](https://suricata.io/) open-source engine for its stateful rule evaluation. Understanding how Suricata works under the hood is helpful for writing effective rules and avoiding unexpected behavior. Suricata was originally built as an Intrusion Detection/Prevention System (IDS/IPS), which means Network Firewall inherits both the power and some behavioral quirks compared to traditional firewalls.

This page covers the foundational concepts you need before deploying Network Firewall: how the inspection engines work, what traffic Network Firewall can and cannot inspect, key service limitations, and how Network Firewall fits alongside other AWS network security controls.

## Understanding Suricata

Key characteristics of Suricata in the Network Firewall context:

* **Connection tracking** - Suricata tracks connections (flows) and makes decisions based on the full flow context. Rules can target specific directions within an established flow using keywords like `flow:to_server` and `flow:established`, which is helpful for writing effective stateful rules.
* **Protocol detection** - Suricata detects application-layer protocols regardless of port number. For example, it can identify TLS traffic on non-standard ports and HTTP on any port.
* **Rule processing** - All stateful rules are Suricata rules and are evaluated based on the rule ordering mode you select. Use Strict ordering for predictable rule evaluation. See [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md) for details on rule ordering.
* **Application-layer inspection** - Suricata inspects content at the application layer including TLS Client Hello (SNI), HTTP headers, and protocol-specific fields.

!!! tip "Best practice"
    Use Strict rule ordering for predictable, priority-based rule evaluation. Do not use Action Order mode, as it can produce surprising results when rules interact. See [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md) for the full recommendation.

## Stateless and stateful engines

Network Firewall has two inspection engines that traffic passes through in sequence:

1. **Stateless engine** - Evaluates traffic on a per-packet basis without connection context. Operates at layers 3-4 only. Processes traffic first.
2. **Stateful engine (Suricata)** - Evaluates traffic with full connection tracking and application-layer inspection at layers 3-7. Processes traffic after the stateless engine forwards it.

!!! tip "Best practice"
    Configure the stateless engine's default actions to "Forward to stateful rule groups" and perform all filtering in the stateful engine. The stateful engine provides connection tracking, protocol detection, application-layer inspection, logging, and the reject action, none of which are available in the stateless engine. See [Customer managed rules](../../customer-managed-rules/docs/index.md) for detailed rule writing guidance.

## What Network Firewall does NOT inspect

Understanding what traffic bypasses Network Firewall is as important as understanding what it inspects. The following traffic types are never seen by firewall endpoints, regardless of your routing configuration:

| Traffic type | Why it bypasses Network Firewall | Alternative control |
|---|---|---|
| DNS queries to the VPC .2 Resolver | DNS resolution uses a dedicated path to the VPC .2 Resolver, also known as AmazonProvidedDNS. These queries never traverse the network firewall endpoints. Note that this applies to the .2 Resolver specifically. Network Firewall can inspect and filter DNS traffic destined to a Route 53 Resolver inbound endpoint, because that traffic follows normal VPC routing. | [Amazon Route 53 Resolver DNS Firewall](https://aws.amazon.com/route53/resolver-dns-firewall/) |
| VPC peering traffic | VPC peering follows the local route in the VPC route table, which cannot be overridden to route through firewall endpoints | security groups |
| AWS Global Accelerator traffic | Global Accelerator uses the AWS global network edge and bypasses VPC route tables | AWS WAF (for HTTP), security groups |
| Traffic within the same subnet | Intra-subnet traffic follows the local route in the VPC route table, which cannot be overridden to route through firewall endpoints | security groups |

***Key insight:*** *DNS is its own dedicated egress path to the internet, separate from the data path that Network Firewall inspects. Network Firewall still sees TLS SNI and HTTP host headers in the actual connections after DNS resolution (which is why domain filtering works), but the DNS resolution itself is invisible to Network Firewall. This means DNS tunneling and domain generation algorithm (DGA) activity can bypass Network Firewall entirely. Deploy DNS Firewall on every VPC to protect this separate egress path.*

!!! tip "Best practice"
    Deploy Amazon Route 53 Resolver DNS Firewall on every VPC where you have workloads using the VPC .2 Resolver (AmazonProvidedDNS). DNS Firewall protects the DNS egress path at the lowest cost, catching DNS-based exfiltration that Network Firewall cannot see. See the [DNS Firewall Best Practices](../../../dns-firewall/index.md) guide for configuration guidance.

## Network Firewall and complementary services

Network Firewall is one layer in a defense-in-depth network security architecture. It does not replace other controls.

### DNS Firewall

Amazon Route 53 Resolver DNS Firewall operates at the DNS resolution layer, blocking queries to prohibited domains before a connection is ever established. Network Firewall operates at the connection layer, inspecting traffic after DNS resolution. Most people overlook DNS Firewall because Network Firewall's domain filtering (via TLS SNI and HTTP host headers) already works for controlling which domains workloads can connect to. The reason you still need DNS Firewall is that DNS is a separate egress path to the internet. Without DNS Firewall, workloads can use DNS tunneling to exfiltrate data or communicate with command-and-control infrastructure through DNS queries alone, without ever establishing a TCP/TLS connection that Network Firewall would see.

Deploy both together: DNS Firewall protects the DNS egress path at the lowest cost, while Network Firewall provides stateful inspection on the data path.

### Security groups

Security groups are not optional. Every elastic network interface (ENI) in a VPC must have a security group attached, and security groups provide the first and last line of defense at the instance level. Network Firewall complements security groups by adding protocol-aware inspection, IPS signatures, domain-based filtering, explicit deny, and support for a large number of rules that security groups cannot perform. Security groups complement Network Firewall by restricting traffic at the instance level regardless of whether routing directs traffic through a firewall endpoint.

### Network ACLs

Network ACLs provide stateless packet filtering at the subnet boundary, and they are the only VPC-native control that can express an explicit deny. That makes them well suited to coarse, stable guardrails: blocking a known-bad CIDR range at a subnet boundary, or enforcing a segmentation boundary that should never be crossed regardless of what any security group allows.

They are less suited to being your primary active filtering control. Because they are stateless, every flow needs matching inbound and outbound rules, including ephemeral port ranges for return traffic. They have a limited number of rules per ACL, they cannot reference security groups or resource identity, and keeping them accurate across many subnets and accounts is a meaningful operational burden.

Use network ACLs for a small number of high-value, rarely changing deny rules, and rely on security groups for resource-level access control and Network Firewall for stateful inspection, domain filtering, and IPS coverage.

## Key concepts

### Firewall policy

A firewall policy defines the monitoring and protection behavior for a firewall. It contains:

* **Rule groups** - Ordered collections of stateless and stateful rules
* **Default actions** - What happens to traffic that does not match any rule
* **Rule ordering mode** - How the stateful engine processes rules (Strict or Action Order)
* **Variables** - Network variables like $HOME_NET used in rules
* **Stream exception policy** - How to handle mid-stream traffic

### Rule groups

[Rule groups](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups.html) are reusable collections of rules. There are two types:

* **Stateless rule groups** - Per-packet rules evaluated before stateful inspection
* **Stateful rule groups** - Connection-aware rules evaluated by Suricata

Network Firewall supports a maximum of 20 stateless rule groups and 20 stateful rule groups per firewall policy. We recommend using only stateful rule groups for the reasons described in [Customer managed rules](../../customer-managed-rules/docs/index.md). See the [Network Firewall quotas](https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html) page for the full list of service limits.

### Firewall endpoints

A [firewall endpoint](https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-components.html) is a Network Firewall resource deployed into a specific subnet and Availability Zone. Traffic is routed to firewall endpoints via route tables for inspection.

* Each endpoint has an hourly charge regardless of traffic volume
* For high availability, deploy an endpoint in each AZ where you have workloads
* Endpoints must be in dedicated subnets (no other resources should be placed in firewall subnets)

For step-by-step deployment instructions, see [Getting started with AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/getting-started.html).

## Limitations and service quotas

There are Suricata features not currently supported by AWS Network Firewall. Check the [limitations and caveats](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html) documentation before you write rules that depend on a Suricata feature, since the list changes as the service adds support.

For the full list of quotas, see [AWS Network Firewall quotas](https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html).

## Suricata resources

* [Suricata User Guide](https://docs.suricata.io/en/latest/)
* [Suricata Rules Format](https://docs.suricata.io/en/latest/rules/intro.html)
* [Suricata Flow Keywords](https://docs.suricata.io/en/latest/rules/flow-keywords.html)
* [Suricata TLS Keywords](https://docs.suricata.io/en/latest/rules/tls-keywords.html)
* [Suricata HTTP Keywords](https://docs.suricata.io/en/latest/rules/http-keywords.html)
* [Suricata Forum](https://forum.suricata.io/)

## What to read next

* [Deployment architecture](../../deployment-architecture/docs/index.md) - Choose the right deployment model for your environment
* [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md) - Configure rule ordering, default actions, and policy settings
