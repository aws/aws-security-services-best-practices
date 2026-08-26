# Core concepts

## Cloud networking is different from on-premises

AWS networking provides enforcement points at every layer (VPC, subnet, ENI, and application) rather than routing all traffic through a single perimeter device. The most common mistake customers make when building network security on AWS is applying an on-premises mental model directly to the cloud. In a traditional data center, all traffic flows through a centralized firewall appliance at the network perimeter. On AWS, that mental model leads to architectures that are more expensive, harder to operate, and less resilient than cloud-native alternatives.

Key differences to internalize:

**There is no single perimeter.** In a traditional network, a firewall sits between "inside" and "outside." On AWS, the boundary is distributed. Each VPC, each subnet, each ENI is a potential enforcement point. The goal is not to funnel all traffic through one chokepoint, but to apply the right control at the right layer.

**Centralized ingress is rarely the right pattern.** On-premises, every inbound connection traverses a shared firewall stack in a DMZ. On AWS, decentralized ingress (each workload owns its own internet entry point, protected by Amazon CloudFront and AWS WAF) is the recommended default. It avoids load-balancer chaining, eliminates single points of failure for unrelated workloads, and still delivers centrally-managed protection through services like AWS Firewall Manager. For a detailed comparison of centralized vs. decentralized ingress, see the [Internet Connectivity](https://aws.github.io/aws-networking-best-practices/connectivity/internet/#decentralized-ingress-preferred) page of the AWS Networking Best Practices Guide.

**Egress is a genuine trade-off.** Unlike ingress (where decentralized is almost always right), IPv4 egress inspection is a 50-50 decision between centralized and decentralized, depending on your cost model, operational ownership preferences, and whether you require a single physical inspection point. Both patterns can deliver uniform firewall policy. For the full trade-off analysis, see [Comparing decentralized vs. centralized IPv4 egress](https://aws.github.io/aws-networking-best-practices/connectivity/internet/#comparing-decentralized-vs-centralized-ipv4-egress).

---

## AWS firewall services and VPC security controls

AWS provides multiple firewall services and built-in VPC security controls. Each operates at a different layer and serves a different purpose. They are complementary; the question is not which one to use, but which combination fits your environment.

!!! tip "Best practice"
    Deploy AWS WAF on every public-facing HTTP/HTTPS endpoint. Deploy DNS Firewall on every VPC. Deploy VPC gateway endpoints for S3 and DynamoDB everywhere. Deploy Network Firewall for egress traffic filtering, IPS/IDS threat detection, and east-west inspection. Scope security groups to least privilege on every resource. Each layer catches what the others miss.

#### Built-in VPC security controls

Security groups, network ACLs, and AWS Shield Standard are not standalone AWS services. They are features of Amazon VPC (or, in Shield Standard's case, automatically applied to all public AWS endpoints). They are available to every AWS customer at no additional cost. While they provide foundational controls, they can be highly effective when configured deliberately. For example, if an EC2 instance should never accept inbound connections, configure its security group with no ingress rules at all. Include these controls as part of every network security plan on AWS.

| Control | Layer | Scope | What it does | When to use | Limitations |
|---------|-------|-------|--------------|-------------|-------------|
| [security groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) | L3/L4 | ENI | Stateful allowlist per resource. Reference other security groups for identity-based rules. | Always. Primary access control for every resource. Design around workload identity, not IPs. | Allow-only (no deny rules). No deep inspection, no domain filtering. |
| [network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html) | L3/L4 | Subnet | Stateless deny/allow rules at the subnet boundary. First-match-wins by rule number. | Explicit deny rules that security groups cannot express. Emergency IP blocking during incidents. | Stateless (must manage return traffic rules). Hard to maintain at scale. |
| [AWS Shield Standard](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-standard-summary.html) | L3/L4 | All public endpoints | Automatic DDoS protection against SYN floods, UDP reflection, DNS amplification. | Always active, no action needed. Already protecting all public-facing AWS endpoints. | No visibility, no SRT access, no cost protection. |

#### AWS firewall services

These are the firewall services you deploy to inspect and filter traffic at various layers.

| Service | Layer | Scope | What it does | When to use | Limitations |
|---------|-------|-------|--------------|-------------|-------------|
| [AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html) | L7 (HTTP/S) | [Supported resources](https://docs.aws.amazon.com/waf/latest/developerguide/how-aws-waf-works-resources.html) | Inspects HTTP/HTTPS request content: headers, body, URI, cookies. Managed rules for OWASP Top 10, bot control, rate limiting. | All internet-facing web applications and APIs. The correct choice for L7 web protection. | HTTP/HTTPS only. Cannot inspect non-HTTP protocols or network-layer traffic. |
| [AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html) | L3-L7 | VPC | Managed stateful inspection with Suricata IPS/IDS, domain filtering (TLS SNI + HTTP host), TLS inspection, protocol detection. | Egress domain filtering and allowlisting. IPS/IDS threat signature detection. East-west inspection. Non-HTTP ingress inspection. TLS inspection. | Not the right tool for ingress HTTP-specific logic like SQLi/XSS detection (use AWS WAF for that). Adds cost per endpoint-hour + per GB. |
| [AWS Network Firewall Proxy](https://aws.amazon.com/blogs/networking-and-content-delivery/reintroducing-network-firewall-proxy-for-secure-egress-connectivity/) *(preview)* | L3-L7 | VPC | Managed explicit forward proxy built into Network Firewall. Uses the same firewall policy, rule groups, and management plane as transparent inspection. Clients configure a proxy endpoint rather than relying on routing. | Environments that already use explicit proxy configurations. Centralized egress from networks with overlapping CIDRs. When you want a single firewall policy for both proxied and routed traffic. | Preview. Requires application-side proxy configuration (environment variables). |
| [Amazon Route 53 Resolver DNS Firewall](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html) | DNS | VPC | Filters outbound DNS queries by domain. Allowlists and denylists + AWS managed threat intelligence lists. Advanced: ML-based detection of DNS tunneling and DGAs. | First egress control to deploy, lowest cost, highest coverage. Every VPC should have DNS Firewall. | Only filters DNS queries. Cannot block hardcoded-IP connections or DNS-over-HTTPS bypass. |
| [AWS Shield Advanced](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary.html) | L3-L7 | CloudFront, ALB, EIP, Global Accelerator, Route 53 | Enhanced DDoS detection, 24/7 SRT access, automatic L7 mitigation, cost protection during events. Includes AWS WAF and Firewall Manager at no additional cost. | Revenue-generating internet-facing applications where minutes of downtime have measurable business impact. | Monthly subscription cost. Justified only when cost of downtime exceeds subscription cost. |

#### Centralized management

| Service | Layer | Scope | What it does | When to use | Limitations |
|---------|-------|-------|--------------|-------------|-------------|
| [AWS Firewall Manager](https://docs.aws.amazon.com/waf/latest/developerguide/fms-chapter.html) | Management | AWS Organization | Deploys and enforces policies for AWS WAF, NFW, DNS Firewall, Shield, security groups, and network ACLs across all accounts. | Multi-account environments (10+ accounts) with distributed firewall deployments. Requires AWS Organizations + AWS Config. | Not a firewall itself. Adds per-policy-per-Region cost. Simpler to skip for centralized single-firewall deployments. |


---

## Important topics not covered in this guide

The following topics are important for overall network security but are covered in depth by the [AWS Networking Best Practices Guide](https://aws.github.io/aws-networking-best-practices/). We link directly to their coverage rather than duplicating it:

- **AWS Direct Connect security:** Hybrid connectivity, encryption in transit, and dedicated connections. See [Hybrid and Multicloud Connectivity](https://aws.github.io/aws-networking-best-practices/connectivity/hybrid-multicloud/).
- **Site-to-Site VPN:** IPsec tunnels, accelerated VPN, and VPN monitoring. See [Hybrid and Multicloud Connectivity](https://aws.github.io/aws-networking-best-practices/connectivity/hybrid-multicloud/).
- **AWS Client VPN and remote access:** Remote workforce connectivity. See [Remote Access](https://aws.github.io/aws-networking-best-practices/connectivity/remote-access/).
- **AWS Transit Gateway and Cloud WAN routing:** Inter-VPC routing, segmentation, and service insertion. See [Connectivity Within AWS](https://aws.github.io/aws-networking-best-practices/connectivity/within-aws/).
- **VPC design fundamentals:** Subnet tiers, CIDR planning, and AZ design. See [Foundation](https://aws.github.io/aws-networking-best-practices/foundation/).
- **Network observability:** VPC Flow Logs, Traffic Mirroring, and Amazon CloudWatch network monitoring. See [Observability](https://aws.github.io/aws-networking-best-practices/observability/).

---

## What to read next

- [Ingress Patterns](../ingress-patterns/docs/index.md): How to protect inbound traffic
- [Egress Patterns](../egress-patterns/docs/index.md): Layered egress defense strategy (including VPC endpoints as step zero)
- [East-West Traffic and Segmentation](../segmentation/docs/index.md): Internal traffic controls
- [Cost Considerations and Reference](../cost-and-reference/docs/index.md): Cost comparison and FAQ
- [AWS Network Security](https://aws.github.io/aws-networking-best-practices/security/) in the AWS Networking Best Practices Guide: perimeter controls, outbound controls, and segmentation patterns
