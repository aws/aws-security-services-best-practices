# Cost Considerations and Reference

!!! info "Prerequisites"
    This section assumes familiarity with [Core concepts](../../fundamentals/docs/index.md), [Ingress Patterns](../../ingress-patterns/docs/index.md), and [Egress Patterns](../../egress-patterns/docs/index.md). Review those pages first for architectural context.

AWS network security costs range from zero (security groups, network ACLs, VPC gateway endpoints, AWS Shield Standard) through fractions of a cent per million queries (Amazon Route 53 Resolver DNS Firewall) to per-endpoint-hour plus per-GB charges (AWS Network Firewall). A layered approach that starts with no-cost controls and adds paid services only where they provide clear value for the risk level produces the most cost-effective architecture.

## Layered defense summary

A well-architected AWS environment uses multiple services together. Each layer catches what the others miss:

| Layer | Service | What it catches |
|-------|---------|-----------------|
| Traffic elimination | VPC endpoints + endpoint policies | Removes AWS API traffic from egress path; prevents exfiltration to unauthorized buckets |
| DNS | DNS Firewall (+ Advanced) | Known-bad domains, DNS tunneling, DGAs |
| Network (instance) | security groups | Unauthorized ports/protocols/sources per resource |
| Network (subnet) | network ACLs | Broad deny patterns, emergency IP blocking |
| Network (VPC) | AWS Network Firewall | IPS/IDS, domain validation via SNI, hardcoded-IP connections, protocol violations |
| Application (L7) | AWS WAF | SQL injection, XSS, bots, L7 DDoS, rate limiting |
| DDoS | AWS Shield Standard/Advanced | Volumetric and protocol-level DDoS |
| Management | AWS Firewall Manager | Consistent policy enforcement across all accounts |
| Application auth | Amazon VPC Lattice | Identity-based service-to-service access control |

---

## Cost comparison

Each service has a different pricing model. Costs vary by Region; refer to the pricing pages for current numbers.

| Service | Pricing model | Pricing page |
|---------|---------------|-------------|
| security groups | No additional cost | N/A |
| network ACLs | No additional cost | N/A |
| VPC endpoints (gateway) | No additional cost | N/A |
| VPC endpoints (interface) | Per hour per AZ + per GB processed | [PrivateLink Pricing](https://aws.amazon.com/privatelink/pricing/) |
| DNS Firewall | Per million DNS queries processed | [Route 53 Pricing](https://aws.amazon.com/route53/pricing/) |
| AWS WAF | Per web ACL + per rule + per million requests | [AWS WAF Pricing](https://aws.amazon.com/waf/pricing/) |
| AWS Network Firewall | Per endpoint-hour + per GB processed | [Network Firewall Pricing](https://aws.amazon.com/network-firewall/pricing/) |
| AWS Shield Standard | No additional cost | N/A |
| AWS Shield Advanced | Monthly subscription + data transfer | [Shield Pricing](https://aws.amazon.com/shield/pricing/) |
| AWS Firewall Manager | Per policy per Region | [Firewall Manager Pricing](https://aws.amazon.com/firewall-manager/pricing/) |

!!! tip "Cost optimization approach"
    Start with no-cost controls (security groups, network ACLs, VPC gateway endpoints, Shield Standard). Add DNS Firewall as the lowest-cost paid egress control. Add AWS WAF for web applications. Add Network Firewall where deep inspection provides clear value for the risk level. The layered approach means you are not paying for Network Firewall to inspect traffic that cheaper controls could have already blocked or eliminated.

!!! note "Network Firewall + NAT gateway pricing discount"
    When Network Firewall and a NAT gateway are deployed together in the same Availability Zone (with traffic flowing through Network Firewall before NAT), NAT gateway data processing charges are waived (1:1 discount). This applies to zonal NAT gateways only. The discount does NOT apply to regional NAT gateways. Factor this into your deployment model decision.

---

## Centralized policy management

!!! tip "Best practice"
    Deploy AWS Firewall Manager to enforce your network security policy consistently across your AWS organization. Firewall Manager automatically deploys AWS WAF, Network Firewall, DNS Firewall, and Shield Advanced policies to every account that meets your scope conditions, remediates non-compliant resources, and alerts on new out-of-scope deployments. Firewall Manager's strength is distributed deployments: the more your firewalls are spread across many accounts and VPCs, the more value it adds. For centralized deployments with a single shared firewall, infrastructure as code often suffices for policy management.

---

## Next steps

Dive deeper into individual service best practices:

- [AWS WAF Best Practices](../../waf/index.md)
- [AWS Network Firewall Best Practices](../../network-firewall/index.md)
- [Amazon Route 53 Resolver DNS Firewall Best Practices](../../dns-firewall/index.md)

For security-specific networking guidance:

- [AWS Network Security](https://aws.github.io/aws-networking-best-practices/security/) (overview of perimeter, outbound, and segmentation controls)
- [Perimeter Controls](https://aws.github.io/aws-networking-best-practices/security/perimeter-inbound/)
- [Outbound Controls](https://aws.github.io/aws-networking-best-practices/security/outbound/)
- [Network Segmentation](https://aws.github.io/aws-networking-best-practices/security/segmentation/)

For the full networking context:

- [AWS Networking Best Practices Guide](https://aws.github.io/aws-networking-best-practices/)
- [Internet Connectivity patterns](https://aws.github.io/aws-networking-best-practices/connectivity/internet/) (centralized vs. decentralized, ingress and egress)
- [Within AWS Connectivity](https://aws.github.io/aws-networking-best-practices/connectivity/within-aws/) (Transit Gateway, Cloud WAN, VPC Lattice, PrivateLink)
