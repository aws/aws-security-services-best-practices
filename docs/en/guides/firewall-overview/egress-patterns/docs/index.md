# Egress Patterns

!!! info "Prerequisites"
    This section assumes familiarity with [Core concepts](../../fundamentals/docs/index.md) and [Ingress Patterns](../../ingress-patterns/docs/index.md). Review those pages first if you are new to the AWS network security services.

The goal for egress security is a deny-all-except model: each workload can only reach the destinations it has been explicitly authorized to contact. Egress filtering operates at three distinct layers: DNS resolution, network traffic inspection, and traffic elimination via VPC endpoints (which removes traffic from the inspection path entirely). Deploy all three together: each addresses a different class of egress threat and they are more effective in combination than any one alone.

## At a glance

- **DNS-layer filtering:** Amazon Route 53 Resolver DNS Firewall in every VPC as the first line of defense. Lowest cost, highest coverage. Blocks resolution of unauthorized domains before connections are ever attempted.
- **Network-layer filtering:** AWS Network Firewall for full traffic inspection. Catches hardcoded-IP connections, filters by domain using TLS SNI and HTTP host headers, runs IPS/IDS signatures, and provides TLS inspection when needed.
- **Traffic elimination:** VPC endpoints remove AWS service traffic from the egress firewall inspection path entirely, reducing firewall load and cost.

---

## Step zero: reduce traffic before filtering

Before configuring your firewall egress rules, first eliminate unnecessary traffic from the paths your firewall will inspect. Traffic that never traverses your egress firewall path never needs to be inspected and never incurs firewall or NAT gateway processing charges. VPC endpoints let you route trusted, high-volume traffic (like an EC2 instance communicating with your S3 buckets) directly through the AWS network, so your firewall inspection is focused only on the traffic you actually want to inspect. This also reduces costs on both the firewall and data transfer sides.

### Deploy VPC endpoints everywhere

[Gateway endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html) for Amazon S3 and Amazon DynamoDB are free and should be deployed in every VPC, regardless of size or environment. They route traffic through the AWS network instead of through your firewall and NAT gateways, eliminating unnecessary inspection load and data processing charges for these high-traffic services. There is no downside to enabling them. Pair gateway endpoints with endpoint policies scoped to your organization's resources to prevent workloads from reaching external buckets or tables, an important exfiltration control.

[Interface endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/create-interface-endpoint.html) for frequently accessed AWS services (STS, AWS KMS, ECR, Systems Manager, Amazon CloudWatch Logs) keep API calls off the firewall and NAT gateway path. Enable private DNS so applications pick up the private path without code changes. In high-egress environments, interface endpoints often pay for themselves in avoided processing fees within days.

For deeper guidance on VPC endpoint architecture, including when to centralize vs. decentralize endpoints, see [AWS PrivateLink Best Practices](https://aws.github.io/aws-networking-best-practices/connectivity/within-aws/#aws-privatelink-best-practices) in the AWS Networking Best Practices Guide.

---

## Layered egress defense

Egress defense in depth combines multiple controls, each catching what the previous one cannot:

### VPC endpoints (eliminate traffic from the inspection path)

Remove AWS service traffic from the egress firewall inspection path entirely so your firewall only inspects traffic that actually needs to leave your VPC. Deploy gateway endpoints for S3 and DynamoDB in every VPC. Deploy interface endpoints for frequently used services.

### Security groups (restrict ports/protocols)

Restrict outbound security group rules to only the ports and protocols the workload actually needs. Remove the default allow-all outbound rule and replace it with explicit rules for the workload's actual egress requirements.

### DNS Firewall (domain filtering at DNS resolution)

Block resolution of unauthorized domains, including known C2 infrastructure, malware distribution sites, and DNS tunneling endpoints, before connections are attempted. DNS Firewall is the highest-value egress control for the cost and should be the first egress layer deployed in every VPC. Use AWS managed threat intelligence domain lists as a baseline. For sensitive workloads, use allowlist mode (permit only known-good domains, deny everything else).

!!! warning "DNS queries do not pass through Network Firewall"
    DNS queries sent to the Route 53 Resolver (the VPC's .2 address) are resolved within the VPC and never traverse Network Firewall endpoints. This means Network Firewall's domain filtering (TLS SNI, HTTP host) only operates on actual connections, not on DNS resolution. DNS tunneling and DGA-based exfiltration bypass Network Firewall entirely. DNS Firewall is the only control that operates at the DNS resolution layer, which is why both services should be deployed together.

### Network Firewall (full traffic inspection)

Network Firewall inspects actual traffic for direct connections to hardcoded IPs, domain-based filtering using TLS SNI and HTTP host headers, IPS/IDS signatures, and protocol violations, catching what DNS Firewall cannot, particularly connections that bypass DNS resolution entirely. AWS managed threat intelligence rule groups block known command-and-control infrastructure without requiring manual rule maintenance.

```
Workload → Security Group → DNS Firewall (DNS query) → Network Firewall (traffic inspection) → NAT GW → Internet
```

!!! tip "Cost-effective ordering"
    By blocking unauthorized domains at the DNS layer first, you reduce the volume of traffic Network Firewall needs to inspect. Properly scoped security groups and DNS Firewall together dramatically reduce the processing load on Network Firewall.

---

## Centralized vs. decentralized egress

This is a genuine trade-off with no single right answer:

**Decentralized egress:**

- Each VPC runs its own firewall endpoints and NAT gateway, keeping the inspection and egress path local
- No TGW/Cloud WAN data processing charges
- Team autonomy. Each team owns its inspection and egress path.
- Simpler dual-stack (IPv4 and IPv6 both exit per-VPC)
- Failure domain bounded to one VPC

**Centralized egress:**

- A shared inspection/egress VPC hosts the firewall endpoints and NAT gateways for all workload VPCs
- Collapses per-VPC firewall endpoint and NAT costs into one location
- Adds AWS Transit Gateway or Cloud WAN data processing on every flow
- Single physical inspection point (useful when compliance mandates this)
- Security or platform team owns the inspection VPC as a shared service

Both deliver uniform firewall policy through AWS Firewall Manager and DNS Firewall. The difference is whether your firewall endpoints are distributed across workload VPCs or concentrated in a shared inspection VPC. Choose based on your cost model, operational ownership preferences, and whether compliance mandates a single physical inspection point.

!!! warning "NAT gateway pricing consideration"
    If using Network Firewall, the 1:1 NAT gateway pricing discount (which waives NAT gateway data processing when Network Firewall is deployed in the same path) does NOT apply to regional NAT gateways. Factor this into your cost analysis if you plan to use both Network Firewall and regional NAT gateways together.

For the full trade-off analysis, see [Comparing decentralized vs. centralized IPv4 egress](https://aws.github.io/aws-networking-best-practices/connectivity/internet/#comparing-decentralized-vs-centralized-ipv4-egress) in the AWS Networking Best Practices Guide.

---

## AWS Network Firewall Proxy (preview)

!!! note "Preview"
    AWS Network Firewall Proxy is currently in preview. Features and behavior may change before general availability.

For organizations that need explicit forward-proxy semantics for outbound traffic, [AWS Network Firewall Proxy](https://aws.amazon.com/blogs/networking-and-content-delivery/reintroducing-network-firewall-proxy-for-secure-egress-connectivity/) provides a managed alternative to self-hosted Squid or proxy fleets. The proxy is built directly into Network Firewall, meaning you use the same firewall policy, same rule groups, and same management plane for both transparent firewall inspection and explicit proxy use cases.

In proxy mode, Network Firewall uses a "no-source-preservation" deployment where the firewall is attached to a NAT gateway. Clients configure their workloads to send traffic to the firewall's FQDN (provided after creation) rather than relying on VPC route tables. The firewall inspects and filters the traffic using your existing rules, then uses the attached NAT gateway to communicate with upstream destinations.

Because it is the same firewall engine, all Network Firewall capabilities apply: stateful and stateless rules, AWS managed rule groups, TLS inspection, URL/domain category filtering, GeoIP filtering, container attribute-based rules, and logging.

Use cases for the proxy mode:

* Environments that already use explicit proxy configurations (corporate environments, containerized workloads with proxy environment variables)
* Centralizing egress from networks with overlapping CIDRs (the no-source-preservation mode handles this natively)
* When you want the same security policy to apply to both transparently inspected traffic and explicitly proxied traffic

For detailed architecture patterns, see the [AWS Network Firewall Best Practices: Deployment Architecture](../../network-firewall/deployment-architecture/docs/index.md#aws-network-firewall-proxy) section on the proxy.

---

## What to read next

- [East-West Traffic and Segmentation](../segmentation/docs/index.md): Internal traffic controls
- [Cost Considerations and Reference](../cost-and-reference/docs/index.md): Cost comparison across services
- [AWS Network Firewall Best Practices](../../network-firewall/index.md): Detailed Network Firewall configuration guidance
- [Outbound Controls](https://aws.github.io/aws-networking-best-practices/security/outbound/) in the AWS Networking Best Practices Guide
