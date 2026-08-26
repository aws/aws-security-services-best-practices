# Ingress Patterns

!!! info "Prerequisites"
    This section assumes familiarity with [Core concepts](../../fundamentals/docs/index.md). Review that page first if you are new to AWS network security services and their layers.

AWS splits ingress protection into two categories based on protocol: HTTP/HTTPS traffic uses AWS WAF at the application layer, while non-HTTP traffic (TCP/UDP) uses AWS Network Firewall for stateful inspection at L3-L7. Decentralized ingress, where each workload VPC owns its own internet entry point, is the recommended default because it eliminates shared failure domains and cross-team operational dependencies while still delivering centrally-managed firewall policy through AWS Firewall Manager.

## At a glance

- **Web traffic (HTTP/HTTPS):** Security groups scoped to least privilege, plus AWS WAF + AWS Shield Advanced. AWS WAF handles application-layer inspection (SQLi, XSS, bots, rate limiting, account takeover prevention), Shield Advanced provides enhanced DDoS protection and SRT access for critical workloads.
- **Non-web traffic (TCP/UDP):** Security groups scoped to least privilege, plus AWS Network Firewall for deeper stateful inspection, IPS/IDS signatures, and protocol validation on traffic that AWS WAF cannot inspect.

---

## Web traffic (HTTP/HTTPS)

!!! tip "Best practice"
    For internet-facing web applications, use AWS WAF (not Network Firewall) as your primary ingress protection. AWS WAF attaches directly to CloudFront distributions and ALBs, providing purpose-built L7 inspection for HTTP/HTTPS traffic. Network Firewall is the right choice for non-HTTP protocols on ingress.

For web applications, the recommended pattern is **AWS WAF in front of each workload** (typically via Amazon CloudFront or directly on an Application Load Balancer (ALB)). This provides L7 protection with managed rule groups, bot control, rate limiting, and DDoS mitigation.

```
Internet → CloudFront (+ WAF) → ALB (+ WAF optional) → Application
```

The recommended HTTP architecture places Amazon CloudFront at the edge, with AWS WAF attached to the CloudFront distribution. CloudFront provides global TLS termination, caching, and automatic DDoS absorption at the edge, ensuring attack traffic is absorbed before it reaches your VPC. AWS WAF inspects every HTTP/HTTPS request for application-layer threats (SQLi, XSS, bot activity, rate abuse). Behind CloudFront, an Application Load Balancer routes traffic to your application with an origin-restricted security group that only allows traffic from CloudFront. Attaching WAF only at the ALB without CloudFront in front means attack traffic still reaches and consumes your VPC capacity before being inspected. This architecture provides the strongest ingress protection for web applications on AWS.

For the complete recommended HTTP architecture, including ALB origin restriction, security group configuration, and WAF rule ordering, see the [Recommended HTTP Architecture](../../../waf/recommended-http-architecture/docs/index.md) page in the AWS WAF Best Practices guide.

Centralized ingress through a shared VPC is an on-premises pattern that is rarely the right choice on AWS. CloudFront + AWS WAF + per-VPC security delivers the same central protection (managed through Firewall Manager) without load-balancer chaining, shared-VPC failure scope, or cross-team operational dependencies.

### Why decentralized ingress is recommended

In a decentralized model, each VPC that hosts an internet-facing application owns its ingress. Application teams manage their own load balancers, certificates, and scaling decisions. The failure of one team's ingress does not affect others.

Central, uniform protection still applies, but it applies at the AWS edge and at each VPC boundary rather than through a shared ingress VPC:

- For L7 traffic, CloudFront and AWS WAF apply a consistent rule baseline at every distribution, managed centrally through Firewall Manager.
- For L4 traffic, per-VPC Network Firewall endpoints (or Gateway Load Balancer (GWLB) with third-party appliances) inspect all ingress traffic before it reaches workloads, with rule sets managed centrally through Firewall Manager.

The firewall policy is centrally defined and centrally managed; the firewall endpoints are distributed per-VPC.

**Benefits of decentralized ingress:**

- Bounded failure domain. A misconfigured listener affects one application, not every workload.
- Team autonomy. No cross-team dependency for routine changes.
- Independent scaling. Each application scales to its own traffic profile.
- Simpler routing. No transit hop, no shared VPC dependency.

### When centralized ingress is justified

Centralized ingress is justified only when a specific compliance baseline mandates a particular proxy layer not available natively, when centralized TLS termination with a private CA is required across all services, or when a single audited internet-exposed surface is mandated as policy.

For the full analysis of centralized vs. decentralized ingress trade-offs, see [Internet Connectivity](https://aws.github.io/aws-networking-best-practices/connectivity/internet/#decentralized-ingress-preferred) in the AWS Networking Best Practices Guide.

---

## Non-web traffic (TCP/UDP services)

For non-HTTP services exposed to the internet (custom protocols, gaming, financial trading, services that must preserve client IPs end-to-end):

```
Internet → IGW → Network Firewall (per-VPC) → NLB → Workload
```

Deploy Network Firewall endpoints in each workload VPC between the internet gateway and the workload subnets using VPC ingress routing. Rule sets are managed centrally through Firewall Manager even though the data plane is distributed.

This is the primary use case for Network Firewall on ingress: non-web traffic that cannot be filtered by AWS WAF.

### Network Firewall ingress best practices

- Deploy Network Firewall endpoints in each Availability Zone used by the workload to avoid cross-AZ asymmetric routing.
- Use VPC ingress routing (route table on the internet gateway) to direct traffic through Network Firewall endpoints before it reaches workload subnets.
- Define rule sets centrally through Firewall Manager, even when firewall endpoints are distributed per-VPC.
- Use AWS managed threat intelligence rule groups to block known-bad source IPs without manual rule maintenance.
- Be deliberate about source IP preservation. Understand how your ingress architecture (internet gateway direct, Global Accelerator, or third-party appliance via GWLB) affects the client IP visible to Network Firewall rules and backend security groups.

For detailed architecture guidance on Network Firewall ingress deployment patterns, see [Design your firewall deployment for internet ingress traffic flows](https://aws.amazon.com/blogs/networking-and-content-delivery/design-your-firewall-deployment-for-internet-ingress-traffic-flows/).

---

## DDoS protection for ingress

AWS Shield Standard automatically protects all public-facing endpoints against common L3/L4 volumetric attacks (SYN floods, UDP reflection, DNS amplification) with no configuration needed.

For L7 DDoS protection, CloudFront is the first line of defense. Its distributed edge capacity absorbs volumetric L7 floods that would exhaust a regional load balancer before it can scale to respond, and blocks malicious requests before they consume any origin compute. Placing CloudFront in front of your workloads also enables WAF body inspection at 64 KB per request, versus 16 KB on regional resources.

!!! tip "Best practice"
    Deploy the `AWSManagedRulesAntiDDoSRuleSet` WAF managed rule group on every CloudFront distribution and Application Load Balancer. It uses machine learning to establish traffic baselines and automatically mitigates L7 DDoS attacks within seconds. Place it **first** in your WAF rule evaluation order so it can respond before any other rule terminates evaluation. For API clients, mobile apps, or SPAs that cannot respond to browser challenges triggered during an event, see the [Anti-DDoS managed rule group](../../../waf/aws-managed-rules/docs/index.md#anti-ddos) guidance for tuning action overrides.

For revenue-generating or business-critical workloads, AWS Shield Advanced adds:

- 24/7 Shield Response Team (SRT) access during active events
- Automatic L7 mitigation that baselines your traffic and generates WAF rules during an attack
- Cost protection that credits back scaling charges incurred during a DDoS event
- The Anti-DDoS managed rule group at no additional WAF cost for Shield Advanced-protected resources

Use AWS Firewall Manager to deploy Shield Advanced protections consistently across all accounts in your organization. For full configuration guidance see [AWS Shield Advanced](../../../waf/using-waf-with-other-services/docs/index.md#aws-shield-advanced) in the AWS WAF Best Practices guide.

---

## What to read next

- [Egress Patterns](../../egress-patterns/docs/index.md): Layered egress defense strategy
- [East-West Traffic and Segmentation](../../segmentation/docs/index.md): Internal traffic controls
- [AWS WAF Best Practices](../../../waf/index.md): Detailed AWS WAF configuration guidance
- [AWS Network Firewall Best Practices](../../../network-firewall/index.md): Detailed Network Firewall configuration guidance
- [Perimeter Controls](https://aws.github.io/aws-networking-best-practices/security/perimeter-inbound/) in the AWS Networking Best Practices Guide
