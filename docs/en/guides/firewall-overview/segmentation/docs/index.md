# East-West Traffic and Segmentation

!!! info "Prerequisites"
    This section assumes familiarity with [Core concepts](../../fundamentals/docs/index.md). Review that page first if you are new to the AWS network security services and their layers.

The goal of network segmentation is blast radius reduction: if something is compromised, segmentation limits how far it can move. Effective segmentation applies multiple layers from strongest to most granular: accounts, VPCs, routing segments, security groups, and identity policies. Security groups with identity-based references provide east-west segmentation at zero additional cost and remain effective as instances scale, move, or get replaced. For workloads requiring deeper inspection between segments, AWS Network Firewall adds IPS/IDS and domain filtering via Transit Gateway or Cloud WAN routing, while separate AWS accounts provide the strongest isolation boundary with no implicit connectivity between trust domains.

## At a glance

- **Primary control:** Security groups designed around workload identity using security group references. This is the most important east-west control and costs nothing.
- **Advanced inspection:** AWS Network Firewall between segments (via Transit Gateway or Cloud WAN routing) when IPS/IDS, protocol validation, or domain filtering is required between workloads.
- **Strongest isolation:** Separate AWS accounts for workloads with different trust levels. No implicit connectivity, no shared IAM namespace, no cost.
- **Global policy-driven segmentation:** AWS Cloud WAN for multi-Region or multi-account environments that need a single declarative policy to define and enforce segment boundaries.
- **Private service connectivity:** AWS PrivateLink for service-to-service access across account or VPC boundaries without opening full network paths.

---

## Security groups for micro-segmentation

Security groups are your primary east-west control. Design them around workload identity using security group references: the ALB security group allows inbound from the internet, the app-tier security group allows inbound only from `sg-web-alb`, and the database security group allows inbound only from `sg-app-tier`. No CIDR management required, and the model holds as instances scale.

This identity-based approach ("the frontend tier can reach the backend tier") is more maintainable and secure than IP-based rules ("this subnet CIDR can reach that subnet CIDR"). When instances scale, move, or get replaced, the access model holds without rule updates.

---

## Network Firewall for advanced east-west inspection

When you need IPS/IDS, protocol validation, or domain filtering between workloads, route east-west traffic through an inspection VPC using Transit Gateway or Cloud WAN as the hub:

```
VPC A → Transit Gateway / Cloud WAN → Inspection VPC (Network Firewall) → Transit Gateway / Cloud WAN → VPC B
```

This model is also valuable when there is no centralized security group management strategy in place. If individual application teams have permissions to create, update, and modify their own security groups, relying on security groups alone for segmentation can be difficult to enforce at scale. Routing east-west traffic through a centralized firewall means that regardless of what individual security groups allow, traffic that the centralized firewall does not permit will not pass. Some customers prefer this approach because it provides a consistent enforcement point that is independent of individual team configurations.

!!! warning "Cost consideration"
    This adds Transit Gateway or Cloud WAN data processing AND Network Firewall processing charges for every byte inspected between workloads. Evaluate whether the additional inspection justifies the cost. Many environments achieve sufficient east-west security through proper security group design and account-level isolation alone.

---

## Account-level isolation

AWS accounts are the strongest segmentation mechanism available. Each account has a separate IAM namespace, separate network namespace, and no implicit connectivity. Use separate accounts for workloads with different trust levels. Account isolation is free.

Place workloads with different trust levels in separate accounts so that even complete unauthorized access to one account's IAM principals cannot directly access resources in another account. This is the strongest failure-scope containment available and requires no networking configuration. Use AWS Organizations Service Control Policies (SCPs) to enforce this boundary by denying VPC peering or Transit Gateway attachment creation without approval, so individual account administrators cannot inadvertently bridge isolated environments.

For the full segmentation hierarchy (accounts, VPCs, Cloud WAN segments, security groups, VPC Lattice), see [Network Segmentation](https://aws.github.io/aws-networking-best-practices/security/segmentation/) in the AWS Networking Best Practices Guide.

---

## AWS Cloud WAN for global segmentation

AWS Cloud WAN lets you define your network topology and segment policy in a single document that enforces it globally across regions and accounts. Declare that "dev traffic cannot reach prod," and Cloud WAN enforces that boundary across all attached VPCs without per-region route table management. Cloud WAN also supports service insertion, steering segment traffic through AWS Network Firewall for inspection. For single-region environments or migrations from on-premises, AWS Transit Gateway with route table isolation achieves the same isolation in a simpler operational model.

For detailed Cloud WAN architecture guidance, see [Connectivity Within AWS](https://aws.github.io/aws-networking-best-practices/connectivity/within-aws/) in the AWS Networking Best Practices Guide.

---

## AWS PrivateLink for private service access

AWS PrivateLink provides private connectivity to services (AWS-managed services, your own services shared across accounts, or third-party SaaS) using private IP addresses, without opening VPC peering or routing full network paths. The access model is strictly unidirectional: consumers can call the producer service, but the producer cannot initiate connections back into the consumer VPC. For cross-account access to databases, shared platform services, or on-premises systems, PrivateLink is the recommended approach when full network-level connectivity is not needed.

---

## Amazon VPC Lattice and identity-based security

[Amazon VPC Lattice](https://aws.amazon.com/vpc/lattice/) provides application-layer service-to-service communication with IAM-based access control. It enables identity-based segmentation independent of network position; a workload's permissions follow it regardless of which VPC or subnet it runs in.

From a network security perspective, VPC Lattice is relevant because it provides an additional layer of access control (IAM auth policies) on top of network-layer controls (security groups, network ACLs). This is particularly valuable for east-west communication between microservices where traditional network segmentation (IP/port rules) is insufficient to express the desired access model.

VPC Lattice is not a firewall in the traditional sense. It does not inspect packet content or apply IPS signatures. It controls who can talk to whom at the service level, which is a complementary concern to what the traffic contains.

For detailed coverage of VPC Lattice architecture, service networks, and best practices, see the [AWS Networking Best Practices Guide](https://aws.github.io/aws-networking-best-practices/connectivity/within-aws/#application-layer-service-communication-with-amazon-vpc-lattice).

---

## What to read next

- [Cost Considerations and Reference](../cost-and-reference/docs/index.md): Cost comparison and FAQ
- [Core concepts](../fundamentals/docs/index.md): Services overview and decision matrix
- [AWS Network Firewall Best Practices: Customer Managed Rules](../../network-firewall/customer-managed-rules/docs/index.md): Rule writing best practices
