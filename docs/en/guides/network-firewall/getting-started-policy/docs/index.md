# Getting started policy

!!! info "Prerequisites"
    This section assumes familiarity with all previous sections of this guide. It brings together the best practices from [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md), [Customer managed rules](../../customer-managed-rules/docs/index.md), and [AWS Managed Rules](../../aws-managed-rules/docs/index.md) into a single deployable template.

Getting started with AWS Network Firewall is the hardest part. Once you have a well-configured policy in place, ongoing operations are straightforward. This page provides a getting started firewall policy template that you can deploy immediately and begin monitoring traffic without blocking anything. It implements all of the best practices covered in this guide, helping you avoid common misconfigurations and start on the right foot.

The template deploys a firewall policy in **monitor mode**. It logs all traffic and threat detections without blocking. The goal is to let the firewall inspect your traffic for a period of time so you have a clear picture of what traffic is flowing through it. Once you understand your traffic patterns, you transition the policy into enforcement mode by adding the drop default action and removing the alert-only overrides from managed rule groups.

## Template repositories

The getting started policy template is available in both CloudFormation and Terraform:

* **CloudFormation:** [aws-networkfirewall-cfn-templates](https://github.com/aws-samples/aws-networkfirewall-cfn-templates/tree/main/getting_started_policy)
* **Terraform:** [aws-network-firewall-terraform](https://github.com/aws-samples/aws-network-firewall-terraform/tree/main/getting_started_policy)

These repositories also contain sample templates for deploying the firewall itself (VPC, subnets, endpoints, routing) across all supported deployment architectures. See [Deployment architecture](../../deployment-architecture/docs/index.md) for guidance on which deployment model to use.

## What the template deploys

The template creates two resources:

1. **A firewall policy** configured with all recommended settings and 15 AWS managed rule groups (all in alert mode)
2. **A custom Suricata rule group** with monitoring rules for traffic visibility

You associate this policy with your existing or new Network Firewall. The template does not create the firewall itself, because that requires VPC and subnet decisions specific to your deployment architecture. See the CloudFormation and Terraform repositories linked above for complete deployment templates that create the firewall, VPC, subnets, and routing alongside this policy.

## Policy configuration explained

### Stateless engine

The stateless engine default action is set to forward all traffic to the stateful engine (`aws:forward_to_sfe`). No stateless rules are configured. All inspection happens in the stateful engine. See [Do not use stateless rules](../../customer-managed-rules/docs/index.md#do-not-use-stateless-rules) for why.

### Stateful engine settings

| Setting | Value | Why |
|---|---|---|
| Rule order | STRICT_ORDER | Deterministic, priority-based evaluation. See [Rule ordering](../../firewall-policy-configuration/docs/index.md#rule-ordering-always-use-strict). |
| Stream exception policy | REJECT | Sends TCP RST for midstream flows so clients reconnect cleanly. See [Stream exception policy](../../firewall-policy-configuration/docs/index.md#stream-exception-policy). |
| TCP idle timeout | 350 seconds | Aligns with the NAT gateway's fixed timeout, and set explicitly so it is visible in your IaC. Increase it if your path has no NAT gateway and carries long-lived flows. See [TCP idle timeout](../../firewall-policy-configuration/docs/index.md#tcp-idle-timeout). |
| Default action | Application alert established (server-directed only) | Logs unmatched traffic without blocking. Waits for application-layer data (TLS SNI, HTTP host) before alerting. See [Default actions](../../firewall-policy-configuration/docs/index.md#default-actions). |

### HOME_NET variable

HOME_NET is set to all RFC 1918 private IP address ranges at the policy level: 10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16. This ensures all private IP traffic flowing through the firewall matches correctly against rules using $HOME_NET, regardless of which VPCs you add in the future. See [$HOME_NET and $EXTERNAL_NET variables](../../firewall-policy-configuration/docs/index.md#home_net-and-external_net-variables) for the full explanation.

### Managed rule groups (all in alert mode)

All managed rule groups are deployed with the `DROP_TO_ALERT` override, which converts their drop/reject actions to alert. This means the rules will detect and log threats without blocking any traffic. Once you are confident the rules are not interfering with legitimate traffic, you remove the override and they begin blocking.

!!! tip "Best practice"
    For managed rule groups, false positives are uncommon because these rules match on confirmed threat patterns (known malicious domains, botnet C2 protocols, exploit payloads) rather than heuristic or behavioral patterns. Most customers can remove the DROP_TO_ALERT overrides after a short monitoring period without encountering issues.

#### Active Threat Defense (Priority 1)

[AttackInfrastructureStrictOrder](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-atd.html) blocks communication with known malicious infrastructure tracked by AWS, including malware staging URLs, botnet command-and-control servers, and cryptomining pools. Powered by AWS threat intelligence from MadPot. This is the single most important managed rule group.

#### Domain and IP reputation (Priority 2-5)

These four rule groups block traffic to domains and IPs known to be associated with malicious activity. They are included at no additional cost and have minimal capacity footprint (200 each).

| Priority | Rule group | What it blocks |
|---|---|---|
| 2 | BotNetCommandAndControlDomainsStrictOrder | Known botnet C2 domains |
| 3 | AbusedLegitBotNetCommandAndControlDomainsStrictOrder | Legitimate services being abused for C2 (file sharing, paste sites) |
| 4 | MalwareDomainsStrictOrder | Known malware distribution domains |
| 5 | AbusedLegitMalwareDomainsStrictOrder | Legitimate services being abused for malware distribution |

#### Threat signature rule groups (Priority 6-15)

These rule groups detect specific attack patterns and protocols in network traffic. The selection is optimized for the most common Network Firewall use case: protecting server workloads (EC2, ECS, EKS) where the threat model is a compromised instance attempting to communicate with C2, download payloads, mine cryptocurrency, or move laterally.

| Priority | Rule group | What it detects | Why included |
|---|---|---|---|
| 6 | ThreatSignaturesBotnetStrictOrder | Botnet C2 protocols across TCP, UDP, and other protocols | Broadest botnet coverage. Compromised servers phone home over many protocols. |
| 7 | ThreatSignaturesBotnetWebStrictOrder | HTTP-based botnet C2 communication | HTTP is the most common C2 channel because it blends with normal web traffic. |
| 8 | ThreatSignaturesMalwareStrictOrder | Malware across TCP, UDP, SMTP, ICMP, SMB, and worm propagation | Broad malware detection across all protocols. |
| 9 | ThreatSignaturesMalwareCoinminingStrictOrder | Cryptocurrency mining protocols and pool communication | Cryptomining is the most common post-compromise activity for server workloads. |
| 10 | ThreatSignaturesExploitsStrictOrder | Direct exploits (ActiveX, FTP, NetBIOS, RPC, shellcode, SQL injection, SNMP) | Strong east-west coverage. Detects lateral exploitation between internal systems. |
| 11 | ThreatSignaturesIOCStrictOrder | Indicators of compromise, attack response signatures, exploit kit infrastructure | Detects post-exploitation activity after initial compromise. |
| 12 | ThreatSignaturesScannersStrictOrder | Reconnaissance tools (Nessus, Nikto, port scanners) | Detects internal recon. Key for east-west (catches scanning before exploitation). |
| 13 | ThreatSignaturesSuspectStrictOrder | Suspicious JA3 fingerprints, IRC chat, anomalous user agents | Catches anomalous client behavior that doesn't match normal server traffic. |
| 14 | ThreatSignaturesEmergingEventsStrictOrder | Active campaigns and breaking threats (rules rotate frequently) | High timeliness value. Catches threats that are happening right now. |
| 15 | ThreatSignaturesDoSStrictOrder | Denial of service patterns | Low capacity cost (200). Provides basic DoS visibility. |

#### What is not included (and why)

The default quota for stateful rules per firewall policy is 30,000. This template uses 29,200 of that. The following rule groups do not fit within the default limit:

| Rule group | Capacity | Notes |
|---|---|---|
| ThreatSignaturesBotnetWindowsStrictOrder | 3,400 | Windows-specific botnet detection. Add if you run Windows workloads. |
| ThreatSignaturesMalwareWebStrictOrder | 3,300 | HTTP/TLS malware. Complements MalwareStrictOrder with web-specific signatures. |
| ThreatSignaturesWebAttacksStrictOrder | 1,400 | Web application attacks (SQLi, XSS). Relevant for ingress or east-west web traffic. |
| ThreatSignaturesPhishingStrictOrder | 4,200 | Credential phishing. More relevant for end-user browsing than server workloads. |
| ThreatSignaturesMalwareMobileStrictOrder | 4,000 | Mobile OS malware. Not relevant unless mobile traffic traverses the firewall. |

ThreatSignaturesFUPStrictOrder is also excluded. It covers acceptable use policy violations (gaming, peer-to-peer traffic, inappropriate content) rather than threat detection, so it is a fit for environments that need acceptable use enforcement rather than a baseline every deployment should have.

!!! tip "Best practice"
    Submit a [Service Quotas increase request](https://console.aws.amazon.com/servicequotas/home/services/network-firewall/quotas) to raise your stateful rule capacity to 50,000 immediately after deploying this template. Two quotas govern this: the total stateful rules per firewall policy (default 30,000, across all rule groups the policy references) and the stateful rule group capacity maximum (default 30,000, for any single rule group). Increases are typically approved quickly and let you add additional managed rule groups and larger custom rule groups for domain allowlists.

#### Capacity planning after the quota increase

A common question: "If I add all the AWS managed rules, how much room will I have for custom rules?"

The 20 stateful rule group limit per policy is the binding constraint, not just capacity. With 50,000 capacity but only 20 rule group slots, you need to balance managed rules against custom rule groups. This template uses 16 of the 20 slots (15 managed + 1 custom), leaving 4 slots.

Recommended approach after the capacity increase:

* Add 2-3 of the excluded managed rule groups (using 2-3 of your 4 remaining slots)
* Keep 1-2 slots for custom rule groups with higher capacity (domain allowlists, environment-specific rules)

For example, adding BotnetWindows (3,400), MalwareWeb (3,300), and WebAttacks (1,400) uses 3 slots and 8,100 capacity, leaving you with 1 custom rule group slot and approximately 12,500 capacity units available for custom rules. That is enough for a substantial domain allowlist or hundreds of custom Suricata rules.

### Custom rule group (Priority 100)

The custom rule group is deployed at the lowest priority (evaluated last, after all managed rules) with 200 capacity units. This keeps the initial capacity available for managed rules. After your service quota increase is approved, create additional custom rule groups with higher capacity for domain allowlists and other custom rules.

The custom rules included are:

**HOME_NET validation** - Alerts on traffic where neither source nor destination matches $HOME_NET. If this rule fires, your HOME_NET configuration is incomplete. See [Detecting misconfigured $HOME_NET](../../firewall-policy-configuration/docs/index.md#detecting-misconfigured-home_net).

**Plaintext HTTP detection** - Alerts on any plaintext HTTP traffic leaving your network. All outbound traffic from server workloads should be TLS encrypted. Plaintext HTTP may indicate misconfigured applications or potential data exposure. The default action will also log this, but a dedicated rule makes it easy to search for and alert on specifically.

**East-West traffic monitoring** - A set of rules that alert on internal-to-internal traffic, helping you discover lateral communication patterns between your VPCs. Includes specific rules for common sensitive ports (databases, SSH, RDP, SMB) so you can see which internal services are communicating with each other. This visibility is essential before building east-west access control rules.

**Inbound traffic monitoring** - Alerts on any traffic initiated from external sources toward your network. In an egress-only or east-west deployment, inbound internet traffic is unexpected and may indicate a routing misconfiguration.

## Transitioning to enforcement mode

After monitoring traffic and understanding your traffic patterns, transition the policy from alert mode to enforcement mode:

### Step 1: Remove DROP_TO_ALERT overrides from managed rule groups

Remove the `Override` block from each managed rule group reference in your template. This allows the managed rules to take their native action (drop or reject) when threats are detected. You can do this incrementally, starting with ATD and domain/IP reputation (highest confidence) and then adding threat signatures.

### Step 2: Add the drop default action

Add the drop default action alongside the existing alert action. Change from:

* `aws:alert_established_app_layer_to_server`

To both:

* `aws:drop_established_app_layer_to_server` (blocks unmatched traffic)
* `aws:alert_established_app_layer_to_server` (logs what is being blocked)

Keep both actions. The alert action ensures blocked traffic is still logged. Without it, dropped traffic would not appear in your alert logs. See [Default actions](../../firewall-policy-configuration/docs/index.md#default-actions) for details.

### Step 3: Add domain allowlist rules

Based on what you observed during the monitoring period, add pass rules for the domains your workloads legitimately need to reach. See [Domain filtering](../../customer-managed-rules/docs/index.md#domain-filtering) and [Sample Suricata rules](../../sample-suricata-rules/docs/index.md#allow-rules-and-domain-allowlisting) for examples.

### Step 4: Convert east-west monitoring to access control

Review the east-west alert logs to understand which internal flows exist. Convert the monitoring rules to explicit pass rules for known-good flows and drop/reject rules for everything else.

## Capacity summary

| Component | Capacity used | Notes |
|---|---|---|
| AttackInfrastructureStrictOrder | 15,000 | Fixed |
| Domain/IP rule groups (4) | 800 | Fixed |
| Threat signature groups (10) | 13,200 | Can add more after capacity increase |
| Custom rule group | 200 | Intentionally small to start |
| **Total** | **29,200 / 30,000** | |
| Rule groups used | 16 / 20 | 4 slots remaining |

## What to read next

* [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md) - Deep dive into each policy setting configured here
* [Customer managed rules](../../customer-managed-rules/docs/index.md) - Writing custom rules for your specific requirements
* [AWS Managed Rules](../../aws-managed-rules/docs/index.md) - Understanding what the managed rules detect
* [Logging and monitoring](../../logging-and-monitoring/docs/index.md) - Analyzing the alert logs this policy generates
