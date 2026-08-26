# Best practices quick reference

The highest-impact recommendations from this guide, without the reasoning behind them. Each one links to the section that explains why. If you are deploying from scratch, the [Getting started policy](../../getting-started-policy/docs/index.md) implements most of them for you in a CloudFormation or Terraform template.

## Deployment architecture

| Do this | Why it matters | Details |
|---|---|---|
| Centralize inspection for multi-account environments, using the native Transit Gateway attachment for new deployments | One set of firewall endpoints and one policy serves every VPC, which lowers endpoint cost and simplifies policy management. | [Deployment architecture](../../deployment-architecture/docs/index.md#centralizing-with-transit-gateway-native-attachment) |
| Deploy a firewall endpoint in every Availability Zone where you have workloads, and route each subnet to the endpoint in its own AZ | Keeps inspection AZ-local, which avoids cross-AZ data transfer charges and keeps each Availability Zone independent. | [Avoid cross-AZ data transfer](../../cost-considerations/docs/index.md#avoid-cross-az-data-transfer) |
| Place your NAT gateway in the same network path as the firewall | NAT gateway hourly and data processing charges are waived one-for-one against your Network Firewall charges. | [NAT gateway bundled discount](../../cost-considerations/docs/index.md#nat-gateway-bundled-discount) |
| Use gateway VPC endpoints for Amazon S3 and Amazon DynamoDB | Gateway endpoints are free and keep that traffic out of firewall data processing. | [Reduce data processing costs](../../cost-considerations/docs/index.md#reduce-data-processing-costs) |
| Deploy Amazon Route 53 Resolver DNS Firewall on every VPC whose workloads use the VPC .2 Resolver | DNS resolution to the .2 Resolver uses a dedicated path that firewall endpoints do not see. DNS Firewall covers that path. | [DNS Firewall](../../prerequisites/docs/index.md#dns-firewall) |
| Keep security groups in place as your resource-level control alongside Network Firewall | Security groups apply to every ENI regardless of how traffic is routed, so the two controls reinforce each other. | [Security groups](../../prerequisites/docs/index.md#security-groups) |
| Manage a centralized deployment with infrastructure as code, and use AWS Firewall Manager when firewalls are distributed across many accounts and VPCs | Firewall Manager's strength is deploying and enforcing policy across many firewalls as accounts and VPCs are added. | [Managing across accounts](../../deployment-architecture/docs/index.md#managing-across-accounts-with-aws-firewall-manager) |

## Firewall policy configuration

| Do this | Why it matters | Details |
|---|---|---|
| Use Strict rule ordering. Do not use Action Order. | Strict ordering evaluates rules in the order you define them, and the first match wins. Action Order groups rules by action type, so precedence between different actions is not something you control. | [Rule ordering](../../firewall-policy-configuration/docs/index.md#rule-ordering-always-use-strict) |
| Set the stateless engine default actions to "Forward to stateful rule groups" and do all filtering in the stateful engine | The stateful engine provides connection tracking, application-layer inspection, logging, and the reject action. | [Do not use stateless rules](../../customer-managed-rules/docs/index.md#do-not-use-stateless-rules) |
| Select "Application drop established (server-directed only)" **and** "Application alert established (server-directed only)" together as your default actions | The application variant waits for the TLS SNI or HTTP host header before deciding, which is what domain filtering depends on. The paired alert action logs what the drop action blocks. | [Default actions](../../firewall-policy-configuration/docs/index.md#default-actions) |
| Set $HOME_NET to all RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) at the policy level, and deploy the $HOME_NET detection rule | The default value covers only the firewall's own VPC CIDR. Once $HOME_NET includes all of your internal ranges, rules that reference it, including AWS managed threat signatures, match traffic from every VPC routed through the firewall. | [$HOME_NET and $EXTERNAL_NET](../../firewall-policy-configuration/docs/index.md#home-net-and-external-net-variables) |
| Set the stream exception policy to Reject | Reject sends a TCP RST so clients reconnect, and the new connection is fully inspected against your current rules. | [Stream exception policy](../../firewall-policy-configuration/docs/index.md#stream-exception-policy) |

## Rules

| Do this | Why it matters | Details |
|---|---|---|
| Write custom Suricata rules directly | Plain text rules work with version control and infrastructure as code, move easily between rule groups, and give you the full Suricata feature set. | [Use custom Suricata rules](../../customer-managed-rules/docs/index.md#use-custom-suricata-rules) |
| Put a `flow:` keyword on every stateful rule whose protocol field is `tcp` or `ip` | Without it, Suricata classifies the rule as IP-only, matches it on the first packet of the flow, and applies that action for the life of the flow. This is the most common reason rules appear to evaluate out of order. | [Always use the flow: keyword](../../customer-managed-rules/docs/index.md#always-use-the-flow-keyword-on-all-tcp-or-ip-protocol-rules) |
| Implement a domain allowlist for egress: permit the domains your workloads need and block the rest | Allowing a known-good list is achievable in a way that identifying every bad destination on the internet is not, and it dramatically reduces the risk surface. | [Domain filtering](../../customer-managed-rules/docs/index.md#domain-filtering) |
| Consolidate your custom rules into as few rule groups as possible, ideally one, and set capacity with room to grow | The 20 stateful rule group limit is shared with managed rule groups, and rule group capacity is fixed once the group is created. | [Consolidate into few rule groups](../../customer-managed-rules/docs/index.md#consolidate-into-few-rule-groups) |
| Deploy new blocking rules as `alert` first, then switch to `reject` or `drop` once you have validated them against real traffic | Alert mode shows you what a rule would have matched before it starts blocking. | [How to use this page](../../sample-suricata-rules/docs/index.md#how-to-use-this-page) |

## AWS Managed Rules

| Do this | Why it matters | Details |
|---|---|---|
| Enable Active Threat Defense on every firewall policy | High-confidence blocking of known malicious infrastructure using Amazon threat intelligence, with no rules for you to write or maintain. | [Active Threat Defense](../../aws-managed-rules/docs/index.md#active-threat-defense-atd) |
| Enable the domain and IP reputation rule groups on every policy | They cover destinations your workloads have no reason to reach, at no additional cost and with a small capacity footprint. | [Domain and IP rule groups](../../aws-managed-rules/docs/index.md#domain-and-ip-rule-groups-free) |
| Start with three threat signature rule groups: Botnet, Malware, and Exploits | Broadest threat coverage with the strongest signal-to-noise ratio, while leaving rule group slots available for your own rules. | [Selecting rule groups by deployment scenario](../../aws-managed-rules/docs/index.md#selecting-rule-groups-by-deployment-scenario) |
| Deploy managed rule groups in alert mode first, then move to drop, starting with Active Threat Defense and the reputation lists | Shows you how the signatures match your traffic before they begin blocking it. | [Alert mode vs drop mode](../../aws-managed-rules/docs/index.md#deploying-managed-rules-in-alert-mode-vs-drop-mode) |

## Logging and monitoring

| Do this | Why it matters | Details |
|---|---|---|
| Publish alert logs and flow logs to separate log groups or S3 prefixes | The two log types answer different questions and are easier to query when they are separated. | [Log destinations](../../logging-and-monitoring/docs/index.md#log-destinations) |
| Create CloudWatch alarms on `StreamExceptionPolicyPackets`, `DroppedPackets` and `RejectedPackets`, and `TLSErrors` | These metrics tell you when traffic symmetry, blocking behavior, or TLS inspection has changed. | [Recommended CloudWatch alarms](../../logging-and-monitoring/docs/index.md#recommended-cloudwatch-alarms) |
| Enable Traffic Analysis Mode before you build your first domain allowlist | It gives you 30 days of observed HTTP and HTTPS domains to build the allowlist from. | [Traffic Analysis Mode](../../logging-and-monitoring/docs/index.md#traffic-analysis-mode) |
