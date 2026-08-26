# Additional references

This page collects hands-on resources for learning and implementing AWS Network Firewall beyond the best practices covered in this guide: sample code repositories, workshops, video walkthroughs, blog posts, and official documentation links.

## Sample code

Start here if you want working code to deploy or extend.

* [Suricata Rule Generator for AWS Network Firewall](https://github.com/aws-samples/sample-suricata-generator) - Open-source GUI application for writing, validating, and managing Suricata rules. Includes rule conflict analysis, bulk domain import, managed rule group filtering, CloudWatch usage analytics, and infrastructure export (CloudFormation, Terraform, direct API). Referenced throughout this guide.
* [AWS Network Firewall CloudFormation Templates](https://github.com/aws-samples/aws-networkfirewall-cfn-templates) - CloudFormation templates for all deployment architectures (centralized, distributed, combined), the getting started policy, and a CloudWatch dashboard.
* [AWS Network Firewall Terraform Templates](https://github.com/aws-samples/aws-network-firewall-terraform) - Terraform equivalents of the CloudFormation templates above, covering all deployment architectures and the getting started policy.
* [AWS Network Firewall Automation Examples](https://github.com/aws-samples/aws-network-firewall-automation-examples/tree/main) - Lambda-based automation patterns for dynamic rule updates, IP list synchronization, and event-driven rule management.

## Workshops

AWS workshops are hands-on labs that walk you through deploying and configuring services in a sandbox AWS account.

The best way to experience these workshops is through the [AWS Activation Day program](https://aws-experience.com/amer/smb/events/series/activation-days). Activation Days are free, instructor-led events open to anyone. AWS Solutions Architects guide you through the workshop content in a live setting with a provisioned sandbox account at no cost. Check the program page for upcoming sessions covering AWS security, identity, and governance services.

If you are an AWS customer with an account team, you can also ask your Solutions Architect to set up a dedicated workshop event for your team. These use the same workshop content as Activation Days but are run privately for your organization.

If you prefer to deploy the workshop into your own environment, the open-source code repositories below contain the infrastructure as code to do so.

### Workshop instructions

* [AWS Advanced Network Security: Network Firewall and DNS Firewall](https://catalog.workshops.aws/network-security/en-US) - Comprehensive workshop covering both Network Firewall and DNS Firewall together. Walks through centralized deployment with Transit Gateway, Suricata rule writing, domain filtering, managed rules, and logging.
* [Building Secure Networks with AWS Cloud WAN, Network Firewall, and DNS Firewall](https://catalog.us-east-1.prod.workshops.aws/workshops/cdef9a06-8156-4669-9e6a-6eb83e4a5adc/en-US) - Same Network Firewall and DNS Firewall content as above, but the centralized networking hub is Cloud WAN instead of Transit Gateway. Includes Cloud WAN service insertion concepts for routing traffic to the firewall.

### Workshop source code

* [sample-aws-network-security-workshop](https://github.com/aws-samples/sample-aws-network-security-workshop) - IaC for the AWS Advanced Network Security workshop (Transit Gateway variant)
* [sample-building-secure-global-hybrid-networks-on-aws-workshop](https://github.com/aws-samples/sample-building-secure-global-hybrid-networks-on-aws-workshop) - IaC for the Building Secure Networks workshop (Cloud WAN variant)

## Videos

* [Introduction, best practices and custom Suricata rules](https://www.youtube.com/watch?v=67pVOv3lPlk) - Broad overview of Network Firewall architecture and rule writing fundamentals.
* [AWS re:Inforce 2023 - Firewalls, and where to put them (NIS306)](https://www.youtube.com/watch?v=lTJxWAiQrHM) - Deployment architecture decision framework, covering when to use Network Firewall vs. WAF vs. security groups.
* [Decrypt, inspect, and re-encrypt TLS egress traffic at scale](https://www.youtube.com/watch?v=S7_hUxWrYmw&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=3&pp=iAQB) - TLS inspection setup and operational considerations.
* [Decrypt, inspect, and re-encrypt TLS traffic at scale](https://www.youtube.com/watch?v=j2pLuHdAj0A&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=40&pp=iAQB) - Extended TLS inspection walkthrough with inbound and outbound scenarios.
* [AWS Network Firewall Suricata HOME_NET variable override](https://www.youtube.com/watch?v=ufx8sO5s4BI&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=22&pp=iAQB) - Visual demonstration of the HOME_NET misconfiguration and how to fix it.
* [AWS Network Firewall support for reject action for TCP traffic](https://www.youtube.com/watch?v=_K_2TVNygF4&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=54&pp=iAQB) - Reject action behavior and when to use it vs. drop.
* [AWS Network Firewall tag-based resource groups](https://www.youtube.com/watch?v=SDj_tMHN5Zk&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=55&pp=iAQB) - Organizing firewall resources with tags for multi-team environments.
* [AWS Network Firewall console experience](https://www.youtube.com/watch?v=BYVObzBWnqo&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=1&pp=iAQB) - Console walkthrough for visual learners who prefer the console over IaC.

## Blogs

### Architecture and deployment

* [Deployment models for AWS Network Firewall](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall/) - Original deployment model blog covering centralized, distributed, and combined architectures with diagrams.
* [Deployment models for AWS Network Firewall: Transit Gateway attachment and multiple VPC endpoints](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall-transit-gateway-attachment-and-multiple-vpc-endpoints/) - Updated deployment models covering the native TGW attachment and multi-endpoint features.
* [Why and how to migrate to a Transit Gateway-attached AWS Network Firewall](https://aws.amazon.com/blogs/security/why-and-how-to-migrate-to-a-transit-gateway-attached-aws-network-firewall/) - Migration guide from inspection VPC to native TGW attachment.
* [Reintroducing Network Firewall Proxy for Secure Egress Connectivity](https://aws.amazon.com/blogs/networking-and-content-delivery/reintroducing-network-firewall-proxy-for-secure-egress-connectivity/) - Explicit proxy mode for Network Firewall with no-source-preservation architecture.
* [How to deploy AWS Network Firewall by using AWS Firewall Manager](https://aws.amazon.com/blogs/security/how-to-deploy-aws-network-firewall-by-using-aws-firewall-manager/) - Multi-account deployment automation with Firewall Manager.
* [Centralized outbound inspection architecture in AWS Cloud WAN](https://aws.amazon.com/blogs/networking-and-content-delivery/centralized-outbound-inspection-architecture-in-aws-cloud-wan/) - Cloud WAN service insertion with Network Firewall.

### Rules and filtering

* [From log analysis to rule creation: How AWS Network Firewall automates domain-based security for outbound traffic](https://aws.amazon.com/blogs/security/from-log-analysis-to-rule-creation-how-aws-network-firewall-automates-domain-based-security-for-outbound-traffic/) - Traffic Analysis Mode for automated domain discovery and rule generation.
* [Introducing Prefix Lists in AWS Network Firewall Stateful Rule Groups](https://aws.amazon.com/blogs/networking-and-content-delivery/introducing-prefix-lists-in-aws-network-firewall-stateful-rule-groups/) - Using managed prefix lists as IP set references in rules.
* [How to control non-HTTP and non-HTTPS traffic to a DNS domain with AWS Network Firewall and AWS Lambda](https://aws.amazon.com/blogs/security/how-to-control-non-http-and-non-https-traffic-to-a-dns-domain-with-aws-network-firewall-and-aws-lambda/) - Filtering non-web protocols by domain using dynamic IP resolution.
* [Use AWS Network Firewall to filter outbound HTTPS traffic from applications hosted on Amazon EKS and collect hostnames provided by SNI](https://aws.amazon.com/blogs/security/use-aws-network-firewall-to-filter-outbound-https-traffic-from-applications-hosted-on-amazon-eks/) - EKS-specific egress filtering patterns.

### TLS inspection

* [TLS inspection configuration for encrypted traffic and AWS Network Firewall](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-traffic-and-aws-network-firewall/) - Step-by-step inbound TLS inspection configuration.
* [TLS inspection configuration for encrypted egress traffic and AWS Network Firewall](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-egress-traffic-and-aws-network-firewall/) - Step-by-step outbound TLS inspection configuration.

### Logging and monitoring

* [Cost considerations and common options for AWS Network Firewall log management](https://aws.amazon.com/blogs/security/cost-considerations-and-common-options-for-aws-network-firewall-log-management/) - Log destination selection, cost optimization, and retention strategies.
* [How to analyze AWS Network Firewall logs using Amazon OpenSearch Service (Part 1)](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-analyze-aws-network-firewall-logs-using-amazon-opensearch-service-part-1/) - OpenSearch integration for log analysis and visualization.
* [How to analyze AWS Network Firewall logs using Amazon OpenSearch Service (Part 2)](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-analyze-aws-network-firewall-logs-using-amazon-opensearch-service-part-2/) - Advanced OpenSearch queries and dashboard creation.
* [AWS Network Firewall now supports rule hit count](https://aws.amazon.com/blogs/security/aws-network-firewall-now-supports-rule-hit-count/) - Per-rule traffic match reporting for finding dormant rules, validating new rules, and evidencing active controls.
* [Introducing the AWS Network Firewall CloudWatch Dashboard](https://aws.amazon.com/blogs/security/introducing-the-aws-network-firewall-cloudwatch-dashboard/) - Native monitoring dashboard setup and usage.
* [Use Contributor Insights to analyze AWS Network Firewall](https://aws.amazon.com/blogs/mt/use-contributor-insights-to-analyze-aws-network-firewall/) - CloudWatch Contributor Insights for top-N analysis.

## AWS documentation

* [AWS Network Firewall Developer Guide](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html) - Complete service documentation.
* [Network Firewall FAQ](https://aws.amazon.com/network-firewall/faqs/) - Common questions and answers.
* [Network Firewall pricing](https://aws.amazon.com/network-firewall/pricing/) - Current pricing for endpoints, processing, and TLS inspection.
* [Suricata rule examples](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html) - Official AWS Suricata rule examples.
* [Troubleshooting rules](https://docs.aws.amazon.com/network-firewall/latest/developerguide/troubleshooting-rules.html) - Common rule issues and solutions.
* [Evaluation order for stateful rule groups](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html) - How strict and action order modes work.
* [Setting rule group capacity](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-rule-group-capacity.html) - How stateful and stateless rule group capacity is calculated.
* [Network Firewall quotas](https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html) - Adjustable and fixed service limits.
* [Stream exception policy](https://docs.aws.amazon.com/network-firewall/latest/developerguide/stream-exception-policy.html) - Midstream flow handling options.
* [TLS inspection configurations](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html) - TLS decryption setup reference.
* [Troubleshooting AWS Network Firewall](https://docs.aws.amazon.com/network-firewall/latest/developerguide/troubleshooting.html) - General troubleshooting guide.

## Related guides

* [AWS Networking Best Practices - Security](https://aws.github.io/aws-networking-best-practices/security/) - Broader AWS networking security guidance.
* [AWS Security Services Best Practices - Firewalls on AWS](../../../firewall-overview/index.md) - Choosing between AWS firewall services (Network Firewall, WAF, security groups, DNS Firewall).
* [AWS Security Services Best Practices - AWS WAF](../../../waf/index.md) - Best practices for the complementary web application firewall.
