# Using AWS WAF with other services

## AWS Firewall Manager (FMS)

You can create a [WAF policy in Firewall Manager](https://docs.aws.amazon.com/waf/latest/developerguide/waf-policies.html). You specify which rule groups you want to have at the top and bottom of web ACLs. You define the scope of resources in your AWS Organization, and FMS creates web ACLs in each member account and associates them with resources in scope. FMS-managed web ACLs can be customized by member accounts, but the top and bottom rule groups cannot be modified.

### Deciding what rules to include in FMS security policies for AWS WAF

FMS security policies for AWS WAF are typically managed by a central security team. This team is responsible for enforcing a baseline of rules across the organization. There might be a few parts of the organization that require a unique baseline and therefore a unique policy.

The FMS-managed web ACL might need to be customized by a member account. A managed rule might be causing false positives that need to be addressed, or there might be an application-specific threat that is not mitigated by the baseline. It is recommended to update the web ACL rather than making application-specific changes to the FMS policy. Generally it is common to have a few FMS policies that apply to a wide range of resources rather than many FMS policies that each apply to a few resources.

### Using CloudFormation to update FMS-managed web ACLs

[AWS WAF V2 resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_WAFv2.html) can be fully defined using CloudFormation templates. There are some considerations when using Firewall Manager to manage web ACLs.

You can define [Firewall Manager policies](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fms-policy.html) for AWS WAF using CloudFormation. The policy contains a definition of the AWS WAF rules you want at the top and bottom of the web ACLs created by FMS. This has a few implications when using CloudFormation (or any other [infrastructure as code](https://docs.aws.amazon.com/whitepapers/latest/introduction-devops-aws/infrastructure-as-code.html) tool).

The CloudFormation template format is not the same between [AWS::WAFev2::WebACL](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html) and [AWS::FMS::Policy](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fms-policy.html). To use an existing AWS WAF web ACL as the basis for a Firewall Manager policy, you need to download the web ACL as JSON (in the AWS WAF console) or use the [GetWebACL](https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACL.html) API. You use this JSON to construct the [SecurityServicePolicyData](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fms-policy-securityservicepolicydata.html) element of the FMS policy resource. In simple cases, it might be easier to recreate the AWS WAF rules manually in the FMS console.

Member accounts can customize web ACLs created by FMS using the AWS console or CLI or SDKs. However, you can't create a standard CloudFormation template that adds custom rules to the FMS-managed web ACL. AWS WAF rules are defined inside the AWS::WAFev2::WebACL resource. Since the web ACL already exists, you can't define it in your CloudFormation template. There are currently two options to work around this.

1. [Import](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import.html) the FMS-managed web ACL into your CloudFormation stack, then update the stack with custom rules. 
2. Define your custom rules in a [AWS::WAFv2::RuleGroup](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html), then use a Lambda-backed [custom resource](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html) that has code to discover the FMS-managed web ACL and create a rule that references the rule group.

### Handling false positives caused by FMS-managed rule groups

In large organizations it is not uncommon for an FMS-managed web ACL to include rules that cause false positives for one or more member accounts. You can use multiple FMS policies to handle these situations.

1. An *exception policy* with the problematic rule in *Count* mode to allow handling of false positives. This policy's scope only includes resources that have a specific tag. Member accounts are responsible for adding the a rule that properly handles the false positive.
2. A *primary policy* has all managed rules in *Block* mode. This policy is used to protect resources that are not concerned about false positives. This policy's scope excludes resources with the tag used by the exception policy.

## Amazon GuardDuty

You can automate the creation of AWS WAF rules based on findings generated by Amazon GuardDuty. See the blog [How to use Amazon GuardDuty and AWS WAF v2 to automatically block suspicious hosts](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-aws-waf-v2-to-automatically-block-suspicious-hosts/).

## AWS Shield Advanced

[Shield Advanced automatic application layer DDoS mitigation](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-automatic-app-layer-response.html) is a Shield Advanced feature that automatically detects application layer attacks and generates AWS WAF rules that isolate and block the anomalous traffic. When enabling this capability, a [rule group managed by Shield Advanced](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-automatic-app-layer-response-rg.html) is added to the bottom of the protected resource's web ACL.

You can use [AWS Shield policies in Firewall Manager](https://docs.aws.amazon.com/waf/latest/developerguide/shield-policies.html) to automatically configure this feature.

## AWS Transfer Family

AWS Transfer Family is a service that manages file transfer protocols. See the blog [Securing AWS Transfer Family with AWS Web Application Firewall and Amazon API Gateway](https://aws.amazon.com/blogs/storage/securing-aws-transfer-family-with-aws-web-application-firewall-and-amazon-api-gateway/).