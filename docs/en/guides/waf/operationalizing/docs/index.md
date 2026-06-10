# Operationalizing

This section assumes you have a basic understanding of [how AWS WAF works](../../prerequisites/docs/index.md), [Amazon Managed Rules](../../aws-managed-rules/docs/index.md), [custom rules](../../custom-rules/docs/index.md), [WAF labels](../../custom-rules/docs/index.md#using-rule-labels), and [logging options](../../waf-logging/docs/index.md).

This guide will cover the high level process to roll out and then operate AWS WAF and provides multiple common scenarios from a single team or application level implementation through Enterprise deployment that already use AWS WAF (or not).

## Overview

The following steps outline the general process for rolling out AWS WAF, whether you are a single application team or deploying accross an entire Organization of accounts.  THis guide provides specific guidance based on the scope you are operating/consuming AWS WAF.

1. **Start with a [pre-configured protection pack](../../aws-managed-rules/docs/index.md#protection-pack-recommendations)** for a strong default set of rules based on your application type, or build your own combination of managed and custom rules manually.

1. **Deploy all rules in Count mode** - Get rules evaluating traffic without blocking so you can observe behavior before enforcing.

1. **Set up logging** - Enable WAF logging so you have the data needed to analyze rule behavior.

1. **Set up dashboards and log queries** - Build visibility into which rules are matching and on what traffic to inform enforcement decisions.

1. **Wait for enough WAF log data to build up** - You will want sufficient WAF logs (a few days or week) to fully understand the implications of WAF rules before moving them to be enforced/*Blocked*

1. **Move rules from *Count* to *Block*, starting with low-risk rules** — Move rules to *Block* mode incrementally, starting with the ones least likely to impact legitimate traffic.

    a. **Focus on low-risk, easy wins** - Find rules that have not matched at all or only match clearly malicious/non-legitimate traffic, enforce these rules first.

    b. **Identify rules that require exceptions** - Find rules that are matching legitimate traffic and determine what exceptions are needed.

    c. **Decide when not to enforce a rule** - Determine if any rules fundamentally conflict with your application and should remain in Count mode or be removed.


1. **Add new rules and AMR versions over time** - Follow the same Count/analyze enforce cycle as your application evolves and new rule versions are released.


## Single Team / Application-Level Usage

This section is for application teams or individual operators who own one or a small number of applications and are responsible for their own WAF configuration. The size of your organization does not matter here — what matters is that you only have a few applications to protect. Whether you are a solo developer, SMB, or an application team within a large enterprise, the steps below are applicable because of *your* scope.  

1. **Select your initial WAF rules** - A [pre-configured protection pack](../../aws-managed-rules/docs/index.md#protection-pack-recommendations) is the fastest path. It selects rules based on your application type and can one click set all rules to a *Count* action. If you prefer to build manually, start with the [baseline managed rule groups](../../aws-managed-rules/docs/index.md#baseline-rules-for-all-deployments), add [use-case specific rules](../../aws-managed-rules/docs/index.md#use-case-specific-rules) that match your stack, and include the [common custom rules recommended for most deployments](../../custom-rules/docs/index.md#common-rules-for-most-deployments). Arrange your rules following the [Recommended WAF Rule Order](../../recommended-waf-rule-order/docs/index.md). If you are unsure if a rule will be helpful, adding it now will provide you data via WAF logs to know if that rule will be useful or not; lean towards including more rules than not at this point.  The only potential counter point would be if adding the additional rules pushes you above  1,500 WCUs (as this has an additional cost).

1. **Deploy all rules in Count mode** - If you have a non-production environment, you can start there to get familiar with the process. However, getting WAF setup in production is important - production traffic provides the volume and variety of real user traffic patterns needed to meaningfully validate the impact of WAF rules proactively. With all rules set to *Count* and a default action of *Allow*, AWS WAF will not block any traffic; the risk of deploying to production is minimal (at most adding single-digit millisecond latency).

1.  **Enable AWS WAF logging** — Logging is critical for validating that none of the rules you deployed in Count mode would negatively impact legitimate traffic. WAF logs capture matching rules and labels, showing you what would have happened if a given rule had been enforced. See [WAF Logging](../../waf-logging/docs/index.md) for a full comparison of log destinations, pros/cons, cost considerations, and retention guidance.

    If you do not have a particular reason to select otherwise, AWS **recommends CloudWatch Logs** as there is no setup required beyond creating a log group to capture, query, and dashboard WAF logs. The native [AWS WAF dashboard](../../monitoring-waf-rules/docs/index.md) works out of the box with CloudWatch Logs, and CloudWatch Logs Insights is available for deeper ad-hoc queries. If your organization already has a centralized logging platform (Splunk, Datadog, etc.) or you expect high log volumes where S3 is more cost-effective, those are also good options — see [WAF Logging](../../waf-logging/docs/index.md) for details on each.

    If your organization centrally manages Amazon Security Lake, your WAF logs may already be captured there without any action on your part. Check with your security or platform team before setting up a separate logging destination.


1. **Set up dashboards and log queries** — You need to be able to visualize and/or query WAF logs to understand how your traffic interacts with managed rules and custom rules before you can move forward with enforcement decisions. If you are sending logs to CloudWatch Logs, the built-in AWS WAF dashboard provides out-of-the-box visualization and log query capabilities, with CloudWatch Logs Insights available for more advanced queries. If you are sending logs to S3, Amazon Athena and Amazon QuickSight provide AWS-native dashboard and query capabilities.  Partner solutions have their own Dashboard and/or query capabilities.  See [Monitoring WAF Rules](../../monitoring-waf-rules/docs/index.md) for details on each approach and existing dashboard solutions.


1. **Wait for enough WAF log data to build up** - Let your rules evaluate production traffic; 1-2 weeks is usually ideal. The goal is to capture a representative sample of your traffic so you can confidently assess what WAF would block once enforcing rules. You can wait a different amounts of time for different applications or rule types.  AWS does **NOT** recommend using WAF logs from non-prod alone to determine if it is safe to enable WAF rules in production.  If you enable WAF in non-prod first, only use this to move rules in non-prod to block; you should repeat the above steps again in production before enforcing WAF rules in production.  

1. **Move rules from *Count* to *Block***  
    For all cases below, you will need to query WAF logs to understand based on historical traffic what is safe to move forward or requires extra attention.  You can see exactly how to query for each type of WAF rule [here](../../monitoring-waf-rules/docs/index.md#evaluating-aws-waf-rules-through-waf-log-queries).  Evaluate which rules to move from **Count** to **Block** in the order shown below.

    - **Focus on low-risk, easy wins** — This should be your primary focus and result in moving many/most WAF rules from *Count* to *Block*.  Many rules will have no or a low hit counts (with all hits easily identifiable as noise/malicious) signifying your application(s) does not need any exceptions to work unimpeeded by an AMR/custom WAF rule.  Below is the general recommendation of what rules tend to be the easiest to validate and begin enforcing.  
        a) Look for any requests matching [IP Reputation](../../aws-managed-rules/docs/index.md#amazon-ip-reputation-list) and [Anonymous IP](../../aws-managed-rules/docs/index.md#anonymous-ip-list), these are easy to validate because the IPs they match are either known-bad or from anonymizing sources, and you can quickly confirm whether any of your legitimate traffic originates from those IPs.   
        b) If you are using the AntiDDoS AMR, at this point the AMR has a strong baseline.  Unless you had a DDoS event since you first implemented you likely do not have any labelled traffic.  Consider moving at least the  rule for Low sensitivity (high confidence) from *Count* to *Block*.
        c) Evaluate your rate based rule(s) and determining appropiate values.  See [determine a good value for a rate based rule](../../monitoring-waf-rules/docs/index.md#using-amazon-s3-and-athena) for example of how to get this datapoint.  
        d) Evaluate [baseline rules](../../aws-managed-rules/docs/index.md#baseline-rules-for-all-deployments) or specific concerns you have for your application such as XSS or SQLi protection.  Many rules within an Amazon Managed Rule are usually low effort to identify as non-impactful.  Focus on finding these first and moving them to *Block*.  

    - **Identify rules requiring an exception** — It is common for a few rules or endpoints to require exceptions. Amazon Managed Rules such as CommonRuleSet are built based on general application design patterns, not *your* specific application. When a rule matches expected or legitimate application traffic, the right approach is usually to create an exception so the rule can be enforced while still allowing your application-specific traffic through. See [creating exceptions](../../operationalizing/docs/index.md#creating-exceptions) for examples of how to do this properly.  Focus on creating straight forward execption and moving all/more rules to *Block* sooner than creating a perfectly scoped exception immediately.  

    - **Decide when not to enforce a rule** — If a rule fundamentally conflicts with how your application works and cannot reasonably be scoped around with exceptions, leave it in Count mode within the AMR or remove it.  For example, CommonRuleSet includes `SizeRestrictions_BODY`, which blocks requests with a body larger than 8 KB, and `CrossSiteScripting_BODY`, which can flag body content containing `<xml>` tags as a potential XSS match. An endpoint that handles file uploads — particularly PDF or DOCX files, which can easily exceed 8 KB and use XML formatting — would regularly trigger both of these rules on legitimate traffic. In cases like these, the rules are unlikely to be useful for that endpoint, and leaving them in *Count* mode is a reasonable choice. The [AWS Managed Rules](../../aws-managed-rules/docs/index.md) section calls out several additional examples of common rule/application conflicts.  Review those examples to understand when leaving a rule unenforced is the right call. The labels from Count mode rules still appear in your WAF logs, so you retain visibility even without enforcement.


9. **Add new rules and AMR versions over time** - Subscribe to [SNS notifications](../../aws-managed-rules/docs/index.md#subscribing-to-sns-notifications) for AMR version updates and set up [CloudWatch alarms for version expiration](../../aws-managed-rules/docs/index.md#monitoring-version-expiration-with-cloudwatch-alarms).  As new rule versions come out, you follow the same steps above:  
    a) Add the new rule (version) to your Protection Pack  
    b) Wait for enough WAF log data to build up  
    c) Review WAF logs and evalute the need for an exception  

## Enterprise Rollout

This section is for central security, platform, or operations teams that manage AWS WAF across an organization, business unit, or large number of AWS accounts. In this model, you typically do not own or operate the applications being protected — application teams do. Your role is to define and deploy a baseline set of WAF rules that apply broadly, centralize WAF logging and metrics, and provide the dashboards and operational visibility that application teams rely on. You may also be responsible for managing exceptions or coordinating with application teams when rules need to be tuned.  Additional context or steps are also included if you already has some degree of existing AWS WAF usage within your organization — whether application teams have deployed it independently for their own workloads, or the organization has been using it without centralized management. The goal here is to bring those existing deployments under a consistent, centrally managed approach without disrupting protections that are already in place. The steps below follow the same process as the [Getting Started](#getting-started) overview but with context specific to operating at enterprise scale, where standardization, centralized visibility, and cross-team coordination are key concerns.

1. **Set up AWS Firewall Manager** — At enterprise scale, you need a centralized way to deploy and manage WAF policies across multiple AWS accounts and resources. AWS Firewall Manager lets you define WAF policies in a central administrator account and automatically apply a Protection Pack configuration to resources across your organization — including new accounts and resources as they are created. This ensures consistent baseline protections without requiring each application team to configure WAF independently. Firewall Manager requires AWS Organizations and a designated Firewall Manager administrator account. If you have not set up Firewall Manager yet, see the [Firewall Manager](../../firewall-manager/docs/index.md) section for setup steps, policy configuration options, and guidance on how to structure policies for your organization. The remaining steps in this section assume you are deploying WAF rules through Firewall Manager policies.

    When defining the Firewall Manager policy, you do not *need* to create multiple policies upfront. Since all rules should start in Count mode, a single baseline policy applied broadly provides a simple starting point — it will not block any traffic, and the WAF logs will show you how rules interact with each application's traffic. You can split into multiple Firewall Manager policies once you have log data showing which applications need different rule sets or exceptions. If your organization has diverse application stacks, this is often the right eventual state, but it does not need to happen on day one.

1. **Select your initial WAF rules** — A [pre-configured protection pack](../../aws-managed-rules/docs/index.md#protection-pack-recommendations) is a useful reference for selecting rules based on your application type, however protection packs cannot be deployed directly through Firewall Manager — you them as your guide when building your Firewall Manager security policies. If you prefer to build your rule set from scratch, start with the [baseline managed rule groups](../../aws-managed-rules/docs/index.md#baseline-rules-for-all-deployments), add [use-case specific rules](../../aws-managed-rules/docs/index.md#use-case-specific-rules) that match your application stacks, and include the [common custom rules recommended for most deployments](../../custom-rules/docs/index.md#common-rules-for-most-deployments) (rate-based rules, geographic restrictions, IP allow/block lists, header validation). Arrange your rules following the [Recommended WAF Rule Order](../../recommended-waf-rule-order/docs/index.md).
  
    If you are unsure whether a rule will be helpful, lean towards including it — with all rules in Count mode, the WAF logs will show whether the rule is relevant to your traffic without any risk of blocking legitimate requests. The only counterpoint is if adding the rule pushes you above 1,500 WCUs per web ACL, as this incurs additional cost.

1. **Placing Rules in First Rules vs. Last Rules** - Protection Pack rules are evaluated in order, and stops at the first rule that evaulates true with a terminating action (i.e. *Allow* & *Block*).  Firewall Manager can add rules to a Protection Pack so they are evaluated before or after locally added rules.  While rules Firewall Manager deployed rules are in *Count*, having these in the **First Rule** group section ensures WAF logs will provide the visibility needed to continue moving forward.  When you look to move rules to *BLock*, placing these rules in **First Rules** or **Last Rules** needs to be considered.  


1. **Deploy all rules in Count mode** — If you have a non-production environment, you can start there to get familiar with the process. However, getting into production is important — production traffic provides the volume and variety of real user requests needed to meaningfully validate your rules. With all rules set to *Count* and a default action of *Allow*, AWS WAF will not block any traffic; the risk of deploying to production at this stage is minimal (at most adding single-digit millisecond latency). When deploying through Firewall Manager, ensure you enable the retrofit option to **not** remove existing web ACLs that application teams may have already configured on their resources. This preserves any protections already in place while your centrally managed policy is rolled out alongside them. See the [Firewall Manager](../../firewall-manager/docs/index.md) section for more details on retrofit configuration.  

    The only use case to **not** enable retrofit is if you deliberately want to remove Protection Packs already deployed by application teams; this is uncommon and usually not the best option due to the potentially destructive and broad impact this can have that is not easily reversable without manual effort.

    **Additional Considerations when AWS WAF is already is use**  
    Because you are expanding existing AWS WAF usage, some application teams may already have Amazon Managed Rules deployed in their own web ACLs — including larger rule groups such as CommonRuleSet.  Adding the same AMR through your Firewall Manager policy will not usually cause a technical conflict — AWS WAF allows the same managed rule group to appear in both the Firewall Manager policy and the application-level web ACL. However, the WCUs are counted separately for each instance, meaning the same rule group deployed twice effectively doubles its WCU consumption against the 1,500 WCU baseline.  For smaller rule groups this is unlikely to be an issue, but larger rule groups like CommonRuleSet (700 WCUs) can push a web ACL over the 1,500 WCU threshold when duplicated, which incurs additional cost. This should not prevent you from including these rule groups in your centralized policy — having a consistent baseline across all applications is the goal.  However, you should proactively identify which application teams already have larger AMRs in place and coordinate with them. In many cases, the application team can remove the duplicate from their own web ACL once the Firewall Manager policy is active; in others, they may need to keep their own copy if they have customized rule actions or exceptions that differ from the central policy. Reviewing existing web ACL configurations before deployment helps you anticipate WCU concerns and plan those conversations ahead of time. See [Discovering Existing WAF Usage Across Your Organization](#discovering-existing-waf-usage-across-your-organization) for guidance on using AWS Config queries and other approaches to inventory existing web ACLs, rule groups, and WCU consumption across your accounts before deploying your Firewall Manager policy.  While uncommon, it is technically possible to exceed the maximum number of WCUs a single Protection Pack can have (5,000) if an application team already has configured rules and Firewall Manager attempts to inject/retrofit more rules; see [Exceeding Protection Pack Maxiumu WCU](../../additional-references/docs/index.md#additional-references)

1.  **Deciding if/how to you want to use multiple Security Policies** -  There are four potential reasons you may or may not want use multiple security policies:

    a. **Cost** - If you do *not* have AWS Shield Advanced, each security policy has a flat $100/month cost.  If you are a Shield Advanced customer, you can create AWS WAFv2 and Shield Advanced type security policies at no cost.

    b. **Multi-region** - Firewall Manager Security policies target a specific region and scope.  Scope can either be REGIONAl for things like ALBs, and CLOUDFRONT for CloudFront distributions.  If you have CloudFront and/or one or more regions wher you want to deploy AWS WAF, you will need a security policy per region.  You can use IAC such as CloudFormation StackSets to deploy the same Firewall Manager Security Policy to multiple region/scopes as a singe logical action but mechanically one per region/scope is needed.

    c. **Multiple BUs or app tiers** - If there are multiple business units within a single AWS Organization, or you have unique dev/qa/prod type tiers, you might want to deploy different WAF rules differently.  For mulitple BU's, this might be different baselines.  For different tier, you might want to restrict non-prod to only corporate/known IP space. You can also use multiple tiers to deploy different AMR versions to non-prod first and before updating production to use the same. See [AMR Versioning]() for more details about why you would want to do this.

    d. **Exception** - Some applications might require exceptions to rules that are a part of your baseline, this could be fundamentally different requirements (such as some applications having country embargo requirements) or exceptions to false positives; there are several ways to handle these exceptions however one of them is separate Firewall Manager security policies.  See [creating exceptions with Firewall Manager in use](../../operationalizing/docs/index.md#creating-exceptions) for more details.


1.  **Enable AWS WAF logging** — Logging is critical for validating that none of the rules you deployed in Count mode would negatively impact legitimate traffic. WAF logs capture matching rules and labels, showing you what would have happened if a given rule had been enforced. See [WAF Logging](../../waf-logging/docs/index.md) for a full comparison of log destinations, pros/cons, cost considerations, and retention guidance.

    When deploying through Firewall Manager, your logging destination options are more limited than standalone WAF — Firewall Manager does not support sending logs to CloudWatch Log Groups. Your options are Amazon S3 or a third-party destination (both via Amazon Data Firehose or CloudWatch Vended Logs for S3).

    - **Amazon S3** is the defacto AWS-native destination for enterprise WAF logging. You can write directly to S3 (which uses CloudWatch Vended Logs under the hood) or route through Amazon Data Firehose. When using Firewall Manager with Firehose, you only need a Firehose delivery stream in each region in the Firewall Manager administrator account — you do not need to create delivery streams in each member account where the web ACL is deployed. The choice between direct S3 and Firehose comes down to cost (based on log volume) and whether you need Firehose features such as data transformation or delivery to additional destinations. See [WAF Logging — Amazon S3](../../waf-logging/docs/index.md#amazon-s3) for details on each option and their cost and technical differences.

    - **Amazon Security Lake** may already be in place if your organization has centralized security data collection. With Security Lake, you do not need to enable WAF logging through Firewall Manager or WAF at all — you enable WAF log collection from your Security Lake configuration instead. See [WAF Logging — Amazon S3](../../waf-logging/docs/index.md#amazon-s3) for more on Security Lake.

    - **Third-party destinations (Splunk, Datadog, SIEM, etc.)** are delivered via Amazon Data Firehose. Firehose also supports writing to a primary destination while writing a secondary copy to S3, which can be useful if you have a compliance need to store logs long term but do not want to keep them in your SIEM. See [WAF Logging — Third-party destinations](../../waf-logging/docs/index.md#third-party-destinations-splunk-datadog-siem-etc) for details.

    Unless you have a business or compliance reason to retain logs longer, configure log retention to cover only the lookback period you need to validate WAF rule impact against your traffic. See [WAF Logging — Log retention](../../waf-logging/docs/index.md#log-retention) for guidance on retention by destination.


1. **Set up dashboards and log queries** — You need to be able to visualize and/or query WAF logs to understand how your traffic interacts with managed rules and custom rules before you can move forward with enforcement decisions. Most enterprise organizations already have a centralized logging and dashboarding strategy in place — WAF logs can fit into that existing approach. If your organization uses a third-party platform (Splunk, Datadog, etc.), those tools provide their own dashboard and query capabilities for WAF log data delivered via Firehose. If you want a dedicated AWS-native solution for WAF log analysis, Amazon QuickSight and Amazon OpenSearch are both strong options that can query WAF logs stored in S3 (via Amazon Athena for QuickSight, or direct ingestion for OpenSearch). See [Monitoring WAF Rules](../../monitoring-waf-rules/docs/index.md) for details on each approach and existing dashboard solutions.


1. **Wait for enough WAF log data to build up** - Let your rules evaluate production traffic for at least a few days; 1-2 weeks is what AWS most commonly recommends especially if coordinating with every application team is not feasible in a timely manner. The goal is to capture a representative sample of traffic across your applications so you can confidently assess what WAF would block once enforced. Different applications or rule types may need different observation periods.  AWS does **NOT** recommend using WAF logs from non-prod alone to determine if it is safe to enable rules in production. If you enable WAF in non-prod first, only use this to move rules in non-prod to block; you should repeat the above steps again in production (i.e. enable WAF rules in count, enable WAF logging) before enforcing WAF rules in production.  Non-production tiers almost always have a limited traffic variety and lower volume than production and is therefore less reliable to identify potential false positives proactively.  At enterprise scale, consider establishing a standard observation period as part of your rollout process so application teams have clear expectations for when enforcement decisions will be made.


1. **Enforce low-risk rules first** — Your primary objective should be to enforce low-effort, high-value rules first. Many rules will have no or low hit rates across your organization — this signifies most applications do not need exceptions for those rules. When a rule does have hits, you need to query by application (hostname) to determine whether the hits are broadly impactful across your organization or isolated to a specific application. If a rule only impacts one or two applications, you can still enforce that rule for everyone else and create targeted exceptions for the affected applications — do not let a single application's conflict hold back enforcement for the rest of your organization. The focus is: move rules to *Block* where it is easiest, exclude specific applications that have conflicts up front, and ensure protection is in place broadly. See [Evaluating Amazon Managed Rules Through WAF Logs](../../monitoring-waf-rules/docs/index.md#evaluating-amazon-managed-rules-through-waf-logs) for exact steps and Athena/CloudWatch Insight Queries for all types of AWS WAF rules. Below is guidance by what is usually your highest value/lowest effort to evaluate first.

    1. Look for any requests matching [IP Reputation](../../aws-managed-rules/docs/index.md#amazon-ip-reputation-list) and [Anonymous IP](../../aws-managed-rules/docs/index.md#anonymous-ip-list) — these are easy to validate because the IPs they match are either known-bad or from anonymizing sources, and you can quickly confirm whether any legitimate traffic across your organization originates from those IPs.  
    
    1. If you are using the [AntiDDoS AMR](../../aws-managed-rules/docs/index.md#antiddos) and have waited at least a few days for WAF logs to build up, this AMR now has a strong baseline. Unless you had a DDoS event since you first implemented it, you likely won't have any meaningful logs. At enterprise scale, ensure you evaluate whether any applications behind your Firewall Manager policy expose API endpoints that cannot handle a Challenge action (e.g., APIs consumed by non-browser clients, IoT devices, or service-to-service calls). These endpoints will fail if the AntiDDoS AMR issues a Challenge, so you need to configure appropriate URIs to exclude from challenges. See the [AntiDDoS AMR](../../aws-managed-rules/docs/index.md#antiddos) section for guidance on handling Challenge in an organization-wide deployment.

    1. Evaluate your rate-based rules and determine appropriate values. At enterprise scale, the goal is to create overarching rate-based rules in your Firewall Manager policy that provide broad protection across all applications — for example, a global per-IP request threshold that catches volumetric abuse. Application teams can layer on their own more granular rate-based rules (e.g., per-endpoint or per-API limits) in their application-level Protection Pack to address application-specific traffic patterns. See [determine a good value for a rate based rule](../../monitoring-waf-rules/docs/index.md#using-amazon-s3-and-athena) for examples of how to get this data point.
    
    1. Evaluate [baseline rules](../../aws-managed-rules/docs/index.md#baseline-rules-for-all-deployments) such as XSS or SQLi protection. Many rules within an Amazon Managed Rule will have no hits or only hits that are clearly malicious — these can be moved to *Block* immediately. For rules that do have hits, query by application to determine if the impacts are isolated. If only specific applications are affected, enforce the rule broadly and create exceptions for those applications. Focus on getting all rules enforced rather than perfecting each exception before moving forward.


6. **Handle rules that impact specific applications** — As you work through enforcement, you will find rules that cause false positives for specific applications. These typically fall into two categories:

    - **App-specific conflicts** — A small number of applications need an exception for a given rule. The rule is enforced broadly, and you create scoped exceptions for the affected applications. This is the most common case.
    - **Org-wide conflicts** — Your application stack broadly does something that is not compatible with a given rule (e.g., your applications pass encoded HTML or structured markup in query strings as part of normal operation, making `CrossSiteScripting_QUERYARGUMENTS` impractical to enforce without many exceptions). See [Amazon Managed Rules](../../aws-managed-rules/docs/index.md) for examples of common rule/application conflicts. In these cases, it may make more sense to leave the rule in *Count* or create broad exceptions. These rules are good candidates to tackle last.

    Before creating exceptions, decide who should be responsible for them. As the Firewall Manager operator, you can arrange rules within security policies to either require the central team to create exceptions or allow application teams to self-service. You can choose the model per rule. See [Creating Exceptions](../../operationalizing/docs/index.md#creating-exceptions) for details on both models.

7. **Create and test exceptions** — Exceptions in an enterprise setup can be created either by the Firewall Manager operator or self-service by application teams using local Protection Pack rules.  
    **Enabling (or not) application team self-service exceptions** — You may decide that some or even all rules deployed as part of your baseline through Firewall Manager should allow application teams the ability to self-service create exceptions. How you achieve this depends on where you place the rule within your security policy and how the enforcement rule is structured.  
    **How Firewall Manager exceptions work** — To create an exception for an AMR, whether as the Firewall Manager operator or an application team, the Firewall Manager security policy rule in question must remain with a *Count* action. This causes the AMR to apply its corresponding label, which downstream rules can then evaluate. Where you place the enforcement rule — and who is allowed to insert exception rules before it — determines who can create exceptions.

    **Firewall Manager operator-only exceptions** — For full details, see [creating exceptions with Firewall Manager in use](../../operationalizing/docs/index.md#creating-exceptions). In short, you create a rule group and place it in the **First Rules** section of your security policy after the AMR in question. Because application team rules within their local Protection Pack cannot evaluate before the security policy's First Rules, they cannot override the enforcement behavior.

    Another option is creating a separate security policy with either different AMRs or different AMR configurations. You must be able to scope the original security policy and the new one to only the relevant resources. This approach works but is generally not recommended for individual applications — it is better suited for broad functional differences such as web applications vs. APIs, or corporate resources vs. public/customer-facing endpoints. The more security policies you maintain, the more places you need to update when applying changes in the future.

    The trade-offs between these two approaches are:

    a) **Single policy with scoped exceptions (Approach 1)**:  
        - Pro: Baseline updates are more straightforward to apply over time since there is a single policy to update.  
        - Con: Exceptions are more complex because they must be scoped to specific applications. If you have many exceptions, this can increase the WCU configuration of your web ACLs, resulting in higher WAF usage costs. Due to a security policy rolls out updates to many endpoints, and the relative complexity of a scoped down exception, there is a higher risk and blast radius of an incorrectly created scoped exception.  

    b) **Multiple policies with different configurations (Approach 2)**:  
        - Pro: Exceptions can be simpler since they do not need to be scoped within a shared rule. You are less likely to drive up WCU consumption because exceptions only exist in the Protection Packs where they are needed.  
        - Con: Baseline updates must be applied to each policy separately, taking care not to remove the unique exceptions or differences between them. Without Shield Advanced, the per-security-policy cost can add up.  

    **Application team self-service exceptions** — For full details, see [creating exceptions with Firewall Manager in use](../../operationalizing/docs/index.md#creating-exceptions). In short, you create a rule group and place it in the **Last Rules** section of your security policy. This makes the default behavior for that AMR rule a *Block* action, but it gives application teams the ability to create an exception within their local Protection Pack that terminates the request with an *Allow* action before the **Last Rules** section is evaluated.

    **When to allow self-service** — Self-service exceptions are not required — you can manage all exceptions centrally and many organizations do. However, in practice most enterprise customers end up allowing self-service for at least specific rules where exceptions are routine and low-risk. There are two common factors to consider when deciding whether to delegate all, some, or none of the WAF rules you deploy through Firewall Manager. First, who is responsible for the security of applications within your organization? Second, what is the operational effort for a central team to manage exceptions across all applications? For any WAF rule that Firewall Manager enforces centrally, application teams cannot create exceptions without involvement from the Firewall Manager operator team. When you are willing to delegate self-service, there are two common patterns:

    a) Determine which rules are critical and must remain centrally controlled, but delegate everything else. For example, if you must comply with a country embargo requirement, you likely do not want application teams to override that rule. On the other hand, if an application legitimately sends request bodies above 8 KB, you could make `SizeRestrictions_BODY` from CommonRuleSet a default block while allowing application teams to self-service create an exception for that rule.

    b) Default with exceptions being handled by the Firewall Manager operator. As exception requests come in, evaluate whether a given rule needs exceptions frequently enough that it makes sense to convert it to self-service. This approach lets you start with tighter central control and relax it incrementally based on actual operational demand.



8. **Decide when not to enforce a rule** — If a rule fundamentally conflicts with how your applications work and cannot reasonably be scoped around with exceptions, leave it in Count mode (if from an AMR) or remove it. For example, if your applications broadly pass encoded HTML or structured markup in query strings as part of normal operation, `CrossSiteScripting_QUERYARGUMENTS` may be impractical to enforce without creating exceptions for nearly every application. In cases like these, leaving the rule in *Count* mode can be a reasonable choice — the labels still appear in your WAF logs so you retain visibility even without enforcement. The [AWS Managed Rules](../../aws-managed-rules/docs/index.md) section calls out several additional examples of common rule/application conflicts. Review those examples to understand when leaving a rule unenforced is the right call. When you choose not to enforce an AMR rule, consider whether a custom rule with application-specific logic can provide equivalent or partial protection for the same threat — for example, a narrower pattern match or a rule scoped to specific endpoints where the threat is most relevant.

9. **Add new rules and AMR versions over time** - Subscribe to [SNS notifications](../../aws-managed-rules/docs/index.md#subscribing-to-sns-notifications) for AMR version updates and set up [CloudWatch alarms for version expiration](../../aws-managed-rules/docs/index.md#monitoring-version-expiration-with-cloudwatch-alarms). When a new version is available, deploy it in Count mode alongside your current version, compare behavior, and promote when you're confident it won't introduce new false positives.



## Non-AWS Deployments

1. **Add CloudFront ahead of non-AWS endpoints**  

AWS WAF can be used to protect any public facing HTTP endpoints.  If an endpoint is not on AWS, just add [Amazon CloudFront]().  This is applicable for other cloud/hosting providers, SAAS products, and even on-prem systems.  The only requirements are that [CloudFront Origin IP]() can connect to your endpoint to establish http and/or https connections to the endpoint.  This could be a server directly exposed to the internet, the VIP of a Firewall or Load Balancers, etc.  

a. If you have/need HTTPS, either create an ACM certificate (recommended) at no cost or import a SSL certificate.  
b. Create a CloudFront distribution with your non-aws endpoint as your Origin, associate your ACM/IAM certificate with that endpoint.  
c. Update DNS to point to CloudFront's distribution name instead of the current value.  
d. Secure the origin to only accept traffic from CloudFront Origin IP (recommended) unless you have some need to *also* allow traffic from something other than CloudFront (less common/usually not recommended)  

From an AWS WAF perspective, once you have Amazon CloudFront ahead of a non-AWS origin, there is no different how you manage or the protection that endpoint received.   

## Creating Exceptions

WAF rules look for patterns in HTTP request fields to determine if a request is malicious. Due to the infinite variety of data that can appear in HTTP requests, there are times when a WAF rule matches a request that is not malicious. This is known as a false positive.

To determine which rule is causing false positives, query your WAF logs to identify the label of the rule that matched the request. For guidance on querying WAF logs, see [Monitoring WAF Rules](../../monitoring-waf-rules/docs/index.md).  

Especially when getting started, it is far more important to focus on getting all/more AMR rules blocking with a broader exception than creating a super precise exception each time you find something requiring one. Many customers overindex on creating an exact exception up front. Once AWS WAF is fully deployed and you have all rules enforced, coming back and fine-tuning exceptions is the recommended path.  Do not let perfect be the enemy of good!

**The Label-Based Exception Pattern**

When a managed rule causes a false positive, the correct approach is the label-based exception pattern. Do **not** write a custom rule that *Allows* the affected requests — *Allow* is a terminating action which results in that requests bypassing all subsequent rules, including other managed rules that might detect a real attack in the same request. Also, in general do **not** use a scope-down statement on the AMR to exclude the affected traffic — scope-down applies to the entire rule group, so excluding a URI from the AMR means *all* rules in that group stop evaluating requests to that URI, removing all of that protection rather than just the single rule causing the false positive.

The pattern works as follows:

1. **Set the managed rule impacting legitimate traffic to Count mode.** In Count mode, the rule still evaluates requests and applies its label, but it no longer blocks. This stops the impact to legitimate traffic immediately while you build the exception.

2. **Write a custom rule below the managed rule group that re-implements the block**, but with exceptions for the specific conditions causing the false positive. This rule matches on the managed rule's label AND excludes the request attributes where the false positive occurs.

**How specific should an exception be?** At minimum, an exception should include the AMR label + the hostname of the affected application. A better exception adds conditions that will always be true when the application makes that specific call — for example, AMR label + hostname + URI path + HTTP method. You can further narrow it with attributes like a specific query parameter, header, or content type if they are *consistently* present. The more specific the exception, the less protection surface you give up — but having all of your rules enforced with broader hostname-level exceptions is usually better than having fewer rules enforced while working out the perfect exception for each false positive. Get rules enforced quickly first, then refine exceptions over time.  

The result is that the managed rule's protection stays enforced for all traffic except the specific cases you've identified as false positives.

**Simple Exception — Single False Positive**

Suppose `CrossSiteScripting_BODY` in the Core Rule Set is triggering on file uploads to `/api/documents`.

Step 1: Set the action for `CrossSiteScripting_BODY` to *Count*. Matched requests are now labeled with `awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body` but not blocked.

Step 2: Add a custom rule below the CRS rule group:

```json
{
  "Name": "enforce-crs-xss-body-except-documents",
  "Priority": 70,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "ByteMatchStatement": {
                "SearchString": "/api/documents",
                "FieldToMatch": { "UriPath": {} },
                "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
                "PositionalConstraint": "STARTS_WITH"
              }
            }
          }
        }
      ]
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "enforce-crs-xss-body-except-documents"
  }
}
```

This blocks all requests that match the XSS signature except those going to `/api/documents`.

**Multiple Exceptions for the Same Rule**

When multiple endpoints or applications require exceptions for the same managed rule, the simple pattern from above (a single enforcement rule with a `NotStatement`) becomes difficult to maintain. Consider a scenario where two different applications behind the same protection pack both need exceptions for `CrossSiteScripting_BODY`: app1.example.com needs an exception for `/uri/1` (a file upload endpoint) and app2.example.com needs an exception for `/api/foo/bar` (an endpoint that accepts XML payloads). If you try to handle both in a single enforcement rule:

```json
{
  "Name": "enforce-crs-xss-body-except-app1-and-app2",
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "OrStatement": {
                "Statements": [
                  {
                    "AndStatement": {
                      "Statements": [
                        {
                          "ByteMatchStatement": {
                            "SearchString": "app1.example.com",
                            "FieldToMatch": { "SingleHeader": { "Name": "host" } },
                            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
                            "PositionalConstraint": "EXACTLY"
                          }
                        },
                        {
                          "ByteMatchStatement": {
                            "SearchString": "/uri/1",
                            "FieldToMatch": { "UriPath": {} },
                            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
                            "PositionalConstraint": "STARTS_WITH"
                          }
                        }
                      ]
                    }
                  },
                  {
                    "AndStatement": {
                      "Statements": [
                        {
                          "ByteMatchStatement": {
                            "SearchString": "app2.example.com",
                            "FieldToMatch": { "SingleHeader": { "Name": "host" } },
                            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
                            "PositionalConstraint": "EXACTLY"
                          }
                        },
                        {
                          "ByteMatchStatement": {
                            "SearchString": "/api/foo/bar",
                            "FieldToMatch": { "UriPath": {} },
                            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
                            "PositionalConstraint": "STARTS_WITH"
                          }
                        }
                      ]
                    }
                  }
                ]
              }
            }
          }
        }
      ]
    }
  },
  "Action": { "Block": {} }
}
```

This will work, but is not easy to follow and cannot be constructed or viewed in the AWS console. When a third application needs an exception — or when an existing application needs a second exception — you must modify this same rule, adding more conditions into the `OrStatement`. Over time, you end up with a single monolithic rule containing dozens of nested conditions. It becomes unclear which conditions belong to which application, why each exception was added, and whether removing one condition might accidentally break another. Auditing or troubleshooting this rule requires tracing through multiple levels of nested logic.

A cleaner approach is to use custom labels to mark each exception independently, then write a single block rule that checks for the managed rule label while excluding any request that carries an exception label. This pattern separates the "what is excepted" logic (individual exception rules) from the "enforce the rule" logic (a single block rule), making both independently readable and auditable.

Using the same scenario — app1.example.com needs an exception for `/uri/1` and app2.example.com needs an exception for `/api/foo/bar`:

Step 1: Set the action for `CrossSiteScripting_BODY` to *Count* (same as above).

Step 2: Add exception rules that label the known false positive patterns. Each exception rule matches on the AMR label plus the specific application and URI causing the false positive, then applies a shared custom label. These rules use *Count* — they don't block or allow anything, they just tag the request:

```json
{
  "Name": "fp-exception-crs-xss-body-app1-uri1",
  "Priority": 70,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "app1.example.com",
            "FieldToMatch": { "SingleHeader": { "Name": "host" } },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "EXACTLY"
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "/uri/1",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "STARTS_WITH"
          }
        }
      ]
    }
  },
  "Action": {
    "Count": {}
  },
  "RuleLabels": [
    { "Name": "custom:fp-exception:crs-xss-body" }
  ],
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "fp-exception-crs-xss-body-app1-uri1"
  }
}
```

```json
{
  "Name": "fp-exception-crs-xss-body-app2-foo-bar",
  "Priority": 71,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "app2.example.com",
            "FieldToMatch": { "SingleHeader": { "Name": "host" } },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "EXACTLY"
          }
        },
        {
          "ByteMatchStatement": {
            "SearchString": "/api/foo/bar",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "STARTS_WITH"
          }
        }
      ]
    }
  },
  "Action": {
    "Count": {}
  },
  "RuleLabels": [
    { "Name": "custom:fp-exception:crs-xss-body" }
  ],
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "fp-exception-crs-xss-body-app2-foo-bar"
  }
}
```

Step 3: Add a single block rule that enforces the managed rule for everything that was NOT marked as an exception. This rule matches requests that have the managed rule label but do NOT have the exception label:

```json
{
  "Name": "enforce-crs-xss-body",
  "Priority": 72,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "LabelMatchStatement": {
                "Scope": "LABEL",
                "Key": "custom:fp-exception:crs-xss-body"
              }
            }
          }
        }
      ]
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "enforce-crs-xss-body"
  }
}
```

**Why this pattern works better:**

- **Readability** — Each exception rule has a descriptive name and a clear, self-contained condition. When reviewing the protection pack, you can immediately understand what each exception does and why it exists without parsing a deeply nested compound statement.
- **Scalability** — When a new application or endpoint needs an exception for the same rule, you add a single new exception rule that applies the same custom label. The enforcement rule does not change. There is no risk of breaking existing exceptions when adding new ones.
- **Auditability** — WAF logs show which custom labels were applied to each request. If a request was not blocked because of an exception, the log record includes `custom:fp-exception:crs-xss-body`, making it straightforward to trace why the enforcement rule did not fire.
- **Independence** — In a Firewall Manager environment, different application teams can each add their own exception rules independently. They all apply the same custom label, so the central enforcement rule works without modification regardless of how many teams have exceptions.
- **Avoids multiple FMS security policies** — Without this pattern, each application needing a different exception for the same rule might require its own Firewall Manager security policy with a different AMR configuration. With the custom label pattern, a single security policy can serve all applications — the Firewall Manager operator adds scoped exception rules (one per application) to the same policy, keeping management centralized and avoiding the operational overhead of maintaining multiple policies just for exception differences.

**Creating Exceptions with FMS in Use**

When AWS Firewall Manager manages your WAF policies, the same label-based exception pattern applies. The key organizational decision is: **who is responsible for creating exceptions?**

There are two models, and you can use both simultaneously for different rules within the same security policy:

- **Centrally managed exceptions** — The Firewall Manager operator creates all exceptions. Application teams submit requests when a rule impacts their legitimate traffic, and the central team reviews and implements the exception in the security policy. This gives the security team full visibility and control over every exception.  
- **Application team self-service exceptions** — Application teams create their own exceptions in their local Protection Pack rules. The central team provides the enforcement structure that allows this, but individual teams can act independently without waiting for a central team to process their request.

**Which model to use is an organizational decision**, not a technical one. It depends on:

- **Who owns application security?** If a central security team is accountable for the WAF posture across the organization, centrally managed exceptions provide tighter control and audit. If application teams own the security of their own services, self-service gives them the autonomy to move quickly without creating bottlenecks.
- **What is the operational cost of centralized exception management?** In a large organization with many applications, routing every exception through a central team can become a bottleneck. If the central team is spending significant time on routine exceptions, delegating those specific rules to self-service reduces operational overhead.
- **What is the risk tolerance for individual rules?** Some rules enforce compliance requirements (geographic restrictions, embargo enforcement) where you do not want any team to bypass them independently. Other rules are general-purpose protections where a scoped exception carries minimal risk.
- **Is the rule a security requirement or a good default?** Not all rules in an AMR represent a strict security requirement. Some are good defaults that provide defense-in-depth but are expected to need exceptions for certain application patterns. For example, `SizeRestrictions_BODY` (which blocks request bodies over 8 KB) is a sensible default for most endpoints, but any application with file uploads or large JSON payloads will legitimately need an exception. Rules like this are strong candidates for self-service — the exception is routine, the risk of granting it is low, and requiring central approval adds overhead without meaningfully improving security posture.

**You can mix and match per rule.** A geographic restriction rule might require central approval while `SizeRestrictions_BODY` or `CrossSiteScripting_BODY` exceptions can be self-service. You can also change the model over time — start with everything going through the Firewall Manager operator and convert specific rules to self-service as you observe which rules generate frequent exception requests. This lets you begin with tighter central control and relax it incrementally based on actual operational demand.

The mechanics below show how to implement each model and where exceptions are placed within a Firewall Manager security policy or Protection Pack.

**Creating Exceptions in First Rule Groups (FMS Operator)**

The standard pattern for centrally managed exceptions is to place the AMR, exception rules, and enforcement rule all within **First rule groups**. The structure is:

1. The AMR rule group with the relevant rule set to *Count* — this evaluates traffic and applies the AMR label without blocking.
2. Exception rules — these match on the AMR label + the specific conditions causing the false positive and apply a custom exception label.
3. The enforcement rule — this blocks requests with the AMR label that do NOT have the exception label.

Because all three components are in first rule groups, application teams cannot modify or override this behavior. When an application team identifies that a rule is impacting their legitimate traffic, they request an exception from the Firewall Manager operator. The operator creates the scoped exception rule and places it between the AMR and the enforcement rule. The pattern is identical to [multiple exceptions for the same rule](#creating-exceptions) — exception rules apply a custom label, and the enforcement rule skips the block when that label is present.

**Example: Firewall Manager operator creates an exception for an application team**

The AMR (CommonRuleSet with `CrossSiteScripting_BODY` set to *Count*) is already in first rule groups and applying labels. The operator adds this exception rule in first rule groups, before the enforcement rule:

```json
{
  "Name": "fp-exception-crs-xss-body-app1-uploads",
  "Priority": 5,
  "Action": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "fp-exception-crs-xss-body-app1-uploads"
  },
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
          }
        },
        {
          "ByteMatchStatement": {
            "FieldToMatch": {
              "SingleHeader": {
                "Name": "host"
              }
            },
            "PositionalConstraint": "EXACTLY",
            "SearchString": "app1.example.com",
            "TextTransformations": [
              { "Priority": 0, "Type": "NONE" }
            ]
          }
        },
        {
          "ByteMatchStatement": {
            "FieldToMatch": {
              "UriPath": {}
            },
            "PositionalConstraint": "STARTS_WITH",
            "SearchString": "/uri/1",
            "TextTransformations": [
              { "Priority": 0, "Type": "NONE" }
            ]
          }
        }
      ]
    }
  },
  "RuleLabels": [
    { "Name": "custom:fp-exception:crs-xss-body" }
  ]
}
```

The enforcement rule (also in first rule groups, after all exception rules):

```json
{
  "Name": "enforce-crs-xss-body",
  "Priority": 10,
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "enforce-crs-xss-body"
  },
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "LabelMatchStatement": {
            "Scope": "LABEL",
            "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "LabelMatchStatement": {
                "Scope": "LABEL",
                "Key": "custom:fp-exception:crs-xss-body"
              }
            }
          }
        }
      ]
    }
  }
}
```

This model is appropriate for rules where the security team requires visibility and approval before any exception is granted — for example, rules that enforce compliance requirements, or rules where an overly broad exception could create meaningful security risk. See [Centrally Managed Exceptions — Full FMS Security Policy](#creating-exceptions) for a complete example showing how all rules fit together.

**Self-Service Exceptions (Application Team)**

If you decide that application teams should be able to create their own exceptions for a given rule, the enforcement rule must be placed in **Last rule groups** (`postProcessRuleGroups`) so that the application team's local Protection Pack rules evaluate before enforcement. The AMR remains in first rule groups (in Count mode, applying labels).

Labels from local Protection Pack rules do **not** carry over to `postProcessRuleGroups`. This means the custom label pattern used in the centrally managed model will not work here. Instead, the application team creates an *Allow* rule in their local Protection Pack that terminates the request before the enforcement rule in last rule groups evaluates.

The evaluation flow is:

1. **First rule groups**: AMR evaluates and applies label.
2. **Local Protection Pack**: Application team's exception rule matches on the false positive condition and terminates with *Allow*.
3. **Last rule groups**: Enforcement rule blocks any remaining request with the AMR label. Requests already terminated by *Allow* in step 2 never reach this rule.

The enforcement rule in **Last rule groups** simply blocks when the AMR label is present:

```json
{
  "Name": "enforce-crs-xss-body",
  "Priority": 1,
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "enforce-crs-xss-body"
  },
  "Statement": {
    "LabelMatchStatement": {
      "Scope": "LABEL",
      "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body"
    }
  }
}
```

The application team's exception rule in their **local Protection Pack** uses *Allow* scoped to the specific false positive conditions (Host name and URI):

```json
{
  "Name": "allow-crs-xss-body-uri1",
  "Priority": 100,
  "Action": {
    "Allow": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "allow-crs-xss-body-uri1"
  },
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "FieldToMatch": {
              "SingleHeader": {
                "Name": "host"
              }
            },
            "PositionalConstraint": "EXACTLY",
            "SearchString": "app1.example.com",
            "TextTransformations": [
              { "Priority": 0, "Type": "NONE" }
            ]
          }
        },
        {
          "ByteMatchStatement": {
            "FieldToMatch": {
              "UriPath": {}
            },
            "PositionalConstraint": "STARTS_WITH",
            "SearchString": "/uri/1",
            "TextTransformations": [
              { "Priority": 0, "Type": "NONE" }
            ]
          }
        }
      ]
    }
  }
}
```

Using *Allow* here is acceptable because it is scoped to only the specific false positive condition (e.g. a particular URI path) — the bypass is narrow and intentional. If no application team has created an exception rule, all requests that match the enforcement rule in last rule groups are blocked. See [Self-Service Exceptions — Full FMS Security Policy](#creating-exceptions) for a complete example.

**Transitioning a Rule from Central to Self-Service**

To convert a rule from centrally managed to self-service, move the enforcement rule from **First rule groups** to **Last rule groups** and simplify it to block solely on the AMR label (removing the `NotStatement` for the custom exception label). The AMR stays in first rule groups (still in Count mode, still applying labels). Application teams can now insert *Allow* rules in their local Protection Pack to terminate specific false positive requests before the enforcement rule evaluates.

Any existing exception rules that the Firewall Manager operator previously created in first rule groups can be removed, as the self-service model uses a different mechanism (terminating *Allow* in local rules rather than custom labels in first rule groups).

**Complete Protection Pack Examples**

The following are full examples showing how all the pieces fit together as a Firewall Manager security policy. These use the same scenario from the examples above: CommonRuleSet with `CrossSiteScripting_BODY` set to *Count*, with app1.example.com needing an exception for `/uri/1` and app2.example.com needing an exception for `/api/foo/bar`. The examples also include a geographic restriction (embargo) rule that is centrally enforced without self-service.

**Note:** Firewall Manager security policies cannot contain inline rules — they reference rule groups. For readability, the examples below show the rules inline within the `preProcessRuleGroups` and `postProcessRuleGroups` sections. In practice, these custom rules would be defined in separate rule groups and referenced by ARN in the security policy.

**Centrally Managed Exceptions — Full FMS Security Policy**

In this example, the AMR, exception rules, and enforcement rule are all in `preProcessRuleGroups`. Application teams cannot create their own exceptions — all exceptions are managed by the Firewall Manager operator.

```yaml
preProcessRuleGroups:

  # 1. CommonRuleSet with CrossSiteScripting_BODY set to Count (applies label, does not block)
  - managedRuleGroupName: AWSManagedRulesCommonRuleSet
    ruleActionOverrides:
      - name: CrossSiteScripting_BODY
        actionToUse: Count

  # 2. Geographic embargo — centrally enforced, no exceptions allowed
  - Name: geo-block-embargo
    Statement:
      GeoMatchStatement:
        CountryCodes:
          - CU
          - IR
          - KP
          - SY
    Action: Block

  # 3. Exception for app1 — labels the false positive so enforcement rule skips it
  - Name: fp-exception-crs-xss-body-app1-uri1
    Statement:
      AndStatement:
        - LabelMatchStatement:
            Scope: LABEL
            Key: awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body
        - ByteMatchStatement:
            FieldToMatch:
              SingleHeader:
                Name: host
            PositionalConstraint: EXACTLY
            SearchString: app1.example.com
            TextTransformations:
              - Priority: 0
                Type: NONE
        - ByteMatchStatement:
            FieldToMatch:
              UriPath: {}
            PositionalConstraint: STARTS_WITH
            SearchString: /uri/1
            TextTransformations:
              - Priority: 0
                Type: NONE
    Action: Count
    RuleLabels:
      - Name: custom:fp-exception:crs-xss-body

  # 4. Exception for app2 — labels the false positive so enforcement rule skips it
  - Name: fp-exception-crs-xss-body-app2-foo-bar
    Statement:
      AndStatement:
        - LabelMatchStatement:
            Scope: LABEL
            Key: awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body
        - ByteMatchStatement:
            FieldToMatch:
              SingleHeader:
                Name: host
            PositionalConstraint: EXACTLY
            SearchString: app2.example.com
            TextTransformations:
              - Priority: 0
                Type: NONE
        - ByteMatchStatement:
            FieldToMatch:
              UriPath: {}
            PositionalConstraint: EXACTLY
            SearchString: /api/foo/bar
            TextTransformations:
              - Priority: 0
                Type: NONE
    Action: Count
    RuleLabels:
      - Name: custom:fp-exception:crs-xss-body

  # 5. Enforcement — blocks XSS matches that were NOT marked as exceptions
  - Name: enforce-crs-xss-body
    Statement:
      AndStatement:
        - LabelMatchStatement:
            Scope: LABEL
            Key: awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body
        - NotStatement:
            Statement:
              LabelMatchStatement:
                Scope: LABEL
                Key: custom:fp-exception:crs-xss-body
    Action: Block

postProcessRuleGroups: []
```

**Self-Service Exceptions — Full FMS Security Policy**

In this example, the AMR and the embargo rule are in `preProcessRuleGroups`, and the `CrossSiteScripting_BODY` enforcement rule is in `postProcessRuleGroups`. This allows application teams to create their own XSS exceptions in their local Protection Pack, while the embargo rule remains centrally enforced without self-service.

The following shows what the full Protection Pack looks like (as you would see from `GetWebACL`) with the FMS-managed rules and the application team's local rule together. Rules are listed in evaluation order:

```yaml
preProcessRuleGroups:

  # 1. CommonRuleSet with CrossSiteScripting_BODY set to Count (applies label, does not block)
  - managedRuleGroupName: AWSManagedRulesCommonRuleSet
    ruleActionOverrides:
      - name: CrossSiteScripting_BODY
        actionToUse: Count

  # 2. Geographic embargo — centrally enforced, no self-service exceptions possible
  - Name: geo-block-embargo
    Statement:
      GeoMatchStatement:
        CountryCodes:
          - CU
          - IR
          - KP
          - SY
    Action: Block

# Application team's local Protection Pack rules (evaluated between pre and post)
Rules:

  # 3. Exception — Allow terminates the request before postProcess enforcement evaluates.
  #    Labels from local rules do NOT carry to postProcessRuleGroups, so Allow is required.
  - Name: allow-crs-xss-body-uri1
    Statement:
      AndStatement:
        - ByteMatchStatement:
            FieldToMatch:
              SingleHeader:
                Name: host
            PositionalConstraint: EXACTLY
            SearchString: app1.example.com
            TextTransformations:
              - Priority: 0
                Type: NONE
        - ByteMatchStatement:
            FieldToMatch:
              UriPath: {}
            PositionalConstraint: STARTS_WITH
            SearchString: /uri/1
            TextTransformations:
              - Priority: 0
                Type: NONE
    Action: Allow

postProcessRuleGroups:

  # 4. Enforcement — blocks any request with the XSS label.
  #    If the app team's Allow rule matched above, the request never reaches here.
  - Name: enforce-crs-xss-body
    Statement:
      LabelMatchStatement:
        Scope: LABEL
        Key: awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body
    Action: Block
```

This demonstrates how you can mix models within the same policy: the embargo rule is centrally enforced in `preProcessRuleGroups` (no self-service), while the XSS enforcement rule is in `postProcessRuleGroups` (self-service exceptions allowed). Note that in the self-service model, application teams use *Allow* as the exception mechanism — this is acceptable because the *Allow* is scoped to a specific host + URI combination, limiting the bypass to a narrow set of requests.

## Discovering Existing WAF Usage Across Your Organization

This section is actively being updated.  Please come back soon or reference public docs for AWS WAF in the meantime.  