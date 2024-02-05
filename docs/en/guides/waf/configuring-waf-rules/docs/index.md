# Configuring WAF Rules

## Understanding terminating actions

One of the most important concepts to understand is that *Allow* and *Block* are [terminating actions](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-actions.html). When a rule matches and has one of these actions, no more rules are evaluated. Be cautious when using the *Allow* action, especially near the top of your web ACL. A rule with the *Allow* action will allow a request even if a subsequent rule would have blocked it (a false negative).

## General approach for selecting rules

This section outlines a general thought process for selecting WAF rules. Assuming your web ACL's default action is *Allow*, it makes sense to block as many unwanted requests as possible near the top of the web ACL. Put rules toward the top that apply to the widest range of unwanted traffic. Put rules toward the end that have narrow criteria or have per-request charges. Rather than prescribing an exact ordering of rules, they are grouped into top, middle, and bottom categories.

### Rules toward the top

* [Rate-based rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html) for blocking request floods
* [Amazon IP reputation list](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html#aws-managed-rule-groups-ip-rep-amazon) managed rule group
* [Anonymous IP list](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html#aws-managed-rule-groups-ip-rep-anonymous) managed rule group
* [Geographic-based rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-geo-match.html) for blocking or rate-limiting requests based on region of origin

### Rules toward the middle

* Custom rules that validate expected HTTP request fields (user agents, headers)
* [AWS Core rule set](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html#aws-managed-rule-groups-baseline-crs) to block OWASP Top 10 threats
* [SQL database](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html#aws-managed-rule-groups-use-case-sql-db) managed rule group (only for applications that use SQL)
* [Known bad inputs](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html#aws-managed-rule-groups-baseline-known-bad-inputs) managed rule group (only for applications that use Java)

### Rules toward the bottom

* [Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html) rule group (with scope-down statement to limit applicability)
* [Fraud Control account takeover prevention](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html) rule group (with scope-down statement to limit applicability)

## Web ACL capacity units (WCU)

Each web ACL has a capacity measured in [web ACL capacity units](https://docs.aws.amazon.com/waf/latest/developerguide/aws-waf-capacity-units.html) (WCU). This capacity is used by rules and rule groups you add to the web ACL. By default the capacity is 1,500 WCU.

To avoid unecessarily reaching this limit, make sure the web ACL only includes rules that are required by the protected applications. You can now use up to 5,000 WCU per web ACL without requesting a limit increase, but there are additional charges that come into play.

## Selecting the default action for your web ACL

If there are no matching rules in the web ACL that have a terminating action, the web ACL applies a [default action](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-default-action.html). There are two possible default actions: *Allow* and *Block*. Most customers set the default action to *Allow*.

If you want to allow most requests and only block attackers, use the *Allow* default action. For example, you might only want to block requests with malicious fields or that originate from an untrusted source IP or geography.

If you want to allow specific requests and block everything else, use the *Block* default action. For example, you might only want to allow requests from a specific IP range or requests that contain specific values.

## Rate-based rules

WAF [rate-based rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html) count requests from up to 10,000 source IPs (per rate-based rule) and block requests when a client exceeds a threshold measured over a trailing 5-minute window. This is an often overlooked feature of AWS WAF, yet it's one of the most simple and valuable rules you can add to web ACLs. A majority of customers should have at least one rate-based rule in every web ACL.

See the blog [The three most important AWS WAF rate-based rules](https://aws.amazon.com/blogs/security/three-most-important-aws-waf-rate-based-rules/) for a full explanation of how to leverage rate-based rules. In summary, the three most important rate-based rules are:

1. A blanket rate-based rule that applies to all requests.
2. URI-specific rate-based rules to protect specific parts of an application with more restrictive limits.
3. Rate-based rules that limit the rate of requests from known malicious source IPs.

AWS Shield Advanced provides DDoS cost protection to safeguard against scaling charges resulting from DDoS-related usage spikes on ALBs and CloudFront distributions protected by Shield Advanced. You can [request a credit](https://docs.aws.amazon.com/waf/latest/developerguide/request-refund.html) for charges through AWS Support. To be eligible to receive a credit for CloudFront and ALB protected resources, you must have associated an AWS WAF web ACL and implemented a rate-based rule in the web ACL.

## Using rule labels

A [label](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html) is metadata added to a web request by a matching rule. Use labels to make the results of one rule available to other rules. Labels can be inspected by other rules lower (not above) in the same web ACL by using the [label match statement](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-label-match.html).

Labels added by rules with terminating actions cannot be inspected by other rules. These labels are included in [WAF log records](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html) and [CloudWatch metric dimensions](https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics) so you can analyze and visualize the behavior of terminating rules.

Labels are commonly used to augment the behavior of a managed rule. The first step is to switch the managed rule's action from *Block* to *Count*. Then create another rule below that matches on managed rule's label along with other conditions that determine if the request should be blocked.

See [How to customize behavior of AWS Managed Rules for AWS WAF](https://aws.amazon.com/blogs/security/how-to-customize-behavior-of-aws-managed-rules-for-aws-waf/) for more information on using labels.

## Using managed rule groups

### Managed rule group providers

[AWS managed rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html) are maintained by Amazon's threat research team. These rules do not have a per-request fee, with the exception of Bot Control and Fraud Control rule groups. See above for a recommendation on which AWS managed rule groups are suitable for most customers.

You can subscribe to [managed rules provided by AWS partners](https://docs.aws.amazon.com/waf/latest/developerguide/marketplace-managed-rule-groups.html) using AWS Marketplace. These rule groups run in your WAF web ACL, but there are additional fees that come into play.

To use an AWS Marketplace rule group in a Firewall Manager policy, each account in your organization must first subscribe to that rule group.

### Versioning

A managed rule group provider might need to update their rules. For rule groups that support [versioning](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-rule-groups-versioning.html), you can choose to let the provider manage which version you use (default) or you can manage the version setting yourself (static).

When using the default version, [subscribe to notifications](https://docs.aws.amazon.com/waf/latest/developerguide/waf-using-managed-rule-groups-sns-topic.html) of new versions. This informs you about upcoming changes to give you time to test them before they become the new default.

When using a static version, it's also important to subscribe to notifications so you are aware of new static versions. Keep your version up to date to ensure your applications have the most current protections. [Track version expiration](https://docs.aws.amazon.com/waf/latest/developerguide/waf-using-managed-rule-groups-expiration.html) to make sure you aren't forced to upgrade before you test.

See [How to customize behavior of AWS Managed Rules for AWS WAF](https://aws.amazon.com/blogs/security/how-to-customize-behavior-of-aws-managed-rules-for-aws-waf/) for more information on version management.

The AWS-managed [IP reputation rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-ip-rep.html) do not use versions. These rule groups are updated frequently based on the evolution of Amazon threat intelligence.

### Scope-down statements

A [scope-down statement](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-scope-down-statements.html) is a statement that you add inside a managed rule group or a rate-based rule to narrow the set of requests that are evaluated.

Use scope-down statements on advanced managed rule groups like Bot Control and Fraud Protection to specify which requests should be evaluated by the rule group. This is an effective way of optimizing your cost since you will not be charged for requests that are excluded by the scope-down statement.

See [How to customize behavior of AWS Managed Rules for AWS WAF](https://aws.amazon.com/blogs/security/how-to-customize-behavior-of-aws-managed-rules-for-aws-waf/) for more information on scope-down statements.

### Handling false positives

WAF rules are often looking for patterns that occur in HTTP request fields to determine if the request is malicious. Due to the infinite variety of data that might appear in HTTP requests, there are times when a WAF rule blocks a request that is not malicious. This is known as a false positive.

To determine which rule is causing false positives, query your WAF logs to identify the label of the rule that blocked the request. Since this rule is incorrectly blocking requests, your instinct might be to write a rule that allows these requests. That turns out to be problematic because _Allow_ is a terminating action, and your rule might allow requests that should have been blocked for other reasons.

Follow these two steps to correct false positives caused by a managed rule. As an example, suppose the `Log4JRCE_BODY` rule inside the AWS managed rule group for [Known bad inputs](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html#aws-managed-rule-groups-baseline-known-bad-inputs) is causing false positives for the URI `/reports`.

1. Switch the action for `Log4JRCE_BODY` from _Block_ to _Count_. Requests matched by this rule will be labeled with `awswaf:managed:aws:known-bad-inputs:Log4JRCE_Body`.
2. Write a rule below the managed rule group that has this behavior:

```
IF Label = awswaf:managed:aws:known-bad-inputs:Log4JRCE_Body AND
   URI != "/reports"
THEN Block
```

Keep in mind that if you put a managed rule in _Count_ mode then you must write a corresponding rule that blocks requests labeled by the managed rule. Otherwise, you will end up with false negatives.

See [How to customize behavior of AWS Managed Rules for AWS WAF](https://aws.amazon.com/blogs/security/how-to-customize-behavior-of-aws-managed-rules-for-aws-waf/) for more information on handling false positives.

## Handling large HTTP requests

AWS WAF has limits on the size and number of HTTP request components it can inspect. See [Handling oversize web request components in AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html) for more details. Here is a summary of the size limits.

* AWS WAF can inspect request bodies up to 64 KB for CloudFront web ACLs. For regional web ACLs, AWS WAF can inspect bodies up to 8 KB.
* For all web ACLs, AWS WAF can inspect 8 KB of headers or cookies or the first 200 headers or cookies, whichever limit comes first.

If you need to allow some oversized requests, add rules to explicitly *Allow* only those requests. Prioritize those rules so that they run before any other rules in the web ACL that inspect the same components. Here is an example that allows oversized requests only for a specific URI and HTTP method.

```
IF Body size > 8,192 (with oversize handling set to Match) AND
   URI path starts with "/upload" AND
   HTTP method exactly matches "POST"
THEN Allow
```

For all other requests, add a rule to inspect components with size limits and *Block* requests that go over the limit. This prevents non-inspected request content from reaching your application.

```
IF Body size > 8,192 (with oversize handling set to Match) OR
   All headers size > 8,192 (with oversize handling set to Match)
THEN Block
```
