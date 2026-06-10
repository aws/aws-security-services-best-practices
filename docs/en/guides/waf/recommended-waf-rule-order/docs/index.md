# Recommended WAF Rule Order

Rule evaluation order is one of the most impactful decisions you make when configuring an AWS WAF protection pack. Rules are evaluated in the order they appear, and [terminating actions](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-actions.html) (*Allow* and *Block*) stop evaluation immediately. Placing rules in the wrong order can cause false positives, false negatives, or unnecessary cost. This section provides a recommended ordering for all common WAF rule types and explains the reasoning behind each position.

## Understanding Terminating Actions

One of the most important concepts to understand is that actions other than *Count* can be [terminating](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-rule-actions.html). *Allow* and *Block* are always terminating — when a rule matches with either action, no further rules are evaluated. *CAPTCHA* and *Challenge* are conditionally terminating — they terminate the request only if the client cannot successfully complete them. Be cautious when using the *Allow* action, especially near the top of your protection pack. A rule with the *Allow* action will allow a request even if a subsequent rule would have blocked it.


When a protection pack matches on a rule with a terminating action, rules afterward the terminate are never evaluated.  This means:
    * Paid rules (Bot Control, Fraud, 3P rules) do not incur usage based costs
    * Labels from those rules are not added; this is relevant for WAF logs and WAF log filtering.  

Rule order is also critical when using labels from one rule in other.  Labels are only added when a request passes through them.  For exmaple, a custom rule using a label from an AMR must come *AFTER* that AMR, this is common for handling [False Positives](../../operationalizing/docs/index.md#creating-exceptions)

## Recommended Rule Evaluation Order

Assuming your protection pack's default action is *Allow*, it makes sense to block as many unwanted requests as possible near the top of the protection pack. Put rules toward the top that apply to the widest range of unwanted traffic. Put rules toward the end that have narrow criteria or have per-request charges.

The high level recommendation is:  

**First Group:**

- [Anti-DDoS](../../aws-managed-rules/docs/index.md#anti-ddos)

**Second Group:**

- [Explicit Allow/Block by IP lists](../../custom-rules/docs/index.md#ip-allowlists-and-denylists)
- [Rate Based rules](../../custom-rules/docs/index.md#rate-based-rules)
- [Geo Blocking rules](../../custom-rules/docs/index.md#geographic-restrictions)
- [IP reputation/anonymous](../../aws-managed-rules/docs/index.md#amazon-ip-reputation-list)

**Third Group:**

- [Free Amazon Managed Rules](../../aws-managed-rules/docs/index.md#baseline-rules-for-all-deployments)

**Fourth Group:**

- [False Positive exceptions](../../operationalizing/docs/index.md#creating-exceptions)
- Application specific rules

**Last Group:**

- [Paid AMRs](../../bot-management/docs/index.md) (Bot Control, [Fraud Control](../../fraud-prevention/docs/index.md))
- [Partner Rules](../../aws-managed-rules/docs/index.md#managed-rules-from-aws-partners)  

The following table provides a more detailed recommendation of rule order.  

| Priority | Rule Type | Action | Rationale |
|----------|-----------|--------|-----------|
|  1 | Shield Advanced Anti-DDoS AMR | Varies | Layer 7 DDoS Detection and Mitigation |
|  2 | IP Allow Lists | Allow | Explicit IPs that should never be blocked except by the Anti-DDoS AMR, use sparingly or not at all |
|  3 | IP Block lists | Block | Explicit IPs that should be blocked.  Common for custom threat intelligence |
|  4 | Geo Blocking Rules | Block | Countries that should not be able to access this endpoint (either a list of blocked countries, or a list of not (allowed country list))|
|  5 | Rate-Based Rules (Blanket) | Block | High bar rate limit usually based on client IP |
|  6 | Rate Based Rules (Scoped) | Block | Common examples include HTTP Method scoped or expensive URI |
|  7 | IP Reputation/Anonmyous Rules | Block | IPs that are known malicious or from obviscated sourced (VPN, cloud providers) |
|  8 | AWS Managed Baseline Rules (CRS, Known Bad Inputs) | Block | Broad threat coverage for all applications |
|  9 | AWS Managed Use-Case Rules (SQL Database, etc.) | Block | Application-specific threat coverage |
| 10 | False Positive Exception and APpplication Specific Rules | Block |  False Positive handling or application specific protection |
| 11 | Partner Manged Rules | Block | Varried types of protection.  Placing after free usage rules to reduce cost. |
| 11 | Bot Control | Block/Challenge | Detect and manage bot traffic (with scope-down) |
| 13 | Fraud Control (ATP, ACFP) | Block | Protect login and account creation pages (with scope-down) |


## Reasoning Behind the Order

The recommended order follows a general principle: **block the most traffic, at the lowest cost, as early as possible**.

- **Anti-DDoS goes first** because it needs to see all traffic to detect and mitigate application layer DDoS attacks. Placing it first ensures DDoS mitigation is applied before any other rule can terminate evaluation. Even IP allowlists should not bypass DDoS detection.
- **IP allow/block lists come next** because they are explicit, low-cost decisions. Allowed IPs skip all downstream evaluation (and cost), and blocked IPs are dropped immediately. Keep allowlists minimal — see [Custom Rules](../../custom-rules/docs/index.md) for why broad IP allowlists can be counterproductive.
- **Rate-based rules (blanket and scoped) follow** because they stop volumetric abuse early before it consumes capacity in more expensive downstream rules. A blanket rate limit catches broad floods; scoped rate limits protect specific expensive or sensitive URIs.
- **Geo blocking rules** remove traffic from regions that have no legitimate reason to access your application. Placing them before IP reputation avoids spending cycles evaluating traffic that will be blocked by geography anyway.
- **IP reputation and anonymous IP rules** drop traffic from known-bad or obfuscated sources. These are inexpensive to evaluate and reduce the volume of requests that reach content-inspection rules.
- **Free AWS Managed Rules (CRS, Known Bad Inputs, use-case rules)** provide broad and application-specific threat coverage. They sit in the middle because traffic that made it past rate limits, geo blocks, and IP reputation is more likely to be legitimate — but still needs content inspection.
- **False positive exceptions and application-specific rules** come after managed rules because they depend on labels generated by those managed rules. These rules re-implement blocks with exceptions for known false positive patterns.
- **Partner managed rules** are placed after free rules to reduce per-request cost — traffic already blocked by upstream rules never reaches partner rule evaluation.
- **Bot Control and Fraud Control go last** because they have the highest per-request charges. Placing them after all other rules ensures only traffic that survived every other filter is evaluated, minimizing cost. Scope-down statements further limit which requests these rule groups inspect.

## Scenarios Where Order May Vary

The recommended order above works well for most web applications. However, certain application profiles may benefit from adjustments.

<!-- TODO: Expand each scenario with specific guidance and examples -->

### Heavy API Traffic vs. Static Content Sites

Applications that serve primarily API traffic may benefit from placing custom validation rules (e.g., required API keys, expected content types) higher in the evaluation order. Static content sites may not need use-case specific managed rules at all.

### Applications Requiring Strict Geographic Restrictions

If your application is strictly limited to specific geographies, consider moving geographic-based rules above IP reputation rules. This ensures that traffic from disallowed regions is blocked before any other evaluation occurs.


## Rate-Based Rules

WAF [rate-based rules](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-rate-based.html) count requests from up to 10,000 source IPs (per rate-based rule) and block requests when a client exceeds a threshold measured over a trailing 5-minute window. This is an often overlooked feature of AWS WAF, yet it's one of the most simple and valuable rules you can add to protection packs. A majority of customers should have at least one rate-based rule in every protection pack.

See the blog [The three most important AWS WAF rate-based rules](https://aws.amazon.com/blogs/security/three-most-important-aws-waf-rate-based-rules/) for a full explanation of how to leverage rate-based rules. In summary, the three most important rate-based rules are:

1. **A blanket rate-based rule** that applies to all requests. This is the rule recommended at position 1 in the evaluation order above.
2. **URI-specific rate-based rules** to protect specific parts of an application with more restrictive limits. These are the rules recommended at position 8 in the evaluation order above.
3. **Rate-based rules for known malicious source IPs** that limit the rate of requests from IPs already identified as malicious by other rules or threat intelligence.
