# WAF Cost

AWS WAF has three core costs plus specific paid premium features and managed rules available a-la-carte as well as bundled.  This section explains how those dimensions interact in practice so you can estimate and optimize your WAF spend. For current pricing numbers, refer to the [AWS WAF Pricing page](https://aws.amazon.com/waf/pricing/).

To best explain WAF costs, this document will use a **core scenario** starting with just standard WAF costs.  For each section for a paid premium feature or managaed rule, it provides examples of that feature as well as incorporating that feature into the **core scenario**.  

**Core scenario**  
One (1) Protection pack   
Five (5) custom rules included in the Protection Pack  
Amazon Managed Rules included in the protection pack:  
  - Common Rule Set (CRS)  
  - Known Bad Inputs (KBI)  
Ten million (10,000,000) requests  

## Cost Dimensions

### Standard WAF Costs

Every WAF deployment has three base cost components:

- **Protection pack (Web ACL)** -  A monthly fixed cost per protection pack. Each protection pack is associated with one or more resources (CloudFront distributions, ALBs, API Gateways, etc.). You pay per protection pack, not per resource associated to it.  
- **Rules** - A Monthly cost per rule in the protection pack. Each rule group (whether custom or managed) counts as a single rule for billing purposes regardless of how many rules are inside the rule group. A protection pack with 3 custom rules and 2 managed rule groups is billed for 5 rules. Premium AMRs that carry their own subscription fee (e.g. Bot Control) which is in addition to this cost.  Custom rule groups have no cost on their own, their association with one or more protection pack(s) only has a cost.  
- **Requests** — A per-request cost for every web request evaluated by the protection pack.  The base per-request rate covers up to 1,500 WCU of rule evaluation and the default body inspection size (8 KB). We cover these in more detail later in this document.  


### **Core scenario** Cost

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom rules + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests | 10,000,000 | $0.60/million | $6.00 |
| | | **Total** | **$18.00** |


### Additional Costs - Features

Beyond the base components, several features carry incremental costs:

**WCU Beyond 1,500**  
Standard WAF costs for requests allows up to 1,500 WCU worth or inline, custom rule group, or Managed Rule groups.  If a protection pack associated with a resource has more than 1,500 WCU, the per-request cost increases in 500-WCU increments. In practice, most WAF deployments are under 1,500 WCU.  

#### WCU Overage  

**Feature Example:** Custom rules + AMRs brings the Protection Pack to 1,501 WCU.  

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| WCU overage (1 × 500 WCU increment) | 10,000,000 | $0.20/million | $2.00 |


**Feature Example:** Custom rules + AMRs brings the Protection Pack to 2,700 WCU.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| WCU overage (3 × 500 WCU increment) | 10,000,000 | $0.60/million | $6.00 |


**Core scenario** + WCU Overage**  
Custom rules + AMRs brings the Protection Pack between 1,501 - 2,000 WCU.  

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom rules + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests | 10,000,000 | $0.60/million | $6.00 |
| WCU overage (1 × 500 WCU increment) | 10,000,000 | $0.20/million | $2.00 |
| | | **Total** | **$20.00** |


#### Body inspection  
AWS WAF inspects up to 8 KB when associated with an Application Load Balancers or AWS AppSync is included in standard WAF costs.

AWS WAF inspects up to 16 KB of the request body for CloudFront, API Gateway, Amazon Cognito, App Runner, and Verified Access is included with standard WAF costs. You can configure a higher maximum body inspection of 32 KB, 48 KB, or 64 KB. Extended body inspection is billed per request *only* when: a WAF rule evaluates the body and the actual body exceeds 16 KB. The rate depends on the size of the actual request body.  

**Feature Example:** 
Body inspection set to 48 KB.  
1,500,000 requests have a body > 16 KB and ≤ 48 KB.  
500,00 have a body > 48 KB and ≤ 64 KB.  

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Requests with body > 16 KB and ≤ 48 KB | 1,500,000 | $0.30/million | $0.45 |
| Requests with body > 48 KB and ≤ 64 KB | 500,000 | $0.60/million | $0.30 |

**Core scenario + Body Inspection (48 KB):**  
Body inspection set to 48 KB.  
1,500,000 requests have a body > 16 KB and ≤ 48 KB.  
500,00 have a body > 48 KB and ≤ 64 KB.  

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom rules + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests | 10,000,000 | $0.60/million | $6.00 |
| Requests with body > 16 KB and ≤ 32 KB | 1,500,000 | $0.30/million | $0.45 |
| Requests with body > 32 KB and ≤ 64 KB | 500,000 | $0.60/million | $0.30 |
| | | **Total** | **$18.75** |


**Core scenario + WCU Overage + Body Inspection (48 KB):**  
Custom rules + AMRs brings the Protection Pack between 1,501 - 2,000.  
Body inspection set to 48 KB.  
1,500,000 requests have a body > 16 KB and ≤ 48 KB.  
500,00 have a body > 48 KB and ≤ 64 KB.  

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom rules + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests | 10,000,000 | $0.60/million | $6.00 |
| WCU overage (1 × 500 WCU increment) | 10,000,000 | $0.20/million | $2.00 |
| Requests with body > 16 KB and ≤ 32 KB | 1,500,000 | $0.30/million | $0.45 |
| Requests with body > 32 KB and ≤ 64 KB | 500,000 | $0.60/million | $0.30 |
| | | **Total** | **$20.75** |


#### Challenge and Captcha Costs  

Challenge and Captcha actions have their own per-use cost on top of standard request pricing.  

**When Challenge and Captcha are included or do **NOT** result in a cost:**

- When a request triggers a WAF rule with a Challenge action but already contains a valid WAF token from a previous Challenge action.  
- When a request triggers a WAF rule with a Captcha action but already contains a valid WAF token from a previous Challenge or Captcha action/attempt.  
- When an AWS Managed Rule (AMR) uses Challenge or Captcha as its default action. Today this is applicable to specific rules within: Bot Control Targeted, Fraud Control rules (ATP, ACFP), and the AntiDDoS managed rules.  
- **JavaScript SDK (passive integration)** — AWS WAF JavaScript SDK executing in the web browser.  


**When Challenge and Captcha are paid:**

- **Challenge** — A billable event occurs each time WAF returns an HTTP 202 interstitial Challenge response. If a user already has a valid Challenge token, the rule passes through and no billable event occurs.  
- **Captcha** — A billable event occurs ***only*** when a user submits an answer to a Captcha puzzle. This applies whether the Captcha was served by a WAF rule action (HTTP 405) or rendered by the application using the Captcha JavaScript SDK — the charge is for the puzzle submission itself.  The only exception is when the Captcha is triggered by an AWS Managed Rule where the default action is Captcha.  
- **AMR set to Count + label-based custom rule** — You might want to apply custom rule logic based on an AMR rule triggering where that AMR rule has a default action of Challenge or Captcha.  A custom rule using the label from a rule with a default action of Challenge/Captcha does NOT in this case waive the Challenge/Captcha cost; the AMR rule must terminate as a default action for this cost to be waived.
- **AMR rule overridden directly to Challenge/Captcha** — If you override any individual AMR rule's action directly to Challenge or Captcha, that is a paid event — even if another rule(s) within the same AMR use Challenge or Captcha as a default action.

**Feature Example:** Custom rule issues Challenge, 1% of traffic has no valid token and a WAF rule triggers an HTTP 202 → 100,000 HTTP 202 responses.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Challenge (custom rule, HTTP 202 returned) | 100,000 | $0.40/million | $0.04 |

**Feature Example:** 50,000 requests match a rule with a Captcha action. Of those, 12,000 users actually submit a Captcha puzzle answer. The remaining 38,000 either already had a valid Captcha token (puzzle never served) or were served the puzzle but abandoned it. Only the 12,000 submitted answers are billable.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Requests matching Captcha rule | 50,000 | — | $0.00 |
| Captcha (submitted puzzle answers) | 12,000 | $4.00/10,000 | $4.80 |

**Feature Example:** Bot Control Targeted (scope-down to 5% of traffic). Bot Control Targeted uses Challenge/Captcha as default actions on some rules — 1% of total traffic (100,000 requests) is served a Challenge or Captcha by Bot Control Targeted as its default action. Because the AMR itself is what terminates the request, these are included at no additional cost.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Bot Control Targeted subscription | 1 | $10.00/month | $10.00 |
| Bot Control Targeted per-request (5% of traffic) | 500,000 | $10.00/million | $5.00 |
| Challenge/Captcha (from Bot Control rules, 100,000 served) | 100,000 | included with AMR | $0.00 |

Adding JavaScript SDK (passive Challenge integration) to all HTML pages does not change the cost — tokens acquired via the SDK are not billable events, and the Bot Control Challenge/Captcha actions are already included with the AMR subscription.


**Core scenario** + Custom Challenge Rule**  
Custom rule issues Challenge, 1% of traffic has no valid token and a WAF rule triggers an HTTP 202 → 100,000 HTTP 202 responses.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Challenge (custom rule, HTTP 202 returned) | 100,000 | $0.40/million | $0.04 |
| | | **Total** | **$18.04** |


**Core scenario** + Captcha on /login**  
Captcha on `/login` using client SDK integration — 10,000 login attempts, 9,500 users submit a Captcha answer.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Captcha (submitted puzzle answers) | 9,500 | $4.00/10,000 | $3.80 |
| | | **Total** | **$21.80** |


**Core scenario** + Bot Control Targeted (5% scope-down)**  
Bot Control Targeted scoped to 5% of traffic. Challenge/Captcha from Bot Control rules is included.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + Bot Control Targeted) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Bot Control Targeted subscription | 1 | $10.00/month | $10.00 |
| Bot Control Targeted per-request (5% of traffic) | 500,000 | $10.00/million | $5.00 |
| Challenge/Captcha (from Bot Control rules) | — | included with AMR | $0.00 |
| | | **Total** | **$34.00** |


**Core scenario** + Bot Control Targeted + Custom Challenge Rule**  
Bot Control Targeted (5% scope-down) plus a custom rule issuing Challenge (1% of traffic, no overlap with Bot Control) → 100,000 HTTP 202 responses. The Bot Control Challenge/Captcha is included, but the custom rule's Challenge is a paid event.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + Bot Control Targeted) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Bot Control Targeted subscription | 1 | $10.00/month | $10.00 |
| Bot Control Targeted per-request (5% of traffic) | 500,000 | $10.00/million | $5.00 |
| Challenge (from Bot Control rules) | — | included with AMR | $0.00 |
| Challenge (custom rule, 100,000 HTTP 202 returned) | 100,000 | $0.40/million | $0.04 |
| | | **Total** | **$34.04** |


**Cost implications of token immunity timing:**

- Shorter immunity times cause users to re-verify more frequently within a session, increasing billable events
- Token domain misconfiguration causes duplicate billable events when users navigate across subdomains — a token acquired on `www.example.com` is not valid on `api.example.com` unless token domain is configured, resulting in a second billable Challenge or Captcha
- High-traffic endpoints with Captcha rules and short immunity times can generate significant per-use charges even from legitimate users

See [CAPTCHA and Challenge](../../captcha-and-challenge/docs/index.md) for integration patterns that minimize billable events (passive and proactive approaches) and immunity time tradeoff guidance.

**Feature Example:** Custom rule issues Challenge on 100% of traffic, immunity timer is 30 seconds resulting in 2,000,000 HTTP 202 responses. (No WAF JS SDK integration)

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Challenge (custom rule, HTTP 202 returned) | 2,000,000 | $0.40/million | $0.80 |

**Feature Example:** Same configuration but immunity timer is 300 seconds, resulting in only 25,000 HTTP 202 responses.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Challenge (custom rule, HTTP 202 returned) | 25,000 | $0.40/million | $0.01 |


**Core scenario** + Challenge (30s immunity)**  
Custom rule issues Challenge on 100% of traffic, immunity timer is 30 seconds → 2,000,000 HTTP 202 responses.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Challenge (custom rule, HTTP 202 returned) | 2,000,000 | $0.40/million | $0.80 |
| | | **Total** | **$18.80** |

**Core scenario** + Challenge (300s immunity)**  
Same configuration but immunity timer is 300 seconds → only 25,000 HTTP 202 responses.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI) | 7 | $1.00/month | $7.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Challenge (custom rule, HTTP 202 returned) | 25,000 | $0.40/million | $0.01 |
| | | **Total** | **$18.01** |

The difference between 30-second and 300-second immunity on the same traffic is $0.79/month (~4%) — entirely from repeated Challenge responses to the same legitimate users.


### Premium AMRs


#### Bot Control Common

For Bot Control, the per-request cost applies to every request evaluated by the rule group — not just requests that match a bot label. If you scope Bot Control to only your `/api/` path, you only pay for requests to that path. Scope-down statements are the primary lever for controlling premium AMR costs.
There is a flat subscription cost per Protection Pack with Bot Control configured.

**Feature Example:** Bot Control Common scoped to 10% of traffic.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Bot Control Common subscription | 1 | $10.00/month | $10.00 |
| Bot Control Common per-request (10% of traffic) | 1,000,000 | $1.00/million | $1.00 |

**Feature Example:** Bot Control Common evaluates 100% of traffic (no scope-down).

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Bot Control Common subscription | 1 | $10.00/month | $10.00 |
| Bot Control Common per-request (100% of traffic) | 10,000,000 | $1.00/million | $10.00 |


**Core scenario** + Bot Control Common (10% requests in scope)**

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + Bot Control Common) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Bot Control Common subscription | 1 | $10.00/month | $10.00 |
| Bot Control Common per-request (10% of traffic) | 1,000,000 | $1.00/million | $1.00 |
| | | **Total** | **$30.00** |

**Core scenario** + Bot Control Common (100% requests in scope)**

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + Bot Control Common) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Bot Control Common subscription | 1 | $10.00/month | $10.00 |
| Bot Control Common per-request (100% of traffic) | 10,000,000 | $1.00/million | $10.00 |
| | | **Total** | **$39.00** |

Most customers do not need BotControl protecting every single request; .css, .js, etc are usually not useful to protect with Bot Control.  

#### Bot Control Targeted

Bot Control Targeted follows the same cost model as Common: a flat subscription fee per Protection Pack plus a per-request cost. It has a higher per-request rate than Common. Some rules within Bot Control Targeted use Challenge or Captcha as their default action — when those rules terminate the request, no additional Challenge/Captcha cost is incurred.

**Feature Example:** Bot Control Targeted scoped to 5% of traffic.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Bot Control Targeted subscription | 1 | $10.00/month | $10.00 |
| Bot Control Targeted per-request (5% of traffic) | 500,000 | $10.00/million | $5.00 |

**Feature Example:** Bot Control Targeted evaluates 100% of traffic.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Bot Control Targeted subscription | 1 | $10.00/month | $10.00 |
| Bot Control Targeted per-request (100% of traffic) | 10,000,000 | $10.00/million | $100.00 |

* Note: This is shown as an example, but in reality you would almost always use Bot Control Targeted with a Scope down statement.

**Core scenario** + Bot Control Targeted (5% requests in scope)**

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + Bot Control Targeted) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Bot Control Targeted subscription | 1 | $10.00/month | $10.00 |
| Bot Control Targeted per-request (5% of traffic) | 500,000 | $10.00/million | $5.00 |
| | | **Total** | **$34.00** |


The lack of a scope-down statement adds $95.00/month from Bot Control Targeted per-request charges.  This is not commonly the best design due to many requests not requiring enhanced protection (e.g. .css, .js)


#### Account Takeover Prevention (ATP)

ATP has a flat per protection pack plus per request that match the login endpoint you configure (not all traffic through the protection pack). Many ATP rules use challenge or Captcha actions.  When used as a default action, these are included in the cost of ATP and are not in addition to ATP costs.  ATP requires configuring which URI to inspect, only requests to that URI path (specifically POST) result in a usage based cost.  

**Feature Example:** ATP configured for `/login`, 50,000 requests/month hit the login path.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| ATP subscription | 1 | $10.00/month | $10.00 |
| ATP per-request (login path only) | 50,000 | $1.00/million | $0.05 |

**Core scenario** + ATP**  
ATP configured for `/login`, 50,000 requests/month hit the login path.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + ATP) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| ATP subscription | 1 | $10.00/month | $10.00 |
| ATP per-request (login path only) | 50,000 | $1.00/million | $0.05 |
| | | **Total** | **$29.05** |


#### Account Creation Fraud Prevention (ACFP)

ACFP follows the same model as ATP but applies to the registration endpoint you configure.

**Feature Example:** ACFP configured for `/register`, 20,000 requests/month hit the registration path.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| ACFP subscription | 1 | $10.00/month | $10.00 |
| ACFP per-request (registration path only) | 20,000 | $1.00/million | $0.02 |

**Core scenario** + ACFP**  
ACFP configured for `/register`, 20,000 requests/month hit the registration path.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + ACFP) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| ACFP subscription | 1 | $10.00/month | $10.00 |
| ACFP per-request (registration path only) | 20,000 | $1.00/million | $0.02 |
| | | **Total** | **$29.02** |


#### Anti-DDoS

The Anti-DDoS managed rule group has a flat fee per Protection Pack plus per-request cost. It uses Challenge as a default action on some rules — when the AMR terminates the request, these Challenge events are included at no additional cost.  Requests that are blocked by this AMR do NOT result in a usage based charge from the Anti-DDoS AMR.  Note, Shield Advanced customers can use this Premium Managed Rule on Shield Advanced protected resources for no additional cost.  See [Shield Advanced & WAF Costs for full details](index.md#shield-advanced-waf-costs)

**Feature Example:** Anti-DDoS evaluates 100% of traffic. 3% of traffic (300,000 requests) is served a Challenge by Anti-DDoS as its default action.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Anti-DDoS subscription | 1 | $15.00/month | $15.00 |
| Anti-DDoS per-request (100% of traffic) | 10,000,000 | $0.80/million | $8.00 |
| Challenge (from Anti-DDoS rules, 300,000 served) | 300,000 | included with AMR | $0.00 |

**Core scenario** + Anti-DDoS**  
Anti-DDoS evaluates 100% of traffic. 3% of traffic (300,000 requests) is served a Challenge by Anti-DDoS as its default action.

| Line item | Quantity | Unit cost | Monthly cost |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/month | $5.00 |
| Rules (5 custom + CRS + KBI + Anti-DDoS) | 8 | $1.00/month | $8.00 |
| Requests (base) | 10,000,000 | $0.60/million | $6.00 |
| Anti-DDoS subscription | 1 | $15.00/month | $15.00 |
| Anti-DDoS per-request (100% of traffic) | 10,000,000 | $0.80/million | $8.00 |
| Challenge (from Anti-DDoS rules, 300,000 served) | 300,000 | included with AMR | $0.00 |
| | | **Total** | **$42.00** |


### Logging

> This section does **NOT** cover the technical implications and strategeis in selecting the best WAF logging option For a complete answer on selecting the right log delivery and storage choice [here](../../waf-logging/docs/index.md).

WAF logging is not billed directly as part of the WAF service but represents an operational cost of using AWS WAF.  Logging costs are broken out into three groups:  
1) **Log Delivery:** This is calculated based on the raw size of WAF logs (no compression)  
2) **Storage/Retention:** In  AWS native storage (and likely many 3P) WAF logs are usually compressed.  
3) **Misc:**  There are some additional costs, we cover what these are however they are rarely meaningful (less than 1% of of log delivery/storage costs)  


A WAF log size varies based on what rules are in the protection pack as well as the request itself.  To help you quantify/estimate your own WAF logging costs, below are some useful min/max waf log sizes:  
- A protection pack with 0 rules and trivial URI, headers, etc results in a ~1.4 KB WAF log item.  
- A [recommended protection pack](../../aws-managed-rules/docs/index.md#protection-pack-recommendations) results in a ~4.6 KB waf log item.  

If your application creates extremely large query strings, URI, headers, etc, this can increase your log size.  The values provided here are reason assumption you can use to accurate create an estimate/ballpark.  For the most accurate answer, enable WAF logging and capture a sample of your requests and calculate your average log size from your actual logs.  

To put these ranges in perspective, one million (1,000,000) WAF requests results in:
- 1.4 GB - 4.6 GB of logs delivered (raw)
- 280 MB - 920 MB of logs on storage (assuming commpressed to 20%)


#### Log Delivery  

AWS WAF supports log delivery via Amazon CloudWatch Vended Logs and Amazon Data Firehose.  Amazon CloudWatch Vended logs can deliver to Amazon S3 or a CloudWath log group, Amazon Data Firehose can deliver to Amazon S3 and other products such as OpenSearch, and 3P SIEM type tools.  

- **CloudWatch Vended Logs** - WAF logs send to S3 follow CloudWatch Vended Logs (Delivery Destination Amazon S3).  AWS WAF provides a credit covering 500 MB Vended Log Ingestion per 1 million WAF requests.  Vended Logs to S3 start at $0.25 per GB and tier down to $0.05 per GB over 50 TB (calculated against raw WAF log size).  Vended Logs to a CloudWatch log group starts at $0.50 per GB and tiers down to $0.05 per GB over 50 TB.  

- **Kinesis Data Firehose** — WAF logs can be delivered via Amazon Data Firehose.  Firehose billing imposes a minimum item (WAF log) size of 5 kb.  For almost all WAF customers, this means you should consider each WAF logs to be 5 KB when calculating log delivery.  Firehose log delivery starts at $0.075 per GB and tiers down to $0.053 per GB above 1 PB (calculated against raw WaF log size, with a minimum of 5kb)


#### Log Storage  


- **CloudWatch Logs Groups** - CloudWatch Log groups on creation can select a storage tier of either Standard ($0.50 per GB/month) or Infrequent Access ($0.25 per GB/Month).  Note, if you store in Infrequent Access, there is an additional cost to query that data.  Consider the additioanl cost to query before selecing Infrequent Access as it can result in more TCO if you end up querying logs.   

- **Amazon S3** — S3 is the most common destination for WAF logs, S3 Storage starts at $0.023 per GB.  S3 POSTs have a small API costs  ($0.005 per 1,000).  While this is technical a cost, compared to the storage and delivery costs, this is almost always trivia (less than 1%) and when creating a cost estimate safely ignored.  

**Cost specific Storage recommendations**
When using KMS for S3 storage, use Amazon S3 Bucket Keys.  Without this feature, *every single* POST (i.e. WAF log beign uploaded to S3) results in a KMS API costs.  With this feature enabled, S3 generates a short-lived bucketlevel key from KMS.  All data creating for a period of a limited period of use the same key, resulting in an API all every so often vs for every single WAF log uploaded.  

**Enable LifeCycle/Retention**  
Both AWS native storage services offer a lifecycle/retention policy allow you to either change the storage tier or outright delete older data automatically.  Unless you have a compliance requirements, consider keeping WAF logs for ~30 days at least or whatever your Organziation has decided for operational and security needs.  This setting is configurable after creation of the CLoudWatch Log group or S3 bucket.  

#### Logging Cost Examples

The scale of your logging and per log average size impacts the cost based on you log delivery choice.  On the log delivery front, smaller average WAF log size and truely massive workloads (tens or hundreds of billions+) are most cost effective with Vended Logs.  For larger average WAF object size and most workloads until you are in the tens of billions, Firehose is usually most cost effective.  On the storage front, while cost is certainly a factor, validate your technical requirements for WAF logs before deciding which logging approach makes the most sense.  See [WAF Logging](../../waf-logging/docs/index.md)


**Log Delivery Cost Examples**  
**Example 1 — 1.4 KB average WAF log size, 10 million requests**

*Amazon Kinesis Data Firehose*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume (5 KB minimum per item) | 5 KB × 10,000,000 | 50 GB |
| Delivery cost | 50 GB × $0.075/GB | $3.75 |
| | **Total** | **$3.75** |

*Amazon CloudWatch Vended Logs*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume | 1.4 KB × 10,000,000 | 14 GB |
| WAF credit (500 MB per 1M requests) | 500 MB × 10 | 5 GB |
| Billable volume | 14 GB − 5 GB | 9 GB |
| Delivery cost | 9 GB × $0.25/GB | $2.25 |
| | **Total** | **$2.25** |


**Example 2 — 4.6 KB average WAF log size, 10 million requests**

*Amazon Kinesis Data Firehose*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume (5 KB minimum per item) | 5 KB × 10,000,000 | 50 GB |
| Delivery cost | 50 GB × $0.075/GB | $3.75 |
| | **Total** | **$3.75** |

*Amazon CloudWatch Vended Logs*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume | 4.6 KB × 10,000,000 | 46 GB |
| WAF credit (500 MB per 1M requests) | 500 MB × 10 | 5 GB |
| Billable volume | 46 GB − 5 GB | 41 GB |
| Delivery cost | 41 GB × $0.25/GB | $10.25 |
| | **Total** | **$10.25** |


**Example 3 — 4.6 KB average WAF log size, 10 billion requests**

*Amazon Kinesis Data Firehose*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume (5 KB minimum per item) | 5 KB × 10,000,000,000 | 50,000 GB |
| Delivery cost | 50,000 GB × $0.075/GB | $3,750.00 |
| | **Total** | **$3,750.00** |

*Amazon CloudWatch Vended Logs*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume | 4.6 KB × 10,000,000,000 | 46,000 GB (46 TB) |
| WAF credit (500 MB per 1M requests) | 500 MB × 10,000 | 5,000 GB (5 TB) |
| Billable volume | 46,000 GB − 5,000 GB | 41,000 GB (41 TB) |
| Tier 1 (First 10 TB) | 10,000 GB × $0.25/GB | $2,500.00 |
| Tier 2 (Next 20 TB) | 20,000 GB × $0.15/GB | $3,000.00 |
| Tier 3 (Next 20 TB) | 11,000 GB × $0.075/GB | $825.00 |
| | **Total** | **$6,325.00** |


**Example 4 — 4.6 KB average WAF log size, 500 billion requests**

*Amazon Kinesis Data Firehose*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume (5 KB minimum per item) | 5 KB × 500,000,000,000 | 2,500,000 GB (2.5 PB) |
| Tier 1 (Fist 250 TB) | 250,000 GB × $0.075/GB | $18,750.00 |
| Tier 2 (Next 750 TB) | 750,000 GB × $0.064/GB | $48,000.00 |
| Tier 3 (Beyond 1 PB) | 1,500,000 GB × $0.053/GB | $79,500.00 |
| | **Total** | **$146,250.00** |

*Amazon CloudWatch Vended Logs*

| Step | Calculation | Result |
|---|---|---|
| Raw log volume | 4.6 KB × 500,000,000,000 | 2,300,000 GB (2.3 PB) |
| WAF credit (500 MB per 1M requests) | 500 MB × 500,000 | 250,000 GB |
| Billable volume | 2,300,000 GB − 250,000 GB | 2,050,000 GB (~2.05 PB) |
| Tier 1 (First 10 TB) | 10,000 GB × $0.25/GB | $2,500.00 |
| Tier 2 (Next 20 TB) | 20,000 GB × $0.15/GB | $3,000.00 |
| Tier 3 (Next 20 TB) | 20,000 GB × $0.075/GB | $1,500.00 |
| Tier 4 (Beyond 50 TB) | 2,000,000 GB × $0.05/GB | $100,000.00 |
| | **Total** | **$107,000.00** |

#### Filtered Logging
WAF log filtering reduces cost significantly. You can configure logging to only capture requests that match specific rules, are blocked, or carry specific labels — rather than logging every request. See [WAF Logging](../../waf-logging/docs/index.md) for filtering guidance.

There is no cost to configure this and beyond changing the number of requests you end up logging, does not change the logging cost formulas.

### Partner Managed Rules

Partner managed rules (available in AWS Marketplace) have their own subscription pricing set by the partner, plus standard WAF per-request costs still apply. These do not include Challenge or Captcha as part of their subscription — any Challenge or Captcha actions from partner rules are billed as standard paid Challenge/Captcha events.

## Estimating Cost

!!! warning "Future Content Updates in progress"
  We are revamping the AWS WAF best practices guide.  This section is not yet created/completed.

### Protecting Existing AWS Resources

<We will go into how to do this in a single account, as well as at scale using AWS Config/other org wide aggregation mechanisms.>

### Protection Non-AWS Origins or Workloads moving onto AWS

<focus on the data points that matter in with non-AWS terminology>

## Cost Optimization

### Shield Advanced

If you subscribe to AWS Shield Advanced, standard WAF costs + the AntiDDoS AMR are waived for Shield Advanced protected resources. This covers:

- $5 per Protection pack per month
- $1 per rule per month
- $0.60 per million requests of WAF usage
- AntiDDoS AMR - Flat fee and Usage fee are waived

Shield Advanced does not cover Bot Control Targeted, ATP, ACFP, or Challenge/Captcha per-use fees.  


### Scope-Down Statements

Scope-down statements are one of the most effective/important cost optimization Premium Managed rules; specifically BotControl Premium Managed rules.  While other Premium rules (Fraud Control, AntiDDoS) support can see cost reductions from scope down, they are not usually applicable due to Fraud Controls requiring configuration to specific URI and HTTP methods and AntiDDoS for techincal reasons is not recommended to be scoped down.

- **Bot Control** — Scope to paths that are targets of automation (login, API, search, checkout). Exclude static assets, health checks, and internal-only paths.
- **ATP/ACFP** — These are already path-scoped by configuration, but ensure your login/registration path definitions are precise and do not accidentally match broader URL patterns.

Scope-down statement do not reduce the effective WCU for requests that would be out of scope.


### JavaScript Integration
If you need to use WAF challenge to protect some or all of your application, implementing the JavaScript for async/deferred challenge can dramatically reduce the number of Protection Pack triggered Challenges resulting in a cost reduction.  Captcha does not however see any cost optimization, the benefits for integration are all technical.

### CloudFront Flat-Rate Plans

CloudFront offers flat rate plans, these cover far more than AWS WAF however include varying degrees of WAF usage and features.  If you use a Flat-rate plan, all WAF features included in that plan do **NOT** have any of the above mentioned WAF related costs.

