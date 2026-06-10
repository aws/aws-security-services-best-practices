# Bot Management

[AWS WAF Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html) is a managed rule group that gives you visibility and control over bot traffic to your applications. Bot traffic can consume excess resources, skew business metrics, degrade performance for legitimate users, and undesired content scraping. Bot Control detects and categorizes bot traffic so you can decide how to handle each category — block, rate-limit, challenge, or allow.

## Web Bot Authentication (WBA)

Web Bot Authentication is a verification method available in Bot Control version 4.0 and above.  Web Bot Authentication uses an cryptographic signatures in HTTP messages to verify that a request genuinely comes from the bot it claims to be.  That signature can also authorize payment from the requestor, allow content providers or anything on the internet to monetize requests without having a one to one relationship with each requesting party.  This is part of a recently devloped [x402 protocol](https://docs.cdp.coinbase.com/x402/welcome).

This is particularly relevant for managing AI bots and crawlers. Many AI services now sign their requests using WBA, allowing you to distinguish a legitimate AI crawler in addition it provides a path to monetize those crawl requests.

Bot Control applies WBA labels to requests based on the verification result:

- `awswaf:managed:aws:bot-control:web_bot_auth:verified` – Signature successfully validated against public key directory
- `awswaf:managed:aws:bot-control:web_bot_auth:invalid` – Signature present but cryptograpic validation failed
- `awswaf:managed:aws:bot-control:web_bot_auth:expired` – Signature used an expired cryptograpic key
- `awswaf:managed:aws:bot-control:web_bot_auth:unknown_bot` – Key ID not found in the key directory

For more background on WBA and how AWS WAF identifyes it, see the announcement [AWS WAF announces Web Bot Auth support](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-waf-web-bot-auth-support/).

## Common vs. Targeted Bot Control

Bot Control is available at two inspection levels. You choose the level when you add the Bot Control rule group to your protection pack.

### Common


The Common level identifies bots that self-identify. This covers search engine crawlers, social media bots, monitoring services, scrapers that don't attempt to hide, and AI and agentic bots.

Use BotControl Common when:

- You want visibility into what bot traffic is hitting your application.
- You need to identify self-identifying bots and control what they can access — for example, allowing a search engine to crawler public pages but blocking it from API endpoints or authenticated areas.
- You want to manage AI bot access to your content by category (allow, block, or rate-limit specific AI crawlers).
- You want to restrict and/or monetize WBA enabled bots crawling your content.

Detecting a bot by name or category is done through a WBA signature or User-Agent (and static/dedicated IPs in many cases).  Bot Control further marks bot requests as verified or unverified.

**Verified:**  
- A request has a valid WBA signature  
- A request has a well known User-Agent plus source IP/reverse DNS.  

**Unverified:**  
- A request has a well known User-Agent but the source IP does not match the well known IP sources for that bot  
- A request has a well known User-Agent but the bot does not have dedicated/known IPs.  

User-Agent is never enough to verify a bot due to User-Agent being client provided.  The below example curl command would show up as an unverified Google bot, it has a well known User-Agent but the source IP will not match the known corresponding source IPs for the bot

```
curl -H "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)" https://checkip.amazonaws.com
```

As of Bot Control version 4.0.0, Bot Control Common does not block any verified bots. Before version 4.0.0, BotControl blocked by default *CategoryAI* bots.  You can still restrict/block any bot (verfied or not) using a custom label based rule.



**Example: Block a specific bot category even when verified**

Bot Control labels requests with both a verification status and a bot category. Even though verified bots are allowed by default, you may want to block specific categories from accessing certain parts of your application. This example blocks all social media bots from accessing your site, regardless of whether they are verified.

```json
{
  "Name": "block-social-media",
  "Priority": 10,
  "Statement": {
    "LabelMatchStatement": {
      "Scope": "LABEL",
      "Key": "awswaf:managed:aws:bot-control:bot:category:social_media"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-social-media"
  }
}
```

### Targeted

The Targeted level of Bot Controls includes all BotControl Common capabilities plus machine learning-based behavioral analysis to detects sophisticated bots attempting to evade other bot detection capabilities. BotControl Targeted help you catch bot that do not self-identify, rotate IPs, use headless browsers, mimic human browsing patterns, use residential proxies, and other deception to blend in with legitimate human traffic.

Use Bot Control Targeted when:

- You need to protect high-value endpoints (checkout, pricing, inventory) from sophisticated automated access.
- You face fraud threats such as credential stuffing, fake account creation, or automated purchasing that evade simple bot signatures. For this use case, you usually want to use  Bot Control along with [Fraud Control managed rule groups](../../fraud-prevention/docs/index.md).
- You need to defend against content threats like scraping of pricing data, product catalogs, or published content by bots that rotate IPs and mimic human behavior. The additional capabilities in BotControl Targeted are for bots taking taking these actions and are *not* well-behaved, don't self-identifying bots, and are malicious/deceitful.
- You are experiencing availability threats where bot traffic volume degrades performance or increases infrastructure costs beyond what rate-limiting alone can address.

WAF rules in BotControl Targeted specific can be divided into several buckets:

**TGT_ vs TGT_ML_**  
BotControl Targeted has rules that are generic as in not specific your application.  e.g. Rate limiting requests without a valid WAF token.  TGT_ML_ rules build a baseline of normal per your application and detect and response based on anomalies from that baseline.

**Session vs not Session**  
Many BotControl Targeted rules contain *Session* in their name.  These rules track behavior based on the presence (or lack of) an AWS WAF token (i.e. Cookie obtained from a WAF Challenge or Captcha).  For example TGT_VolumetricSession is similar to a traditional Rate Based WAF rule except it counts by unique value of this cookie instead of client IP.

For some additional/practical examples of using BotControl Targeted, check out the blog [How to use AWS WAF Bot Control for Targeted Bots signals and mitigate evasive bots](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-use-aws-waf-bot-control-for-targeted-bots-signals-and-mitigate-evasive-bots-with-adaptive-user-experience/).


## Using Scope-Down Statements with Bot Control

Bot Control has per-request charges, so every request it evaluates has a cost. Scope-down statements let you limit which requests Bot Control inspects. Requests excluded by the scope-down statement are not charged for Bot Control evaluation.

For most applications, a good starting point is to scope Bot Control to dynamic endpoints and exclude static assets (CSS, JavaScript).  You can also scope down to avoid inspection for authenticated only sections of your application; the idea being you can detect and block bots from authentication (legitimately or maliciously).

Consider whether Bot Control needs to evaluate all dynamic endpoints or just the ones where bot traffic causes business impact — login pages, search, pricing APIs, checkout flows, etc. See the Common and Targeted examples below for how to configure scope-down statements.

There is no single correct configuration — it depends on your application. The guiding principle is to match the inspection level to the risk of the endpoint:

| | In Scope | Out of Scope |
|---|---|---|
| **Bot Control Common** | Premium or paid content, public-facing pages where scraping or metric skew matters | Static assets (CSS, JS, images, fonts), health-check paths |
| **Bot Control Targeted** | Sensitive or high-value endpoints — login, account creation, checkout, pricing APIs, file upload | Static assets, already-authenticated internal pages |

Bot Control Common provides broad visibility into who is crawling your content, so scope it to the pages where that visibility has business value. Bot Control Targeted adds behavioral analysis and challenge-response detection, so scope it narrowly to the endpoints where sophisticated bots could cause  damage such as undesired automation or abuse of expensive APIs.


**Example: Common Bot Control scoped to a specific URI**

This applies Common-level Bot Control only to requests hitting `/api/search`, excluding all other traffic from Bot Control evaluation and charges.

```json
{
  "Name": "bot-control-common",
  "Priority": 9,
  "OverrideAction": {
    "None": {}
  },
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesBotControlRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesBotControlRuleSet": {
            "InspectionLevel": "COMMON",
            "EnableMachineLearning": false
          }
        }
      ],
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "SearchString": "/api/search",
          "FieldToMatch": { "UriPath": {} },
          "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
          "PositionalConstraint": "STARTS_WITH"
        }
      }
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "bot-control-common"
  }
}
```

**Example: Targeted Bot Control scoped to checkout and pricing endpoints**

This applies Targeted-level Bot Control to high-value endpoints where sophisticated bots cause the most business impact.

```json
{
  "Name": "bot-control-targeted",
  "Priority": 9,
  "OverrideAction": {
    "None": {}
  },
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesBotControlRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesBotControlRuleSet": {
            "InspectionLevel": "TARGETED",
            "EnableMachineLearning": true
          }
        }
      ],
      "ScopeDownStatement": {
        "OrStatement": {
          "Statements": [
            {
              "ByteMatchStatement": {
                "SearchString": "/checkout",
                "FieldToMatch": { "UriPath": {} },
                "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                "PositionalConstraint": "STARTS_WITH"
              }
            },
            {
              "ByteMatchStatement": {
                "SearchString": "/api/pricing",
                "FieldToMatch": { "UriPath": {} },
                "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                "PositionalConstraint": "STARTS_WITH"
              }
            }
          ]
        }
      }
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "bot-control-targeted"
  }
}
```



## WBA for AI Bot Monetization
!!! warning "Future Content Updates in progress"
  The sections below this point are actively being updated and may be incomplete.  Please come back soon or reference public docs for AWS WAF in the meantime.  

Beyond being a new authoritative way to identify bots, WBA enables content monetization strategies for AI bot traffic. Before WBA, monetizing a third party consuming your content required a one-to-one agreement and technical implementation authorizing their access. This can work if there are only a few relationships needed, but is not practical as AI/Agentic bots proliferate. WBA provides a common way to detect and monetize crawling requests without any one-on-one relationship.

Because WBA reliably identifies AI/Agentic bot requests, you can make policy decisions per bot — allowing access to bots from AI providers you have a commercial relationship with while blocking or rate-limiting others. This lets you treat AI bot access as a business decision rather than a purely security one.

For a detailed walkthrough of managing AI bots with AWS WAF including monetization considerations, see the blog [How to manage AI Bots with AWS WAF and enhance security](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-manage-ai-bots-with-aws-waf-and-enhance-security/).

For how WBA integrates with AI agent frameworks, see [Reduce CAPTCHAs for AI agents browsing the web with Web Bot Auth in Amazon Bedrock AgentCore Browser](https://aws.amazon.com/blogs/machine-learning/reduce-captchas-for-ai-agents-browsing-the-web-with-web-bot-auth-preview-in-amazon-bedrock-agentcore-browser/).

## Related Resources

- [AWS WAF Bot Control documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html)
- [Bot Control rule group reference](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html)
- [Detect and block advanced bot traffic](https://aws.amazon.com/blogs/security/detect-and-block-advanced-bot-traffic/)
- [Fine-tune and optimize AWS WAF Bot Control mitigation capability](https://aws.amazon.com/blogs/security/fine-tune-and-optimize-aws-waf-bot-control-mitigation-capability/)
- [Protect against bots with AWS WAF Challenge and CAPTCHA actions](https://aws.amazon.com/blogs/networking-and-content-delivery/protect-against-bots-with-aws-waf-challenge-and-captcha-actions/)
- [CAPTCHA and Challenge](../../captcha-and-challenge/docs/index.md) — Token-based mitigation actions that work alongside Bot Control
- [Recommended WAF Rule Order](../../recommended-waf-rule-order/docs/index.md) — Where Bot Control fits in your rule evaluation order
