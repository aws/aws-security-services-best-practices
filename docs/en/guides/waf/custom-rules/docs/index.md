# Custom Rules

Custom rules complement managed rules by addressing application-specific threats and scenarios that pre-built rule groups do not cover. Use custom rules to enforce business logic, handle false positives from managed rules, and protect sensitive endpoints with fine-grained conditions.

For guidance on which AWS Managed Rules to pair with your custom rules, see [AWS Managed Rules](../../aws-managed-rules/docs/index.md). For log analysis techniques to identify when custom rules are needed, see [Monitoring WAF Rules](../../monitoring-waf-rules/docs/index.md).

## Common Rules for Most Deployments

Most WAF deployments benefit from the following types of custom rules.

### Rate-based rules

Rate-based rules are one of the most common and valuable custom rules for any type of application or endpoint. They limit the number of requests a single client can make over a time window, protecting against volumetric abuse, brute force, and DDoS. See [Recommended WAF Rule Order](../../recommended-waf-rule-order/docs/index.md) for where to place rate-based rules in your protection pack.

**Blanket rate-based rule** — Limits the total request rate from any single IP across all endpoints. This is your first line of defense against volumetric abuse.

<!-- TODO: Add screenshot of blanket rate-based rule in the console -->

```json
{
  "Name": "blanket-rate-limit",
  "Priority": 1,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 2000,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "blanket-rate-limit"
  }
}
```

**URI-specific rate-based rule** — Applies a stricter rate limit to a sensitive endpoint like `/login`. Attackers frequently target authentication endpoints with credential stuffing or brute force at rates well below a blanket threshold.

<!-- TODO: Add screenshot of URI-specific rate-based rule in the console -->

```json
{
  "Name": "login-rate-limit",
  "Priority": 8,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "SearchString": "/login",
          "FieldToMatch": {
            "UriPath": {}
          },
          "TextTransformations": [
            {
              "Priority": 0,
              "Type": "LOWERCASE"
            }
          ],
          "PositionalConstraint": "STARTS_WITH"
        }
      }
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "login-rate-limit"
  }
}
```

**Composite key rate-based rule (IP + WAF token)** — Aggregates requests by both source IP and the AWS WAF token cookie. This is useful when multiple users share the same IP (e.g., behind a corporate NAT) — the WAF token differentiates individual clients so legitimate users aren't penalized by a neighbor's behavior.

<!-- TODO: Add screenshot of composite key rate-based rule in the console -->

```json
{
  "Name": "composite-ip-token-rate-limit",
  "Priority": 2,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 500,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "CUSTOM_KEYS",
      "CustomKeys": [
        {
          "IP": {}
        },
        {
          "Cookie": {
            "Name": "aws-waf-token",
            "TextTransformations": [
              {
                "Priority": 0,
                "Type": "NONE"
              }
            ]
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
    "MetricName": "composite-ip-token-rate-limit"
  }
}
```

**Rate-based rule scoped to Anonymous IP label** — Applies a stricter rate limit to requests that the Anonymous IP List managed rule group has labeled as coming from anonymizing sources. This lets you keep the Anonymous IP rule group in Count mode while still limiting the rate of requests from those sources rather than blocking them outright.

<!-- TODO: Add screenshot of label-scoped rate-based rule in the console -->

```json
{
  "Name": "rate-limit-anonymous-ips",
  "Priority": 8,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 200,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "LabelMatchStatement": {
          "Scope": "LABEL",
          "Key": "awswaf:managed:aws:anonymous-ip-list:AnonymousIPList"
        }
      }
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "rate-limit-anonymous-ips"
  }
}
```

### Geographic restrictions

Block or rate-limit requests based on geographic origin when your application only serves specific regions.  You can use this when your audience is from a specific list of countries or you have a business or compliance requirement to block access from specific countries.

Note: Geo and region based IP evaluation is not perfect, there is no single authoritative source saying which country or region IPs are assigned to.  It is uncommon but you should expect will eventually happen that an IP will be mapped to the incorrect geo or region, this is especially true if the IP is close to a geographic boarder.  If you are using Geo restrictions based on where you expect your audience to be, consider including near by countries for Geo based controls or not outright blocking those nearby countries. For example, if you only expect clients from US (United States), you may want to consider including CA (Canada) and MX (Mexico) to reduce the risk of blocking users that are close to these boarders.

It is also important to acknowledge that Geo based restrictions are relevative easy to overcome using VPNs, TOR, and cloud/hosting providers.  Legitmiate users as well as bad actors use these tool and can appear as if they are coming fom another country based on their IP, bypassing Geo based restrictions.  If you require authoritative *proof* a user is from a specific country/region, you *cannot* depend on their IP address alone to authoritatively verify this.

**Block requests from specific countries** — Blocks all requests originating from countries where your application has no legitimate users or comply with compliance requirement such as country embargo lists.


```json
{
  "Name": "block-restricted-countries",
  "Priority": 3,
  "Statement": {
    "GeoMatchStatement": {
      "CountryCodes": ["CN", "RU", "KP"]
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-restricted-countries"
  }
}
```

**Allow only specific countries** — If your application exclusively serves a known set of regions, block everything else by inverting the match with a NOT statement.

<!-- TODO: Add screenshot of allow-only geo rule in the console -->

```json
{
  "Name": "allow-only-approved-countries",
  "Priority": 3,
  "Statement": {
    "NotStatement": {
      "Statement": {
        "GeoMatchStatement": {
          "CountryCodes": ["US", "CA", "GB", "DE", "FR"]
        }
      }
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "allow-only-approved-countries"
  }
}
```

### IP allowlists and denylists

Explicitly allow trusted sources or block known bad actors using [IP sets](https://docs.aws.amazon.com/waf/latest/developerguide/waf-ip-set-managing.html).

**IP allowlist** — Allows requests from trusted sources (e.g., monitoring systems, partner integrations) before any other rules evaluate them. Because Allow is a terminating action, allowed requests bypass all subsequent rules — including managed rules that detect web exploits and DDoS patterns. Even trusted systems should not normally be sending traffic that resembles an attack, so broadly allowing IPs removes a layer of protection you likely still want. Instead of a blanket Allow rule, consider scoping the IP set to specific rules that are causing issues — for example, excluding trusted IPs from a rate-based rule using a scope-down statement, or using a label-based exception to bypass a specific managed rule for those IPs. Reserve Allow-based IP allowlists for cases where you are certain the source should bypass all inspection.

<!-- TODO: Add screenshot of IP allowlist rule in the console -->

```json
{
  "Name": "allow-trusted-ips",
  "Priority": 4,
  "Statement": {
    "IPSetReferenceStatement": {
      "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/trusted-ips/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
    }
  },
  "Action": {
    "Allow": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "allow-trusted-ips"
  }
}
```

**IP denylist** — Blocks requests from known bad actors. Useful for quickly blocking IPs identified through log analysis or threat intelligence that aren't yet on the AWS IP reputation list.

<!-- TODO: Add screenshot of IP denylist rule in the console -->

```json
{
  "Name": "block-denied-ips",
  "Priority": 2,
  "Statement": {
    "IPSetReferenceStatement": {
      "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/denied-ips/a1b2c3d4-5678-90ab-cdef-EXAMPLE22222"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-denied-ips"
  }
}
```

### Header validation

Validate expected HTTP request fields to reject obviously malformed or unexpected requests before they reach more expensive managed rule evaluations.

**Block requests missing a required header** — If your application expects a specific header on all requests (e.g., an API key header, a custom application header), block requests that don't include it.

<!-- TODO: Add screenshot of header validation rule in the console -->

```json
{
  "Name": "require-api-key-header",
  "Priority": 5,
  "Statement": {
    "NotStatement": {
      "Statement": {
        "SizeConstraintStatement": {
          "FieldToMatch": {
            "SingleHeader": {
              "Name": "x-api-key"
            }
          },
          "ComparisonOperator": "GT",
          "Size": 0,
          "TextTransformations": [
            {
              "Priority": 0,
              "Type": "NONE"
            }
          ]
        }
      }
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "require-api-key-header"
  }
}
```

**Block requests missing a custom application header** — If your application injects a custom header at the CDN or load balancer layer (e.g., `x-app-origin`) to verify requests came through your infrastructure, block any request that doesn't include it.

<!-- TODO: Add screenshot of custom header validation rule in the console -->

```json
{
  "Name": "require-app-origin-header",
  "Priority": 5,
  "Statement": {
    "NotStatement": {
      "Statement": {
        "SizeConstraintStatement": {
          "FieldToMatch": {
            "SingleHeader": {
              "Name": "x-app-origin"
            }
          },
          "ComparisonOperator": "GT",
          "Size": 0,
          "TextTransformations": [
            {
              "Priority": 0,
              "Type": "NONE"
            }
          ]
        }
      }
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "require-app-origin-header"
  }
}
```

## Scenario-Based Custom Rule Examples

<!-- TODO: Add realistic, practical examples for each of the following scenarios -->
<!-- TODO: Add composite key rate-based rule examples (e.g., rate limiting by IP + URI path, IP + query string) -->
<!-- TODO: Add URI-specific rule examples for protecting sensitive endpoints (e.g., login, checkout, API endpoints) -->
<!-- TODO: Add examples of rules using AMR labels for fine-grained control (e.g., matching on specific AMR labels with additional conditions) -->

This section provides realistic examples of common scenarios where custom rules are needed, including:

- Composite key rate-based rules for more granular rate limiting
- URI-specific rules for protecting sensitive endpoints
- Rules that use AWS Managed Rule labels for fine-grained control
- Combining multiple conditions with AND/OR logic


## Using Rule Labels

A [label](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html) is metadata added to a web request by a matching rule. Use labels to make the results of one rule available to other rules. Labels can be inspected by other rules lower (not above) in the same protection pack by using the [label match statement](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-label-match.html).

Labels added by rules with terminating actions cannot be inspected by other rules. These labels are included in [WAF log records](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html) and [CloudWatch metric dimensions](https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics) so you can analyze and visualize the behavior of terminating rules.

Labels are commonly used to augment the behavior of a managed rule. The first step is to switch the managed rule's action from *Block* to *Count*. Then create another rule below that matches on the managed rule's label along with other conditions that determine if the request should be blocked.

See [How to customize behavior of AWS Managed Rules for AWS WAF](https://aws.amazon.com/blogs/security/how-to-customize-behavior-of-aws-managed-rules-for-aws-waf/) for more information on using labels.

<!-- TODO: Add practical examples of label-based custom rules, including inspecting labels from specific AMR rule groups -->
<!-- TODO: Add guidance on how labels appear in WAF logs and how to use them for monitoring (cross-reference Monitoring WAF Rules section) -->

## False Positive Handling

When a WAF rule matches legitimate traffic (a false positive), you need to create an exception that preserves protection for all other traffic while allowing the specific legitimate requests through. This is done using the label-based exception pattern — setting the problematic rule to *Count* mode and writing a custom rule that re-implements the block with exclusions for the false positive conditions.

For the full exception pattern with examples (single exception, multiple exceptions for the same rule, and Firewall Manager scenarios), see [Creating Exceptions](../../operationalizing/docs/index.md#creating-exceptions).

## Handling Large HTTP Requests

AWS WAF has limits on the size and number of HTTP request components it can inspect. See [Handling oversize web request components in AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html) for more details.  The default and max body size that can be inspected depends on the resource AWS WAF is associated with.

* For CloudFront, API Gateway, Amazon Cognito, App Runner, and Verified Access protection packs, AWS WAF can inspect request bodies up to 16 KB by default. You can increase this limit up to 64 KB in the protection pack configuration, for additional processing fees.
* For Application Load Balancer and AWS AppSync protection packs, the body inspection limit is fixed at 8 KB.  This limit cannot be increased today. If you need a larger amount of body inspected, consider adding CloudFront or using another AWS WAF suppported regional service such as API Gateway.

### Allowing Specific Oversized Requests

If specific endpoints legitimately receive oversized requests (e.g., file upload endpoints), you should block oversized requests everywhere except those endpoints rather than allowing them. This keeps the rest of your protection pack rules in effect for those requests.

```json
{
  "Name": "block-oversized-body-except-uploads",
  "Priority": 5,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "SizeConstraintStatement": {
            "FieldToMatch": { "Body": {} },
            "ComparisonOperator": "GT",
            "Size": 8192,
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "OversizeHandling": "MATCH"
          }
        },
        {
          "NotStatement": {
            "Statement": {
              "ByteMatchStatement": {
                "SearchString": "/upload",
                "FieldToMatch": { "UriPath": {} },
                "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
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
    "MetricName": "block-oversized-body-except-uploads"
  }
}
```
