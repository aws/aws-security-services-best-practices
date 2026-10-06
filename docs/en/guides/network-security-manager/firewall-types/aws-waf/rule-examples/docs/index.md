<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# Rule Examples

!!! info "Looking for which NSM policy each NSM rule belongs in?"
    The recommended design shows how these NSM rules combine into NSM policies, with the priority, scope, and business need for each.

    **[AWS WAF Recommended Design →](../../recommended-design/docs/index.md)**

## Overview

This section describes the configuration of each NSM rule that the NSM policies in [AWS WAF Recommended Design](../../recommended-design/docs/index.md) contain.

<!-- TODO -->

## NSM firewall configuration rules

### WAF logging

Sends WAF logs from every in-scope web ACL to a central log destination.

The following example sends WAF logs to an Amazon S3 bucket.

```json
{
  "LoggingConfiguration": {
    "LogDestinationConfigs": [
      "aws-waf-logs-111111111111-us-east-1"
    ],
    "LogType": "WAF_LOGS",
    "LogScope": "CUSTOMER"
  }
}
```

The following example sends WAF logs to an Amazon Data Firehose delivery stream.

```json
{
  "LoggingConfiguration": {
    "LogDestinationConfigs": [
      "arn:aws:firehose:us-east-1:111111111111:deliverystream/aws-waf-logs-central"
    ],
    "LogType": "WAF_LOGS",
    "LogScope": "CUSTOMER"
  }
}
```

The following example redacts the `authorization` and `cookie` headers from logs, and keeps only the logs for requests that a WAF rule blocked or counted.

```json
{
  "LoggingConfiguration": {
    "LogDestinationConfigs": [
      "arn:aws:firehose:us-east-1:111111111111:deliverystream/aws-waf-logs-central"
    ],
    "LogType": "WAF_LOGS",
    "LogScope": "CUSTOMER",
    "RedactedFields": [
      {
        "SingleHeader": {
          "Name": "authorization"
        }
      },
      {
        "SingleHeader": {
          "Name": "cookie"
        }
      }
    ],
    "LoggingFilter": {
      "Filters": [
        {
          "Behavior": "KEEP",
          "Requirement": "MEETS_ANY",
          "Conditions": [
            {
              "ActionCondition": {
                "Action": "BLOCK"
              }
            },
            {
              "ActionCondition": {
                "Action": "COUNT"
              }
            }
          ]
        }
      ],
      "DefaultBehavior": "DROP"
    }
  }
}
```

<!-- TODO -->

### Default action

Sets the web ACL default action for requests that no WAF rule blocks.

```json
{
  "DefaultAction": {
    "Allow": {}
  }
}
```

<!-- TODO -->

### Token domains

Sets the token domains that AWS WAF accepts for CAPTCHA and Challenge tokens.

```json
{
  "TokenDomains": [
    "example.com"
  ]
}
```

<!-- TODO -->

### Visibility configuration

Turns on Amazon CloudWatch metrics and sampled requests for the web ACL.

```json
{
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "nsm-web-acl"
  }
}
```

<!-- TODO -->

## Managed rule group NSM rules

### Anti-DDoS

Adds the Anti-DDoS AMR rule group (`AWSManagedRulesAntiDDoSRuleSet`) with every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesAntiDDoSRuleSet",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesAntiDDoSRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesAntiDDoSRuleSet": {
            "ClientSideActionConfig": {
              "Challenge": {
                "UsageOfAction": "ENABLED",
                "Sensitivity": "HIGH",
                "ExemptUriRegularExpressions": [
                  {
                    "RegexString": "\\/api\\/|\\.(acc|avi|css|gif|jpe?g|js|mp[34]|ogg|otf|pdf|png|tiff?|ttf|webm|webp|woff2?)$"
                  }
                ]
              }
            },
            "SensitivityToBlock": "LOW"
          }
        }
      ]
    }
  },
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesAntiDDoSRuleSet"
  }
}
```

<!-- TODO -->

### Amazon IP reputation list

Adds the Amazon IP reputation list AMR rule group (`AWSManagedRulesAmazonIpReputationList`) with every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesAmazonIpReputationList",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesAmazonIpReputationList"
    }
  },
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesAmazonIpReputationList"
  }
}
```

<!-- TODO -->

### Anonymous IP list

Adds the anonymous IP list AMR rule group (`AWSManagedRulesAnonymousIpList`) with every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesAnonymousIpList",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesAnonymousIpList"
    }
  },
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesAnonymousIpList"
  }
}
```

<!-- TODO -->

### Core Rule Set

Adds the Core Rule Set AMR rule group (`AWSManagedRulesCommonRuleSet`) with every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesCommonRuleSet",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesCommonRuleSet"
    }
  },
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesCommonRuleSet"
  }
}
```

<!-- TODO -->

### Known Bad Inputs

Adds the Known Bad Inputs AMR rule group (`AWSManagedRulesKnownBadInputsRuleSet`) with every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesKnownBadInputsRuleSet",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesKnownBadInputsRuleSet"
    }
  },
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesKnownBadInputsRuleSet"
  }
}
```

<!-- TODO -->

### Use-case AMRs

Adds one use-case AMR rule group, such as WordPress, SQL database, Linux, POSIX, Windows, or PHP, with every WAF rule in count mode.

The following example uses the WordPress AMR rule group. The other use-case AMRs use the same structure with their own rule group names.

```json
{
  "Name": "AWS-AWSManagedRulesWordPressRuleSet",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesWordPressRuleSet"
    }
  },
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesWordPressRuleSet"
  }
}
```

<!-- TODO -->

### Partner managed rule groups

Adds an AWS Marketplace partner managed rule group.

```json
{
  "Name": "ExampleVendor-ExampleRuleGroup",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "ExampleVendor",
      "Name": "ExampleRuleGroup"
    }
  },
  "OverrideAction": {
    "None": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "ExampleVendor-ExampleRuleGroup"
  }
}
```

<!-- TODO -->

### Bot Control

Adds the Bot Control AMR rule group (`AWSManagedRulesBotControlRuleSet`) with a scope-down statement and every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesBotControlRuleSet",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesBotControlRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesBotControlRuleSet": {
            "InspectionLevel": "COMMON"
          }
        }
      ],
      "ScopeDownStatement": {
        "NotStatement": {
          "Statement": {
            "ByteMatchStatement": {
              "FieldToMatch": {
                "UriPath": {}
              },
              "PositionalConstraint": "STARTS_WITH",
              "SearchString": "/static/",
              "TextTransformations": [
                {
                  "Priority": 0,
                  "Type": "NONE"
                }
              ]
            }
          }
        }
      }
    }
  },
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesBotControlRuleSet"
  }
}
```

<!-- TODO -->

### Account Takeover Prevention

Adds the Account Takeover Prevention (ATP) AMR rule group (`AWSManagedRulesATPRuleSet`), scoped down to an application's login page, with every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesATPRuleSet",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesATPRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesATPRuleSet": {
            "LoginPath": "/api/login",
            "RequestInspection": {
              "PayloadType": "JSON",
              "UsernameField": {
                "Identifier": "/username"
              },
              "PasswordField": {
                "Identifier": "/password"
              }
            },
            "EnableRegexInPath": false
          }
        }
      ],
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "FieldToMatch": {
            "UriPath": {}
          },
          "PositionalConstraint": "STARTS_WITH",
          "SearchString": "/api/login",
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
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesATPRuleSet"
  }
}
```

<!-- TODO -->

### Account Creation Fraud Prevention

Adds the Account Creation Fraud Prevention (ACFP) AMR rule group (`AWSManagedRulesACFPRuleSet`), scoped down to an application's sign-up page, with every WAF rule in count mode.

```json
{
  "Name": "AWS-AWSManagedRulesACFPRuleSet",
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesACFPRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesACFPRuleSet": {
            "CreationPath": "/api/signup",
            "RegistrationPagePath": "/signup",
            "RequestInspection": {
              "PayloadType": "JSON",
              "UsernameField": {
                "Identifier": "/username"
              },
              "PasswordField": {
                "Identifier": "/password"
              },
              "EmailField": {
                "Identifier": "/email"
              }
            },
            "EnableRegexInPath": false
          }
        }
      ],
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "FieldToMatch": {
            "UriPath": {}
          },
          "PositionalConstraint": "STARTS_WITH",
          "SearchString": "/api/signup",
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
  "OverrideAction": {
    "Count": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "AWS-AWSManagedRulesACFPRuleSet"
  }
}
```

<!-- TODO -->

## Custom NSM rules

### IP allow list

Allows requests from trusted addresses, with one IP set for IPv4 and one for IPv6 combined in an OR statement in a single WAF rule.

```json
{
  "Name": "IP-allow-list",
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "IPSetReferenceStatement": {
            "ARN": "arn:aws:wafv2:us-east-1:111111111111:global/ipset/trusted-ips-v4/a1b2c3d4-5678-90ab-cdef-EXAMPLE22222"
          }
        },
        {
          "IPSetReferenceStatement": {
            "ARN": "arn:aws:wafv2:us-east-1:111111111111:global/ipset/trusted-ips-v6/a1b2c3d4-5678-90ab-cdef-EXAMPLE33333"
          }
        }
      ]
    }
  },
  "Action": {
    "Allow": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "IP-allow-list"
  }
}
```

<!-- TODO -->

### IP block list

Blocks requests from addresses that you don't want to reach your applications, such as addresses from threat intelligence, with one IP set for IPv4 and one for IPv6 combined in an OR statement in a single WAF rule.

```json
{
  "Name": "IP-block-list",
  "Statement": {
    "OrStatement": {
      "Statements": [
        {
          "IPSetReferenceStatement": {
            "ARN": "arn:aws:wafv2:us-east-1:111111111111:global/ipset/blocked-ips-v4/a1b2c3d4-5678-90ab-cdef-EXAMPLE44444"
          }
        },
        {
          "IPSetReferenceStatement": {
            "ARN": "arn:aws:wafv2:us-east-1:111111111111:global/ipset/blocked-ips-v6/a1b2c3d4-5678-90ab-cdef-EXAMPLE55555"
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
    "MetricName": "IP-block-list"
  }
}
```

<!-- TODO -->

### Geo blocking

Blocks requests from a list of blocked countries, or from every country that isn't on an allowed list.

The following example blocks every country that isn't on an allowed list.

```json
{
  "Name": "Geo-block-not-allowed-countries",
  "Statement": {
    "NotStatement": {
      "Statement": {
        "GeoMatchStatement": {
          "CountryCodes": [
            "US",
            "CA"
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
    "MetricName": "Geo-block-not-allowed-countries"
  }
}
```

<!-- TODO -->

### Blanket rate limit

Blocks clients, usually by IP address, that exceed a high request rate across all requests.

```json
{
  "Name": "Rate-limit-blanket",
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
    "MetricName": "Rate-limit-blanket"
  }
}
```

<!-- TODO -->

### Scoped rate limits

Block clients that exceed a lower request rate for a specific HTTP method or URI.

```json
{
  "Name": "Rate-limit-login",
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "FieldToMatch": {
            "UriPath": {}
          },
          "PositionalConstraint": "STARTS_WITH",
          "SearchString": "/api/login",
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
    "MetricName": "Rate-limit-login"
  }
}
```

<!-- TODO -->

### Application exceptions

Add an exception label to requests that one application needs to exempt from one WAF rule in an AMR rule group. The following example exempts App1's `/custom-feature/` path from the Core Rule Set `CrossSiteScripting_Body` WAF rule.

```json
{
  "Name": "App1-AMR-exception",
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
              {
                "Priority": 0,
                "Type": "LOWERCASE"
              }
            ]
          }
        },
        {
          "ByteMatchStatement": {
            "FieldToMatch": {
              "UriPath": {}
            },
            "PositionalConstraint": "STARTS_WITH",
            "SearchString": "/custom-feature/",
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
    "Count": {}
  },
  "RuleLabels": [
    {
      "Name": "exception:core-rule-set:CrossSiteScripting_Body"
    }
  ],
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "App1-AMR-exception"
  }
}
```

<!-- TODO -->

### Application-specific protections

Add protections that only one application needs.

The following example blocks requests to an administration path that App1 doesn't expose publicly.

```json
{
  "Name": "App1-block-admin-path",
  "Statement": {
    "ByteMatchStatement": {
      "FieldToMatch": {
        "UriPath": {}
      },
      "PositionalConstraint": "STARTS_WITH",
      "SearchString": "/admin/",
      "TextTransformations": [
        {
          "Priority": 0,
          "Type": "NONE"
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
    "MetricName": "App1-block-admin-path"
  }
}
```

<!-- TODO -->

### AMR block with exceptions

Blocks requests that carry one AMR label, unless the request also carries the matching exception label. Create one NSM rule like this for each unique label that the AMR rule groups add, so that an exception for one AMR WAF rule never exempts a request from another.

The following example blocks requests that the Core Rule Set `CrossSiteScripting_Body` WAF rule labeled, unless they carry the `exception:core-rule-set:CrossSiteScripting_Body` label.

```json
{
  "Name": "Block-CRS-CrossSiteScripting_Body-unless-excepted",
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
                "Key": "exception:core-rule-set:CrossSiteScripting_Body"
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
    "MetricName": "Block-CRS-CrossSiteScripting_Body-unless-excepted"
  }
}
```

<!-- TODO -->
