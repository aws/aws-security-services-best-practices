<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# Scopes

## Overview

A scope defines where NSM policies apply. When you deploy an NSM policy, the NSM deployment connects it to a scope, and NSM applies the NSM policy to every protected AWS resource that the scope selects. Because a scope is its own NSM resource, you can reuse one scope across many NSM deployments, and update it once to change where every NSM policy that uses it applies. Like other NSM resources, scopes support versions and drafts. For more information, see [Versioning and Drafts](../../prerequisites/docs/index.md#versioning-and-drafts).

!!! info "Make scopes match how you already work"
    Scopes are flexible by design. You can select resources by account, OU, resource type, tag, ARN, and resource property, and combine them with AND, OR, and NOT. Use that flexibility to match how your organization already identifies its applications and environments. Don't change how you organize accounts or tag resources to fit NSM.

    The scopes on this page, including the common scopes and the scope examples, show how to use that flexibility. They aren't a required structure. If your organization identifies applications by account, build scopes by account. If it uses tags, build scopes by tag.

## Best practices

**Build scopes from your existing organization structure**

Scopes support account IDs, organizational units (OUs), resource types, tags, Amazon Resource Names (ARNs), and resource properties, combined with AND, OR, and NOT logic. Build scopes from the accounts, OUs, tags, and resource properties that you already have, instead of reorganizing around NSM.

<!-- TODO -->

**Reuse shared scopes, owned by a central team**

Because a scope is its own resource, you can update it once and every NSM policy that uses it picks up the change. Reuse shared scopes such as **All Public Facing Resources** instead of creating a copy for each NSM policy. When more than one team uses NSM, a central team should own the shared scopes, so that every team that reuses them can rely on what they select.

**Use separate scopes when different teams own them**

We recommend that each scope have one owning team, and that teams don't edit a scope that another team owns. Because a change to a scope changes where every NSM policy that uses it applies, one owner for each scope means that a team can't move another team's NSM policies by accident. When a team needs a variation of a shared scope, it creates its own scope instead of changing the shared one.

Be careful when other teams reuse a scope that one team created for its own use. A broad, stable scope, such as **All Public Facing Resources**, is a good one to share. A scope created for one application or for a tactical need, such as a short-term incident response, can look broad but change whenever the owning team's needs change. If other teams reuse it, have the central team take it over as a shared scope, or have each team create its own.

<a id="common-scopes"></a>
**Common scopes**

The recommended NSM policies for every firewall type use the following common scopes. Add scopes that are specific to one firewall type, such as VPCs or subnets for AWS Network Firewall, to this list. Build each scope from the accounts, OUs, tags, and resource properties that you already have. One scope can include CloudFront distributions or regional resources, but not both, so a common scope that covers both is a pair of scopes, one for each.

* [**All Public Facing Resources**](#all-public-facing-resources) – Starts at the organization root. Includes all CloudFront distributions and API Gateway stages, plus Application Load Balancers where the scheme is internet-facing.
* [**Technology apps**](#technology-apps) – One scope for each technology that a use-case AMR rule group protects, such as WordPress, PHP, SQL database, Linux, POSIX, or Windows. For example, a **WordPress apps** scope matches resources tagged `app-type = WordPress`. Use the tagging convention that your application teams already follow.
* [**Application**](#application) – One scope for each application, such as **App1**. Build it from the application's account, tags, or, when no other option fits, ARNs. Keep these scopes narrow, so that each NSM policy reaches only the web ACLs that need it.

<!-- TODO -->

**Scope examples**

For JSON examples of each common scope, see [Scope examples](#scope-examples).

## How a scope selects resources

A scope configuration has two parts, which accounts are in scope and which resources in those accounts are in scope.

**Account filter**

The account filter selects accounts and organizational units (OUs). Set exactly one of the following:

* `includeAll` – Every account in the organization.
* `include` – Only the listed account IDs and OUs.
* `exclude` – Every account except the listed account IDs and OUs.

If you use NSM across an organization, every scope must have an account filter. If you use NSM in a single account, omit the account filter, and the scope applies only to your own account. You can't add or remove the account filter after you create the scope.

**Resource scopes**

Resource scopes select resources by resource type. For each resource type, set exactly one of the following:

* `includeAll` – Every resource of that type in the selected accounts.
* `include` – Only the resources that match.
* `exclude` – Every resource of that type except the resources that match.

The `include` and `exclude` members match resources with an explicit list of ARNs (`explicitArns`), an expression (`expression`), or both. An expression is a condition (`criteria`) that matches a tag or a resource-type-specific property, such as the scheme of an Application Load Balancer, or combines other expressions with `and`, `or`, and `not`.

Scopes support the following resource types:

| Resource type | Resource | Global or Regional |
|---|---|---|
| `AWS::CloudFront::Distribution` | Amazon CloudFront distribution | Global |
| `AWS::ElasticLoadBalancingV2::LoadBalancer::application` | Application Load Balancer | Regional |
| `AWS::ApiGateway::Stage` | Amazon API Gateway REST API stage | Regional |
| `AWS::ElasticLoadBalancing::LoadBalancer` | Classic Load Balancer | Regional |
| `AWS::EC2::EIP` | Elastic IP address | Regional |

**Global and regional resources need separate scopes**

One scope can include CloudFront distributions or regional resources, but not both. When you want an NSM policy to apply to both, create one scope for CloudFront distributions and one for regional resources. Each NSM deployment has exactly one scope, so deploy the NSM policy with one NSM deployment for each scope.

## Scope examples

The following examples show the common scopes that the recommended NSM policies for each firewall type use. Each example is a request body for the NSM `CreateScope` API, for an organization that uses NSM across multiple accounts. Account IDs, OU IDs, and ARNs are placeholders.

In AWS CloudFormation, the `AWS::NetworkSecurityManager::Scope` resource takes the scope configuration as a JSON string, and member names start with a capital letter, such as `AccountFilter` and `ResourceScopes`.

### All Public Facing Resources

Starts at the organization root. Includes all CloudFront distributions, and all API Gateway stages and the Application Load Balancers where the scheme is internet-facing. Because CloudFront distributions and regional resources need separate scopes, this common scope is a pair of scopes, one for each.

**All Public Facing Resources - CloudFront**

```json
{
  "scopeName": "All Public Facing Resources - CloudFront",
  "scopeDescription": "Every CloudFront distribution in the organization.",
  "scopeConfiguration": {
    "accountFilter": {
      "includeAll": {}
    },
    "resourceScopes": {
      "AWS::CloudFront::Distribution": {
        "includeAll": true
      }
    }
  }
}
```

**All Public Facing Resources - Regional**

```json
{
  "scopeName": "All Public Facing Resources - Regional",
  "scopeDescription": "Every public-facing regional resource in the organization.",
  "scopeConfiguration": {
    "accountFilter": {
      "includeAll": {}
    },
    "resourceScopes": {
      "AWS::ApiGateway::Stage": {
        "includeAll": true
      },
      "AWS::ElasticLoadBalancingV2::LoadBalancer::application": {
        "include": {
          "expression": {
            "criteria": {
              "albConfig": {
                "scheme": "internet-facing"
              }
            }
          }
        }
      }
    }
  }
}
```

Scopes don't have a property condition for the API Gateway endpoint type, so this scope includes private API stages. To leave private API stages out, use `exclude` with a tag or with their ARNs.

### Technology apps

One scope for each technology that a use-case AMR rule group protects, such as WordPress, PHP, SQL database, Linux, POSIX, or Windows. The following **WordPress apps** example matches resources tagged `app-type = WordPress` anywhere in the organization. Use the tagging convention that your application teams already follow. Because CloudFront distributions and regional resources need separate scopes, this common scope is a pair of scopes, one for each.

**WordPress apps - CloudFront**

```json
{
  "scopeName": "WordPress apps - CloudFront",
  "scopeDescription": "CloudFront distributions that serve WordPress applications.",
  "scopeConfiguration": {
    "accountFilter": {
      "includeAll": {}
    },
    "resourceScopes": {
      "AWS::CloudFront::Distribution": {
        "include": {
          "expression": {
            "criteria": {
              "tags": {
                "app-type": "WordPress"
              }
            }
          }
        }
      }
    }
  }
}
```

**WordPress apps - Regional**

```json
{
  "scopeName": "WordPress apps - Regional",
  "scopeDescription": "Regional resources that serve WordPress applications.",
  "scopeConfiguration": {
    "accountFilter": {
      "includeAll": {}
    },
    "resourceScopes": {
      "AWS::ApiGateway::Stage": {
        "include": {
          "expression": {
            "criteria": {
              "tags": {
                "app-type": "WordPress"
              }
            }
          }
        }
      },
      "AWS::ElasticLoadBalancingV2::LoadBalancer::application": {
        "include": {
          "expression": {
            "criteria": {
              "tags": {
                "app-type": "WordPress"
              }
            }
          }
        }
      }
    }
  }
}
```

These scopes match WordPress-tagged resources whether they're public-facing or internal. To match only one business unit's WordPress applications, replace `includeAll` in the account filter with `include` and that business unit's OU.

### Application

One scope for each application, such as **App1**. Keep these scopes narrow, so that each NSM policy reaches only the resources that need it. If an application uses both CloudFront distributions and regional resources, create one scope for each. You can scope to an application in three ways, and combine conditions when one isn't specific enough. Choose the one that matches how your organization already identifies the application.

**By account**

When the application has its own account, select that account. The following example selects every CloudFront distribution in the App1 account.

```json
{
  "scopeName": "App1",
  "scopeDescription": "App1 CloudFront distributions, selected by account.",
  "scopeConfiguration": {
    "accountFilter": {
      "include": {
        "accountIds": [
          "222222222222"
        ]
      }
    },
    "resourceScopes": {
      "AWS::CloudFront::Distribution": {
        "includeAll": true
      }
    }
  }
}
```

**By tag**

When the application shares accounts with other applications, select the resources that carry the application's tag. The following example selects every Application Load Balancer tagged `application = app1`, in any account.

```json
{
  "scopeName": "App1",
  "scopeDescription": "App1 Application Load Balancers, selected by tag.",
  "scopeConfiguration": {
    "accountFilter": {
      "includeAll": {}
    },
    "resourceScopes": {
      "AWS::ElasticLoadBalancingV2::LoadBalancer::application": {
        "include": {
          "expression": {
            "criteria": {
              "tags": {
                "application": "app1"
              }
            }
          }
        }
      }
    }
  }
}
```

**By ARN**

When no other option fits, list the application's resources by ARN. A scope built from ARNs doesn't pick up new resources on its own, so you must update it each time the application adds or replaces a resource.

```json
{
  "scopeName": "App1",
  "scopeDescription": "App1 CloudFront distribution, selected by ARN.",
  "scopeConfiguration": {
    "accountFilter": {
      "include": {
        "accountIds": [
          "222222222222"
        ]
      }
    },
    "resourceScopes": {
      "AWS::CloudFront::Distribution": {
        "include": {
          "explicitArns": [
            "arn:aws:cloudfront::222222222222:distribution/EDFDVBD6EXAMPLE"
          ]
        }
      }
    }
  }
}
```

**By combining conditions with AND, OR, and NOT**

When one tag or one account isn't specific enough, combine conditions in an expression. Use `and` when a resource must match every condition, `or` when it must match at least one, and `not` when it must not match. An expression can be at most two levels deep, so an `and` or `or` can contain conditions but not another `and`, `or`, or `not`.

*AND: App1's production, internet-facing Application Load Balancers*

App1 shares accounts with other applications and has both production and test Application Load Balancers. The following example selects only Application Load Balancers that are tagged `application = app1`, are tagged `environment = production`, and are internet-facing.

```json
{
  "scopeName": "App1 - Production",
  "scopeDescription": "App1 production, internet-facing Application Load Balancers.",
  "scopeConfiguration": {
    "accountFilter": {
      "includeAll": {}
    },
    "resourceScopes": {
      "AWS::ElasticLoadBalancingV2::LoadBalancer::application": {
        "include": {
          "expression": {
            "and": [
              {
                "criteria": {
                  "tags": {
                    "application": "app1"
                  }
                }
              },
              {
                "criteria": {
                  "tags": {
                    "environment": "production"
                  }
                }
              },
              {
                "criteria": {
                  "albConfig": {
                    "scheme": "internet-facing"
                  }
                }
              }
            ]
          }
        }
      }
    }
  }
}
```

*OR and NOT: App1's regional resources across two accounts*

App1 runs in two accounts. Its API Gateway stages carry one of two tags, because the team renamed the application, and its account also has sandbox Application Load Balancers that NSM policies for App1 shouldn't reach. The following example selects App1's API Gateway stages that are tagged `application = app1` or `application = app1-legacy`, and every Application Load Balancer in those accounts that isn't tagged `environment = sandbox`.

```json
{
  "scopeName": "App1 - Regional",
  "scopeDescription": "App1 API Gateway stages under either tag, and non-sandbox Application Load Balancers, in App1's accounts.",
  "scopeConfiguration": {
    "accountFilter": {
      "include": {
        "accountIds": [
          "222222222222",
          "333333333333"
        ]
      }
    },
    "resourceScopes": {
      "AWS::ApiGateway::Stage": {
        "include": {
          "expression": {
            "or": [
              {
                "criteria": {
                  "tags": {
                    "application": "app1"
                  }
                }
              },
              {
                "criteria": {
                  "tags": {
                    "application": "app1-legacy"
                  }
                }
              }
            ]
          }
        }
      },
      "AWS::ElasticLoadBalancingV2::LoadBalancer::application": {
        "include": {
          "expression": {
            "not": {
              "criteria": {
                "tags": {
                  "environment": "sandbox"
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Because an `and` or `or` can't contain a `not`, you can't write "tagged `application = app1` and not tagged `environment = sandbox`" as one expression. To get the same result, tag the resources that you want, or narrow the account filter so that `not` applies only within the application's accounts, as in the preceding example.
