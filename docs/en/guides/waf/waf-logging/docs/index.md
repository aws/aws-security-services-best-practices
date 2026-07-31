# WAF Logging

AWS WAF can log every request it inspects, capturing the action taken, which rules matched, labels applied, and request details such as headers, query strings, source IP, etc. These logs are essential for validating that rules are working as intended, investigating security incidents, tuning rules to reduce false positives, and understanding traffic patterns over time. Without WAF logs, you cannot determine why a request was blocked or allowed, nor can you retroactively confirm whether your applications were targeted by a newly disclosed vulnerability.

AWS WAF supports multiple [delivery mechanisms and storage destinations](#which-logging-approach-is-right-for-you) — each with different advantages including cost, query performance, native ETL capabilities, and operational complexity. This page walks through the [native AWS log destinations](#native-aws-log-destinations) available and how to [query logs](#querying-waf-logs) depending on where you store them. You should also determine your [log retention](#log-retention) requirements — identify how long you need this data based on your operational use cases, compliance obligations, or incident response lookback periods — and decide whether to apply [log filtering](#log-filtering) to reduce volume by excluding traffic that does not provide business or security value.


## Log destinations  

AWS WAF logs can be sent to Amazon CloudWatch Logs, Amazon S3, Amazon OpenSearch Serverless, or third-party destinations. See [AWS WAF logging destinations](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html) for full details on each option.

| Dimension | CloudWatch Log Group | Amazon S3 | OpenSearch Serverless | Third-party (Splunk, Datadog, etc.) |
|---|---|---|---|---|
| **Delivery via** | CloudWatch Vended Logs | Firehose or CloudWatch Vended Logs | Firehose | Firehose |
| **Storage cost** | $0.03/GB/month | $0.023/GB/month (Standard); $0.004/GB/month (Glacier) | $0.30/GB/month (Managed Storage — Hot) | Platform Dependant |
| **Query cost** | $5/TB scanned (Logs Insights) | $5/TB scanned (Athena) | Included in OCU search capacity | Included in third-party license |
| **Query tool** | CloudWatch Logs Insights | Amazon Athena (SQL) | OpenSearch Dashboards / query DSL / SQL | Platform-native |
| **Built-in dashboard** | Native AWS WAF dashboard | None (add QuickSight) | OpenSearch Dashboards (included) | Platform-native |
| **Cross-account delivery** | Not supported | Yes | Yes (via Firehose) | Yes (via Firehose) |
| **Cross-region delivery** | Not supported | Yes | Yes (via Firehose) | Yes (via Firehose) |
| **Firewall Manager support** | Not supported as log destination | Yes | Yes (via Firehose) | Yes (via Firehose) |
| **Best for** | Fast setup; native WAF dashboard; moderate log volumes | Cost-effective long-term storage; high volumes; ad-hoc queries | Real-time dashboards; full-text search; frequent investigations | Existing SIEM/observability platform |



## Log delivery  

AWS WAF supports two delivery mechanisms. The delivery mechanism you choose determines which storage destination you can choose, how quickly logs reach your storage destination, what capabilities are available in transit and delivery cost. 

| Dimension | CloudWatch Vended Logs | Amazon Data Firehose |
|---|---|---|
| **Delivery frequency** | Up to every 5 minutes | Configurable from 60 seconds (best effort/buffer hints) * |
| **Time to first insight** **   | ~5 minutes from request inspection | 60 seconds (best effort/buffer hints) * from request inspection |
| **Delivery cost** | $0.50/GB vended log delivery charge (to S3); ingestion charge applies (to CloudWatch Logs) | $0.029/GB with a 5 KB minimum record size — effectively $0.145 per million WAF log records |
| **Supported storage destinations** | CloudWatch Logs, Amazon S3 | Amazon S3, OpenSearch Serverless, third-party (Splunk, Datadog, etc.) |
| **Cross-account delivery** | Yes (to S3); not supported (to CloudWatch Logs) | Yes |
| **Cross-region delivery** | Yes (to S3); not supported (to CloudWatch Logs) | Yes |
| **Firewall Manager support** | Yes (to S3); not supported (to CloudWatch Logs) | Yes |
| **ETL / transformation** | None | Record transformation via Lambda, format conversion, dynamic partitioning |
| **S3 prefix control** | Fixed per-minute structure | Fully customizable (recommended: hourly) |

\* Amazon Data Firehose allows the configuration of buffer hints, this is the desired delivery frequency/max buffer before delivery however these are uses as best effort and may not occur in all cases.  
\*\* Time to first insight refers to the time from when WAF inspects a request until that log record can be queried from the logging destination.  

If you are sending WAF logs to S3 and querying with Athena, the S3 prefix structure and Athena partitioning strategy you choose have a direct impact on query performance and cost. See [Effective log querying in S3](#effective-log-querying-in-s3) for detailed guidance.

## Log retention

Unless you have a business or compliance reason to retain logs longer, configure log retention to cover only the lookback period for how you use WAF logs. For many customers that do not have an explicit compliance requirement, 30 or 90 days is sufficient to support active investigation.

- **CloudWatch Logs** — Set the retention period on the log group (e.g., 30, 60, or 90 days). Logs older than the retention period are automatically deleted.
- **Amazon S3** — Use [S3 Lifecycle policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html) to transition logs to cheaper storage classes or expire them after a defined period.
- **Amazon OpenSearch Serverless** — Configure a [data lifecycle policy](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-lifecycle.html) on your time-series collection to automatically delete indexes older than your retention period.
- **Third-party destinations** — Retention is managed within the third-party platform according to its own policies and licensing.

## Field redaction

If you want to avoid logging fields that might contain sensitive data, you can [redact fields from AWS WAF logs](https://docs.aws.amazon.com/waf/latest/developerguide/logging-management.html). Note that AWS WAF logs never include the BODY. Certain types of Amazon Managed Rules will include the section of a body that matches the rule however.

Common headers to redact include `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`, and `X-Amz-Security-Token`. These are just examples — your application may use other headers or other request attributes such as query strings that contain sensitive information worth redacting. Review what your application sends and receives to determine what should not appear in WAF logs.

Redaction is permanent — once a field is redacted, that value is never written to the log and cannot be retrieved. If you later need that data for an investigation, it will not be available.

## Log filtering

AWS WAF allows you to filter which requests are sent to your logging destination. This is almost always used as a cost control — some traffic may not have the business value to justify the logging cost and can be skipped. There is no one universal right answer. Below are several common examples of what customers do or do not capture:

* A security team needs to be able to validate if a security incident occurred retroactively. They only log allowed traffic. If a request was blocked, security wise there is not a risk that the request somehow exploited the application in a way that was unknown or undetected. For example a new high severity CVE is announced, you need to validate if the query string pattern targeted your endpoints. Blocked requests do not matter — you were targeted or IP spraying happened to hit your endpoint, but they were blocked. Allowed traffic gives you detailed information about what exactly the request contained, where it went, etc. so you can focus the investigation for those applications.

* Your customer base is geo focused/restricted. Logging requests that are blocked by a *list of countries not to block* or *specific list of countries to block*. Custom rules enforcing this can emit a custom label and used to filter and not log these. The risk comes from geo IP lookup not being 100% reliable. A user that is from one geo but their IP for whatever reason comes up as another — you will not have a corresponding WAF log to investigate.

* High confidence rules, specifically in the context of DDoS. DDoS events produce high volumes of traffic, in some cases this could be hundreds, thousands, millions, or more times more traffic than you normally experience. In the specific context of logging, without log filtering, this also equates to a corresponding WAF logging cost spike. Using high confidence labels such as `awswaf:managed:aws:anti-ddos:low-suspicion-ddos-request` or `awswaf:managed:aws:amazon-ip-list:AWSManagedIPDDoSList` in most cases can remove all or reduce the majority of the DDoS spike from being logged.

**Reasons not to enable WAF log filtering**  
Without the WAF log for a given request, you will not be able to reliably identify why a WAF action was taken (or not taken), request attributes such as query string, headers, etc. For allowed requests, you *may* be able to get this from application logs if you have tehse enabled and they contain the relevant details.

## Which logging approach is right for you

### Quick Selection

| Destination | Best use cases |
|---|---|
| **CloudWatch Logs** | Simplest to set up and start using with AWS WAF with the native WAF dashboard.  Works well for single application/endpoint use cases. |
| **Amazon S3 + Athena** | Lowest retention cost; excellent for long-term retention such as compliance or audit requirements; ad-hoc queries that can tolerate longer execution times (incident investigation, periodic reviews); you already have an S3-based data lake strategy. Requires additional services (i.e. QuickSight) to produce dashboards. |
| **OpenSearch/OpenSearch Serverless** | Native dashboarding capability with much faster query times than Athena even at massive scale (you still need to build those dashboards); security teams performing frequent investigations; moderate to high log volumes where query frequency justifies the OCU baseline cost. OpenSearch Clusters (not serverless) require management and scaling operational effort.  |  
| **Third-party (Splunk, Datadog, etc.)** | Your organization already has a centralized SIEM/observability platform; you need WAF logs correlated with application logs, infrastructure metrics, and other security data in one tool; existing investment in third-party dashboards and alerting workflows. |

### Cost summary

| Dimension | CloudWatch Logs | Amazon S3 | OpenSearch Serverless | Third-party (Splunk, Datadog, etc.) |
|---|---|---|---|---|
| **Primary cost driver** | Ingestion | Storage | Managed Storage and/or Index OCU | Third-party license |
| **Cost per unit** | $0.50/GB ingested | $0.023/GB/month (Standard); $0.004/GB/month (Glacier) | $0.30/GB/month (Managed Storage — Hot); OCU $0.24/hr per OCU | License-dependent |
| **Storage cost** | $0.03/GB/month | $0.023/GB/month (Standard); $0.004/GB/month (Glacier) | $0.30/GB/month (Managed Storage — Hot); OCU $0.24/hr per OCU | License-dependent |
| **Query cost** | $5/TB scanned (Logs Insights) | $5/TB scanned (Athena) | Included in OCU search capacity | Included in third-party license |

### Recommendations

Start by considering how you intend to use WAF logs. If you plan to actively investigate WAF log data — incident response, rule tuning, traffic analysis — and your organization already operates a centralized SIEM or observability platform (Splunk, Datadog, OpenSearch, etc.), deliver WAF logs there via Firehose. Your team already has the workflows, dashboards, and alerting in place — avoid duplicating tooling and use what you already know.

For small teams or individual applications using WAF, use **CloudWatch Logs** with the native AWS WAF dashboard. This gives you immediate visibility with zero additional setup and is sufficient when you primarily need to validate rule behavior and troubleshoot recent traffic.

For centralized or organization-wide WAF log collection, the AWS natice choice between **Amazon S3** and **OpenSearch Serverless** depends on how you intend to consume the data. If your use case is periodic ad-hoc queries — incident investigations, compliance audits, rule impact reviews — S3 with Athena provides the lowest cost at rest and scales to any volume. If your use case is operational — frequent interactive queries, real-time dashboards, alerting on WAF patterns — OpenSearch Serverless provides the query performance and built-in visualization to support that without stitching together additional services (Athena + QuickSight).

Regardless of which destination you choose:

- **[Log retention](#log-retention)** — Set retention based on your compliance requirements or how long you need data for your use case (incident investigation lookback, rule tuning validation). If you do not have a specific requirement, 30 days is a good minimum — it provides enough historical traffic to validate rule changes and investigate recent incidents without accumulating unnecessary cost.
- **[Field redaction](#field-redaction)** — Redact any headers or request attributes that contain sensitive data (credentials, tokens, API keys). This prevents sensitive information from being stored in your log destination.
- **[Log filtering](#log-filtering)** — Many customers do not filter WAF logs. Consider filtering traffic that does not provide business or security value to reduce log volume and cost, depending on your use case.

## Considerations for logs stored in S3
### S3 prefix structure

CloudWatch Vended Logs and Amazon Data Firehose write WAF logs using different S3 prefix structures. Amazon Data Firehose allows you to customize the structure while CloudWatch Vended Logs does not. These prefix patterns directly affect how Amazon Athena partitions and queries your data.

CloudWatch Vended Logs writes with a fixed **per-minute** prefix structure:

```
AWSLogs/{AccountId}/WAFLogs/{Scope}/{WebAclName}/{YYYY}/{MM}/{dd}/{HH}/{mm}/log_file.log.gz
```

This prefix structure is set by the AWS WAF service and cannot be changed.

Amazon Data Firehose gives you control over the S3 prefix. Configuring **hourly** granularity produces 60x fewer partition paths for the same time range:

```
{BucketPrefix}/{YYYY}/{MM}/{dd}/{HH}/log_file.log.gz
```

The trade-off is that queries scoped to less than one hour still scan the full hour's data. Depending on your query patterns and partitioning strategy, this granularity difference can have a meaningful impact on query performance (see [Effective log querying in S3](#effective-log-querying-in-s3)).

### Effective log querying in S3  

When you query WAF logs stored in S3 using Amazon Athena, query performance depends on how your Athena table is partitioned. The examples below assume a WAF deployment producing 10 GB of logs per day and three common queries:

```sql
-- Single day
SELECT * FROM waf_logs
WHERE log_time >= '2026/06/25/00/00' AND log_time < '2026/06/26/00/00'

-- Specific 5-minute window
SELECT * FROM waf_logs
WHERE log_time >= '2026/06/25/14/30' AND log_time < '2026/06/25/14/35'

-- Last 30 days
SELECT * FROM waf_logs
WHERE log_time >= '2026/05/25/00/00' AND log_time < '2026/06/26/00/00'
```

**No partitions**  

Without partitions, Athena scans all data in the table every time you query, regardless of your `WHERE` clause. A query cannot target specific data based on time and must scan everything — Athena reads all objects and discards what doesn't match. This is not recommended for WAF logs due to the cost and time implications at any meaningful scale.

| Query Scope | Data Retention | Data Scanned | Data Used | Scan Time |
|---|---|---|---|---|
| 5 minutes | 30 days | 300 GB | 35 MB | ~43s |
| 5 minutes | 365 days | 3.6 TB | 35 MB | ~514s |
| 1 day | 30 days | 300 GB | 10 GB | ~43s |
| 1 day | 90 days | 900 GB | 10 GB | ~129s |
| 1 day | 365 days | 3.6 TB | 10 GB | ~514s |
| 30 days | 90 days | 900 GB | 300 GB | ~129s |
| 30 days | 365 days | 3.6 TB | 300 GB | ~514s |

**Recommendation: Partition Projection**  

You define partitions in your table construction that tell Athena how to compute where data might exist. Athena only checks and scans data from relevant date/times, making it more cost effective than no partitions. The trade-off is that Athena must do pre-work to resolve each partition path via S3 LIST calls before scanning begins. At scale (thousands of partitions), this can add meaningful time before each query starts — but you still only pay for the data actually scanned.

> **Pros:** No additional infrastructure or cost beyond the Athena table definition; only scans data within the queried timeframe; simple to set up.  
> **Cons:** Pre-work time grows linearly with the number of partitions in the query range; minute-level granularity with wide time ranges can result in significant delays before scanning begins.

The partition granularity available to you depends on how your logs are written to S3 — see [S3 prefix structure](#s3-prefix-structure). CloudWatch Vended Logs uses per-minute prefixes (1,440 partitions per day), while Amazon Data Firehose can be configured with hourly prefixes (24 partitions per day).

**Query for 1 day — Hourly Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 10 GB | 10 GB | 24 | <0.1s | ~1.4s | ~1.5s |
| 90 days | 10 GB | 10 GB | 24 | <0.1s | ~1.4s | ~1.5s |
| 365 days | 10 GB | 10 GB | 24 | <0.1s | ~1.4s | ~1.5s |

**Query for 1 day — Minute Partition Granularity**

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 10 GB | 10 GB | 1,440 | ~2.9s | ~1.4s | ~4.3s |
| 90 days | 10 GB | 10 GB | 1,440 | ~2.9s | ~1.4s | ~4.3s |
| 365 days | 10 GB | 10 GB | 1,440 | ~2.9s | ~1.4s | ~4.3s |

**Query for 5 minutes — Hourly Partition Granularity**  

With hourly partitions, a query targeting a 5-minute window still scans the entire hour's data because the hour is the smallest unit Athena can isolate. This is the trade-off of hourly granularity — narrow queries pay for the full hour.

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 417 MB | 35 MB | 1 | <0.1s | ~0.1s | ~0.1s |
| 90 days | 417 MB | 35 MB | 1 | <0.1s | ~0.1s | ~0.1s |
| 365 days | 417 MB | 35 MB | 1 | <0.1s | ~0.1s | ~0.1s |

**Query for 5 minutes — Minute Partition Granularity**

With minute partitions, Athena targets only the 5 relevant partitions and scans just the data within that window.

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 35 MB | 35 MB | 5 | <0.1s | <0.1s | <0.1s |
| 90 days | 35 MB | 35 MB | 5 | <0.1s | <0.1s | <0.1s |
| 365 days | 35 MB | 35 MB | 5 | <0.1s | <0.1s | <0.1s |

**Query for 30 days — Hourly Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 300 GB | 300 GB | 720 | ~1.4s | ~43s | ~44s |
| 90 days | 300 GB | 300 GB | 720 | ~1.4s | ~43s | ~44s |
| 365 days | 300 GB | 300 GB | 720 | ~1.4s | ~43s | ~44s |

**Query for 30 days — Minute Partition Granularity**

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 300 GB | 300 GB | 43,200 | ~86s | ~43s | ~129s |
| 90 days | 300 GB | 300 GB | 43,200 | ~86s | ~43s | ~129s |
| 365 days | 300 GB | 300 GB | 43,200 | ~86s | ~43s | ~129s |

**Partition Projection Summary**

Partition projection reduces how much data is scanned overall but depends on the partition size and query evaluation period.  Hourly granularity keeps pre-work negligible (seconds even for 30-day queries) but scans a full hour of data for narrow queries (417 MB scanned for a 5-minute window that contains 35 MB). Minute granularity scans only the exact data needed but introduces significant pre-work for wide time ranges — a 30-day query must resolve 43,200 partitions, adding tens of seconds or more before each scan begins. For short queries (single day or less), either granularity completes quickly. For wide queries (30+ days), hourly granularity finishes in ~44 seconds total while minute granularity takes ~129 seconds due to pre-work — even though both scan the same amount of data.

**Recommendation: Catalog-based Partitions (Glue Crawler)** 

You configure an AWS Glue Crawler to automatically discover and register partitions in the Glue Data Catalog. Athena queries the catalog directly to find matching partitions instead of issuing S3 LIST API calls per partition in scope; this removes almost all of the pre-work at query time. This requires initial Crawler setup and has a small per-run cost, but is a managed service with no ongoing maintenance once configured. See [WAF Costs](../../waf-cost/docs/index.md) for Glue Crawler cost details in the context of WAF logging. Similar to partition projection, Athena only scans data for the relevant time range however does not have the pre-work partition projection must complete per query. This is the most cost and time efficient approach per query.

> **Pros:** No pre-work delay regardless of partition count or granularity; only scans data within the queried timeframe; partition granularity (minute vs. hourly) has no impact on query time; managed service with no ongoing maintenance.  
> **Cons:** Requires initial Glue Crawler setup; small per-run cost for the Crawler; adds a dependency on the Glue Data Catalog.

**Query for 1 day — Hourly Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 10 GB | 10 GB | 24 | ~0.5s | ~1.4s | ~1.9s |
| 90 days | 10 GB | 10 GB | 24 | ~0.5s | ~1.4s | ~1.9s |
| 365 days | 10 GB | 10 GB | 24 | ~0.5s | ~1.4s | ~1.9s |

**Query for 1 day — Minute Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 10 GB | 10 GB | 1,440 | ~0.5s | ~1.4s | ~1.9s |
| 90 days | 10 GB | 10 GB | 1,440 | ~0.5s | ~1.4s | ~1.9s |
| 365 days | 10 GB | 10 GB | 1,440 | ~0.5s | ~1.4s | ~1.9s |

**Query for 5 minutes — Hourly Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 417 MB | 35 MB | 1 | ~0.5s | ~0.1s | ~0.6s |
| 90 days | 417 MB | 35 MB | 1 | ~0.5s | ~0.1s | ~0.6s |
| 365 days | 417 MB | 35 MB | 1 | ~0.5s | ~0.1s | ~0.6s |

**Query for 5 minutes — Minute Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 35 MB | 35 MB | 5 | ~0.5s | <0.1s | ~0.5s |
| 90 days | 35 MB | 35 MB | 5 | ~0.5s | <0.1s | ~0.5s |
| 365 days | 35 MB | 35 MB | 5 | ~0.5s | <0.1s | ~0.5s |

**Query for 30 days — Hourly Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 300 GB | 300 GB | 720 | ~0.5s | ~43s | ~43.5s |
| 90 days | 300 GB | 300 GB | 720 | ~0.5s | ~43s | ~43.5s |
| 365 days | 300 GB | 300 GB | 720 | ~0.5s | ~43s | ~43.5s |

**Query for 30 days — Minute Partition Granularity**  

| Data Retention | Data Scanned | Data Used | Partitions Scanned | Pre-work Time | Scan Time | Total Time |
|---|---|---|---|---|---|---|
| 30 days | 300 GB | 300 GB | 43,200 | ~0.5s | ~43s | ~43.5s |
| 90 days | 300 GB | 300 GB | 43,200 | ~0.5s | ~43s | ~43.5s |
| 365 days | 300 GB | 300 GB | 43,200 | ~0.5s | ~43s | ~43.5s |

**S3 querying summary**  

Always use date/time ranges for queries — both CloudWatch Log Insights and Athena bill based on data scanned ($5/TB scanned). Only keep logs as long as you need them.

If you send WAF logs to S3 using CloudWatch Vended Logs:
- A Glue Crawler is recommended; it is a one-time setup with a <1% cost impact on a WAF logging cost estimate and can significantly reduce total query execution time.
- Partition projection can be acceptable if you rarely expect to query WAF logs. The trade-off is queries hit more partitions and can result in longer overall query times.

If you send WAF logs to S3 using Amazon Data Firehose:
- If you use a Glue Crawler, per-minute granularity has no meaningful impact on scan cost or pre-work time per query.
- If you do **not** use a Glue Crawler, hourly granularity reduces the pre-work per query execution to 1/60th.
- Firehose can be configured to send data every 60 seconds (buffer hint), meaning new WAF logs show up in approximately 1 minute.

Unless you require a specific feature of Amazon Data Firehose (buffer delivery time, ETL), use the delivery mechanism that is most cost effective for you. If this is CloudWatch Vended Logs, set up a Glue Crawler so queries are performant. If you use Amazon Data Firehose, either write logs in hourly prefixes to S3 or ensure you also create a Glue Crawler.
