# WAF Logging

## Storing AWS WAF logs

You can use [Amazon Data Firehose](https://docs.aws.amazon.com/firehose/latest/dev/what-is-this-service.html), [Amazon Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html), or [CloudWatch vended logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AWS-logs-and-resource-policy.html) to deliver WAF logs to various downstream destinations. AWS WAF logs can be sent to Amazon S3, Amazon CloudWatch Logs, or third-party destinations. See [AWS WAF logging destinations](https://docs.aws.amazon.com/waf/latest/developerguide/logging.html) for full details on each option.

### CloudWatch Logs

Logs are sent to a CloudWatch Log Group, which the native [AWS WAF dashboard](../../monitoring-waf-rules/docs/index.md) can query directly for built-in insights (top matched rules, blocked request trends, traffic breakdowns). CloudWatch Logs Insights provides ad-hoc querying.

> **Pros:** Fastest to set up; native AWS WAF dashboard works out of the box; no additional infrastructure needed; CloudWatch Logs Insights available for deeper queries.  
> **Cons:** Ingestion cost per GB is higher than S3; does not natively support cross-account or cross-region delivery.

**Note:** CloudWatch Log Groups are **not supported** as a logging destination when WAF is deployed through AWS Firewall Manager. You can centralize AWS WAF logs to a CloudWatch log group in a central account, but this is not supported natively and requires a non-trivial setup. First you set up a CloudWatch log group in the same region as the Protection Pack (`us-east-1` for global Protection Packs). Then define a [subscription filter with AWS Lambda](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html#LambdaFunctionExample). The Lambda function writes log events to a CloudWatch log group in your central account. You can also use Amazon Data Firehose with a cross-account delivery stream to centralize logs.

See [Monitoring WAF Rules](../../monitoring-waf-rules/docs/index.md) for information on using logs in CloudWatch Logs to monitor WAF behavior.

### Amazon S3

Amazon S3 is the most cost-effective native AWS option for storing AWS WAF logs. When using Amazon S3 for AWS WAF logs, they are typically stored in a central S3 bucket. In a protection pack you can specify the ARN of a bucket in any account or region. See [the documentation](https://docs.aws.amazon.com/waf/latest/developerguide/logging-s3.html) for information about the bucket policy changes you need.

There are three ways to get WAF logs into an S3 bucket:

1. **Amazon Data Firehose** — Provides additional capabilities such as partitioning log data (e.g., by date or account), configurable buffer size and durations, and transforming records before they are written to S3. When using Firewall Manager with Firehose, you only need a Firehose delivery stream in each region in the Firewall Manager administrator account — you do not need to create delivery streams in each member account where the web ACL is deployed.

2. **CloudWatch Vended Logs** — Delivers directly to S3 by specifying the target S3 bucket in the WAF logging configuration. This simplifies setup and reduces operational overhead compared to Firehose.

3. **Amazon Security Lake** — Captures WAF logs and stores them in S3 in OCSF-normalized format. This option may already be in place if your organization has centralized security data collection. With Security Lake, you do not need to enable WAF logging through Firewall Manager or WAF at all; you enable where you want to capture WAF logs from your Amazon Security Lake configuration instead. Security Lake has the same cost model as CloudWatch Vended Logs plus an OCSF ETL charge per GB. You pay slightly more up front, but query performance and cross-data-source query benefits are significant.

**Note:** Options 1 and 2 can store AWS WAF logs in the same account as the Protection Pack or in another/central AWS account. Option 3 only supports storing AWS WAF logs in a central account, however option 3 does not prevent an application team from enabling WAF logging themselves (not ideal due to duplicate log costs but possible).

Which approach is most cost-effective depends primarily on the volume of WAF logs you generate. At lower volumes, Firehose is typically cheaper; at very high log volumes (tens of billions of requests per month), the cost difference narrows or even flips to Vended Logs. See [WAF Costs](../../waf-cost/docs/index.md) for a detailed breakdown of WAF log cost estimation across destinations.

> **Pros:** Cost-effective for high volumes and long retention; supports cross-account and cross-region delivery; full SQL querying via Athena; integrates with Amazon QuickSight for dashboards.  
> **Cons:** Requires creating an Athena table to query and building a dashboard such as using [Amazon QuickSight](../../monitoring-waf-rules/docs/index.md#using-amazon-s3-and-athena); the native AWS WAF dashboard does not query WAF logs in S3.

See [AWS WAF pricing](https://aws.amazon.com/waf/pricing/) for current cost details on each approach.

### Third-party destinations (Splunk, Datadog, SIEM, etc.)

Logs are delivered via [Amazon Data Firehose](https://docs.aws.amazon.com/firehose/latest/dev/create-destination.html) to your existing centralized logging platform. Firehose supports delivering WAF logs directly to [third-party destinations](https://docs.aws.amazon.com/firehose/latest/dev/create-destination.html) such as Splunk, Datadog, New Relic, and other supported partners. This is useful if your organization uses a third-party SIEM or log analytics platform and you want WAF logs delivered there natively without an intermediate S3 step. See [Sending logs to an Amazon Data Firehose delivery stream](https://docs.aws.amazon.com/waf/latest/developerguide/logging-kinesis.html) for configuration details.

Amazon Data Firehose also supports writing to a primary destination while writing a secondary copy to S3. This can be useful if you have a compliance need to store logs long term but do not want to keep them in your SIEM or similar platform.

> **Pros:** Integrates with existing alerting, correlation, and investigation workflows; supports cross-account and cross-region delivery; good choice if your organization already has a centralized logging strategy.  
> **Cons:** Third-party platforms either have a license cost and/or operational burden on you; you are dependent on the third-party tool for querying and dashboards.

## Log retention

Unless you have a business or compliance reason to retain logs longer, configure log retention to cover only the lookback period you need to validate WAF rule impact against your traffic.

- **CloudWatch Logs** — Set the retention period on the log group (e.g., 30, 60, or 90 days). Logs older than the retention period are automatically deleted.
- **Amazon S3** — Use [S3 Lifecycle policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html) to transition logs to cheaper storage classes or expire them after a defined period.
- **Third-party destinations** — Retention is managed within the third-party platform according to its own policies and licensing.

## Filtering WAF logs

If you want to avoid logging fields that might contain sensitive data, you can [omit fields from AWS WAF logs](https://docs.aws.amazon.com/waf/latest/developerguide/logging-management.html). Note that AWS WAF does not log the HTTP body.

AWS WAF logs are detailed, as they can contain up to 100 rule labels. To optimize the cost of storing AWS WAF logs you can specify conditions that determine whether logs are kept or dropped (see [log filtering](https://docs.aws.amazon.com/waf/latest/developerguide/logging-management.html)). You can only filter based on rule labels and rule actions, not based on values in HTTP request fields.
