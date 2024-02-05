# Monitoring WAF Rules

## Analyzing AWS WAF metrics

Using [CloudWatch metrics for AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html) you can create graphs on a dashboard that show over time how many requests were allowed, blocked, or counted by each rule in a web ACL. You can also see the same metrics by label.

These metrics are useful in a few scenarios.

* Monitor the rate of requests matched by a new rule in *Count* mode before you decide to switch it to *Block* mode.
* Create an alarm that triggers when there is a spike of blocked or counted requests. This could indicate a threat that needs investigation.
* Determine which rule is contributing the most blocked requests over the past few days. This can help you isolate a rule that is not working as intended.
* Create an alarm that triggers when a rule in the [Shield Advanced rule group](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-automatic-app-layer-response-rg.html) starts blocking or counting a high number of requests.

## Analyzing AWS WAF logs

When storing AWS WAF logs in CloudWatch Logs, you can use Contributor Insights and Logs Insights to visualize logs with a CloudWatch dashboard. See the blog [Visualize AWS WAF logs with an Amazon CloudWatch dashboard](https://aws.amazon.com/blogs/security/visualize-aws-waf-logs-with-an-amazon-cloudwatch-dashboard/).

You can [analyze your AWS WAF logs in Amazon S3 using Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/waf-logs.html). The documentation provides example queries as a starting point.

You can leverage your Athena queries to [create a dashboard in Amazon QuickSight](https://aws.amazon.com/blogs/security/enabling-serverless-security-analytics-using-aws-waf-full-logs/).