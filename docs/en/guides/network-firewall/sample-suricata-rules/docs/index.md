# Sample Suricata rules

!!! info "Prerequisites"
    This section assumes familiarity with [Customer managed rules](../../customer-managed-rules/docs/index.md). Review that topic first for foundational concepts like `flow:to_server`, rule types, and domain filtering patterns.

AWS Network Firewall uses Suricata rule syntax for stateful inspection, and this page provides individual rule examples explained by use case, covering the most common filtering scenarios including domain category blocking, direct-to-IP blocking, GeoIP filtering, port/protocol enforcement, and domain allowlisting. Each rule includes what it does, why you want it, and when to use or skip it.

If you are just getting started with Network Firewall and want a complete, ready-to-deploy policy that implements these best practices, see the [Getting started policy](../../getting-started-policy/docs/index.md) page. It includes a deployable CloudFormation and Terraform template with 15 managed rule groups and recommended policy settings.

This page is organized with the most widely used blocking rules first, followed by alerting rules for visibility, then allowlist patterns, and finally advanced options like custom default block rules at the bottom.

## How to use this page

Browse the rules below and identify which ones apply to your environment. Most customers will want the domain category blocking, direct-to-IP blocking, and port/protocol enforcement rules as a starting point. Copy the rules you need, adjust the `msg:` fields and SIDs to match your naming convention, and deploy in alert-only mode first (change `reject`/`drop` to `alert`) to validate before enforcing.

A [complete rules template](#complete-rules-template) at the bottom of this page shows how these rules fit together in a single ruleset using the recommended "Application drop established (server-directed only)" default action from [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md).

!!! note "About flow:to_server in these samples"
    Every rule on this page carries `flow:to_server` for consistency, including the application-layer rules. On a `tcp`, `udp`, or `ip` protocol rule the keyword is doing real work: it stops Suricata from treating the rule as IP-only and acting on the first packet of the flow. On rules whose protocol field is an application-layer protocol (`tls`, `http`, `ssh`) or that match an application-layer buffer (`tls.sni`, `http.host`), it is harmless but not required. See [Which rules need a flow: keyword](../../customer-managed-rules/docs/index.md#which-rules-need-a-flow-keyword).

---

## Blocking rules

These rules actively block or reject traffic. They represent the most common and useful custom rules customers deploy on Network Firewall.

### Domain category blocking

For official documentation on this feature, see [URL and domain filtering](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-url-filtering.html).

```
reject tls $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_domain_category:Command and Control; ja4.hash; content:"_"; flow:to_server; sid:202602061;)
reject tls $HOME_NET any -> any any (msg:"Category:Malicious"; aws_domain_category:Malicious; ja4.hash; content:"_"; flow:to_server; sid:202602063;)
reject tls $HOME_NET any -> any any (msg:"Category:Malware"; aws_domain_category:Malware; ja4.hash; content:"_"; flow:to_server; sid:202602064;)
reject tls $HOME_NET any -> any any (msg:"Category:Phishing"; aws_domain_category:Phishing; ja4.hash; content:"_"; flow:to_server; sid:202602065;)
reject tls $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_domain_category:Proxy Avoidance; ja4.hash; content:"_"; flow:to_server; sid:202602066;)
reject tls $HOME_NET any -> any any (msg:"Category:Spam"; aws_domain_category:Spam; ja4.hash; content:"_"; flow:to_server; sid:202602067;)
reject http $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_url_category:Command and Control; flow:to_server; sid:202602068;)
reject http $HOME_NET any -> any any (msg:"Category:Malicious"; aws_url_category:Malicious; flow:to_server; sid:2026020610;)
reject http $HOME_NET any -> any any (msg:"Category:Malware"; aws_url_category:Malware; flow:to_server; sid:2026020611;)
reject http $HOME_NET any -> any any (msg:"Category:Phishing"; aws_url_category:Phishing; flow:to_server; sid:2026020612;)
reject http $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_url_category:Proxy Avoidance; flow:to_server; sid:2026020613;)
reject http $HOME_NET any -> any any (msg:"Category:Spam"; aws_url_category:Spam; flow:to_server; sid:2026020614;)
```

**What it does:** Blocks traffic to domains categorized by AWS as command and control, malicious, malware, phishing, proxy avoidance, or spam. Uses `aws_domain_category` for TLS traffic (inspects the SNI field) and `aws_url_category` for HTTP traffic (inspects the host header and URL path).

**Why you want it:** AWS maintains and updates the category database automatically. These categories represent domains that have no legitimate business use in most environments. Blocking them provides broad protection without maintaining your own threat intelligence feeds.

**When to skip:** Rarely. You may want to start with `alert` instead of `reject` for the "Proxy Avoidance" category if your environment uses legitimate VPN or proxy services that might be miscategorized.

### Block direct-to-IP communication

```
reject http $HOME_NET any -> any any (http.host; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"HTTP direct to IP via http host header"; flow:to_server; sid:202501026;)
reject tls $HOME_NET any -> any any (tls.sni; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"TLS direct to IP via TLS SNI"; flow:to_server; sid:202501027;)
reject tls $HOME_NET any -> any any (ja4.hash; content:"_"; startswith; content:!"d"; offset:3; depth:1; msg:"JA4 No SNI Reject"; flow:to_server; sid:1297713;)
```

**What it does:** Blocks HTTP and TLS connections where the destination is specified as an IP address rather than a domain name. The third rule blocks TLS connections that have no SNI field at all (detected via JA4 fingerprint characteristics).

**Why you want it:** Legitimate application traffic almost always uses domain names. Direct-to-IP connections are a common indicator of command-and-control communication, data exfiltration tools, and misconfigured applications. Blocking these connections forces traffic through DNS resolution (where DNS Firewall can also inspect it) and through your domain allowlist.

**When to skip:** If your workloads legitimately connect to IP addresses directly (some legacy protocols, health checks to IP endpoints, or NTP to IP-based pools). Add specific pass rules for those IPs above these reject rules.

### GeoIP blocking

```
drop ip $HOME_NET any -> any any (msg:"Egress traffic to blocked geo"; geoip:dst,XX; metadata:geo XX; flow:to_server; sid:202501028;)
drop ip any any -> $HOME_NET any (msg:"Ingress traffic from blocked geo"; geoip:src,XX; metadata:geo XX; flow:to_server; sid:202501029;)
```

**What it does:** Drops all traffic destined to (or originating from) IP addresses geolocated in the specified country codes. Replace `XX` with the [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) country codes relevant to your policy.

**Why you want it:** If your workloads have no legitimate business reason to communicate with IP addresses in certain geographies, blocking at the IP level provides a broad safety net. GeoIP blocking catches traffic that might bypass domain-based filtering (direct-to-IP connections, non-HTTP/TLS protocols).

You can also use the `!` (NOT) operator to invert the logic and only allow traffic to specific countries:

```
drop ip $HOME_NET any -> any any (msg:"Egress to non-approved geo"; geoip:dst,!US,!CA; flow:to_server; sid:202501030;)
```

This drops all egress traffic to any country except the US and Canada.

**When to skip:** If your workloads communicate with services that use global CDN infrastructure or cloud providers with points of presence in many countries. GeoIP databases are not 100% accurate, so false positives are possible. Use `alert` instead of `drop` initially to validate.

### Block QUIC traffic

```
drop quic $HOME_NET any -> any any (msg:"QUIC traffic blocked"; flow:to_server; sid:3898932;)
```

**What it does:** Drops all outbound QUIC (HTTP/3) traffic.

**Why you want it:** QUIC runs over UDP port 443 and encrypts nearly all connection metadata, making it difficult to inspect. Most browsers and applications fall back to TLS over TCP when QUIC is unavailable, which Network Firewall can inspect normally. Blocking QUIC forces traffic through inspectable channels.

**When to skip:** If your workloads specifically require QUIC for performance (video streaming, real-time communications) and you have other controls in place for those flows. Consider blocking QUIC broadly and adding specific pass rules for workloads that need it.

### Block high-risk TLDs

```
reject tls $HOME_NET any -> any any (tls.sni; content:".xyz"; nocase; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501040;)
reject http $HOME_NET any -> any any (http.host; content:".xyz"; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501041;)
reject tls $HOME_NET any -> any any (tls.sni; content:".top"; nocase; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501044;)
reject http $HOME_NET any -> any any (http.host; content:".top"; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501045;)
reject tls $HOME_NET any -> any any (tls.sni; content:".buzz"; nocase; endswith; msg:"High risk TLD .buzz blocked"; flow:to_server; sid:202501046;)
reject http $HOME_NET any -> any any (http.host; content:".buzz"; endswith; msg:"High risk TLD .buzz blocked"; flow:to_server; sid:202501047;)
```

**What it does:** Blocks traffic to domains ending in generic TLDs (.xyz, .top, .buzz) that have disproportionately high rates of association with unwanted activity.

**Why you want it:** These TLDs are rarely used by legitimate enterprise software dependencies. Blocking them provides a low-false-positive safety net alongside your domain allowlist and category filtering.

**When to skip:** If your workloads legitimately communicate with services on these TLDs. Some legitimate services use newer generic TLDs. Validate with alert-only mode first.

### Port/protocol enforcement

```
reject tcp $HOME_NET any -> any 443 (msg:"Egress Port TCP/443 but not TLS"; app-layer-protocol:!tls; flow:to_server; sid:202501030;)
reject tls $HOME_NET any -> any !443 (msg:"Egress TLS but not port TCP/443"; flow:to_server; sid:202501031;)
reject tcp $HOME_NET any -> any 80 (msg:"Egress Port TCP/80 but not HTTP"; app-layer-protocol:!http; flow:to_server; sid:202501032;)
reject http $HOME_NET any -> any !80 (msg:"Egress HTTP but not port TCP/80"; flow:to_server; sid:202501033;)
reject tcp $HOME_NET any -> any 22 (msg:"Egress Port TCP/22 but not SSH"; app-layer-protocol:!ssh; flow:to_server; sid:202501060;)
reject ssh $HOME_NET any -> any !22 (msg:"Egress SSH but not port TCP/22"; flow:to_server; sid:202501061;)
```

**What it does:** Enforces that protocols run on their expected ports, and only on those ports. TLS must use port 443 and port 443 must carry TLS. HTTP must use port 80 and port 80 must carry HTTP. SSH must use port 22 and port 22 must carry SSH.

**Why you want it:** Protocol/port mismatches are a common evasion technique. Running a non-TLS protocol on port 443 can bypass security controls that assume port 443 equals encrypted web traffic. These rules catch protocol tunneling, misconfigured applications, and attempts to exfiltrate data over standard ports using non-standard protocols.

**When to skip:** If your environment has legitimate applications that use non-standard port/protocol combinations (TLS on port 8443, HTTP on port 8080). Add specific pass rules for those combinations above these enforcement rules.

---

## Alert rules

These rules generate log entries for visibility and investigation without blocking traffic. Use them to discover unexpected communication patterns, identify misconfigurations, and build context for future blocking decisions.

### Alert on high-risk destination ports

```
alert ip $HOME_NET any -> any 53 (msg:"Possible DNS Firewall bypass - direct DNS to external resolver"; flow:to_server; sid:202501055;)
alert ip $HOME_NET any -> any 1389 (msg:"Possible Log4j callback"; flow:to_server; sid:202501059;)
alert ip $HOME_NET any -> any [4444,666,3389] (msg:"Egress traffic to high risk port"; flow:to_server; sid:202501058;)
```

**What it does:** Generates alerts (but does not block) when traffic is destined to ports commonly associated with concerning activity: port 53 (direct DNS to external resolvers, bypassing DNS Firewall), port 1389 (LDAP callbacks used in Log4j-style exploitation), and ports 4444/666/3389 (common reverse shell, backdoor, and remote desktop ports).

**Why you want it:** These alerts surface traffic that warrants investigation. Port 53 egress to external resolvers is particularly important because it indicates a workload bypassing your VPC Resolver (and DNS Firewall). Port 3389 (RDP) egress from server workloads is almost never legitimate.

**When to skip:** Convert to `reject` or `drop` if you are confident these ports should never carry legitimate traffic in your environment. Keep as `alert` if you need visibility before enforcement.

### Alert on AWS service traffic (identify privatelink candidates)

```
alert tls $HOME_NET any -> any any (alert; tls.sni; dotprefix; content:".amazonaws.com"; nocase; endswith; msg:"AWS traffic over NFW - consider VPC endpoint"; flow:to_server; sid:202501070;)
```

**What it does:** Generates an alert for any TLS traffic to `*.amazonaws.com` domains flowing through the firewall.

**Why you want it:** Traffic to AWS service endpoints (S3, DynamoDB, STS, etc.) that passes through Network Firewall should usually be going over VPC endpoints (PrivateLink) instead. VPC endpoints keep traffic on the AWS network, reduce Network Firewall data processing costs, and enable VPC endpoint policies for fine-grained access control. This alert rule helps you identify which AWS services your workloads are reaching through the firewall so you can prioritize setting up VPC endpoints for them.

**When to skip:** If you have already configured VPC endpoints for all AWS services your workloads use, this rule should generate no alerts. You can keep it as a safety net to catch new services being accessed without endpoints.

### Alert on suspicious TLDs

```
alert tls $HOME_NET any -> any any (tls.sni; pcre:"/^(?!.*\.(com|org|net|io|edu|aws)$).*/i"; msg:"Request to possible suspicious TLD"; flow:to_server; sid:202501065;)
alert http $HOME_NET any -> any any (http.host; pcre:"/^(?!.*\.(com|org|net|io|edu|aws)$).*/i"; msg:"Request to possible suspicious TLD"; flow:to_server; sid:202501066;)
```

**What it does:** Generates alerts for traffic to any domain not ending in .com, .org, .net, .io, .edu, or .aws. This is a visibility rule, not a blocking rule.

**Why you want it:** Most legitimate enterprise traffic goes to a small set of well-known TLDs. Traffic to unusual TLDs is worth investigating even if not blocked. These alerts help you discover unexpected communication patterns and build your allowlist.

**When to skip:** If your environment legitimately communicates with many diverse TLDs (international operations, CDN providers on country TLDs), this rule will generate excessive alerts. Expand the exclusion list in the PCRE to include your legitimate TLDs.

### Detect $HOME_NET misconfiguration

```
alert ip $HOME_NET any -> any any (noalert; flowbits:set,egress_from_home_net; flow:to_server; sid:8925324;)
alert ip any any -> $HOME_NET any (noalert; flowbits:set,ingress_to_home_net; flow:to_server; sid:8923323;)
alert ip any any -> any any (msg:"$HOME_NET may not be set right! Set it at the firewall policy level."; flowbits:isnotset,ingress_to_home_net; flowbits:isnotset,egress_from_home_net; flowbits:isnotset,home_net_alerted; flowbits:set,home_net_alerted; flow:to_server; sid:8923283;)
```

**What it does:** Detects traffic flowing through the firewall where neither the source nor the destination matches `$HOME_NET`. If this rule fires, it means your `$HOME_NET` variable does not include the CIDR ranges of all VPCs routing traffic through the firewall.

**Why you want it:** A misconfigured `$HOME_NET` is one of the most common reasons rules do not match as expected. This detection rule alerts you to the problem before it causes a security gap. The `home_net_alerted` flowbit limits the rule to a single alert per flow rather than one per packet, which keeps log volume manageable if the rule starts firing broadly.

**When to skip:** Never. This is a safety-net rule that should always be present. It is the canonical version of this detection and is what the [getting started policy](../../getting-started-policy/docs/index.md) templates deploy.

---

## Allow rules and domain allowlisting

These rules explicitly allow traffic. In a default-deny posture, your domain allowlist is what permits your workloads to reach the internet destinations they need.

### Allow exact FQDNs

```
pass tls $HOME_NET any -> any any (tls.sni; content:"api.example.com"; startswith; nocase; endswith; flow:to_server; sid:100001;)
pass http $HOME_NET any -> any any (http.host; content:"api.example.com"; startswith; endswith; flow:to_server; sid:100002;)
```

**What it does:** Allows traffic to exactly `api.example.com` without logging. The `startswith` + `endswith` combination ensures no subdomain or path manipulation can match.

### Allow exact FQDNs with logging

```
pass tls $HOME_NET any -> any any (alert; tls.sni; content:"api.example.com"; startswith; nocase; endswith; msg:"Allowed api.example.com"; flow:to_server; sid:100003;)
```

**What it does:** Allows traffic to `api.example.com` while generating a log entry. The `alert;` keyword on a pass rule causes it to log while still allowing the traffic.

**Why you want it:** Logging allowed traffic gives you visibility into what is actually communicating through your firewall, not just what is being blocked. This is essential for capacity planning, cost analysis, and security monitoring.

### Allow a second-level domain and all subdomains

```
pass tls $HOME_NET any -> any any (tls.sni; dotprefix; content:".example.com"; nocase; endswith; flow:to_server; sid:100004;)
```

**What it does:** Allows traffic to `example.com` and any subdomain (*.example.com) using the `dotprefix` keyword. The `dotprefix` keyword automatically prepends a dot to the content match, so `.example.com` matches both `example.com` itself and `sub.example.com`.

**Why you want it:** When you trust an entire domain and all its subdomains (AWS services, your own organization's domains), a wildcard match reduces the number of rules you need to maintain.

**When to skip:** Be cautious with wildcard domain rules for domains you do not fully control. A broad rule like `*.github.com` would allow traffic to any GitHub-hosted content, which may not match your intent.

### Allow multiple domains in a single rule (PCRE)

```
pass tls $HOME_NET any -> any any (tls.sni; pcre:"/(^|\.)(example\.com|example\.net|contoso\.com)$/i"; flow:to_server; sid:100010;)
pass http $HOME_NET any -> any any (http.host; pcre:"/(^|\.)(example\.com|example\.net|contoso\.com)$/i"; flow:to_server; sid:100011;)
```

**What it does:** Allows traffic to any of the listed second-level domains and their subdomains in one rule. The `(^|\.)` prefix makes the match behave like `dotprefix`, so the rule matches both `example.com` and `api.example.com` but not `notexample.com`. The trailing `$` anchors the match to the end of the SNI or host header so a domain like `example.com.attacker.net` does not match. The `/i` flag makes the match case-insensitive.

**Why you want it:** Capacity. A rule group's capacity is fixed at creation and each Suricata rule costs exactly 1 capacity unit no matter how complex it is, so one PCRE rule covering 200 domains costs 1 capacity unit instead of 200. This is the recommended alternative to splitting a large domain allowlist across multiple rule groups, which consumes slots from the 20 stateful rule group limit. See [Understanding and calculating capacity](../../customer-managed-rules/docs/index.md#understanding-and-calculating-capacity).

**Trade-offs to be aware of:**

* Escape the dots in each domain (`example\.com`, not `example.com`). An unescaped dot matches any character.
* PCRE evaluation is more expensive than `content` matching, so keep the number of alternations in a single rule reasonable rather than putting your entire allowlist into one enormous expression.
* All domains in the rule share one SID and one `msg:`, so alert logs and rule hit counts tell you the rule matched, not which domain matched. Check the `tls.sni` or `http.hostname` field in the log event for that. Group domains that belong together (one application, one vendor) so the `msg:` stays meaningful.
* Suricata rules have a maximum length of 8,192 characters, which bounds how many domains one rule can hold.

**When to skip:** If your allowlist is small enough to fit comfortably in individual `content` rules, use those instead. One domain per rule is easier to read, easier to review in a pull request, and gives you per-domain hit counts.

### Allow low-risk protocols silently

```
pass ntp $HOME_NET any -> any 123 (flow:to_server; sid:202501034;)
pass icmp $HOME_NET any -> any any (flow:to_server; sid:202501035;)
```

**What it does:** Silently allows NTP (time synchronization) and ICMP (ping, traceroute) traffic without generating log events.

**Why you want it:** NTP and ICMP are high-volume, low-risk protocols that generate noise in your logs without providing security value. Allowing them silently reduces log volume and cost while keeping your default-deny posture for everything else.

**When to skip:** If you want to restrict NTP to specific servers (Amazon Time Sync Service at 169.254.169.123), replace the broad pass with a targeted rule. If you want to block ICMP entirely for compliance reasons, remove the ICMP pass rule.

### Verify symmetric routing (diagnostic)

```
alert tcp any any -> any any (msg:"Routing is symmetric. You can safely remove this test rule."; flow:established; sid:123456;)
```

**What it does:** Generates an alert for any TCP flow that reaches the `established` state, confirming that Suricata saw both directions of the TCP handshake.

**Why you want it:** This is a temporary diagnostic rule for validating that your routing configuration is symmetric. After deploying Network Firewall or making routing changes, add this rule and curl an HTTPS endpoint from behind the firewall. If you see an alert log event with `app_proto: "tls"`, it confirms the stateful engine saw both directions of the handshake. Remove after confirming.

---

## Custom default block rules

This section covers an alternative approach to the policy-level default actions described in [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md). For most deployments, we recommend using "Application drop established (server-directed only)" as the policy-level default action. The custom default block rules below are for customers who need additional control over how blocked traffic is logged and handled.

### When to use custom default block rules instead of policy default actions

Custom default block rules provide benefits that the built-in default actions do not:

* Log JA4 hashes when TLS traffic is blocked
* Differentiate between egress traffic and ingress traffic in log messages
* Send TCP RSTs (reject) for egress traffic while silently dropping (no TCP RST) ingress traffic
* Separate log entries by protocol (TLS, HTTP, TCP, UDP, ICMP)

If you do not need these capabilities, use the policy-level "Application drop established (server-directed only)" default action and skip this section entirely.

### How to implement custom default block rules

If you use custom default block rules, do not also select any policy-level default drop actions. They serve the same purpose and using both produces redundant log entries.

### Egress default block rules

```
reject tls $HOME_NET any -> any any (msg:"Default Egress HTTPS Reject"; ssl_state:client_hello; ja4.hash; content:"_"; flowbits:set,blocked; flow:to_server; sid:999991;)
alert tls $HOME_NET any -> any any (msg:"PQC"; flowbits:isnotset,blocked; flowbits:set,PQC; noalert; flow:to_server; sid:999993;)
reject http $HOME_NET any -> any any (msg:"Default Egress HTTP Reject"; flowbits:set,blocked; flow:to_server; sid:999992;)
reject tcp $HOME_NET any -> any any (msg:"Default Egress TCP Reject"; flowbits:isnotset,blocked; flowbits:isnotset,PQC; flow:to_server, established; sid:999994;)
drop udp $HOME_NET any -> any any (msg:"Default Egress UDP Drop"; flow:to_server; sid:999995;)
drop icmp $HOME_NET any -> any any (msg:"Default Egress ICMP Drop"; flow:to_server; sid:999996;)
drop ip $HOME_NET any -> any any (msg:"Default Egress All Other IP Drop"; ip_proto:!TCP; ip_proto:!UDP; ip_proto:!ICMP; flow:to_server; sid:999997;)
```

**How the flowbits logic works:** The `ssl_state:client_hello` and `ja4.hash` combination ensures the TLS reject fires only after the Client Hello is received. The `PQC` flowbit handles post-quantum TLS implementations that fragment the Client Hello across multiple packets. If the Client Hello is not yet complete (PQC fragmentation), the flow is marked as PQC and the generic TCP reject is skipped, giving Suricata time to reassemble the full Client Hello before making a decision.

**Why the TCP reject uses `flow:to_server, established`:** `established` means the rule cannot match the TCP SYN, so the three-way handshake completes and Suricata gets a chance to see application-layer data (the TLS Client Hello or HTTP host header) before the generic TCP reject can fire. Without `established`, this rule would reject the SYN before any domain information exists, breaking domain-based filtering.

### Ingress default block rules

```
drop tls any any -> $HOME_NET any (msg:"Default Ingress HTTPS Drop"; ssl_state:client_hello; ja4.hash; content:"_"; flowbits:set,blocked; flow:to_server; sid:999999;)
alert tls any any -> $HOME_NET any (msg:"PQC"; flowbits:isnotset,blocked; flowbits:set,PQC; noalert; flow:to_server; sid:9999910;)
drop http any any -> $HOME_NET any (msg:"Default Ingress HTTP Drop"; flowbits:set,blocked; flow:to_server; sid:9999911;)
drop tcp any any -> $HOME_NET any (msg:"Default Ingress TCP Drop"; flowbits:isnotset,blocked; flowbits:isnotset,PQC; flow:to_server; sid:9999912;)
drop udp any any -> $HOME_NET any (msg:"Default Ingress UDP Drop"; flow:to_server; sid:9999913;)
drop icmp any any -> $HOME_NET any (msg:"Default Ingress ICMP Drop"; flow:to_server; sid:9999914;)
drop ip any any -> $HOME_NET any (msg:"Default Ingress All Other IP Drop"; ip_proto:!TCP; ip_proto:!UDP; ip_proto:!ICMP; flow:to_server; sid:9999915;)
```

**Why drop instead of reject for ingress:** You do not want to send TCP RSTs to unknown external sources (it confirms your host exists and can be used for reconnaissance).

**When to skip the ingress rules:** If your firewall only inspects egress traffic (the most common pattern in centralized deployments where ingress goes through separate paths like CloudFront + AWS WAF).

### JA3/JA4 hash logging

If you use the custom default block rules, you may also want to enable JA3/JA4 fingerprint logging for additional forensic visibility:

```
alert tls $HOME_NET any -> any any (ja3.hash; content:!"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; noalert; flow:to_server; sid:202501024;)
alert tls any any -> $HOME_NET any (ja3s.hash; content:!"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; noalert; flow:to_client; sid:202501025;)
```

**What it does:** Enables JA3 (client) and JA3S (server) TLS fingerprint hash logging for all TLS connections without generating alert log events. The `content:!"xxx..."` trick forces Suricata to compute and log the hash for every TLS flow (since no real hash will match that dummy value).

**Why you want it:** JA3/JA4 hashes appear in your alert logs, giving you visibility into which TLS clients and servers are communicating through your firewall. This data is valuable for identifying unexpected client software and investigating suspicious connections.

**When to skip:** If you are not using TLS fingerprint data for analysis or filtering and want to minimize processing overhead.

---

## Complete rules template

The following template combines the most common rules from this page into a single, ready-to-deploy ruleset. It uses the recommended "Application drop established (server-directed only)" and "Application alert established (server-directed only)" default actions from [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md), so no custom default block rules are needed.

Place your environment-specific domain allowlist rules in the designated section near the bottom.

```
# =============================================================================
# AWS Network Firewall - Sample Suricata Rules Template
# =============================================================================
# Rule ordering: Strict
# Default actions: "Application drop established (server-directed only)"
#                  "Application alert established (server-directed only)"
# $HOME_NET: Set to all RFC 1918 space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
#            at the firewall policy level.
# =============================================================================

# --- Domain Category Blocking (TLS) ---
reject tls $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_domain_category:Command and Control; ja4.hash; content:"_"; flow:to_server; sid:202602061;)
reject tls $HOME_NET any -> any any (msg:"Category:Malicious"; aws_domain_category:Malicious; ja4.hash; content:"_"; flow:to_server; sid:202602063;)
reject tls $HOME_NET any -> any any (msg:"Category:Malware"; aws_domain_category:Malware; ja4.hash; content:"_"; flow:to_server; sid:202602064;)
reject tls $HOME_NET any -> any any (msg:"Category:Phishing"; aws_domain_category:Phishing; ja4.hash; content:"_"; flow:to_server; sid:202602065;)
reject tls $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_domain_category:Proxy Avoidance; ja4.hash; content:"_"; flow:to_server; sid:202602066;)
reject tls $HOME_NET any -> any any (msg:"Category:Spam"; aws_domain_category:Spam; ja4.hash; content:"_"; flow:to_server; sid:202602067;)

# --- Domain Category Blocking (HTTP) ---
reject http $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_url_category:Command and Control; flow:to_server; sid:202602068;)
reject http $HOME_NET any -> any any (msg:"Category:Malicious"; aws_url_category:Malicious; flow:to_server; sid:2026020610;)
reject http $HOME_NET any -> any any (msg:"Category:Malware"; aws_url_category:Malware; flow:to_server; sid:2026020611;)
reject http $HOME_NET any -> any any (msg:"Category:Phishing"; aws_url_category:Phishing; flow:to_server; sid:2026020612;)
reject http $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_url_category:Proxy Avoidance; flow:to_server; sid:2026020613;)
reject http $HOME_NET any -> any any (msg:"Category:Spam"; aws_url_category:Spam; flow:to_server; sid:2026020614;)

# --- Block Direct-to-IP Communication ---
reject http $HOME_NET any -> any any (http.host; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"HTTP direct to IP via http host header"; flow:to_server; sid:202501026;)
reject tls $HOME_NET any -> any any (tls.sni; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"TLS direct to IP via TLS SNI"; flow:to_server; sid:202501027;)
reject tls $HOME_NET any -> any any (ja4.hash; content:"_"; startswith; content:!"d"; offset:3; depth:1; msg:"JA4 No SNI Reject"; flow:to_server; sid:1297713;)

# --- GeoIP Blocking (replace XX with your blocked country codes) ---
# drop ip $HOME_NET any -> any any (msg:"Egress traffic to blocked geo"; geoip:dst,XX; metadata:geo XX; flow:to_server; sid:202501028;)
# Or use the NOT operator to allow only specific countries:
# drop ip $HOME_NET any -> any any (msg:"Egress to non-approved geo"; geoip:dst,!US,!CA; flow:to_server; sid:202501029;)

# --- Block QUIC ---
drop quic $HOME_NET any -> any any (msg:"QUIC traffic blocked"; flow:to_server; sid:3898932;)

# --- Block High-Risk TLDs ---
reject tls $HOME_NET any -> any any (tls.sni; content:".xyz"; nocase; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501040;)
reject http $HOME_NET any -> any any (http.host; content:".xyz"; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501041;)
reject tls $HOME_NET any -> any any (tls.sni; content:".top"; nocase; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501044;)
reject http $HOME_NET any -> any any (http.host; content:".top"; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501045;)

# --- Port/Protocol Enforcement ---
reject tcp $HOME_NET any -> any 443 (msg:"Egress Port TCP/443 but not TLS"; app-layer-protocol:!tls; flow:to_server; sid:202501030;)
reject tls $HOME_NET any -> any !443 (msg:"Egress TLS but not port TCP/443"; flow:to_server; sid:202501031;)
reject tcp $HOME_NET any -> any 80 (msg:"Egress Port TCP/80 but not HTTP"; app-layer-protocol:!http; flow:to_server; sid:202501032;)
reject http $HOME_NET any -> any !80 (msg:"Egress HTTP but not port TCP/80"; flow:to_server; sid:202501033;)
reject tcp $HOME_NET any -> any 22 (msg:"Egress Port TCP/22 but not SSH"; app-layer-protocol:!ssh; flow:to_server; sid:202501060;)
reject ssh $HOME_NET any -> any !22 (msg:"Egress SSH but not port TCP/22"; flow:to_server; sid:202501061;)

# --- Alert on High-Risk Ports ---
alert ip $HOME_NET any -> any 53 (msg:"Possible DNS Firewall bypass - direct DNS to external resolver"; flow:to_server; sid:202501055;)
alert ip $HOME_NET any -> any 1389 (msg:"Possible Log4j callback"; flow:to_server; sid:202501059;)
alert ip $HOME_NET any -> any [4444,666,3389] (msg:"Egress traffic to high risk port"; flow:to_server; sid:202501058;)

# --- Alert on AWS Traffic (identify privatelink candidates) ---
alert tls $HOME_NET any -> any any (alert; tls.sni; dotprefix; content:".amazonaws.com"; nocase; endswith; msg:"AWS traffic over NFW - consider VPC endpoint"; flow:to_server; sid:202501070;)

# --- Allow Low-Risk Protocols ---
pass ntp $HOME_NET any -> any 123 (flow:to_server; sid:202501034;)
pass icmp $HOME_NET any -> any any (flow:to_server; sid:202501035;)

# --- YOUR DOMAIN ALLOW-LIST GOES HERE ---
# Add your environment-specific pass rules below this line.
# Examples:
# pass tls $HOME_NET any -> any any (tls.sni; content:"api.yourapp.com"; startswith; nocase; endswith; flow:to_server; sid:100001;)
# pass tls $HOME_NET any -> any any (tls.sni; dotprefix; content:".yourcompany.com"; nocase; endswith; flow:to_server; sid:100002;)
# Many domains in one rule (1 capacity unit total):
# pass tls $HOME_NET any -> any any (tls.sni; pcre:"/(^|\.)(yourcompany\.com|yourapp\.com)$/i"; flow:to_server; sid:100003;)

# --- Detect $HOME_NET Misconfiguration (always include) ---
alert ip $HOME_NET any -> any any (noalert; flowbits:set,egress_from_home_net; flow:to_server; sid:8925324;)
alert ip any any -> $HOME_NET any (noalert; flowbits:set,ingress_to_home_net; flow:to_server; sid:8923323;)
alert ip any any -> any any (msg:"$HOME_NET may not be set right! Set it at the firewall policy level."; flowbits:isnotset,ingress_to_home_net; flowbits:isnotset,egress_from_home_net; flowbits:isnotset,home_net_alerted; flowbits:set,home_net_alerted; flow:to_server; sid:8923283;)
```

## What to read next

* [Customer managed rules](../../customer-managed-rules/docs/index.md) - Rule writing concepts and best practices
* [AWS Managed Rules](../../aws-managed-rules/docs/index.md) - AWS-maintained rule groups to complement your custom rules
* [Logging and monitoring](../../logging-and-monitoring/docs/index.md) - Analyze what your rules are doing
