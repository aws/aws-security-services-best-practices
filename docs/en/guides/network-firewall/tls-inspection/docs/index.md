# TLS inspection

!!! info "Prerequisites"
    This section assumes familiarity with [Customer managed rules](../../customer-managed-rules/docs/index.md) and [Firewall policy configuration](../../firewall-policy-configuration/docs/index.md). Review those topics first, particularly the domain filtering and stream exception policy sections.

AWS Network Firewall's [TLS inspection](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html) decrypts, inspects, and re-encrypts TLS traffic using certificates managed in [AWS Certificate Manager (ACM)](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html), supporting both inbound inspection (terminating client connections to your servers) and outbound inspection (forward-proxying connections from your clients to external servers). Most Network Firewall deployments do not need TLS inspection because domain filtering via TLS SNI provides sufficient visibility for egress filtering. TLS inspection is the right choice when you need content-level inspection of encrypted traffic, built-in SNI validation, or URL-level (not just domain-level) filtering for HTTPS.

## When to use TLS inspection

TLS inspection adds cost (Advanced Inspection pricing tier), operational complexity (certificate management, client trust store distribution), and introduces fixed idle timeouts on the SSL proxy that differ from the configurable firewall TCP idle timeout. Evaluate these trade-offs before enabling.

TLS inspection is appropriate when:

* You need to inspect the **content** of encrypted traffic (HTTP headers, full URLs, request bodies) beyond just the TLS SNI domain name
* You want built-in protection against TLS SNI manipulation (the firewall validates that SNI matches the server certificate automatically)
* Compliance requirements mandate inspection of encrypted traffic
* You need URL-path-level filtering for HTTPS traffic using `aws_url_category` (which requires decryption to access the inner HTTP request)

TLS inspection is not needed when:

* Domain filtering via TLS SNI is sufficient for your security requirements (the most common case)
* Workloads use certificate pinning that would break with TLS interception
* You are using the multi-endpoint feature (TLS inspection is not supported with VPC endpoint associations)

## Inbound TLS inspection

[Inbound TLS inspection](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html#tls-inspection-inbound) decrypts and inspects traffic destined to servers within your VPCs. You import or issue a server certificate in ACM for each domain, define a scope configuration specifying which traffic to decrypt, and Network Firewall terminates the client TLS connection, inspects the decrypted traffic, then re-encrypts to the backend.

For a step-by-step walkthrough, see the blog post [TLS inspection configuration for encrypted traffic and AWS Network Firewall](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-traffic-and-aws-network-firewall/).

!!! warning "Inbound TLS inspection is usually not the right approach for web applications"
    For public-facing web applications, CloudFront + AWS WAF in front of an ALB origin is the recommended architecture. AWS WAF attaches directly to the protected resource (CloudFront distribution, ALB, API Gateway) and provides purpose-built layer 7 web application protection without requiring you to configure manual TLS certificate management or scope configurations. Network Firewall does not fall under Shield Advanced cost protections. The primary use case for inbound TLS inspection on Network Firewall is traffic destined to a Network Load Balancer (NLB) where you need deep packet inspection before traffic reaches your backend and cannot use WAF.

### Inbound scope configuration

!!! tip "Best practice"
    Write inbound TLS inspection scope statements as specifically as possible with source/destination CIDRs and ports. Network Firewall drops non-TLS traffic that matches the scope configuration (for example, plain HTTP on port 80 will be dropped if the scope includes port 80). TLS traffic is also dropped if the Client Hello does not include an SNI, or if the SNI does not match the server certificate.

!!! danger "Common misconfiguration"
    Using a broadly scoped TLS inspection configuration (any source, any destination, any port) causes unexpected drops. Non-TLS traffic matching the scope is dropped because the firewall cannot identify it as TLS. TLS connections without SNI are also dropped. Scope your configuration to the specific destination CIDRs and ports (typically 443) of the servers you want to inspect.

### Inbound certificate requirements

For inbound inspection, Network Firewall supports certificates issued by Certificate Authorities on the [Mozilla Included CA Certificate List](https://wiki.mozilla.org/CA/Included_Certificates). You can also use AWS Private CA to create a certificate for Network Firewall's inbound inspection, but in that case the client must have the private CA in its trust store.

The backend server certificate (on your ALB or NLB) must also be signed by a public CA on the Mozilla list. If you use a private CA certificate on the backend, Network Firewall will reject it with "Certificate verification failed" in TLS logs, even if the client-facing certificate works correctly.

## Outbound TLS inspection

[Outbound TLS inspection](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html#tls-inspection-outbound) decrypts and inspects traffic from clients within your VPCs to external servers. Network Firewall operates as a TLS forward proxy, dynamically generating server certificates signed by your CA for each destination server.

For a step-by-step walkthrough, see the blog post [TLS inspection configuration for encrypted egress traffic and AWS Network Firewall](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-egress-traffic-and-aws-network-firewall/).

### CA certificate requirements

You must import a Certificate Authority (CA) certificate into ACM. This CA's private key is used by the SSL proxy to dynamically sign server certificates on the fly. The CA certificate must meet these requirements:

* X509v3 "Basic Constraints" extension with `CA:TRUE`, marked as critical
* X509v3 "Key Usage" extension with `keyCertSign` set, marked as critical

If these requirements are not met, you receive: *"CertificateAuthorityArn is invalid because it references a certificate authority that doesn't comply with RFC 5280 basic constraints."* Verify that your CA certificate includes both the Basic Constraints and Key Usage extensions with the required values.

!!! danger "Common misconfiguration"
    You cannot use a public CA (DigiCert, GoDaddy, etc.) for outbound TLS inspection. The SSL proxy needs the CA private key to dynamically sign certificates. Public CAs never provide CA private keys. You must generate your own private CA (OpenSSL, Microsoft AD CS, AWS Private CA, etc.), import the CA certificate and private key into ACM, and distribute the CA certificate to client trust stores.

### Installing the CA certificate on clients

For clients to trust the dynamically generated certificates, the CA certificate must be added to their trusted root certificate store:

* **Amazon Linux** - Copy to `/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust`
* **Ubuntu** - Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
* **Windows** - Import to the Trusted Root Certification Authorities store

### Certificate revocation checking

With outbound TLS inspection, you can enable certificate revocation checking. Network Firewall verifies the revocation status of server certificates using OCSP and CRL on behalf of clients. Revoked or expired certificates are rejected and logged in the TLS log.

## SNI manipulation protection

When TLS inspection is enabled (either direction), Network Firewall automatically validates that the SNI in the Client Hello matches the certificate presented by the server. Mismatches are blocked and produce a TLS error log entry. This provides built-in protection against client-side SNI spoofing without any rule configuration.

## Writing rules with TLS inspection

After decryption, traffic arrives at the stateful engine as plaintext HTTP (or HTTP/2). Key considerations for rule writing:

* `tls.sni` keyword rules still work for in-scope traffic because the SSL proxy captures the SNI from the Client Hello and passes it as metadata to Suricata
* HTTP/1.1 and HTTP/2 require separate rules. Suricata's HTTP/2 overloading feature is [explicitly not supported](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html) in Network Firewall
* When writing default block rules with TLS inspection enabled, account for HTTP/2 traffic using `app-layer-protocol:!http2` or separate `drop http2` rules

## TLS inspection idle timeouts

The SSL proxy has fixed idle timeouts that are independent of the configurable firewall TCP idle timeout:

* Approximately 5 seconds for new connections (connections that have not fully established)
* Approximately 120 seconds for established connections that go idle

These cannot be adjusted. If your backend operations take longer than 120 seconds of idle time on the proxy-to-server connection (for example, a long-running database query), the proxy may close the server-side connection even though the client-side connection is kept alive by TCP keepalives. The client keepalives are not forwarded to the proxy-to-server leg.

## Session holding

[Session holding](https://docs.aws.amazon.com/network-firewall/latest/developerguide/session-holding-tls.html) controls when TCP establishment packets reach destination servers during outbound TLS inspection. When enabled, the firewall holds client-side packets until it extracts the SNI from the Client Hello, then evaluates TLS.SNI-based rules before initiating any downstream connection.

Without session holding, the firewall immediately establishes a full TCP connection with the destination server before SNI is available. Even if a deny rule ultimately blocks the connection, the destination server has already received a TCP SYN and completed the handshake. With session holding, if the SNI matches a deny rule, the connection is dropped at the firewall and no packets are ever sent to the destination.

Note that session holding is incompatible with the "Application drop established (bidirectional)" and "Application drop established (server-directed only)" default actions. Because "Application drop established (server-directed only)" is the [default action this guide recommends](../../firewall-policy-configuration/docs/index.md#default-actions), enabling session holding means changing it. Use "Drop all" or the [custom default block rules](../../sample-suricata-rules/docs/index.md#custom-default-block-rules) instead, and be aware that "Drop all" requires explicit pass rules for the TCP handshake.

## Key considerations

* TLS versions 1.1, 1.2, and 1.3 are supported
* Network Firewall only supports a specific list of client cipher suites
* TLS inspection is **not supported** for firewalls using the multi-endpoint (VPC endpoint associations) feature
* TLS inspection has its own pricing tier (Advanced Inspection endpoint + traffic processing). See [Cost considerations](../../cost-considerations/docs/index.md) and [Network Firewall pricing](https://aws.amazon.com/network-firewall/pricing/)
* Traffic in TLS inspection scope will have `"tls_inspected": true` in firewall log events

For the complete list of considerations and limitations, see [TLS inspection considerations](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-considerations.html) and [Certificate requirements](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-certificate-requirements.html).

## What to read next

* [Customer managed rules](../../customer-managed-rules/docs/index.md) - Domain filtering approaches that work without TLS decryption
* [Logging and monitoring](../../logging-and-monitoring/docs/index.md) - TLS inspection logging and error analysis
* [Cost considerations](../../cost-considerations/docs/index.md) - TLS inspection pricing impact
