# Fraud Prevention

AWS WAF Fraud Control provides two managed rule groups that protect authentication and account creation endpoints from credential-based attacks. Both rule groups have per-request charges beyond the base WAF fee and require configuration so they only trigger (and cost) for login/signup attempts they protect. Fraud Control is not available for Amazon Cognito user pools.

Both rule groups work best with the [AWS WAF application integration](https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-integration.html) for token-based client verification. The application integration SDK generates tokens that provide additional signals to the Fraud Control rules. Without the SDK, Fraud Control still functions but with reduced detection capability. See [CAPTCHA and Challenge](../../captcha-and-challenge/docs/index.md) for details on application integration.  Login and sign-up requests are POSTs, which must already carry a WAF token for session and client fingerprint based rules to provide full detection capability.

## Account Takeover Prevention (ATP)

The [Account Takeover Prevention (ATP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-atp.html) rule group (`AWSManagedRulesATPRuleSet`) inspects login attempts to detect and block credential-based attacks against your application's login endpoint.

**What it does**

- Checks username and password combinations against a stolen credential database that is updated regularly as new leaked credentials are found on the dark web.
- Aggregates login attempt data by IP address and client session to detect and block clients sending too many suspicious login requests.
- For CloudFront distributions, inspects your application's responses to login attempts, tracking success and failure rates. This enables ATP to temporarily block client sessions or IP addresses with too many login failures.


**What it protects you from**

- Credential stuffing — Automated replay of stolen username/password pairs from breach databases.
- Password spraying — Trying a small set of common passwords across many accounts to avoid lockout thresholds.
- Brute-force attacks — High-volume login attempts against a single account or small set of accounts.
- Credential testing — Validating whether stolen credentials are still active before selling or using them elsewhere.
- Username/email enumeration — Systematically probing login endpoints to discover valid accounts by observing differences in error responses or timing.

**Configuration**

ATP requires you to specify your login endpoint path and the request fields that contain the username and password. ATP only evaluates requests that match this endpoint — it does not inspect all traffic. This built-in scoping means you do not need a separate scope-down statement, though you can add one for further refinement.

<!-- TODO: Add JSON example of ATP rule group configuration with login endpoint path and credential field mappings -->

**Considerations**

- Response inspection (tracking login success/failure rates) is only available when ATP is associated with a CloudFront distribution.
- ATP needs to know the exact request format for your login endpoint — the HTTP method, the path, and where the username and password appear in the request body. If your login endpoint accepts multiple formats (e.g., JSON and form-encoded), you may need to configure both.

<!-- TODO: What is the recommended approach when an application has multiple login endpoints (e.g., /login, /api/auth, /oauth/token)? Can ATP be configured for multiple endpoints in a single rule group, or do you need multiple instances? -->

## Account Creation Fraud Prevention (ACFP)

The [Account Creation Fraud Prevention (ACFP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-acfp.html) rule group (`AWSManagedRulesACFPRuleSet`) inspects account creation attempts to detect and block fraudulent sign-ups.

**What it does**

- Monitors sign-up requests for anomalous activity and automatically blocks suspicious requests using request identifiers, behavioral analysis, and machine learning.
- Checks username and password combinations against a stolen credential database to prevent accounts from being created with known compromised credentials.
- Evaluates the domains used in email addresses and monitors phone numbers and address fields for patterns associated with fraudulent account creation.
- For CloudFront distributions, inspects your application's responses to account creation attempts, tracking success and failure rates to temporarily block sessions or IPs with too many failed attempts.

**What it protects you from**

- Fake account creation — Automated mass registration of accounts for spam, abuse, or resale.
- Promo and referral abuse — Creating throwaway accounts to exploit sign-up bonuses, free trials, or referral programs.
- Credential laundering — Registering accounts with known compromised credentials to establish seemingly legitimate identities.
- Downstream fraud staging — Creating accounts that will later be used for payment fraud, phishing, or social engineering.
- Volumetric abuse — High-volume sign-ups reusing the same phone number, email address, or other identity attributes across many accounts.

**Configuration**

Like ATP, ACFP requires you to specify your registration endpoint path and the request fields that contain the account creation data (email, password, phone, address). ACFP only evaluates requests that match this endpoint.

<!-- TODO: Add JSON example of ACFP rule group configuration with registration endpoint path and field mappings -->

**Considerations**

- Response inspection is only available when ACFP is associated with a CloudFront distribution.

<!-- TODO: What is the recommended approach for applications with multi-step registration flows (e.g., step 1: email/password, step 2: phone/address)? Does ACFP need to see all fields in a single request? -->

## Related Resources

- [AWS WAF Fraud Control documentation](https://docs.aws.amazon.com/waf/latest/developerguide/waf-fraud-control.html)
- [ATP rule group reference](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html)
- [ACFP rule group reference](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-acfp.html)
- [AWS WAF application integration SDKs](https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-integration.html)
- [CAPTCHA and Challenge](../../captcha-and-challenge/docs/index.md) — Token-based mitigation actions that enhance Fraud Control detection
- [Recommended WAF Rule Order](../../recommended-waf-rule-order/docs/index.md) — Where Fraud Control fits in your rule evaluation order
