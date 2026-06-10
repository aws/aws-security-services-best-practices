# CAPTCHA and Challenge

AWS WAF provides two token-based mitigation actions — [CAPTCHA](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html) and [Challenge](https://docs.aws.amazon.com/waf/latest/developerguide/waf-challenge.html) — that help distinguish legitimate human users from automated clients. Both actions issue tokens (a cookie) with configurable immunity times, but they differ in user experience and detection approach. CAPTCHA presents a visual puzzle that requires human interaction, while Challenge runs a silent browser interrogation that is invisible to the end user. This section covers when to use each action, how to configure immunity times, and best practices for integrating these actions into your WAF rule set.

## When to Use CAPTCHA vs. Challenge

### User Experience

CAPTCHA introduces visible friction — a puzzle the user must solve before proceeding. This friction can be acceptable on low-frequency, high-value actions like login, account creation, or checkout where the security benefit outweighs the interruption. It is less acceptable on high-traffic pages or actions users perform repeatedly in a session.

CAPTCHA puzzles can be especially impactful for applications serving very young users, elderly users, or users with varying levels of technical literacy which may result in higher abandonment rates from the presented CAPTCHA puzzle.  

Challenge is invisible to the user. The browser completes a silent interrogation without any interaction.

### Bot Interactions

Challenge defeats automated clients that lack a full browser engine — scripts, curl, basic HTTP libraries, and simple headless setups that do not execute JavaScript. If a client cannot run the silent browser interrogation, the request is terminated.  This is both good as it stops simple bots but also presents a problem for API or SDKs that cannot complete JavaScript; effectively blocking those requests.

CAPTCHA raises the bar further by requiring visual reasoning, spatial interaction, and behavioral patterns that are significantly more expensive and complex for automation to solve — but no challenge is permanent. Sophisticated bots can eventually defeat any CAPTCHA through solver services, ML-based solvers, or human farms. The goal is to increase the cost and latency of automation to the point where it is no longer economically viable at scale.

Even if a bot successfully completes a Challenge or CAPTCHA, being able to get a token is not just a pass/fail gate. The token carries fingerprinting signals — browser environment details, interaction patterns, and session identifiers — that downstream rules like Bot Control Targeted use to detect anomalous behavior and track sessions over time. A bot that acquires a token still exposes itself to behavioral analysis through the signals embedded in that token.

When layering both actions, use Challenge broadly as a baseline token acquisition mechanism and reserve CAPTCHA for endpoints where Bot Control signals indicate elevated risk — for example, triggering CAPTCHA only when a request carries a targeted bot signal or high-risk label.

### Reactive vs. Passive vs. Deliberate  

**Reactive**  
Protection packs can use Challenge or Captcha as a rule action, and many AMRs use these as their default action. When WAF terminates a request with a Challenge or Captcha, this frequently just works without issue. However, there are several reasons to proactively integrate these actions rather than waiting for WAF to trigger them reactively:

- WAF tokens allow you to aggregate activity by session, not only by IP. If you wait until a critical interaction to issue a challenge, you miss this signal for the earlier portion of the user's session.
- Many AMRs use WAF tokens to improve detection capabilities. Reactively challenging limits these detections to later in the client's interaction, reducing early and high-sensitivity coverage.
- iFrames, widgets, and similar embeds may not render a Captcha correctly — browsers handle interstitial redirects inconsistently in embedded contexts, resulting in a broken or unusable experience for the end user.
- Challenge and Captcha need to trigger on GET requests for text/html content. If triggered on a POST or other content type, the browser cannot follow the interstitial redirect. This is not specific to AWS WAF — HTTP 202 and 405 interstitial redirects are a standard mechanism for JavaScript-based challenges, and the same content-type limitation applies to any implementation


**Passive**  
Passive integration means having Challenge silently execute in the background during page loads. Your page includes an async/defer JavaScript snippet provided by AWS WAF. An end user's first request won't have a token, but after that initial page load and JS execution, all subsequent requests will contain a valid WAF token. When a user with a valid token triggers a WAF rule with a Challenge action, the rule does not result in an HTTP 202 interstitial redirect — this is critical for non-GET requests or non-text/html content types that cannot handle the redirect

**Proactive**  
You can configure your application to trigger the Captcha before a user completes a POST, such as submitting a form or clicking a button. See [this example](https://docs.aws.amazon.com/waf/latest/developerguide/waf-js-captcha-api-conditional.html) for how to implement AWS WAF Captcha. In short, when the user clicks the button, AwsWafCaptcha triggers the Captcha and presents the puzzle. If they successfully solve it (no HTTP 405), the application proceeds with the POST — but now with a valid WAF token present. On the WAF side, this POST request already carries a valid Captcha token, so a Captcha action rule passes without an HTTP 405 interstitial redirect.


**Summary**  

Use passive integration whenever possible — it silently acquires tokens during page loads and avoids interstitial redirects entirely. For Captcha, use proactive integration to trigger the puzzle client-side before a POST for the best user experience. Reactive Challenge and Captcha actions are best suited for catching non-legitimate traffic, but can cause issues with non-GET requests, non-text/html content types, iFrames, and embedded widgets.

## Configuring Immunity Times

Both CAPTCHA and Challenge actions use immunity times to determine how long a valid token exempts a client from re-verification. When a client successfully completes a Challenge or solves a CAPTCHA, the resulting WAF token is valid for the configured immunity period. Subsequent requests carrying that token pass through without triggering the action again until the token expires.

Immunity time is fundamentally a tradeoff between three factors:

- **Security** — Shorter immunity times mean tokens expire sooner, reducing the window in which a stolen or replayed token can be used and increasing the frequency at which clients must re-prove legitimacy. Longer immunity times leave a larger gap where a compromised token remains valid.
- **User experience** — For Captcha specifically, shorter immunity means users are presented with puzzles more frequently, which increases friction and can lead to abandonment. Challenge immunity has no direct UX impact since it is invisible.
- **Cost** — Each Captcha attempt is billable, so shorter immunity times can cause users to solve multiple Captcha puzzles within a single session, directly increasing cost. For Challenge, cost only applies when WAF returns a Challenge action (the HTTP 202 interstitial). Tokens acquired via the JavaScript SDK integration are not billable Challenge events — so if you have passive integration in place, most clients already carry a valid token and never trigger the billable Challenge action. Without the JavaScript SDK, shorter Challenge immunity times will increase the number of billable Challenge responses.


### Immunity Time Configuration

Immunity times can be set at two levels:

- **Protection pack level** — Sets the default immunity time for all CAPTCHA and Challenge actions in the protection pack. This applies unless overridden by a rule-level setting.
- **Rule level** — Overrides the protection pack default for a specific rule. Use this when certain endpoints need shorter or longer immunity than the general default.

The default immunity time is 300 seconds (5 minutes) for both CAPTCHA and Challenge. Adjust based on your application's session patterns and risk profile.


## Token Domain Configuration

WAF tokens are scoped by default to the hostname that issued the Challenge or Captcha (whether reactive or passive). For example, if a user connects to `www.example.com` and WAF issues an HTTP 202 Challenge, the resulting token is valid only for `www.example.com`. If that site then makes a request to `api.example.com` and WAF has a rule with a Challenge action, WAF will issue another HTTP 202 Challenge — even though the user already proved legitimacy moments ago. This back-and-forth adds latency and drives up billable Challenge or Captcha costs.

[Token domain configuration](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-domains.html) allows you to specify additional hostnames or a domain suffix that the WAF token should be considered valid for. In this example, configuring a token domain of either:

- `www.example.com`, `api.example.com`
or
- `example.com`

means the first Challenge still occurs, but the token acquired is valid for any hostname under `example.com`. This avoids re-challenges and re-captchas, the corresponding latency, additional cost, and — in the case of Captcha — unnecessary user friction. This is especially common in architectures where a frontend subdomain and an API subdomain are both protected by the same WAF protection pack.

## Challenge and Captcha used by AMR  
Challenge and Captcha are paid features of AWS WAF. The exception is when an AWS Managed Rule (AMR) uses Challenge or Captcha as its default action — today this includes Bot Control Targeted, Fraud Control rules, and the AntiDDoS managed rules.

For this exception to apply, the AMR itself must be what terminates the request with a Challenge or Captcha action. If you override a default action, or use a custom rule that acts on a label from a rule whose default action is Challenge or Captcha, these *are* paid Challenge/Captcha events and are not included as part of the AMR subscription.

Partner Managed Rules, custom rules, or overrides of any WAF rule or managed rule all have standard usage-based costs per [Challenge and Captcha costs](../../waf-cost/docs/index.md#challenge_and_captcha_costs).


## Rule Order for Captcha & Challenge  

See [Recommended WAF Rule Order](../../recommended-waf-rule-order/docs/index.md) for where to position CAPTCHA and Challenge rules in your protection pack. See [Bot Management — Web Browser Automation Detection](../../bot-management/docs/index.md#web-browser-automation-wba-detection) for how Challenge interacts with WBA detection. See [Custom Rules](../../custom-rules/docs/index.md) for writing label-based rules that trigger CAPTCHA or Challenge actions conditionally.
