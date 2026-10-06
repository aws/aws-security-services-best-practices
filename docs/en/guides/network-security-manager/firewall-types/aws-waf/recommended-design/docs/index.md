---
hide:
  - toc
---

<!--
AUTHORING NOTES (applies to every NSM page)
- Always qualify "rule" as "WAF rule" or "NSM rule". Never use "rule" on its own.
- Avoid the word "policy" unless it refers to an NSM policy, and then write "NSM policy". Qualify other policies, such as "Firewall Manager policy".
- Each firewall type's "Recommended Design" page uses the same table columns (Priority, Importance, NSM policy, Scopes, Business need, NSM rules), Importance values, write-up fields (Contains, Why it's its own NSM policy, Scope, Most common owner), and scopes from the shared Common scopes list.
- Copy this entire comment block to the top of any new NSM page.
-->

# AWS WAF Recommended Design

<!-- TODO: recommended priority ranges -->

For the priority principles that apply to every firewall type, see [Policy Priority](../../../../policy-priority/docs/index.md). The scopes in this table come from the [Scope examples](../../../../scopes/docs/index.md#scope-examples).

The following table shows our general recommendation for the AWS WAF NSM policies of any organization, listed in the recommended order, with the business need that each NSM policy meets and the NSM rules that it contains. The order of the NSM traffic inspection rules follows the [Recommended WAF Rule Order](../../../../../waf/recommended-waf-rule-order/docs/index.md) in the AWS WAF Best Practices guide. NSM policies that contain only NSM firewall configuration rules or NSM policy settings, such as **WAF Mandatory things**, **Shield Advanced**, and **WAF default things**, don't affect WAF rule order. Their priority decides only which NSM policy wins when two NSM policies set the same property.

These priorities are an example, not hard requirements. What matters is the relative order of the NSM policies, not the numbers themselves. The numbers matter only in that they leave adequate spacing to add NSM policies over time, including room for thousands of applications that each have their own exceptions. These placements work for most organizations, so adjust them to fit your organization.

The **Importance** column uses the following values:

* **Recommended** – We recommend this NSM policy for every organization.
* **Consider** – Evaluate this NSM policy and make sure that it's applicable for you.
* **Use case** – Add this NSM policy when your applications have the use case that it addresses.
* **Optional** – Not a best practice, but if you choose to use it, this is where it belongs.

<div class="expandable-table" markdown>

| Priority | Importance | NSM policy | Scopes | Business need | NSM rules and their purpose |
|---|---|---|---|---|---|
| 10 | Recommended | [**Anti-DDoS**](#policy-anti-ddos) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Every public-facing application needs application layer DDoS detection and mitigation that sees all traffic before any other WAF rule can end evaluation. | **AWSManagedRulesAntiDDoSRuleSet.** Adds the [Anti-DDoS](../../../../../waf/aws-managed-rules/docs/index.md#anti-ddos) AMR rule group. |
| 10\* | Consider | [**Shield Advanced**](#policy-shield-advanced) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Public-facing applications need enhanced DDoS protection, cost protection, and access to the Shield Response Team (SRT). | No NSM rules. A setting on the NSM policy turns on AWS Shield Advanced protection for each in-scope resource. |
| 20 | Recommended | [**WAF Mandatory things**](#policy-waf-mandatory-things) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Every public-facing application must meet the same baseline, no matter which team owns it. | **WAF logging NSM rule.** Sends request logs from every public-facing application to one place for investigations and audits. |
| 30 | Optional | [**IP allow list**](#policy-ip-allow-list) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources)<br>[**Application**](../../../../scopes/docs/index.md#application) | A small number of trusted IP addresses must never be blocked, except by the Anti-DDoS AMR. Use sparingly or not at all. | **IP allow list NSM rule.** Allows requests from an IP set of trusted addresses. |
| 40 | Consider | [**Threat intelligence/block lists**](#policy-threat-intelligence-block-lists) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Threat analysts need to act on new threat intelligence across every public-facing application within minutes. | **Threat intelligence NSM rules.** Block requests that match threat intelligence, such as IP block lists, JA3 or JA4 fingerprints, or anything else that a WAF rule can match, and stay current as the threat analysts update them. |
| 50 | Recommended | [**IP reputation**](#policy-ip-reputation) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Requests from known malicious or anonymized sources, such as VPNs and hosting providers, need to be dropped before content inspection. | **AWSManagedRulesAmazonIpReputationList.** Adds the [Amazon IP reputation list](../../../../../waf/aws-managed-rules/docs/index.md#amazon-ip-reputation-list) AMR rule group.<br><br>**AWSManagedRulesAnonymousIpList.** Adds the [anonymous IP list](../../../../../waf/aws-managed-rules/docs/index.md#anonymous-ip-list) AMR rule group. |
| 60 | Consider | [**Geo blocking**](#policy-geo-blocking) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources)<br>[**Application**](../../../../scopes/docs/index.md#application) | Requests from countries that have no legitimate reason to access your applications need to be blocked before any content inspection. | **Geo blocking NSM rule.** Blocks requests from a list of blocked countries, or from every country that isn't on an allowed list. |
| 70 | Recommended | [**Rate limits (blanket)**](#policy-rate-limits-blanket) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Every public-facing application needs a high-bar rate limit that stops request floods before they reach more expensive WAF rules. | **Blanket rate-based NSM rule.** Blocks clients, usually by IP address, that exceed a high request rate across all requests. |
| 100 | Recommended | [**AMRs-in-Count**](#policy-amrs-in-count) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Every public-facing application needs the same baseline AWS Managed Rules, with matching requests labeled so that later NSM policies decide whether to block them. | **AWSManagedRulesCommonRuleSet.** Adds the [Core Rule Set (CRS)](../../../../../waf/aws-managed-rules/docs/index.md#core-rule-set-crs) with every WAF rule in count mode.<br><br>**AWSManagedRulesKnownBadInputsRuleSet.** Adds the [Known Bad Inputs](../../../../../waf/aws-managed-rules/docs/index.md#known-bad-inputs) rule group with every WAF rule in count mode.<br><br>These are examples. Add any other baseline AMR rule group that every public-facing application needs. For every baseline AMR rule group, see [Baseline rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html). |
| 101–199 | Use case | [**Use-case AMRs in count**](#policy-use-case-amrs-in-count) | [**Technology apps**](../../../../scopes/docs/index.md#technology-apps) | Only applications that use a technology, such as WordPress or a SQL database, need the protections in the matching use-case AMR rule group. | **One NSM policy for each use-case AMR rule group**, such as **WordPress-AMRs-in-Count**. Adds the use-case AMR rule group with every WAF rule in count mode, scoped to the applications that use that technology. For every use-case AMR rule group, see [Use-case specific rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html). |
| 200–9499 | Use case | [**Application exceptions**](#policy-application-exceptions)<br><br>**AMR exceptions**, such as **app1.example.com exceptions**<br><br>**Application-specific protections** | [**Application**](../../../../scopes/docs/index.md#application) | **AMR exceptions:** App1 has a feature that conflicts with a WAF rule in an AMR rule group, and the team needs that feature to keep working.<br><br>**Application-specific protections:** Application teams need protections specific to their applications, evaluated after the AMRs and before the central team's block NSM policies. | **App1-AMR-exception.** Lets requests to App1's custom feature through, without weakening protections for any other application.<br><br>**Application-specific NSM rules.** Protections that only one application needs. |
| 9500 | Recommended | [**AMR block with exceptions**](#policy-amr-block-with-exceptions) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | The baseline AMRs need to be enforced on every application by default, rather than left to each team. | **One block NSM rule for each AMR label**, such as **Block-CRS-CrossSiteScripting_Body-unless-excepted.** Stops requests that carry that AMR label, unless an application team has an approved exception for it. |
| 9501–9599 | Use case | [**Use-case AMR blocks with exceptions**](#policy-use-case-amr-blocks-with-exceptions) | [**Technology apps**](../../../../scopes/docs/index.md#technology-apps) | Each use-case AMR rule group needs to be enforced on every application it applies to by default. | **One NSM policy for each use-case AMR rule group**, such as **WordPress block with exceptions**. Stops the requests that the use-case AMR rule group labeled, unless an application team has an approved exception. |
| 9600 | Optional | [**Partner managed rules**](#policy-partner-managed-rules) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources)<br>[**Application**](../../../../scopes/docs/index.md#application) | Some applications need protections from AWS Marketplace partner rule groups. | **Partner rule group NSM rules.** Add partner managed rule groups after the free WAF rules, so that requests that were already blocked don't add per-request cost. |
| 9700 | Consider | [**Bot Control**](#policy-bot-control) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources)<br>[**Application**](../../../../scopes/docs/index.md#application) | Applications need to detect and manage bot traffic. | **AWSManagedRulesBotControlRuleSet.** Adds Bot Control with a scope-down statement. Runs near the end because it has per-request charges. |
| 9800 | Use case | [**Fraud Control**](#policy-fraud-control) | [**Application**](../../../../scopes/docs/index.md#application) | Login and account creation pages need protection against account takeover and fraudulent sign-ups. | **AWSManagedRulesATPRuleSet** and **AWSManagedRulesACFPRuleSet.** Add Account Takeover Prevention and Account Creation Fraud Prevention, scoped down to each application's login and sign-up pages. Runs last because it has the highest per-request charges. |
| 10,000 | Recommended | [**WAF default things**](#policy-waf-default-things) | [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) | Every web ACL needs a default action and a visibility configuration, with a fallback that any more specific NSM policy can override. | **Default action NSM rule.** Sets the web ACL default action, so that requests that no WAF rule blocks continue to the application.<br><br>**Visibility configuration NSM rule.** Turns on Amazon CloudWatch metrics and sampled requests for the web ACL, which AWS WAF requires. |

</div>

\* **Shield Advanced** is a different firewall type than AWS WAF. NSM tracks priority separately for each firewall type, so the **Shield Advanced** NSM policy can share priority 10 with **Anti-DDoS** without competing with it.

The following describes what each NSM policy in the table contains, why it's its own NSM policy, and the scope we recommend for it.

<a id="policy-anti-ddos"></a>
**10 – Anti-DDoS**

* **Contains:** The [Anti-DDoS](../../rule-examples/docs/index.md#anti-ddos) AMR rule group.
* **Why it's its own NSM policy:** It must run before every other NSM traffic inspection rule, so that it sees all traffic before any other WAF rule can end evaluation, including the IP allow list. Priorities 1–9 stay free, so that you can still add exceptions before it.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Cloud architect or central operator.

<a id="policy-shield-advanced"></a>
**10\* – Shield Advanced**

* **Contains:** No NSM rules. Shield Advanced protection is a setting on the NSM policy itself.
* **What it provides:** Shield Advanced provides enhanced layer 3 and layer 4 DDoS protection, including for non-HTTP and Regional endpoints. It also includes layer 7 protections, such as the Anti-DDoS AMR, under a different cost model, and adds features such as Shield Response Team (SRT) engagement and cost protection.
* **Why it's its own NSM policy:** It configures Shield Advanced rather than AWS WAF, and you might choose to protect a different set of resources than the WAF baseline. It doesn't affect WAF rule order.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Cloud architect or central operator.

<a id="policy-waf-mandatory-things"></a>
**20 – WAF Mandatory things**

* **Contains:** NSM firewall configuration rules for settings that security mandates on every public-facing web ACL, such as [WAF logging](../../rule-examples/docs/index.md#waf-logging) to a central bucket. It doesn't contain settings that depend on application context, such as the default action or token domains. Those belong in **WAF default things** or in application NSM policies.
* **Why it's its own NSM policy:** These settings rarely need exceptions, and any exception would be a truly unique one-off. Its low priority number means that it wins when another NSM policy sets the same property. It contains only NSM firewall configuration rules, so it doesn't affect WAF rule order.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Cloud architect or central operator.

<a id="policy-ip-allow-list"></a>
**30 – IP allow list**

* **Contains:** An [IP allow list](../../rule-examples/docs/index.md#ip-allow-list) NSM rule, with an IP set of trusted addresses and an allow action. Use sparingly or not at all, because allowed requests skip every WAF rule after it.
* **Why it's its own NSM policy:** It must run after Anti-DDoS and before every blocking NSM policy, and allow lists often differ by application.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) for organization-wide trusted addresses, or [**Application**](../../../../scopes/docs/index.md#application) for addresses that only one application trusts.
* **Most common owner:** App team requested.

<a id="policy-threat-intelligence-block-lists"></a>
**40 – Threat intelligence/block lists**

* **Contains:** NSM rules that block requests that match threat intelligence, such as an [IP block list](../../rule-examples/docs/index.md#ip-block-list) NSM rule with IPv4 and IPv6 IP sets. Threat intelligence doesn't need to be IP-based. It can include JA3 or JA4 fingerprints, or anything else that a WAF rule can match.
* **Why it's its own NSM policy:** The threat analysts own and update it on their own schedule, and changes to their threat intelligence reach every in-scope resource without changing anyone else's NSM policies.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Threat analysts.

<a id="policy-ip-reputation"></a>
**50 – IP reputation**

* **Contains:** The [Amazon IP reputation list](../../rule-examples/docs/index.md#amazon-ip-reputation-list) and [anonymous IP list](../../rule-examples/docs/index.md#anonymous-ip-list) AMR rule groups.
* **Why it's its own NSM policy:** These WAF rules are inexpensive to evaluate and remove known-bad and anonymized traffic before content inspection, so they run right after threat intelligence, before the geo and rate checks and the baseline AMRs.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Cloud architect or central operator.

<a id="policy-geo-blocking"></a>
**60 – Geo blocking**

* **Contains:** A [geo blocking](../../rule-examples/docs/index.md#geo-blocking) NSM rule that blocks a list of countries, or every country that isn't on an allowed list.
* **Why it's its own NSM policy:** Allowed and blocked countries often differ by application, so geo blocking often needs a different scope than the central baseline.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) for countries that the whole organization blocks, or [**Application**](../../../../scopes/docs/index.md#application) for application-specific restrictions.
* **Most common owner:** Cloud architect or central operator.

<a id="policy-rate-limits-blanket"></a>
**70 – Rate limits (blanket)**

* **Contains:** A [blanket rate limit](../../rule-examples/docs/index.md#blanket-rate-limit) NSM rule with a high-bar rate-based WAF rule, usually by client IP address, across all requests.
* **Why it's its own NSM policy:** It stops request floods before they reach more expensive WAF rules, and its threshold applies to every public-facing application.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Cloud architect or central operator.

<a id="policy-amrs-in-count"></a>
**100 – AMRs-in-Count**

* **Contains:** The baseline AMR rule groups that every public-facing application needs, with every WAF rule in count mode, such as the [Core Rule Set](../../rule-examples/docs/index.md#core-rule-set) and [Known Bad Inputs](../../rule-examples/docs/index.md#known-bad-inputs). For every baseline AMR rule group, see [Baseline rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-baseline.html).
* **Why it's its own NSM policy:** Count mode labels matching requests without blocking them, so application exception NSM policies can act on those labels before **AMR block with exceptions** enforces them.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Cloud architect or central operator.

<a id="policy-use-case-amrs-in-count"></a>
**101–199 – Use-case AMRs in count**

* **Contains:** One NSM policy for each [use-case AMR](../../rule-examples/docs/index.md#use-case-amrs) rule group that your applications need, such as WordPress or SQL database. Each has every WAF rule in count mode. For every use-case AMR rule group, see [Use-case specific rule groups](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-use-case.html).
* **Why each is its own NSM policy:** Each use-case AMR rule group applies only to applications that use that technology, so each needs its own scope.
* **Scope:** The [**Technology apps**](../../../../scopes/docs/index.md#technology-apps) scope for that technology.
* **Most common owner:** Cloud architect or central operator.

!!! note "Exceptions to NSM policies below priority 200"
    Apart from the AMRs in count, the NSM policies above this point aren't normally in the purview of application teams to request exceptions to. Keep exceptions to these NSM policies to true one-offs. If application teams regularly need exceptions to one of these NSM policies, consider moving that NSM policy closer to or above priority 200, so that you can grant exceptions with the [label-based exceptions](../../label-based-exceptions/docs/index.md) pattern that follows.

<a id="policy-application-exceptions"></a>
**200–9499 – Application exceptions**

One NSM policy for each application, owned by that application's team, that grants the application exceptions to the baseline AMRs. The same NSM policy can also contain protections that only that application needs. The range leaves room for thousands of applications.

* **AMR exceptions**, such as **app1.example.com exceptions**
  * **Contains:** [Application exceptions](../../rule-examples/docs/index.md#application-exceptions) for App1, such as a WAF rule that adds an exception label to requests for one URI path.
  * **Why it's its own NSM policy:** The App1 team owns it, and it must reach only App1's web ACLs. It runs after the AMRs in count and before the block NSM policies, because a WAF rule can read only the labels that earlier WAF rules added.
  * **Scope:** [**Application**](../../../../scopes/docs/index.md#application), for App1 only.
  * **Most common owner:** App team requested.
* **Application-specific protections**
  * **Contains:** [Application-specific protections](../../rule-examples/docs/index.md#application-specific-protections) for each application, such as [scoped rate limits](../../rule-examples/docs/index.md#scoped-rate-limits) for a login page or an expensive API.
  * **Why each is its own NSM policy:** Each application team owns its own NSM policy, so protections for one application don't affect any other application.
  * **Scope:** [**Application**](../../../../scopes/docs/index.md#application), one for each application.
  * **Most common owner:** App team requested.

<a id="policy-amr-block-with-exceptions"></a>
**9500 – AMR block with exceptions**

* **Contains:** [AMR block with exceptions](../../rule-examples/docs/index.md#amr-block-with-exceptions) NSM rules, one for each unique label that the baseline AMRs add. Each blocks requests that carry its AMR label, unless the request also carries the matching exception label.
* **Why it's its own NSM policy:** It must run after every exception NSM policy, so that it can read their exception labels.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources), the same scope as **AMRs-in-Count**.
* **Most common owner:** Cloud architect or central operator.

<a id="policy-use-case-amr-blocks-with-exceptions"></a>
**9501–9599 – Use-case AMR blocks with exceptions**

* **Contains:** One NSM policy for each use-case AMR rule group, with [AMR block with exceptions](../../rule-examples/docs/index.md#amr-block-with-exceptions) NSM rules that block requests that the AMR rule group labeled, unless the request also carries an exception label.
* **Why each is its own NSM policy:** Each block NSM policy must reach the same resources as the use-case AMR NSM policy that it enforces.
* **Scope:** The same [**Technology apps**](../../../../scopes/docs/index.md#technology-apps) scope as the matching use-case AMR NSM policy.
* **Most common owner:** Cloud architect or central operator.

<a id="policy-partner-managed-rules"></a>
**9600 – Partner managed rules**

* **Contains:** [Partner managed rule groups](../../rule-examples/docs/index.md#partner-managed-rule-groups) from AWS Marketplace.
* **Why it's its own NSM policy:** Partner rule groups have per-request costs, so they run after the free WAF rules, and requests that were already blocked don't add cost.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) or [**Application**](../../../../scopes/docs/index.md#application), depending on which applications need the partner protections.
* **Most common owner:** App team requested.

<a id="policy-bot-control"></a>
**9700 – Bot Control**

* **Contains:** The [Bot Control](../../rule-examples/docs/index.md#bot-control) AMR rule group with a scope-down statement.
* **Why it's its own NSM policy:** Bot Control has per-request charges, so it runs near the end, after every other filter.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources) or [**Application**](../../../../scopes/docs/index.md#application), depending on which applications need bot management.
* **Most common owner:** App team requested.

<a id="policy-fraud-control"></a>
**9800 – Fraud Control**

* **Contains:** The [Account Takeover Prevention](../../rule-examples/docs/index.md#account-takeover-prevention) (ATP) and [Account Creation Fraud Prevention](../../rule-examples/docs/index.md#account-creation-fraud-prevention) (ACFP) AMR rule groups, scoped down to each application's login and sign-up pages.
* **Why it's its own NSM policy:** Fraud Control has the highest per-request charges, so it runs last, and each application has its own login and sign-up pages.
* **Scope:** [**Application**](../../../../scopes/docs/index.md#application).
* **Most common owner:** App team requested.

<a id="policy-waf-default-things"></a>
**10,000 – WAF default things**

* **Contains:** NSM firewall configuration rules for settings that have application considerations, such as the web ACL [default action](../../rule-examples/docs/index.md#default-action), [token domains](../../rule-examples/docs/index.md#token-domains), and [visibility configuration](../../rule-examples/docs/index.md#visibility-configuration).
* **Why it's its own NSM policy:** Its high priority number makes it a fallback that any more specific NSM policy can override. It doesn't affect WAF rule order.
* **Scope:** [**All Public Facing Resources**](../../../../scopes/docs/index.md#all-public-facing-resources).
* **Most common owner:** Cloud architect or central operator.
