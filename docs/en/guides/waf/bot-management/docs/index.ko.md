# 봇 관리

[AWS WAF Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html)은 애플리케이션에 대한 봇 트래픽에 대한 가시성과 제어를 제공하는 관리형 규칙 그룹입니다. 봇 트래픽은 과도한 리소스를 소비하고, 비즈니스 지표를 왜곡하고, 합법적인 사용자의 성능을 저하시키며, 원치 않는 콘텐츠 스크래핑을 유발할 수 있습니다. Bot Control은 봇 트래픽을 감지하고 분류하여 각 카테고리를 어떻게 처리할지 결정할 수 있게 합니다. 차단, 비율 제한, 챌린지 또는 허용.

## Web Bot Authentication (WBA)

Web Bot Authentication은 Bot Control 버전 4.0 이상에서 사용 가능한 검증 방법입니다. Web Bot Authentication은 HTTP 메시지의 암호화 서명을 사용하여 요청이 주장하는 봇에서 실제로 왔는지 검증합니다. 해당 서명은 요청자의 결제를 승인하여 콘텐츠 제공자 또는 인터넷의 모든 것이 각 요청 당사자와 일대일 관계 없이 요청을 수익화할 수 있도록 합니다. 이것은 최근 개발된 [x402 프로토콜](https://docs.cdp.coinbase.com/x402/welcome)의 일부입니다.

이것은 AI 봇 및 크롤러 관리에 특히 관련됩니다. 많은 AI 서비스가 이제 WBA를 사용하여 요청에 서명하므로, 합법적인 AI 크롤러를 구별할 수 있을 뿐만 아니라 해당 크롤 요청을 수익화하는 경로를 제공합니다.

Bot Control은 검증 결과에 따라 요청에 WBA 레이블을 적용합니다:

- `awswaf:managed:aws:bot-control:web_bot_auth:verified` - 공개 키 디렉토리에 대해 서명이 성공적으로 검증됨
- `awswaf:managed:aws:bot-control:web_bot_auth:invalid` - 서명이 있지만 암호화 검증 실패
- `awswaf:managed:aws:bot-control:web_bot_auth:expired` - 서명이 만료된 암호화 키를 사용
- `awswaf:managed:aws:bot-control:web_bot_auth:unknown_bot` - 키 디렉토리에서 키 ID를 찾을 수 없음

WBA에 대한 자세한 배경 및 AWS WAF가 이를 식별하는 방법은 발표 [AWS WAF announces Web Bot Auth support](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-waf-web-bot-auth-support/)를 참조하세요.

## Common vs. Targeted Bot Control

Bot Control은 두 가지 검사 수준으로 제공됩니다. protection pack에 Bot Control 규칙 그룹을 추가할 때 수준을 선택합니다.

### Common

Common 수준은 자체 식별하는 봇을 식별합니다. 여기에는 검색 엔진 크롤러, 소셜 미디어 봇, 모니터링 서비스, 숨기려 하지 않는 스크래퍼, AI 및 에이전트 봇이 포함됩니다.

BotControl Common 사용 시기:

- 애플리케이션에 어떤 봇 트래픽이 도달하는지 가시성이 필요한 경우.
- 자체 식별하는 봇을 식별하고 접근할 수 있는 것을 제어해야 하는 경우. 예를 들어, 검색 엔진이 공개 페이지를 크롤링하도록 허용하지만 API 엔드포인트 또는 인증된 영역에서는 차단.
- 카테고리별로 AI 봇의 콘텐츠 접근을 관리하려는 경우(특정 AI 크롤러를 허용, 차단 또는 비율 제한).
- WBA 활성화된 봇이 콘텐츠를 크롤링하는 것을 제한 및/또는 수익화하려는 경우.

이름이나 카테고리별로 봇을 감지하는 것은 WBA 서명 또는 User-Agent(많은 경우 고정/전용 IP 포함)를 통해 수행됩니다. Bot Control은 봇 요청을 추가로 검증됨 또는 미검증으로 표시합니다.

**검증됨:**
- 요청에 유효한 WBA 서명이 있음
- 요청에 잘 알려진 User-Agent와 소스 IP/역방향 DNS가 있음

**미검증:**
- 요청에 잘 알려진 User-Agent가 있지만 소스 IP가 해당 봇의 잘 알려진 IP 소스와 일치하지 않음
- 요청에 잘 알려진 User-Agent가 있지만 봇에 전용/알려진 IP가 없음

User-Agent는 클라이언트가 제공하므로 봇을 검증하기에 충분하지 않습니다. 아래 예시 curl 명령은 미검증 Google 봇으로 나타나며, 잘 알려진 User-Agent가 있지만 소스 IP가 봇의 알려진 해당 소스 IP와 일치하지 않습니다.

```
curl -H "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)" https://checkip.amazonaws.com
```

Bot Control 버전 4.0.0부터 Bot Control Common은 검증된 봇을 차단하지 않습니다. 버전 4.0.0 이전에는 BotControl이 기본적으로 *CategoryAI* 봇을 차단했습니다. 사용자 정의 레이블 기반 규칙을 사용하여 여전히 모든 봇(검증됨 또는 아님)을 제한/차단할 수 있습니다.

**예: 검증된 경우에도 특정 봇 카테고리 차단**

Bot Control은 검증 상태와 봇 카테고리 모두로 요청에 레이블을 지정합니다. 검증된 봇이 기본적으로 허용되더라도 특정 카테고리가 애플리케이션의 특정 부분에 접근하는 것을 차단하고 싶을 수 있습니다. 이 예는 검증 여부에 관계없이 모든 소셜 미디어 봇이 사이트에 접근하는 것을 차단합니다.

```json
{
  "Name": "block-social-media",
  "Priority": 10,
  "Statement": {
    "LabelMatchStatement": {
      "Scope": "LABEL",
      "Key": "awswaf:managed:aws:bot-control:bot:category:social_media"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "block-social-media"
  }
}
```

### Targeted

Bot Control의 Targeted 수준은 모든 BotControl Common 기능에 더해 다른 봇 감지 기능을 회피하려는 정교한 봇을 감지하는 머신 러닝 기반 행동 분석을 포함합니다. BotControl Targeted는 자체 식별하지 않고, IP를 교체하고, 헤드리스 브라우저를 사용하고, 인간 브라우징 패턴을 모방하고, 주거용 프록시를 사용하고, 합법적인 인간 트래픽과 혼합하기 위한 기타 속임수를 사용하는 봇을 포착하는 데 도움이 됩니다.

Bot Control Targeted 사용 시기:

- 정교한 자동화된 접근으로부터 고가치 엔드포인트(결제, 가격, 재고)를 보호해야 하는 경우.
- 간단한 봇 서명을 회피하는 크리덴셜 스터핑, 가짜 계정 생성 또는 자동화된 구매와 같은 사기 위협에 직면한 경우. 이 사용 사례에서는 일반적으로 Bot Control과 함께 [Fraud Control 관리형 규칙 그룹](../../fraud-prevention/docs/index.md)을 사용합니다.
- IP를 교체하고 인간 행동을 모방하는 봇에 의한 가격 데이터, 제품 카탈로그 또는 게시된 콘텐츠의 스크래핑과 같은 콘텐츠 위협에 대해 방어해야 하는 경우.
- 봇 트래픽 볼륨이 비율 제한만으로는 해결할 수 없을 정도로 성능을 저하시키거나 인프라 비용을 증가시키는 가용성 위협을 경험하는 경우.

BotControl Targeted의 WAF 규칙은 여러 버킷으로 나눌 수 있습니다:

**TGT_ vs TGT_ML_**
BotControl Targeted에는 애플리케이션에 특정하지 않은 일반적인 규칙이 있습니다. 예: 유효한 WAF 토큰 없는 요청 비율 제한. TGT_ML_ 규칙은 애플리케이션별 정상 기준선을 구축하고 해당 기준선의 이상에 따라 감지하고 대응합니다.

**Session vs 비Session**
많은 BotControl Targeted 규칙에는 이름에 *Session*이 포함됩니다. 이 규칙은 AWS WAF 토큰(즉, WAF Challenge 또는 Captcha에서 얻은 쿠키)의 존재(또는 부재)를 기반으로 동작을 추적합니다. 예를 들어 TGT_VolumetricSession은 클라이언트 IP 대신 이 쿠키의 고유 값으로 카운트하는 것을 제외하면 기존 Rate Based WAF 규칙과 유사합니다.

BotControl Targeted 사용의 추가/실용적 예는 블로그 [How to use AWS WAF Bot Control for Targeted Bots signals and mitigate evasive bots](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-use-aws-waf-bot-control-for-targeted-bots-signals-and-mitigate-evasive-bots-with-adaptive-user-experience/)를 참조하세요.

## Bot Control과 함께 범위 축소 문 사용

Bot Control에는 요청당 요금이 있으므로 평가하는 모든 요청에 비용이 있습니다. 범위 축소 문을 사용하면 Bot Control이 검사하는 요청을 제한할 수 있습니다. 범위 축소 문에 의해 제외된 요청은 Bot Control 평가에 대해 과금되지 않습니다.

대부분의 애플리케이션에서 좋은 시작점은 Bot Control을 동적 엔드포인트로 범위를 지정하고 정적 자산(CSS, JavaScript)을 제외하는 것입니다. 인증된 전용 섹션에 대한 검사를 피하기 위해 범위를 축소할 수도 있습니다. 인증에서 봇을 감지하고 차단할 수 있다는 아이디어입니다(합법적이든 악의적이든).

Bot Control이 모든 동적 엔드포인트를 평가해야 하는지, 봇 트래픽이 비즈니스 영향을 유발하는 엔드포인트만 평가하면 되는지 고려하세요. 로그인 페이지, 검색, 가격 API, 결제 흐름 등. 범위 축소 문 구성 방법은 아래의 Common 및 Targeted 예를 참조하세요.

단일 올바른 구성은 없으며 애플리케이션에 따라 다릅니다. 지침 원칙은 검사 수준을 엔드포인트의 위험에 맞추는 것입니다:

| | 범위 내 | 범위 외 |
|---|---|---|
| **Bot Control Common** | 프리미엄 또는 유료 콘텐츠, 스크래핑 또는 지표 왜곡이 중요한 공개 페이지 | 정적 자산(CSS, JS, 이미지, 폰트), 헬스 체크 경로 |
| **Bot Control Targeted** | 민감하거나 고가치 엔드포인트 - 로그인, 계정 생성, 결제, 가격 API, 파일 업로드 | 정적 자산, 이미 인증된 내부 페이지 |

Bot Control Common은 콘텐츠를 크롤링하는 대상에 대한 광범위한 가시성을 제공하므로, 해당 가시성이 비즈니스 가치가 있는 페이지로 범위를 지정하세요. Bot Control Targeted는 행동 분석 및 챌린지-응답 감지를 추가하므로, 정교한 봇이 피해를 줄 수 있는 엔드포인트로 좁게 범위를 지정하세요.

**예: 특정 URI로 범위가 지정된 Common Bot Control**

이것은 `/api/search`에 도달하는 요청에만 Common 수준 Bot Control을 적용하여, 다른 모든 트래픽을 Bot Control 평가 및 요금에서 제외합니다.

```json
{
  "Name": "bot-control-common",
  "Priority": 9,
  "OverrideAction": {
    "None": {}
  },
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesBotControlRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesBotControlRuleSet": {
            "InspectionLevel": "COMMON",
            "EnableMachineLearning": false
          }
        }
      ],
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "SearchString": "/api/search",
          "FieldToMatch": { "UriPath": {} },
          "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
          "PositionalConstraint": "STARTS_WITH"
        }
      }
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "bot-control-common"
  }
}
```

**예: 결제 및 가격 엔드포인트로 범위가 지정된 Targeted Bot Control**

이것은 정교한 봇이 가장 큰 비즈니스 영향을 미치는 고가치 엔드포인트에 Targeted 수준 Bot Control을 적용합니다.

```json
{
  "Name": "bot-control-targeted",
  "Priority": 9,
  "OverrideAction": {
    "None": {}
  },
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesBotControlRuleSet",
      "ManagedRuleGroupConfigs": [
        {
          "AWSManagedRulesBotControlRuleSet": {
            "InspectionLevel": "TARGETED",
            "EnableMachineLearning": true
          }
        }
      ],
      "ScopeDownStatement": {
        "OrStatement": {
          "Statements": [
            {
              "ByteMatchStatement": {
                "SearchString": "/checkout",
                "FieldToMatch": { "UriPath": {} },
                "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                "PositionalConstraint": "STARTS_WITH"
              }
            },
            {
              "ByteMatchStatement": {
                "SearchString": "/api/pricing",
                "FieldToMatch": { "UriPath": {} },
                "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
                "PositionalConstraint": "STARTS_WITH"
              }
            }
          ]
        }
      }
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "bot-control-targeted"
  }
}
```

## AI 봇 수익화를 위한 WBA
!!! warning "향후 콘텐츠 업데이트 진행 중"
  이 시점 이후의 섹션은 현재 업데이트 중이며 불완전할 수 있습니다. 곧 다시 방문하거나 그동안 AWS WAF 공개 문서를 참조하세요.

봇을 식별하는 새로운 권위 있는 방법인 것 외에도, WBA는 AI 봇 트래픽에 대한 콘텐츠 수익화 전략을 가능하게 합니다. WBA 이전에는, 콘텐츠를 소비하는 타사를 수익화하려면 일대일 계약과 접근을 승인하는 기술적 구현이 필요했습니다. 관계가 몇 개만 필요한 경우 이것이 작동할 수 있지만, AI/에이전트 봇이 확산됨에 따라 실용적이지 않습니다. WBA는 일대일 관계 없이 크롤링 요청을 감지하고 수익화하는 공통 방법을 제공합니다.

WBA가 AI/에이전트 봇 요청을 신뢰성 있게 식별하므로, 봇별로 정책 결정을 내릴 수 있습니다. 상업적 관계가 있는 AI 프로바이더의 봇에 대한 접근을 허용하면서 다른 봇을 차단하거나 비율 제한합니다. 이를 통해 AI 봇 접근을 순전히 보안 결정이 아닌 비즈니스 결정으로 처리할 수 있습니다.

수익화 고려 사항을 포함하여 AWS WAF로 AI 봇을 관리하는 자세한 안내는 블로그 [How to manage AI Bots with AWS WAF and enhance security](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-manage-ai-bots-with-aws-waf-and-enhance-security/)를 참조하세요.

WBA가 AI 에이전트 프레임워크와 통합하는 방법은 [Reduce CAPTCHAs for AI agents browsing the web with Web Bot Auth in Amazon Bedrock AgentCore Browser](https://aws.amazon.com/blogs/machine-learning/reduce-captchas-for-ai-agents-browsing-the-web-with-web-bot-auth-preview-in-amazon-bedrock-agentcore-browser/)를 참조하세요.

## 관련 리소스

- [AWS WAF Bot Control 문서](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html)
- [Bot Control 규칙 그룹 참조](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-bot.html)
- [고급 봇 트래픽 감지 및 차단](https://aws.amazon.com/blogs/security/detect-and-block-advanced-bot-traffic/)
- [AWS WAF Bot Control 완화 기능 세부 조정 및 최적화](https://aws.amazon.com/blogs/security/fine-tune-and-optimize-aws-waf-bot-control-mitigation-capability/)
- [AWS WAF Challenge 및 CAPTCHA 작업으로 봇으로부터 보호](https://aws.amazon.com/blogs/networking-and-content-delivery/protect-against-bots-with-aws-waf-challenge-and-captcha-actions/)
- [CAPTCHA 및 Challenge](../../captcha-and-challenge/docs/index.md) - Bot Control과 함께 작동하는 토큰 기반 완화 작업
- [권장 WAF 규칙 순서](../../recommended-waf-rule-order/docs/index.md) - 규칙 평가 순서에서 Bot Control의 위치
