# CAPTCHA 및 Challenge

AWS WAF는 합법적인 인간 사용자를 자동화된 클라이언트와 구별하는 데 도움이 되는 두 가지 토큰 기반 완화 작업, [CAPTCHA](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge.html) 및 [Challenge](https://docs.aws.amazon.com/waf/latest/developerguide/waf-challenge.html)를 제공합니다. 두 작업 모두 구성 가능한 면제 시간이 있는 토큰(쿠키)을 발급하지만, 사용자 경험과 탐지 접근 방식이 다릅니다. CAPTCHA는 인간의 상호 작용이 필요한 시각적 퍼즐을 제시하고, Challenge는 최종 사용자에게 보이지 않는 자동 브라우저 검사를 실행합니다. 이 섹션에서는 각 작업을 사용할 시기, 면제 시간 구성 방법, 이러한 작업을 WAF 규칙 세트에 통합하기 위한 모범 사례를 다룹니다.

## CAPTCHA vs. Challenge 사용 시기

### 사용자 경험

CAPTCHA는 눈에 보이는 마찰을 도입합니다. 사용자가 진행하기 전에 풀어야 하는 퍼즐입니다. 이 마찰은 보안 이점이 중단을 능가하는 로그인, 계정 생성 또는 결제와 같은 저빈도, 고가치 작업에서 허용될 수 있습니다. 사용자가 세션 중 반복적으로 수행하는 고트래픽 페이지나 작업에서는 덜 허용됩니다.

CAPTCHA 퍼즐은 매우 어린 사용자, 고령 사용자, 기술 리터러시 수준이 다양한 사용자를 대상으로 하는 애플리케이션에 특히 영향을 미칠 수 있으며, 제시된 CAPTCHA 퍼즐로 인해 이탈률이 높아질 수 있습니다.

Challenge는 사용자에게 보이지 않습니다. 브라우저가 상호 작용 없이 자동 검사를 완료합니다.

### 봇 상호 작용

Challenge는 전체 브라우저 엔진이 없는 자동화된 클라이언트(스크립트, curl, 기본 HTTP 라이브러리, JavaScript를 실행하지 않는 간단한 헤드리스 설정)를 무력화합니다. 클라이언트가 자동 브라우저 검사를 실행할 수 없으면 요청이 종료됩니다. 이것은 간단한 봇을 중지하지만, JavaScript를 완료할 수 없는 API 또는 SDK에도 문제를 제시하여 해당 요청을 효과적으로 차단합니다.

CAPTCHA는 시각적 추론, 공간적 상호 작용, 자동화가 해결하기에 상당히 더 비용이 많이 들고 복잡한 행동 패턴을 요구하여 기준을 더 높입니다. 그러나 어떤 챌린지도 영구적이지 않습니다. 정교한 봇은 결국 솔버 서비스, ML 기반 솔버 또는 인간 농장을 통해 모든 CAPTCHA를 해결할 수 있습니다. 목표는 대규모로 더 이상 경제적으로 실행 가능하지 않을 정도로 자동화의 비용과 지연을 증가시키는 것입니다.

봇이 Challenge 또는 CAPTCHA를 성공적으로 완료하더라도, 토큰을 얻는 것은 단순한 합격/불합격 관문이 아닙니다. 토큰은 브라우저 환경 세부 정보, 상호 작용 패턴, 세션 식별자와 같은 핑거프린팅 신호를 전달하며, Bot Control Targeted와 같은 다운스트림 규칙이 비정상적인 동작을 감지하고 시간에 따라 세션을 추적하는 데 사용합니다. 토큰을 획득한 봇은 여전히 해당 토큰에 포함된 신호를 통한 행동 분석에 노출됩니다.

두 작업을 함께 사용할 때, Challenge를 기본 토큰 획득 메커니즘으로 광범위하게 사용하고 Bot Control 신호가 위험 증가를 나타내는 엔드포인트에 대해서만 CAPTCHA를 예약하세요. 예를 들어, 요청이 대상 봇 신호 또는 고위험 레이블을 전달할 때만 CAPTCHA를 트리거합니다.

### 반응적 vs. 수동적 vs. 의도적

**반응적**
protection pack은 Challenge 또는 Captcha를 규칙 작업으로 사용할 수 있으며, 많은 AMR이 이를 기본 작업으로 사용합니다. WAF가 Challenge 또는 Captcha로 요청을 종료할 때, 이것은 종종 문제 없이 작동합니다. 그러나 WAF가 반응적으로 트리거할 때까지 기다리기보다 사전에 이러한 작업을 통합해야 하는 여러 이유가 있습니다:

- WAF 토큰을 사용하면 IP뿐만 아니라 세션별로 활동을 집계할 수 있습니다. 중요한 상호 작용까지 챌린지를 발급하기를 기다리면, 사용자 세션의 초기 부분에 대한 이 신호를 놓칩니다.
- 많은 AMR이 탐지 기능을 개선하기 위해 WAF 토큰을 사용합니다. 반응적 챌린지는 이러한 탐지를 클라이언트 상호 작용의 후반으로 제한하여 초기 및 고감도 커버리지를 줄입니다.
- iFrame, 위젯 및 유사한 임베드는 Captcha를 올바르게 렌더링하지 못할 수 있습니다. 브라우저는 임베드된 컨텍스트에서 인터스티셜 리디렉션을 일관되지 않게 처리하여, 최종 사용자에게 깨지거나 사용할 수 없는 경험을 초래합니다.
- Challenge 및 Captcha는 text/html 콘텐츠에 대한 GET 요청에서 트리거되어야 합니다. POST 또는 다른 콘텐츠 유형에서 트리거되면, 브라우저가 인터스티셜 리디렉션을 따를 수 없습니다.

**수동적**
수동적 통합은 페이지 로드 중 백그라운드에서 Challenge를 자동으로 실행하는 것을 의미합니다. 페이지에 AWS WAF가 제공하는 async/defer JavaScript 스니펫을 포함합니다. 최종 사용자의 첫 번째 요청에는 토큰이 없지만, 초기 페이지 로드 및 JS 실행 후 모든 후속 요청에는 유효한 WAF 토큰이 포함됩니다. 유효한 토큰이 있는 사용자가 Challenge 작업이 있는 WAF 규칙을 트리거하면, 규칙이 HTTP 202 인터스티셜 리디렉션으로 이어지지 않습니다. 이것은 리디렉션을 처리할 수 없는 비 GET 요청이나 비 text/html 콘텐츠 유형에 중요합니다.

**사전적**
사용자가 POST를 완료하기 전에(예: 폼 제출 또는 버튼 클릭) 애플리케이션이 Captcha를 트리거하도록 구성할 수 있습니다. AWS WAF Captcha 구현 방법에 대한 [이 예제](https://docs.aws.amazon.com/waf/latest/developerguide/waf-js-captcha-api-conditional.html)를 참조하세요. 간략히 말해, 사용자가 버튼을 클릭하면 AwsWafCaptcha가 Captcha를 트리거하고 퍼즐을 제시합니다. 성공적으로 해결하면(HTTP 405 없음), 애플리케이션은 POST를 진행합니다. 이제 유효한 WAF 토큰이 있습니다. WAF 측에서 이 POST 요청은 이미 유효한 Captcha 토큰을 전달하므로, Captcha 작업 규칙이 HTTP 405 인터스티셜 리디렉션 없이 통과합니다.

**요약**

가능하면 수동적 통합을 사용하세요. 페이지 로드 중 자동으로 토큰을 획득하고 인터스티셜 리디렉션을 완전히 피합니다. Captcha의 경우, 최상의 사용자 경험을 위해 POST 전에 클라이언트 측에서 퍼즐을 트리거하는 사전적 통합을 사용하세요. 반응적 Challenge 및 Captcha 작업은 비합법적 트래픽을 포착하는 데 가장 적합하지만, 비 GET 요청, 비 text/html 콘텐츠 유형, iFrame, 임베드된 위젯에서 문제를 일으킬 수 있습니다.

## 면제 시간 구성

CAPTCHA와 Challenge 작업 모두 면제 시간을 사용하여 유효한 토큰이 클라이언트를 재검증에서 면제하는 기간을 결정합니다. 클라이언트가 Challenge를 성공적으로 완료하거나 CAPTCHA를 풀면, 결과 WAF 토큰은 구성된 면제 기간 동안 유효합니다. 해당 토큰을 전달하는 후속 요청은 토큰이 만료될 때까지 작업을 다시 트리거하지 않고 통과합니다.

면제 시간은 근본적으로 세 가지 요소 간의 트레이드오프입니다:

- **보안** - 짧은 면제 시간은 토큰이 더 빨리 만료되어, 도난되거나 재생된 토큰이 사용될 수 있는 기간을 줄이고 클라이언트가 합법성을 다시 증명해야 하는 빈도를 높입니다. 긴 면제 시간은 침해된 토큰이 유효한 상태로 남는 더 큰 격차를 남깁니다.
- **사용자 경험** - 특히 Captcha의 경우, 짧은 면제는 사용자에게 퍼즐이 더 자주 제시되어 마찰이 증가하고 이탈로 이어질 수 있습니다. Challenge 면제는 보이지 않으므로 직접적인 UX 영향이 없습니다.
- **비용** - 각 Captcha 시도는 청구 가능하므로, 짧은 면제 시간은 사용자가 단일 세션 내에서 여러 Captcha 퍼즐을 풀게 하여 직접적으로 비용을 증가시킬 수 있습니다. Challenge의 경우, 비용은 WAF가 Challenge 작업(HTTP 202 인터스티셜)을 반환할 때만 적용됩니다. JavaScript SDK 통합을 통해 획득한 토큰은 청구 가능한 Challenge 이벤트가 아닙니다. 수동적 통합이 있으면 대부분의 클라이언트가 이미 유효한 토큰을 전달하고 청구 가능한 Challenge 작업을 트리거하지 않습니다.

### 면제 시간 구성

면제 시간은 두 수준에서 설정할 수 있습니다:

- **Protection pack 수준** - protection pack의 모든 CAPTCHA 및 Challenge 작업에 대한 기본 면제 시간을 설정합니다. 규칙 수준 설정으로 재정의하지 않는 한 적용됩니다.
- **규칙 수준** - 특정 규칙에 대해 protection pack 기본값을 재정의합니다. 특정 엔드포인트가 일반 기본값보다 짧거나 긴 면제가 필요할 때 사용하세요.

기본 면제 시간은 CAPTCHA와 Challenge 모두 300초(5분)입니다. 애플리케이션의 세션 패턴과 위험 프로필에 따라 조정하세요.

## 토큰 도메인 구성

WAF 토큰은 기본적으로 Challenge 또는 Captcha를 발급한 호스트 이름(반응적이든 수동적이든)으로 범위가 지정됩니다. 예를 들어, 사용자가 `www.example.com`에 연결하고 WAF가 HTTP 202 Challenge를 발급하면, 결과 토큰은 `www.example.com`에만 유효합니다. 해당 사이트가 `api.example.com`에 요청하고 WAF에 Challenge 작업이 있는 규칙이 있으면, 사용자가 몇 초 전에 합법성을 증명했더라도 WAF가 다른 HTTP 202 Challenge를 발급합니다. 이 왕복은 지연 시간을 추가하고 청구 가능한 Challenge 또는 Captcha 비용을 높입니다.

[토큰 도메인 구성](https://docs.aws.amazon.com/waf/latest/developerguide/waf-tokens-domains.html)을 사용하면 WAF 토큰이 유효한 것으로 간주되어야 하는 추가 호스트 이름 또는 도메인 접미사를 지정할 수 있습니다. 이 예에서 토큰 도메인을 다음 중 하나로 구성합니다:

- `www.example.com`, `api.example.com`
또는
- `example.com`

이렇게 하면 첫 번째 Challenge는 여전히 발생하지만, 획득한 토큰은 `example.com` 아래의 모든 호스트 이름에 유효합니다. 이는 재챌린지 및 재captcha, 해당 지연 시간, 추가 비용, Captcha의 경우 불필요한 사용자 마찰을 방지합니다. 이것은 프론트엔드 서브도메인과 API 서브도메인이 모두 동일한 WAF protection pack으로 보호되는 아키텍처에서 특히 일반적입니다.

## AMR이 사용하는 Challenge 및 Captcha
Challenge 및 Captcha는 AWS WAF의 유료 기능입니다. 예외는 AWS 관리형 규칙(AMR)이 Challenge 또는 Captcha를 기본 작업으로 사용하는 경우입니다. 현재 Bot Control Targeted, Fraud Control 규칙, AntiDDoS 관리형 규칙이 이에 해당합니다.

이 예외가 적용되려면, AMR 자체가 Challenge 또는 Captcha 작업으로 요청을 종료해야 합니다. 기본 작업을 재정의하거나, 기본 작업이 Challenge 또는 Captcha인 규칙의 레이블에 작용하는 사용자 정의 규칙을 사용하면, 이러한 *유료* Challenge/Captcha 이벤트이며 AMR 구독에 포함되지 않습니다.

파트너 관리형 규칙, 사용자 정의 규칙 또는 모든 WAF 규칙이나 관리형 규칙의 재정의에는 [Challenge 및 Captcha 비용](../../waf-cost/docs/index.md#challenge-and-captcha-costs)에 따른 표준 사용량 기반 비용이 적용됩니다.

## Captcha 및 Challenge의 규칙 순서

protection pack에서 CAPTCHA 및 Challenge 규칙을 배치할 위치는 [권장 WAF 규칙 순서](../../recommended-waf-rule-order/docs/index.md)를 참조하세요. Challenge가 WBA 탐지와 어떻게 상호 작용하는지는 [봇 관리 - 웹 브라우저 자동화 탐지](../../bot-management/docs/index.md#web-bot-authentication-wba)를 참조하세요. CAPTCHA 또는 Challenge 작업을 조건부로 트리거하는 레이블 기반 규칙 작성은 [사용자 정의 규칙](../../custom-rules/docs/index.md)을 참조하세요.
