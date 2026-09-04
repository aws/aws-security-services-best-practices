# 운영화

이 섹션은 [AWS WAF 작동 방식](../../prerequisites/docs/index.md), [Amazon 관리형 규칙](../../aws-managed-rules/docs/index.md), [사용자 정의 규칙](../../custom-rules/docs/index.md), [WAF 레이블](../../custom-rules/docs/index.md#using-rule-labels), [로깅 옵션](../../waf-logging/docs/index.md)에 대한 기본적인 이해를 전제로 합니다.

이 가이드는 AWS WAF를 배포하고 운영하는 상위 수준 프로세스를 다루며, 단일 팀 또는 애플리케이션 수준 구현부터 이미 AWS WAF를 사용하는(또는 사용하지 않는) 엔터프라이즈 배포까지 여러 일반적인 시나리오를 제공합니다.

## 개요

다음 단계는 단일 애플리케이션 팀이든 전체 Organization의 계정에 배포하든 AWS WAF 배포의 일반적인 프로세스를 설명합니다.

1. **[사전 구성된 protection pack](../../aws-managed-rules/docs/index.md#protection-pack-권장-사항)으로 시작** - 애플리케이션 유형에 따라 강력한 기본 규칙 세트를 제공하거나, 관리형 및 사용자 정의 규칙의 조합을 수동으로 구축합니다.

2. **모든 규칙을 Count 모드로 배포** - 적용 전에 동작을 관찰할 수 있도록 트래픽을 차단하지 않고 규칙이 트래픽을 평가하도록 합니다.

3. **로깅 설정** - 규칙 동작을 분석하는 데 필요한 데이터를 확보하도록 WAF 로깅을 활성화합니다.

4. **대시보드 및 로그 쿼리 설정** - 어떤 규칙이 어떤 트래픽에서 매칭하는지에 대한 가시성을 구축하여 적용 결정에 도움을 줍니다.

5. **충분한 WAF 로그 데이터가 축적될 때까지 대기** - 규칙을 적용/*차단*으로 전환하기 전에 WAF 규칙의 영향을 완전히 이해하기 위해 충분한 WAF 로그(며칠 또는 일주일)가 필요합니다.

6. **규칙을 *Count*에서 *Block*으로 전환, 저위험 규칙부터 시작** - 합법적 트래픽에 영향을 줄 가능성이 가장 낮은 규칙부터 점진적으로 *Block* 모드로 전환합니다.

    a. **저위험, 쉬운 성과에 집중** - 전혀 매칭하지 않았거나 명확하게 악성/비합법적 트래픽에만 매칭하는 규칙을 찾아 이 규칙을 먼저 적용합니다.

    b. **예외가 필요한 규칙 식별** - 합법적 트래픽에 매칭하는 규칙을 찾고 어떤 예외가 필요한지 결정합니다.

    c. **규칙을 적용하지 않을 시기 결정** - 애플리케이션과 근본적으로 충돌하여 Count 모드로 유지하거나 제거해야 하는 규칙이 있는지 결정합니다.

7. **시간이 지남에 따라 새 규칙 및 AMR 버전 추가** - 애플리케이션이 발전하고 새 규칙 버전이 릴리스됨에 따라 동일한 Count/분석/적용 주기를 따릅니다.

## 단일 팀/애플리케이션 수준 사용

이 섹션은 하나 또는 소수의 애플리케이션을 소유하고 자체 WAF 구성을 담당하는 애플리케이션 팀 또는 개별 운영자를 위한 것입니다. 조직의 규모는 중요하지 않습니다. 중요한 것은 보호할 애플리케이션이 몇 개뿐이라는 것입니다.

1. **초기 WAF 규칙 선택** - [사전 구성된 protection pack](../../aws-managed-rules/docs/index.md#protection-pack-권장-사항)이 가장 빠른 경로입니다. 수동으로 구축하려면 [기본 관리형 규칙 그룹](../../aws-managed-rules/docs/index.md#모든-배포를-위한-기본-규칙)으로 시작하고, 스택에 맞는 [사용 사례별 규칙](../../aws-managed-rules/docs/index.md#사용-사례별-규칙)을 추가하며, [대부분의 배포에 권장되는 일반 사용자 정의 규칙](../../custom-rules/docs/index.md#대부분의-배포에-공통인-규칙)을 포함하세요. [권장 WAF 규칙 순서](../../recommended-waf-rule-order/docs/index.md)에 따라 규칙을 배치하세요.

2. **모든 규칙을 Count 모드로 배포** - 비프로덕션 환경이 있다면 거기서 시작하여 프로세스에 익숙해질 수 있습니다. 그러나 프로덕션에 WAF를 설정하는 것이 중요합니다. 프로덕션 트래픽은 WAF 규칙의 영향을 사전에 의미 있게 검증하는 데 필요한 실제 사용자 트래픽 패턴의 볼륨과 다양성을 제공합니다. 모든 규칙이 *Count*로 설정되고 기본 작업이 *Allow*인 경우 AWS WAF는 트래픽을 차단하지 않으므로 프로덕션에 배포하는 위험은 최소입니다(최대 한 자릿수 밀리초의 지연 시간 추가).

3. **AWS WAF 로깅 활성화** - 로깅은 Count 모드로 배포한 규칙이 합법적 트래픽에 부정적 영향을 미치지 않는지 검증하는 데 중요합니다. 특별한 이유가 없다면, AWS는 **CloudWatch Logs**를 권장합니다. 로그 그룹을 생성하는 것 외에 WAF 로그를 캡처, 쿼리, 대시보드화하는 데 설정이 필요하지 않습니다.

4. **대시보드 및 로그 쿼리 설정** - 적용 결정을 내리기 전에 트래픽이 관리형 규칙 및 사용자 정의 규칙과 어떻게 상호 작용하는지 이해하기 위해 WAF 로그를 시각화 및/또는 쿼리할 수 있어야 합니다.

5. **충분한 WAF 로그 데이터가 축적될 때까지 대기** - 규칙이 프로덕션 트래픽을 평가하도록 합니다. 1-2주가 일반적으로 이상적입니다. 목표는 규칙 적용 시 WAF가 차단할 것을 확신 있게 평가할 수 있도록 트래픽의 대표 샘플을 캡처하는 것입니다.

6. **규칙을 *Count*에서 *Block*으로 전환** - 아래 표시된 순서로 어떤 규칙을 **Count**에서 **Block**으로 전환할지 평가합니다.

    - **저위험, 쉬운 성과에 집중** - 이것이 주요 초점이어야 하며 많은/대부분의 WAF 규칙을 *Count*에서 *Block*으로 전환하는 결과를 가져옵니다.
        a) [IP 평판](../../aws-managed-rules/docs/index.md#amazon-ip-평판-목록) 및 [익명 IP](../../aws-managed-rules/docs/index.md#익명-ip-목록)에 매칭하는 요청을 찾습니다.
        b) AntiDDoS AMR을 사용하는 경우, 최소한 낮은 민감도(높은 신뢰도) 규칙을 *Count*에서 *Block*으로 전환하는 것을 고려합니다.
        c) 비율 기반 규칙을 평가하고 적절한 값을 결정합니다.
        d) [기본 규칙](../../aws-managed-rules/docs/index.md#모든-배포를-위한-기본-규칙) 또는 XSS나 SQLi 보호와 같은 특정 우려 사항을 평가합니다.

    - **예외가 필요한 규칙 식별** - 몇 가지 규칙이나 엔드포인트에 예외가 필요한 것은 일반적입니다. 예제는 [예외 생성](#예외-생성)을 참조하세요.

    - **규칙을 적용하지 않을 시기 결정** - 규칙이 애플리케이션 작동 방식과 근본적으로 충돌하고 예외로 합리적으로 범위를 지정할 수 없는 경우, AMR 내에서 Count 모드로 두거나 제거하세요.

7. **시간이 지남에 따라 새 규칙 및 AMR 버전 추가** - AMR 버전 업데이트에 대한 [SNS 알림](../../aws-managed-rules/docs/index.md#sns-알림-구독)을 구독하고 [버전 만료에 대한 CloudWatch 알람](../../aws-managed-rules/docs/index.md#cloudwatch-알람으로-버전-만료-모니터링)을 설정하세요.

## 엔터프라이즈 배포

이 섹션은 조직, 비즈니스 단위 또는 다수의 AWS 계정에 걸쳐 AWS WAF를 관리하는 중앙 보안, 플랫폼 또는 운영 팀을 위한 것입니다. 이 모델에서는 일반적으로 보호되는 애플리케이션을 소유하거나 운영하지 않습니다. 애플리케이션 팀이 합니다. 역할은 광범위하게 적용되는 기본 WAF 규칙 세트를 정의하고 배포하며, WAF 로깅 및 지표를 중앙 집중화하고, 애플리케이션 팀이 의존하는 대시보드와 운영 가시성을 제공하는 것입니다.

1. **AWS Firewall Manager 설정** - 엔터프라이즈 규모에서는 여러 AWS 계정과 리소스에 걸쳐 WAF 정책을 배포하고 관리하는 중앙 집중식 방법이 필요합니다. AWS Firewall Manager를 사용하면 중앙 관리자 계정에서 WAF 정책을 정의하고 조직 전체의 리소스에 Protection Pack 구성을 자동으로 적용할 수 있습니다.

2. **초기 WAF 규칙 선택** - [사전 구성된 protection pack](../../aws-managed-rules/docs/index.md#protection-pack-권장-사항)은 애플리케이션 유형에 따라 규칙을 선택하는 데 유용한 참조이지만, protection pack은 Firewall Manager를 통해 직접 배포할 수 없으므로 Firewall Manager 보안 정책을 구축할 때 가이드로 사용하세요.

3. **First Rules vs. Last Rules에 규칙 배치** - Protection Pack 규칙은 순서대로 평가되며, 종료 작업(즉, *Allow* 및 *Block*)으로 평가되는 첫 번째 규칙에서 중지합니다. Firewall Manager는 로컬로 추가된 규칙 전후에 평가되도록 Protection Pack에 규칙을 추가할 수 있습니다.

4. **모든 규칙을 Count 모드로 배포** - Firewall Manager를 통해 배포할 때, 애플리케이션 팀이 이미 리소스에 구성한 기존 web ACL을 **제거하지 않도록** retrofit 옵션을 활성화해야 합니다.

5. **여러 보안 정책 사용 여부/방법 결정** - 여러 보안 정책을 원하거나 원하지 않을 수 있는 네 가지 잠재적 이유가 있습니다:

    a. **비용** - AWS Shield Advanced가 없으면 각 보안 정책에 월 $100의 고정 비용이 있습니다.
    b. **다중 리전** - Firewall Manager 보안 정책은 특정 리전 및 범위를 대상으로 합니다.
    c. **여러 BU 또는 앱 등급** - 단일 AWS Organization 내에 여러 비즈니스 단위가 있거나 고유한 dev/qa/prod 유형 등급이 있는 경우.

## 비AWS 배포

!!! warning "향후 콘텐츠 업데이트 진행 중"
    이 시점 이후의 섹션은 현재 업데이트 중이며 불완전할 수 있습니다.

## 예외 생성

관리형 규칙이 합법적 트래픽에 영향을 미칠 때, 해당 특정 트래픽에 대한 예외를 생성하면서 다른 모든 트래픽에 대한 보호를 유지해야 합니다. 패턴은 다음과 같습니다:

1. **합법적 트래픽에 영향을 미치는 관리형 규칙을 Count 모드로 설정합니다.** Count 모드에서 규칙은 여전히 요청을 평가하고 레이블을 적용하지만 더 이상 차단하지 않습니다.

2. **관리형 규칙 그룹 아래에 차단을 다시 구현하는 사용자 정의 규칙을 작성합니다.** 단, 오탐을 유발하는 특정 조건에 대한 예외를 포함합니다. 이 규칙은 관리형 규칙의 레이블과 일치하고 오탐이 발생하는 요청 속성을 제외합니다.

**예외는 얼마나 구체적이어야 하나요?** 최소한 예외에는 AMR 레이블 + 영향을 받는 애플리케이션의 호스트 이름이 포함되어야 합니다. 더 나은 예외는 애플리케이션이 특정 호출을 할 때 항상 참인 조건을 추가합니다. 예를 들어, AMR 레이블 + 호스트 이름 + URI 경로 + HTTP 메서드. 예외가 구체적일수록 포기하는 보호 표면이 적지만, 더 넓은 호스트 이름 수준 예외로 모든 규칙을 적용하는 것이 각 오탐에 대한 완벽한 예외를 만들어내는 동안 적용되는 규칙이 적은 것보다 일반적으로 더 좋습니다. 먼저 빠르게 규칙을 적용한 다음 시간이 지남에 따라 예외를 개선하세요.

**간단한 예외 - 단일 오탐**

Core Rule Set의 `CrossSiteScripting_BODY`가 `/api/documents`에 대한 파일 업로드에서 트리거된다고 가정합니다.

1단계: `CrossSiteScripting_BODY`의 작업을 *Count*로 설정합니다. 일치하는 요청은 이제 `awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body`로 레이블이 지정되지만 차단되지 않습니다.

2단계: CRS 규칙 그룹 아래에 사용자 정의 규칙을 추가합니다:

```json
{
  "Name": "enforce-crs-xss-body-except-documents",
  "Priority": 70,
  "Statement": {
    "AndStatement": {
      "Statements": [
        { "LabelMatchStatement": { "Scope": "LABEL", "Key": "awswaf:managed:aws:core-rule-set:CrossSiteScripting_Body" } },
        { "NotStatement": { "Statement": { "ByteMatchStatement": { "SearchString": "/api/documents", "FieldToMatch": { "UriPath": {} }, "TextTransformations": [{ "Priority": 0, "Type": "NONE" }], "PositionalConstraint": "STARTS_WITH" } } } }
      ]
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "enforce-crs-xss-body-except-documents" }
}
```

이것은 `/api/documents`로 가는 요청을 제외하고 XSS 서명과 일치하는 모든 요청을 차단합니다.

**동일 규칙에 대한 여러 예외**

여러 엔드포인트 또는 애플리케이션이 동일한 관리형 규칙에 대한 예외가 필요한 경우, 레이블 기반 패턴을 사용하는 것이 좋습니다. 예외 규칙은 Count 작업으로 사용자 정의 레이블을 추가하고, 단일 적용 규칙이 해당 레이블이 없는 모든 것을 차단합니다. 이 패턴은 더 읽기 쉽고 유지하기 쉽습니다.

전체 JSON 예제는 이 페이지의 영어 버전을 참조하세요.

**Firewall Manager에서의 예외**

Firewall Manager를 사용할 때 예외에 대한 두 가지 모델이 있습니다:

1. **중앙 관리 예외** - 보안 팀이 예외를 생성하고 유지합니다. AMR과 적용 규칙 모두 **First rule groups**(`preProcessRuleGroups`)에 배치됩니다.

2. **셀프 서비스 예외** - 애플리케이션 팀이 자체 예외를 생성합니다. AMR은 First rule groups에 남아 있고(Count 모드, 레이블 적용), 적용 규칙은 **Last rule groups**(`postProcessRuleGroups`)에 배치됩니다. 애플리케이션 팀은 로컬 Protection Pack에서 적용 규칙이 평가되기 전에 요청을 *Allow*로 종료하는 예외 규칙을 생성합니다.

전체 FMS 보안 정책 예제(중앙 관리 및 셀프 서비스 모두)는 이 페이지의 영어 버전을 참조하세요.

## 조직 전체의 기존 WAF 사용 현황 파악

!!! warning "향후 콘텐츠 업데이트 진행 중"
    이 섹션은 현재 업데이트 중이며 불완전할 수 있습니다.

Firewall Manager 정책을 배포하기 전에 기존 web ACL, 규칙 그룹, WCU 소비를 계정 전체에서 인벤토리하는 지침은 향후 업데이트에서 제공될 예정입니다.
