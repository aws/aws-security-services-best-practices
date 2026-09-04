# 사용자 정의 규칙

사용자 정의 규칙은 사전 구축된 규칙 그룹이 다루지 않는 애플리케이션별 위협 및 시나리오를 해결하여 관리형 규칙을 보완합니다. 비즈니스 로직을 적용하고, 관리형 규칙의 오탐을 처리하며, 세분화된 조건으로 민감한 엔드포인트를 보호하기 위해 사용자 정의 규칙을 사용하세요.

사용자 정의 규칙과 함께 사용할 AWS 관리형 규칙에 대한 지침은 [AWS 관리형 규칙](../../aws-managed-rules/docs/index.md)을 참조하세요. 사용자 정의 규칙이 필요한 시기를 식별하기 위한 로그 분석 기법은 [WAF 규칙 모니터링](../../monitoring-waf-rules/docs/index.md)을 참조하세요.

## 대부분의 배포에 공통인 규칙

대부분의 WAF 배포는 다음 유형의 사용자 정의 규칙에서 이점을 얻습니다.

### 비율 기반 규칙

비율 기반 규칙은 모든 유형의 애플리케이션 또는 엔드포인트에 대한 가장 일반적이고 가치 있는 사용자 정의 규칙 중 하나입니다. 단일 클라이언트가 시간 기간 동안 만들 수 있는 요청 수를 제한하여 볼류메트릭 남용, 무차별 대입, DDoS로부터 보호합니다. protection pack에서 비율 기반 규칙을 배치할 위치는 [권장 WAF 규칙 순서](../../recommended-waf-rule-order/docs/index.md)를 참조하세요.

#### 임계값 선택

적절한 임계값을 설정하려면, [WAF 로그 쿼리 및 시각화](../../monitoring-waf-rules/docs/index.md#rate-based-rules-identifying-the-right-threshold)의 비율 기반 규칙 쿼리를 사용하여 기존 트래픽 패턴을 분석하는 것부터 시작하세요. 해당 쿼리는 정상 트래픽에서 소스 IP당 최대 요청 비율을 보여줍니다.

정상 피크를 알게 되면 시작 임계값으로 50-100% 버퍼를 추가하세요. 예를 들어, 가장 높은 합법적 소스 IP가 5분 기간에 1,000개의 요청을 보내면 1,500-2,000의 임계값으로 시작하세요. 시작할 때의 목표는 크게 시작하여 합법적 트래픽 차단을 피하는 것입니다. 트래픽 패턴에 대한 확신을 얻으면서 시간이 지남에 따라 임계값을 줄일 수 있습니다.

트래픽에 영향을 주지 않고 더 낮은 임계값을 안전하게 실험하려면, 다른 값으로 여러 비율 기반 규칙을 만드세요. 가장 낮은 임계값 규칙을 *Count* 모드로 설정하여 차단하지 않고 일치를 기록하고, 더 높은 임계값 규칙은 *Block* 모드로 유지하세요.

#### 평가 기간 선택

`EvaluationWindowSec` 매개변수는 WAF가 카운트를 임계값과 비교하기 전에 요청을 누적하는 기간을 제어합니다. AWS WAF는 60, 120, 300, 600초의 기간을 지원합니다. 더 짧은 기간은 버스트를 더 빨리 감지하지만 정상 트래픽 급증에 더 민감합니다. 더 긴 기간은 짧은 버스트를 완화하지만 지속적인 남용에 반응하는 데 더 오래 걸립니다.

**더 짧은 기간(60-120초) 사용 시기:** 짧고 집중적인 버스트를 빠르게 감지하고 중지해야 할 때 사용하세요.

**더 긴 기간(300-600초) 사용 시기:** 애플리케이션에 짧은 버스트로 도착하는 합법적 트래픽이 있을 때 사용하세요.

**일괄 비율 기반 규칙** - 모든 엔드포인트에서 단일 IP의 총 요청 비율을 제한합니다. 볼류메트릭 남용에 대한 첫 번째 방어선입니다.

```json
{
  "Name": "blanket-rate-limit",
  "Priority": 1,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 2000,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP"
    }
  },
  "Action": {
    "Block": {}
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "blanket-rate-limit"
  }
}
```

**URI별 비율 기반 규칙** - `/login`과 같은 민감한 엔드포인트에 더 엄격한 비율 제한을 적용합니다.

```json
{
  "Name": "login-rate-limit",
  "Priority": 8,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 100,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "ByteMatchStatement": {
          "SearchString": "/login",
          "FieldToMatch": { "UriPath": {} },
          "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
          "PositionalConstraint": "STARTS_WITH"
        }
      }
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "login-rate-limit" }
}
```

**복합 키 비율 기반 규칙(IP + 쿠키)** - 소스 IP와 쿠키 값 모두로 요청을 집계합니다. 여러 사용자가 동일한 IP를 공유할 때(예: 기업 NAT 뒤) 유용합니다. 쿠키가 개별 클라이언트를 구별하여 합법적 사용자가 이웃의 행동으로 인해 불이익을 받지 않습니다.

```json
{
  "Name": "composite-ip-token-rate-limit",
  "Priority": 2,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 500,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "CUSTOM_KEYS",
      "CustomKeys": [
        { "IP": {} },
        { "Cookie": { "Name": "aws-waf-token", "TextTransformations": [{ "Priority": 0, "Type": "NONE" }] } }
      ]
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "composite-ip-token-rate-limit" }
}
```

**익명 IP 레이블로 범위가 지정된 비율 기반 규칙** - Anonymous IP List 관리형 규칙 그룹이 익명화 소스에서 온 것으로 레이블한 요청에 더 엄격한 비율 제한을 적용합니다. 이를 통해 Anonymous IP 규칙 그룹을 Count 모드로 유지하면서도 해당 소스의 요청 비율을 제한할 수 있습니다.

```json
{
  "Name": "rate-limit-anonymous-ips",
  "Priority": 8,
  "Statement": {
    "RateBasedStatement": {
      "Limit": 200,
      "EvaluationWindowSec": 300,
      "AggregateKeyType": "IP",
      "ScopeDownStatement": {
        "LabelMatchStatement": { "Scope": "LABEL", "Key": "awswaf:managed:aws:anonymous-ip-list:AnonymousIPList" }
      }
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "rate-limit-anonymous-ips" }
}
```

### 지리적 제한

애플리케이션이 특정 지역만 서비스하는 경우 지리적 출처에 따라 요청을 차단하거나 비율 제한합니다. 청중이 특정 국가 목록에서 오는 경우 또는 특정 국가의 접근을 차단해야 하는 비즈니스 또는 규정 준수 요구 사항이 있는 경우 사용할 수 있습니다.

참고: 지역 및 리전 기반 IP 평가는 완벽하지 않으며, IP가 어떤 국가 또는 리전에 할당되는지에 대한 단일 권위 있는 소스가 없습니다. 드물지만 IP가 잘못된 지역 또는 리전에 매핑될 수 있으며, 이는 IP가 지리적 경계에 가까울 때 특히 그렇습니다. 예상 청중이 있는 곳에 기반한 지역 제한을 사용하는 경우, 지역 기반 제어에 인접 국가를 포함하거나 해당 인접 국가를 완전히 차단하지 않는 것을 고려하세요.

지역 기반 제한은 VPN, TOR, 클라우드/호스팅 프로바이더를 사용하여 상대적으로 쉽게 극복할 수 있다는 점도 인식해야 합니다. 사용자가 특정 국가/리전 출신이라는 권위 있는 *증거*가 필요한 경우, IP 주소만으로 이를 권위 있게 확인하는 것에 *의존할 수 없습니다*.

**특정 국가의 요청 차단** - 애플리케이션에 합법적인 사용자가 없는 국가 또는 국가 금수 목록과 같은 규정 준수 요구 사항에 따라 발신된 모든 요청을 차단합니다.

```json
{
  "Name": "block-restricted-countries",
  "Priority": 3,
  "Statement": { "GeoMatchStatement": { "CountryCodes": ["CN", "RU", "KP"] } },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "block-restricted-countries" }
}
```

**특정 국가만 허용** - 애플리케이션이 알려진 리전 세트만 서비스하는 경우, NOT 문으로 매치를 반전하여 나머지를 모두 차단합니다.

```json
{
  "Name": "allow-only-approved-countries",
  "Priority": 3,
  "Statement": { "NotStatement": { "Statement": { "GeoMatchStatement": { "CountryCodes": ["US", "CA", "GB", "DE", "FR"] } } } },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "allow-only-approved-countries" }
}
```

### IP 허용 목록 및 거부 목록

[IP 세트](https://docs.aws.amazon.com/waf/latest/developerguide/waf-ip-set-managing.html)를 사용하여 신뢰할 수 있는 소스를 명시적으로 허용하거나 알려진 악성 행위자를 차단합니다.

**IP 허용 목록** - 신뢰할 수 있는 소스(예: 모니터링 시스템, 파트너 통합)의 요청을 다른 규칙이 평가하기 전에 허용합니다. Allow는 종료 작업이므로, 허용된 요청은 웹 익스플로잇 및 DDoS 패턴을 감지하는 관리형 규칙을 포함한 모든 후속 규칙을 우회합니다. 신뢰할 수 있는 시스템도 일반적으로 공격과 유사한 트래픽을 보내지 않아야 하므로, IP를 광범위하게 허용하면 여전히 원하는 보호 계층이 제거됩니다. 일괄 Allow 규칙 대신, IP 세트를 문제를 일으키는 특정 규칙으로 범위를 지정하는 것을 고려하세요. Allow 기반 IP 허용 목록은 소스가 모든 검사를 우회해야 한다고 확신하는 경우에만 사용하세요.

```json
{
  "Name": "allow-trusted-ips",
  "Priority": 4,
  "Statement": { "IPSetReferenceStatement": { "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/trusted-ips/a1b2c3d4-5678-90ab-cdef-EXAMPLE11111" } },
  "Action": { "Allow": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "allow-trusted-ips" }
}
```

**IP 거부 목록** - 알려진 악성 행위자의 요청을 차단합니다. 로그 분석이나 위협 인텔리전스를 통해 식별된 IP를 빠르게 차단하는 데 유용합니다.

```json
{
  "Name": "block-denied-ips",
  "Priority": 2,
  "Statement": { "IPSetReferenceStatement": { "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/denied-ips/a1b2c3d4-5678-90ab-cdef-EXAMPLE22222" } },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "block-denied-ips" }
}
```

### 헤더 검증

예상 HTTP 요청 필드를 검증하여 명백하게 잘못 형성되거나 예상치 못한 요청이 더 비싼 관리형 규칙 평가에 도달하기 전에 거부합니다.

**필수 헤더가 누락된 요청 차단** - 애플리케이션이 모든 요청에서 특정 헤더(예: API 키 헤더, 사용자 정의 애플리케이션 헤더)를 예상하는 경우, 포함하지 않는 요청을 차단합니다.

```json
{
  "Name": "require-api-key-header",
  "Priority": 5,
  "Statement": {
    "NotStatement": {
      "Statement": {
        "SizeConstraintStatement": {
          "FieldToMatch": { "SingleHeader": { "Name": "x-api-key" } },
          "ComparisonOperator": "GT", "Size": 0,
          "TextTransformations": [{ "Priority": 0, "Type": "NONE" }]
        }
      }
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "require-api-key-header" }
}
```

## 시나리오 기반 사용자 정의 규칙 예제

이 섹션은 사용자 정의 규칙이 필요한 일반적인 시나리오의 현실적인 예를 제공합니다:

- 더 세분화된 비율 제한을 위한 복합 키 비율 기반 규칙
- 민감한 엔드포인트를 보호하기 위한 URI별 규칙
- 세분화된 제어를 위해 AWS 관리형 규칙 레이블을 사용하는 규칙
- AND/OR 로직으로 여러 조건 결합

## 규칙 레이블 사용

[레이블](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html)은 일치하는 규칙에 의해 웹 요청에 추가되는 메타데이터입니다. 한 규칙의 결과를 다른 규칙에서 사용할 수 있도록 레이블을 사용합니다. 레이블은 [레이블 매치 문](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rule-statement-type-label-match.html)을 사용하여 동일한 protection pack에서 더 아래(위가 아님)에 있는 다른 규칙에서 검사할 수 있습니다.

종료 작업이 있는 규칙에서 추가된 레이블은 다른 규칙에서 검사할 수 없습니다. 이러한 레이블은 [WAF 로그 레코드](https://docs.aws.amazon.com/waf/latest/developerguide/logging-fields.html) 및 [CloudWatch 지표 차원](https://docs.aws.amazon.com/waf/latest/developerguide/monitoring-cloudwatch.html#waf-metrics)에 포함되어 종료 규칙의 동작을 분석하고 시각화할 수 있습니다.

레이블은 일반적으로 관리형 규칙의 동작을 보강하는 데 사용됩니다. 첫 번째 단계는 관리형 규칙의 작업을 *Block*에서 *Count*로 전환하는 것입니다. 그런 다음 관리형 규칙의 레이블과 요청을 차단해야 하는지 결정하는 다른 조건을 매칭하는 다른 규칙을 아래에 생성합니다.

레이블 사용에 대한 자세한 내용은 [How to customize behavior of AWS Managed Rules for AWS WAF](https://aws.amazon.com/blogs/security/how-to-customize-behavior-of-aws-managed-rules-for-aws-waf/)를 참조하세요.

## 오탐 처리

WAF 규칙이 합법적 트래픽과 일치하는 경우(오탐), 특정 합법적 요청을 허용하면서 다른 모든 트래픽에 대한 보호를 유지하는 예외를 생성해야 합니다. 이것은 레이블 기반 예외 패턴을 사용하여 수행됩니다. 문제가 되는 규칙을 *Count* 모드로 설정하고 오탐 조건에 대한 제외와 함께 차단을 다시 구현하는 사용자 정의 규칙을 작성합니다.

예제가 포함된 전체 예외 패턴(단일 예외, 동일 규칙에 대한 여러 예외, Firewall Manager 시나리오)은 [예외 생성](../../operationalizing/docs/index.md#creating-exceptions)을 참조하세요.

## 대형 HTTP 요청 처리

AWS WAF에는 검사할 수 있는 HTTP 요청 구성 요소의 크기 및 수에 대한 제한이 있습니다. 자세한 내용은 [AWS WAF에서 초과 크기 웹 요청 구성 요소 처리](https://docs.aws.amazon.com/waf/latest/developerguide/waf-oversize-request-components.html)를 참조하세요. 검사할 수 있는 기본 및 최대 본문 크기는 AWS WAF가 연결된 리소스에 따라 다릅니다.

* CloudFront, API Gateway, Amazon Cognito, App Runner, Verified Access protection pack의 경우, AWS WAF는 기본적으로 최대 16KB의 요청 본문을 검사할 수 있습니다. protection pack 구성에서 추가 처리 요금으로 이 제한을 최대 64KB까지 늘릴 수 있습니다.
* Application Load Balancer 및 AWS AppSync protection pack의 경우, 본문 검사 제한은 8KB로 고정되어 있습니다. 이 제한은 현재 늘릴 수 없습니다.

### 특정 초과 크기 요청 허용

특정 엔드포인트가 합법적으로 초과 크기 요청을 수신하는 경우(예: 파일 업로드 엔드포인트), 초과 크기 요청을 허용하는 대신 해당 엔드포인트를 제외하고 모든 곳에서 차단해야 합니다. 이렇게 하면 해당 요청에 대한 나머지 protection pack 규칙이 계속 유효합니다.

```json
{
  "Name": "block-oversized-body-except-uploads",
  "Priority": 5,
  "Statement": {
    "AndStatement": {
      "Statements": [
        { "SizeConstraintStatement": { "FieldToMatch": { "Body": {} }, "ComparisonOperator": "GT", "Size": 8192, "TextTransformations": [{ "Priority": 0, "Type": "NONE" }], "OversizeHandling": "MATCH" } },
        { "NotStatement": { "Statement": { "ByteMatchStatement": { "SearchString": "/upload", "FieldToMatch": { "UriPath": {} }, "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }], "PositionalConstraint": "STARTS_WITH" } } } }
      ]
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": { "SampledRequestsEnabled": true, "CloudWatchMetricsEnabled": true, "MetricName": "block-oversized-body-except-uploads" }
}
```
