# WAF 비용

AWS WAF에는 세 가지 핵심 비용과 개별 또는 번들로 제공되는 특정 유료 프리미엄 기능 및 관리형 규칙이 있습니다. 이 섹션에서는 이러한 차원이 실제로 어떻게 상호 작용하는지 설명하여 WAF 지출을 추정하고 최적화할 수 있도록 합니다. 현재 요금 숫자는 [AWS WAF 요금 페이지](https://aws.amazon.com/waf/pricing/)를 참조하세요.

WAF 비용을 가장 잘 설명하기 위해, 이 문서는 표준 WAF 비용만으로 시작하는 **핵심 시나리오**를 사용합니다. 유료 프리미엄 기능 또는 관리형 규칙의 각 섹션에서는 해당 기능의 예를 제공하고 **핵심 시나리오**에 해당 기능을 통합합니다.

**핵심 시나리오**
Protection pack 1개
Protection Pack에 포함된 사용자 정의 규칙 5개
Protection pack에 포함된 Amazon 관리형 규칙:
  - Core Rule Set (CRS)
  - Known Bad Inputs (KBI)
요청 1,000만(10,000,000)개

## 비용 차원

### 표준 WAF 비용

모든 WAF 배포에는 세 가지 기본 비용 구성 요소가 있습니다:

- **Protection pack (Web ACL)** - Protection pack당 월별 고정 비용. 각 protection pack은 하나 이상의 리소스(CloudFront 배포, ALB, API Gateway 등)에 연결됩니다. 연결된 리소스가 아닌 protection pack당 요금을 지불합니다.
- **규칙** - Protection pack의 규칙당 월별 비용. 각 규칙 그룹(사용자 정의 또는 관리형)은 규칙 그룹 내부에 얼마나 많은 규칙이 있든 청구 목적으로 단일 규칙으로 계산됩니다. 3개의 사용자 정의 규칙과 2개의 관리형 규칙 그룹이 있는 protection pack은 5개 규칙으로 청구됩니다.
- **요청** - Protection pack에서 평가하는 모든 웹 요청에 대한 요청당 비용. 기본 요청당 요율은 최대 1,500 WCU의 규칙 평가와 기본 본문 검사 크기(8KB)를 포함합니다.

### **핵심 시나리오** 비용

| 항목 | 수량 | 단가 | 월별 비용 |
|---|---|---|---|
| Protection pack (Web ACL) | 1 | $5.00/월 | $5.00 |
| 규칙 (사용자 정의 5 + CRS + KBI) | 7 | $1.00/월 | $7.00 |
| 요청 | 10,000,000 | $0.60/백만 | $6.00 |
| | | **합계** | **$18.00** |

### 추가 비용 - 기능

기본 구성 요소 외에 여러 기능에 증분 비용이 있습니다:

**1,500 이상의 WCU**
표준 WAF 요청 비용은 최대 1,500 WCU의 인라인, 사용자 정의 규칙 그룹 또는 관리형 규칙 그룹을 허용합니다. 리소스에 연결된 protection pack이 1,500 WCU 이상이면, 요청당 비용이 500 WCU 증분으로 증가합니다. 실제로 대부분의 WAF 배포는 1,500 WCU 미만입니다.

#### WCU 초과

**기능 예:** 사용자 정의 규칙 + AMR이 Protection Pack을 1,501 WCU로 만듦.

| 항목 | 수량 | 단가 | 월별 비용 |
|---|---|---|---|
| WCU 초과 (1 x 500 WCU 증분) | 10,000,000 | $0.20/백만 | $2.00 |

#### 본문 검사

Application Load Balancer 또는 AWS AppSync와 연결 시 AWS WAF가 최대 8KB를 검사하는 것은 표준 WAF 비용에 포함됩니다.

CloudFront, API Gateway, Amazon Cognito, App Runner, Verified Access의 경우 최대 16KB의 요청 본문 검사가 표준 WAF 비용에 포함됩니다. 32KB, 48KB 또는 64KB의 더 높은 최대 본문 검사를 구성할 수 있습니다. 확장 본문 검사는 WAF 규칙이 본문을 평가하고 실제 본문이 16KB를 초과할 때 *에만* 요청당 청구됩니다.

#### Challenge 및 Captcha 비용

Challenge 및 Captcha 작업에는 표준 요청 요금 위에 자체 사용당 비용이 있습니다.

**Challenge 및 Captcha가 포함되거나 비용이 발생하지 **않는** 경우:**

- 요청이 Challenge 작업이 있는 WAF 규칙을 트리거하지만 이전 Challenge 작업의 유효한 WAF 토큰을 이미 포함하는 경우.
- 요청이 Captcha 작업이 있는 WAF 규칙을 트리거하지만 이전 Challenge 또는 Captcha 작업/시도의 유효한 WAF 토큰을 이미 포함하는 경우.
- AWS 관리형 규칙(AMR)이 Challenge 또는 Captcha를 기본 작업으로 사용하는 경우. 현재 Bot Control Targeted, Fraud Control 규칙(ATP, ACFP), AntiDDoS 관리형 규칙 내의 특정 규칙에 해당합니다.
- **JavaScript SDK(수동적 통합)** - 웹 브라우저에서 실행되는 AWS WAF JavaScript SDK.

**Challenge 및 Captcha가 유료인 경우:**

- **Challenge** - WAF가 HTTP 202 인터스티셜 Challenge 응답을 반환할 때마다 청구 가능한 이벤트가 발생합니다.
- **Captcha** - 사용자가 Captcha 퍼즐에 대한 답변을 제출할 때 ***만*** 청구 가능한 이벤트가 발생합니다.
- **AMR을 Count로 설정 + 레이블 기반 사용자 정의 규칙** - 기본 작업이 Challenge/Captcha인 AMR 규칙의 레이블을 사용하는 사용자 정의 규칙은 Challenge/Captcha 비용을 면제하지 않습니다. AMR 규칙이 기본 작업으로 종료해야 이 비용이 면제됩니다.

**비용에 대한 토큰 면제 시간의 영향:**

- 짧은 면제 시간은 사용자가 세션 내에서 더 자주 재검증하게 하여 청구 가능한 이벤트를 증가시킵니다
- 토큰 도메인 잘못된 구성은 사용자가 서브도메인을 탐색할 때 중복 청구 가능한 이벤트를 유발합니다
- 짧은 면제 시간과 Captcha 규칙이 있는 고트래픽 엔드포인트는 합법적 사용자에게서도 상당한 사용당 요금을 생성할 수 있습니다

청구 가능한 이벤트를 최소화하는 통합 패턴(수동적 및 사전적 접근 방식) 및 면제 시간 트레이드오프 지침은 [CAPTCHA 및 Challenge](../../captcha-and-challenge/docs/index.md)를 참조하세요.

### 프리미엄 AMR

#### Bot Control Common

Bot Control의 경우, 요청당 비용은 봇 레이블과 일치하는 요청뿐만 아니라 규칙 그룹에서 평가하는 모든 요청에 적용됩니다. Bot Control을 `/api/` 경로로만 범위를 지정하면 해당 경로에 대한 요청에 대해서만 비용을 지불합니다. 범위 축소 문은 프리미엄 AMR 비용을 제어하는 주요 레버입니다.
Bot Control이 구성된 Protection Pack당 정액 구독 비용이 있습니다.

대부분의 고객은 BotControl이 모든 단일 요청을 보호할 필요가 없습니다. .css, .js 등은 일반적으로 Bot Control로 보호하는 것이 유용하지 않습니다.

#### Bot Control Targeted

Bot Control Targeted는 Common과 동일한 비용 모델을 따릅니다: Protection Pack당 정액 구독 요금과 요청당 비용. Common보다 높은 요청당 요율을 가집니다. Bot Control Targeted 내의 일부 규칙은 Challenge 또는 Captcha를 기본 작업으로 사용합니다. 해당 규칙이 요청을 종료하면 추가 Challenge/Captcha 비용이 발생하지 않습니다.

#### Account Takeover Prevention (ATP)

ATP에는 Protection Pack당 정액 요금과 구성한 로그인 엔드포인트와 일치하는 요청당 비용이 있습니다(protection pack을 통한 모든 트래픽이 아님). ATP의 많은 규칙이 challenge 또는 Captcha 작업을 사용합니다. 기본 작업으로 사용될 때 이러한 비용은 ATP 비용에 포함되며 추가되지 않습니다.

#### Account Creation Fraud Prevention (ACFP)

ACFP는 ATP와 동일한 모델을 따르지만 구성한 등록 엔드포인트에 적용됩니다.

#### Anti-DDoS

Anti-DDoS 관리형 규칙 그룹에는 Protection Pack당 정액 요금과 요청당 비용이 있습니다. 일부 규칙에서 Challenge를 기본 작업으로 사용합니다. AMR이 요청을 종료하면 이러한 Challenge 이벤트는 추가 비용 없이 포함됩니다. 이 AMR에 의해 차단된 요청은 Anti-DDoS AMR의 사용량 기반 요금을 발생시키지 않습니다. Shield Advanced 고객은 Shield Advanced 보호 리소스에서 이 프리미엄 관리형 규칙을 추가 비용 없이 사용할 수 있습니다. 전체 세부 사항은 [Shield Advanced 및 WAF 비용](#shield-advanced)을 참조하세요.

### 로깅

> 이 섹션은 최적의 WAF 로깅 옵션을 선택하는 기술적 영향 및 전략을 다루지 **않습니다**. 올바른 로그 전달 및 저장 선택에 대한 완전한 답변은 [여기](../../waf-logging/docs/index.md)를 참조하세요.

WAF 로깅은 WAF 서비스의 일부로 직접 청구되지 않지만 AWS WAF 사용의 운영 비용을 나타냅니다. 로깅 비용은 세 그룹으로 나뉩니다:
1) **로그 전달:** WAF 로그의 원시 크기(압축 없음)를 기반으로 계산
2) **저장/보존:** AWS 네이티브 저장소(및 아마도 많은 타사)에서 WAF 로그는 일반적으로 압축됩니다.
3) **기타:** 일부 추가 비용이 있지만 로그 전달/저장 비용의 1% 미만으로 거의 의미가 없습니다.

WAF 로그 크기는 protection pack의 규칙과 요청 자체에 따라 다릅니다. WAF 로깅 비용을 정량화/추정하는 데 도움이 되는 유용한 최소/최대 WAF 로그 크기:
- 0개 규칙과 사소한 URI, 헤더 등이 있는 protection pack은 ~1.4KB WAF 로그 항목을 생성합니다.
- [권장 protection pack](../../aws-managed-rules/docs/index.md#protection-pack-권장-사항)은 ~4.6KB WAF 로그 항목을 생성합니다.

#### 로그 전달

AWS WAF는 Amazon CloudWatch Vended Logs 및 Amazon Data Firehose를 통한 로그 전달을 지원합니다.

- **CloudWatch Vended Logs** - S3로 보내는 WAF 로그는 CloudWatch Vended Logs(전달 대상 Amazon S3)를 따릅니다. AWS WAF는 100만 WAF 요청당 500MB Vended 로그 수집을 포함하는 크레딧을 제공합니다.
- **Kinesis Data Firehose** - WAF 로그는 Amazon Data Firehose를 통해 전달할 수 있습니다. Firehose 청구는 최소 항목(WAF 로그) 크기 5KB를 부과합니다.

#### 로그 저장

- **CloudWatch Logs 그룹** - 생성 시 Standard($0.50/GB/월) 또는 Infrequent Access($0.25/GB/월)의 저장 등급을 선택할 수 있습니다.
- **Amazon S3** - WAF 로그의 가장 일반적인 대상으로, S3 저장은 $0.023/GB부터 시작합니다.

**비용 관련 저장 권장 사항**
S3 저장에 KMS를 사용할 때 Amazon S3 Bucket Keys를 사용하세요. 이 기능 없이는 *모든 단일* POST(즉, S3에 업로드되는 WAF 로그)가 KMS API 비용을 발생시킵니다.

**수명 주기/보존 활성화**
두 AWS 네이티브 저장 서비스 모두 저장 등급을 변경하거나 오래된 데이터를 자동으로 삭제할 수 있는 수명 주기/보존 정책을 제공합니다. 규정 준수 요구 사항이 없다면, WAF 로그를 최소 약 30일 또는 조직이 운영 및 보안 요구에 따라 결정한 기간 동안 유지하는 것을 고려하세요.

#### 필터링된 로깅

WAF 로그 필터링은 비용을 크게 줄입니다. 모든 요청을 기록하는 대신 특정 규칙과 일치하거나, 차단되거나, 특정 레이블을 전달하는 요청만 캡처하도록 로깅을 구성할 수 있습니다. 필터링 지침은 [WAF 로깅](../../waf-logging/docs/index.md)을 참조하세요.

이를 구성하는 데 비용이 없으며, 기록하게 되는 요청 수를 변경하는 것 외에는 로깅 비용 공식을 변경하지 않습니다.

### 파트너 관리형 규칙

파트너 관리형 규칙(AWS Marketplace에서 제공)에는 파트너가 설정한 자체 구독 요금이 있으며, 표준 WAF 요청당 비용은 여전히 적용됩니다. 이는 구독의 일부로 Challenge 또는 Captcha를 포함하지 않습니다. 파트너 규칙의 모든 Challenge 또는 Captcha 작업은 표준 유료 Challenge/Captcha 이벤트로 청구됩니다.

## 비용 추정

!!! warning "향후 콘텐츠 업데이트 진행 중"
  AWS WAF 모범 사례 가이드를 개편하고 있습니다. 이 섹션은 아직 생성/완료되지 않았습니다.

### 기존 AWS 리소스 보호

### 비AWS 오리진 또는 AWS로 이전 중인 워크로드 보호

## 비용 최적화

### Shield Advanced

AWS Shield Advanced를 구독하면, Shield Advanced 보호 리소스에 대한 표준 WAF 비용 + AntiDDoS AMR이 면제됩니다. 이것은 다음을 포함합니다:

- Protection pack당 월 $5
- 규칙당 월 $1
- WAF 사용량 백만 요청당 $0.60
- AntiDDoS AMR - 정액 요금 및 사용량 요금 면제

Shield Advanced는 Bot Control Targeted, ATP, ACFP 또는 Challenge/Captcha 사용당 요금을 포함하지 않습니다.

### 범위 축소 문

범위 축소 문은 프리미엄 관리형 규칙, 특히 BotControl 프리미엄 관리형 규칙의 가장 효과적/중요한 비용 최적화 중 하나입니다. 다른 프리미엄 규칙(Fraud Control, AntiDDoS)도 범위 축소에서 비용 절감을 볼 수 있지만, Fraud Control은 특정 URI 및 HTTP 메서드에 대한 구성이 필요하고 AntiDDoS는 기술적 이유로 범위 축소가 권장되지 않으므로 일반적으로 적용되지 않습니다.

- **Bot Control** - 자동화의 대상이 되는 경로(로그인, API, 검색, 결제)로 범위를 지정하세요. 정적 자산, 헬스 체크, 내부 전용 경로를 제외하세요.
- **ATP/ACFP** - 이미 구성에 의해 경로 범위가 지정되어 있지만, 로그인/등록 경로 정의가 정확하고 더 넓은 URL 패턴과 실수로 일치하지 않는지 확인하세요.

### JavaScript 통합

애플리케이션의 일부 또는 전부를 보호하기 위해 WAF challenge를 사용해야 하는 경우, 비동기/지연 challenge를 위한 JavaScript를 구현하면 Protection Pack이 트리거하는 Challenge 수를 극적으로 줄여 비용을 절감할 수 있습니다.

### CloudFront 정액 요금제

CloudFront는 정액 요금제를 제공하며, AWS WAF 이상을 포함하지만 다양한 수준의 WAF 사용 및 기능을 포함합니다. 정액 요금제를 사용하면, 해당 플랜에 포함된 모든 WAF 기능에 위에 언급된 WAF 관련 비용이 **없습니다**.
