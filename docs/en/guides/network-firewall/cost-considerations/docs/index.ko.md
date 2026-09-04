# 비용 고려 사항

!!! info "사전 요구 사항"
    이 섹션은 [배포 아키텍처](../../deployment-architecture/docs/index.md)에 대한 이해를 전제로 합니다. 배포 모델 선택이 비용에 미치는 영향을 이해하려면 해당 주제를 먼저 검토하세요.

AWS Network Firewall 비용은 엔드포인트 시간당 요금(AZ별, 트래픽 양에 관계없이), 데이터 처리 요금(스테이트리스 엔진에서 GB당 측정), 선택적 TLS 검사 요금(고급 검사 등급), 그리고 2026년 8월부터 방화벽을 통해 흐르는 트래픽에 대한 표준 AWS 데이터 전송 요금으로 구성됩니다. 이러한 비용 동인을 이해하고 최적화 전략을 구현하면 보안을 저해하지 않으면서 Network Firewall 지출을 크게 줄일 수 있습니다. 현재 요금은 [Network Firewall 요금](https://aws.amazon.com/network-firewall/pricing/) 페이지를 참조하세요.

## 요금 모델

Network Firewall 요금은 다음으로 구성됩니다:

* **엔드포인트 시간당 요금** - 방화벽 엔드포인트별, AZ별, 트래픽 양에 관계없이
* **데이터 처리 요금** - 방화벽이 처리하는 트래픽 GB당(스테이트리스 엔진에서 측정)
* **고급 검사 요금(TLS 검사에만 해당)** - TLS 검사가 활성화된 경우 추가 시간당 요율 및 GB당 요금
* **표준 AWS 데이터 전송 요금** - Network Firewall을 통해 흐르는 트래픽에 표준 데이터 전송 요율이 적용됩니다(아래 [향후 데이터 전송 변경 사항](#데이터-전송-변경-사항2026년-8월) 참조)

!!! note "트래픽 처리 측정 방식"
    데이터 처리 요금은 각 방향에서 한 번 방화벽 엔드포인트를 통과하는 트래픽을 기반으로 합니다. CloudWatch 스테이트리스 `ReceivedBytes` 지표가 청구 가능한 처리 GB의 가장 정확한 표현입니다. `PrivateLinkEndpoints BytesProcessed` 지표는 내부 패킷 처리로 인해 이 양의 약 두 배를 표시합니다. 이는 이중 청구를 반영하는 것이 아닙니다.

## NAT 게이트웨이 번들 할인

!!! tip "모범 사례"
    NAT 게이트웨이를 항상 Network Firewall과 동일한 네트워킹 경로에 배포하세요. 이렇게 하면 표준 NAT 게이트웨이 시간당 및 데이터 처리 요금이 완전히 면제됩니다. 이것은 이그레스 필터링에 Network Firewall을 사용하는 가장 중요한 비용 이점 중 하나이며 자주 간과됩니다.

NAT 게이트웨이를 Network Firewall과 동일한 네트워킹 경로에 생성하고 배치하면, 표준 NAT 게이트웨이 시간당 및 데이터 처리 사용 요금이 면제됩니다. 이 할인은 표준 Network Firewall 요금과 일대일로 적용됩니다.

### 요구 사항

NAT 게이트웨이 번들 할인을 받으려면:

* NAT 게이트웨이와 Network Firewall은 **동일한 리전** 및 **동일한 AWS 결제자 ID**에 있어야 합니다(동일한 계정이 필요하지 않으며, 동일한 결제자 내 교차 계정도 적격)
* NAT 게이트웨이는 Network Firewall 엔드포인트와 **동일한 네트워킹 경로**에 구성되어야 합니다(직접 서비스 체인이거나 Transit Gateway가 사이에 있을 수 있음)

### 할인에서 제외되는 것

* Network Firewall 고급 검사 엔드포인트 요금(TLS 검사)
* Network Firewall 고급 검사 트래픽 처리 요금(TLS 검사)
* 리전 NAT 게이트웨이(RNAT)

### 할인 확인

AWS 청구서를 검토하여 번들 할인이 적용되고 있는지 확인할 수 있습니다. NAT 게이트웨이 항목에 Network Firewall 사용량까지 NAT 게이트웨이 시간당 및 데이터 처리 요금을 상쇄하는 해당 크레딧이 표시되어야 합니다.

자세한 내용은 [Network Firewall 요금](https://aws.amazon.com/network-firewall/pricing/) 페이지를 참조하세요.

## 엔드포인트 비용 최소화

!!! tip "모범 사례"
    다중 계정 환경에서는 중앙 집중식 검사를 사용하세요. 더 적은 방화벽 엔드포인트를 통해 트래픽을 통합하면 VPC별 방화벽 배포에 비해 엔드포인트 시간당 비용이 크게 줄어듭니다. 3개 엔드포인트(AZ당 하나)의 중앙 집중식 배포는 분산 모델의 30개 이상 엔드포인트와 동일한 목적을 수행합니다.

### 중앙 집중식 검사 사용

각 엔드포인트는 유휴 상태에서도 시간당 요금이 부과되므로, Transit Gateway 또는 Cloud WAN을 통한 중앙 집중식 검사는 일반적으로 모든 VPC에 엔드포인트를 배포하는 것보다 다중 계정 환경에서 비용 효율적입니다.

배포 모델 비교는 [배포 아키텍처](../../deployment-architecture/docs/index.md)를 참조하세요.

### 네이티브 Transit Gateway 지원

Network Firewall의 [네이티브 Transit Gateway 지원](https://aws.amazon.com/about-aws/whats-new/2025/07/aws-network-firewall-native-transit-gateway-support/)은 별도의 검사 VPC가 필요 없어 중앙 집중식 검사를 단순화합니다. 표준 Network Firewall 및 Transit Gateway 요금 외에 네이티브 TGW 통합에 대한 추가 요금은 없으며, 총 비용 프로필은 중앙 집중식 검사 VPC 배포와 비교할 수 있습니다. 차이점은 비용 *할당*입니다: 네이티브로 연결된 방화벽만이 트래픽을 생성한 계정에 Network Firewall 데이터 처리를 청구할 수 있습니다. [비용 할당](#비용-할당)을 참조하세요.

### 다중 엔드포인트 지원

Transit Gateway 없이 여러 VPC에서 방화벽을 공유하려면, [다중 엔드포인트 지원](https://aws.amazon.com/about-aws/whats-new/2025/05/aws-network-firewall-multiple-vpc-endpoints/) 기능을 통해 단일 기본 방화벽에 최대 50개의 보조 엔드포인트를 연결할 수 있습니다. 보조 엔드포인트는 별도의 방화벽을 생성하는 것에 비해 시간당 비용이 절감됩니다.

!!! note "TLS 검사 제한"
    VPC 엔드포인트 연결(다중 엔드포인트 기능)이 있는 방화벽에서는 TLS 검사가 지원되지 않습니다.

### 사용하지 않는 엔드포인트 삭제

!!! tip "모범 사례"
    방화벽 엔드포인트를 분기별로 감사하세요. 더 이상 워크로드가 없는 AZ의 엔드포인트를 삭제하세요. 사용하지 않는 각 엔드포인트는 트래픽 처리 여부에 관계없이 전체 시간당 요금이 부과됩니다.

방화벽 엔드포인트는 트래픽을 처리하든 하지 않든 시간당 요금이 부과됩니다. 더 이상 필요하지 않거나 워크로드가 없는 AZ의 엔드포인트를 삭제하세요.

## 데이터 처리 비용 절감

!!! tip "모범 사례"
    방화벽 뒤의 모든 VPC에 S3 및 DynamoDB용 게이트웨이 VPC 엔드포인트를 배포하세요. 게이트웨이 엔드포인트는 무료이며, 해당 트래픽에 대한 방화벽 데이터 처리 요금을 제거하고, 대부분의 배포에서 가장 영향력 있는 단일 비용 최적화입니다.

### 검사가 필요하지 않은 트래픽을 검사하지 마세요

* **Transit Gateway 또는 Cloud WAN 라우팅 테이블**을 사용하여 네트워크를 세분화하세요. 통신할 필요가 없으면 VPC-Prod가 VPC-Dev와 대화하지 못하게 하세요. 해당 트래픽을 방화벽을 통해 라우팅하지 마세요.
* **VPC 엔드포인트**를 Amazon S3 및 Amazon DynamoDB에 사용하세요(무료 게이트웨이 엔드포인트). 게이트웨이 VPC 엔드포인트에는 데이터 처리 또는 시간당 요금이 없습니다.
* 방화벽 뒤 프라이빗 서브넷의 다른 AWS 서비스에는 **PrivateLink 엔드포인트**를 사용하세요. 이 결정을 내릴 때 [PrivateLink 요금](https://aws.amazon.com/privatelink/pricing/)과 [Network Firewall 요금](https://aws.amazon.com/network-firewall/pricing/)을 비교하세요.
* 워크로드가 자주 접근해야 하고 방화벽 검사가 필요하지 않은 공유 서비스 VPC에는 **VPC 피어링**을 사용하세요. 이렇게 하면 Network Firewall과 Transit Gateway 데이터 처리 요금이 모두 방지됩니다.

### 상위 트래픽 드라이버 식별

[네이티브 방화벽 모니터링 대시보드](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-using-dashboard.html)의 "Top Talkers" 섹션을 사용하여 어떤 소스/대상 쌍이 방화벽을 통해 가장 많은 트래픽을 생성하는지 식별하세요. 이는 VPC 엔드포인트 또는 기타 메커니즘을 통해 방화벽에서 어떤 트래픽을 우회시킬지 우선순위를 정하는 데 도움이 됩니다. 도메인 수준 가시성을 위해, [트래픽 분석 보고서 기능](https://docs.aws.amazon.com/network-firewall/latest/developerguide/reporting.html)은 어떤 HTTP/HTTPS 도메인이 가장 많은 데이터 처리 요금을 발생시키는지 보여줍니다.

### 기본 차단에 DNS Firewall 사용

Amazon Route 53 Resolver DNS Firewall은 트래픽이 Network Firewall에 도달하기 전에 DNS 계층에서 차단할 수 있습니다. 완전히 차단하려는 도메인의 경우, DNS에서 차단하는 것이:

* 더 저렴합니다(차단된 트래픽에 데이터 처리 요금 없음)
* 더 빠릅니다(패킷 소스에 더 가깝게 차단)
* 더 간단합니다(기본 도메인 차단에 Suricata 규칙 불필요)

광범위한 도메인 차단에는 DNS Firewall을 사용하고, 더 깊은 검사가 필요한 트래픽에는 Network Firewall을 사용하세요.

## 교차 AZ 데이터 전송 방지

!!! tip "모범 사례"
    라우팅 테이블이 소스 워크로드와 동일한 가용 영역의 방화벽 엔드포인트로 트래픽을 보내는지 확인하세요. 교차 AZ 라우팅은 데이터 전송 비용을 두 배로 늘리고 지연 시간을 추가합니다. 각 AZ에는 로컬 엔드포인트를 가리키는 라우트가 있는 자체 방화벽 엔드포인트가 있어야 합니다.

라우팅 테이블은 다른 AZ의 엔드포인트가 아닌 동일 AZ의 로컬 방화벽 엔드포인트로 트래픽을 보내야 합니다. 교차 AZ 라우팅은 방화벽 처리 요금에 추가하여 데이터 전송 요금이 발생합니다.

**서버가 아닌 클라이언트에 가장 가까운 방화벽 엔드포인트로 라우팅하세요.**

## Suricata 규칙 생성기로 트래픽 비용 분석

[AWS Network Firewall용 Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator)에는 CloudWatch 플로우 및 알림 로그를 쿼리하여 방화벽 데이터 처리 비용이 어디에서 발생하는지 정확히 보여주는 트래픽 비용 분석기가 포함되어 있습니다. 플로우 로그(트래픽 볼륨)와 알림 로그(TLS SNI 및 HTTP 호스트 이름)를 연관시켜 대상별 대역폭 분석을 생성하고, VPC 엔드포인트가 비용 효율적인 곳을 권장합니다.

### 분석기가 제공하는 것

트래픽 비용 분석기는 세 개의 탭 대시보드를 생성합니다:

**인터넷 트래픽** - 호스트 이름 확인(HTTP 호스트 헤더, TLS SNI)이 포함된 비AWS 대상. 대상별 비용 분석, 트래픽을 생성하는 내부 호스트를 식별하기 위한 소스 IP 드릴다운, 최적화 기회(Windows Update, CDN 트래픽, 패키지 레지스트리)를 보여줍니다.

![인터넷 트래픽 분석](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/internet_traffic.png)

**AWS 서비스 트래픽** - 트래픽 볼륨 및 서비스별 비용이 포함된 AWS 서비스 엔드포인트. 월간 절감 예측 및 손익분기점 계산이 포함된 VPC 엔드포인트 권장 사항을 포함합니다.

![AWS 서비스 트래픽 분석](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/aws_service_traffic.png)

**내부 트래픽** - 소스-대상 플로우 분석 및 관련 비용이 포함된 VPC 간 통신 패턴.

![내부 트래픽 분석](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/internal_traffic.png)

### VPC 엔드포인트 권장 사항

분석기는 트래픽에서 감지된 각 AWS 서비스에 대한 비용-편익 분석을 수행합니다:

* **게이트웨이 엔드포인트(S3, DynamoDB)** - 동일 리전 트래픽이 감지되면 항상 권장됩니다. 게이트웨이 엔드포인트는 무료이며 방화벽 데이터 처리 요금을 완전히 제거합니다.
* **인터페이스 엔드포인트** - 트래픽 볼륨이 손익분기 임계값(인터페이스 엔드포인트 월 비용이 해당 트래픽의 방화벽 데이터 처리 비용보다 적은 지점)을 초과하는 경우에만 권장됩니다. 임계값은 리전별로 다르며 자동으로 계산됩니다.

예를 들어, 245 GB/월의 트래픽이 방화벽을 통해 S3로 흐르면, 분석기는 약 $16/월을 절약할 수 있는 무료 게이트웨이 엔드포인트를 권장합니다. 85 GB/월의 SSM의 경우 비용이 손익분기 이하이므로 인터페이스 엔드포인트를 건너뛰도록 권장할 수 있으며, 180 GB/월의 Lambda는 엔드포인트를 정당화합니다.

### 소스 IP 드릴다운

대시보드의 행을 더블클릭하면 개별 플로우 타임스탬프 및 볼륨과 함께 트래픽을 생성하는 내부 호스트가 표시됩니다. 이를 통해 높은 비용 트래픽 패턴을 담당하는 특정 워크로드를 식별하고 대상에 맞는 조치를 취할 수 있습니다.

![드릴다운](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/drilldown.png)

### 분석 실행 방법

1. [Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator)에서 규칙 파일을 열기
2. **Tools > Analyze Traffic Costs**로 이동
3. 플로우 로그 그룹, 알림 로그 그룹(호스트 이름 가시성을 위해 선택 사항이지만 권장됨), AWS 리전 및 시간 범위(7-90일 또는 사용자 정의 날짜 범위) 구성
4. **Analyze** 클릭 - 도구가 CloudWatch Logs Insights를 쿼리하고 60-120초 내에 결과 반환

분석에는 플로우 및 알림 로그가 모두 CloudWatch Logs에 게시되어야 합니다. 알림 로그는 호스트 이름 확인(TLS SNI 및 HTTP 호스트 헤더)을 제공합니다. 이것이 없으면 트래픽은 IP 주소로만 식별할 수 있습니다. 필요한 IAM 권한은 `logs:StartQuery` 및 `logs:GetQueryResults`입니다.

결과는 CloudWatch를 다시 쿼리하지 않고 오프라인 액세스를 위해 `.stats` 파일로 저장할 수 있으며, 보고를 위해 CSV로 내보낼 수 있습니다.

!!! tip "이 분석 실행의 ROI"
    일반적인 30일 분석은 CloudWatch Logs Insights 쿼리 요금으로 $0.50-$2.00가 소요되지만, 일반적으로 $50-200/월의 VPC 엔드포인트 절감 기회를 식별합니다. 매월 또는 주요 워크로드 변경 후 실행하세요.

## 비용 할당

여러 계정 또는 비즈니스 단위가 중앙 집중식 Network Firewall을 공유하는 조직의 경우, [Transit Gateway 유연 비용 할당](https://docs.aws.amazon.com/vpc/latest/tgw/metering-policy.html)을 사용하여 트래픽 사용 패턴에 따라 비용을 할당하세요.

!!! tip "모범 사례"
    Network Firewall 데이터 처리 비용의 계정별 또는 비즈니스 단위별 청구를 활성화하려면, 방화벽이 [Transit Gateway 연결](../../deployment-architecture/docs/index.md#transit-gateway-네이티브-연결을-통한-중앙-집중화)을 사용하여 Transit Gateway에 네이티브로 연결되어야 합니다. 이것이 고객 관리 검사 VPC 대신 네이티브 연결을 선택하는 가장 강력한 이유 중 하나입니다. 고객 관리 검사 VPC의 방화벽에서는 유연 비용 할당이 Transit Gateway 데이터 처리 요금만 할당할 수 있으며 Network Firewall 데이터 처리 요금은 할당할 수 없습니다.

## 로깅 비용 절감

!!! tip "모범 사례"
    자체 로그 항목이 필요하지 않은 중간 규칙(flowbits 설정자, JA3 해시 활성화자)에 `noalert;` 키워드를 사용하세요. 이렇게 하면 중요한 규칙의 가시성을 잃지 않으면서 로그 볼륨을 줄입니다.

* 더 효율적인 쿼리를 위해 플로우 및 알림 로그를 별도의 로그 그룹 또는 S3 접두사에 게시하세요
* 중간 로직을 수행하지만 로그 이벤트를 생성할 필요가 없는 규칙에 `noalert;` 키워드를 사용하세요
* 자세한 내용은 [로깅 및 모니터링](../../logging-and-monitoring/docs/index.md)을 참조하세요

## TLS 검사 비용

!!! danger "일반적인 잘못된 구성"
    방화벽에서 TLS 검사를 활성화하면 비용이 크게 증가합니다(고급 검사 등급 요금은 TLS 검사된 트래픽뿐만 아니라 해당 방화벽을 통한 모든 트래픽에 적용됩니다). 활성화하기 전에 특정 워크로드에 대해 보안 이점이 비용 증가를 정당화하는지 평가하세요.

TLS 검사는 자체 요금 등급이 있는 유료 고급 검사 기능입니다:

* 고급 검사 엔드포인트에 대한 리전/AZ별 추가 시간당 요율
* 일부 리전에서는 TLS 검사로 처리된 트래픽에 대한 추가 GB당 요금

TLS 검사가 활성화된 경우에도 NAT 게이트웨이 번들 할인은 표준 Network Firewall 요금(엔드포인트 시간당 + 표준 데이터 처리)에 여전히 적용됩니다. 그러나 추가 고급 검사 시간당 및 GB당 요금은 별도이며 번들 할인에 포함되지 않습니다.

대부분의 사용 사례에서 TLS SNI를 통한 도메인 필터링(TLS 검사가 필요하지 않음)이 충분한 보안을 제공한다고 많은 고객이 판단합니다. 특정 워크로드에 대해 TLS 검사의 보안 이점이 추가 비용을 정당화하는지 평가하세요.

## 데이터 전송 변경 사항(2026년 8월)

!!! warning "청구 변경, 2026년 8월 발효"
    2026년 8월 청구 주기부터 Network Firewall 트래픽에 표준 AWS 데이터 전송 요율이 적용됩니다. 고객에게는 2026년 5월부터 이메일로 통지되었습니다. 소급 요금은 적용되지 않았습니다.

이전에 Network Firewall은 고객을 대신하여 특정 데이터 전송 요금을 흡수했습니다. 2026년 8월부터 다음 표준 AWS 데이터 전송 요금이 적용됩니다:

* **데이터 전송 아웃(DTO)** - 방화벽에서 인터넷으로 전송되는 트래픽
* **리전 간 데이터 전송(DTIR)** - 방화벽을 통해 AWS 리전 간에 전송되는 트래픽
* **리전/퍼블릭 IP** - 동일 리전 내에서 인터넷 게이트웨이를 통해 방화벽을 경유하여 전송되는 트래픽
* **동일 VPC 교차 AZ(DTAZ)** - 고객이 동일 AWS 리전 내에서 퍼블릭 IP를 사용하여 방화벽을 통해 트래픽을 전송하지 않는 한 요금 없음

**변경되지 않는 것:** Network Firewall 엔드포인트 시간당 요금 및 GB당 트래픽 처리 요금은 변경되지 않습니다.

### 청구 가시성

* 새 항목이 엔드포인트 및 처리 요금과 별도로 데이터 전송 아래에 표시됩니다
* Cost Explorer 및 CUR에서 요금은 `DataTransfer-Out-Bytes`와 같은 사용 유형으로 AWS Network Firewall 서비스 이름 아래에 표시됩니다

## 다음 읽을 내용

* [배포 아키텍처](../../deployment-architecture/docs/index.md) - 비용 효율적인 배포 모델 선택
* [로깅 및 모니터링](../../logging-and-monitoring/docs/index.md) - 로그 비용 최적화
* [Network Firewall 요금](https://aws.amazon.com/network-firewall/pricing/) - 공식 요금 페이지
