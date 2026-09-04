# 사전 요구 사항 및 기본 사항

AWS Network Firewall은 상태 저장 규칙 평가를 위해 [Suricata](https://suricata.io/) 오픈소스 엔진을 사용합니다. Suricata의 내부 작동 방식을 이해하면 효과적인 규칙을 작성하고 예상치 못한 동작을 방지하는 데 도움이 됩니다. Suricata는 원래 침입 탐지/방지 시스템(IDS/IPS)으로 구축되었기 때문에, Network Firewall은 기존 방화벽과 비교하여 강력한 기능과 함께 일부 동작 특성도 함께 가지고 있습니다.

이 페이지에서는 Network Firewall을 배포하기 전에 알아야 할 기본 개념을 다룹니다: 검사 엔진의 작동 방식, Network Firewall이 검사할 수 있는 트래픽과 검사할 수 없는 트래픽, 주요 서비스 제한 사항, 그리고 Network Firewall이 다른 AWS 네트워크 보안 제어와 어떻게 함께 사용되는지에 대해 설명합니다.

## Suricata 이해하기

Network Firewall 환경에서 Suricata의 주요 특성:

* **연결 추적** - Suricata는 연결(플로우)을 추적하고 전체 플로우 컨텍스트를 기반으로 결정을 내립니다. `flow:to_server` 및 `flow:established`와 같은 키워드를 사용하여 설정된 플로우 내 특정 방향을 대상으로 규칙을 작성할 수 있으며, 이는 효과적인 상태 저장 규칙을 작성하는 데 유용합니다.
* **프로토콜 탐지** - Suricata는 포트 번호에 관계없이 애플리케이션 계층 프로토콜을 탐지합니다. 예를 들어, 비표준 포트의 TLS 트래픽이나 임의 포트의 HTTP를 식별할 수 있습니다.
* **규칙 처리** - 모든 상태 저장 규칙은 Suricata 규칙이며, 선택한 규칙 순서 모드에 따라 평가됩니다. 예측 가능한 규칙 평가를 위해 Strict 순서를 사용하세요. 규칙 순서에 대한 자세한 내용은 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)을 참조하세요.
* **애플리케이션 계층 검사** - Suricata는 TLS Client Hello(SNI), HTTP 헤더, 프로토콜별 필드를 포함한 애플리케이션 계층의 콘텐츠를 검사합니다.

!!! tip "모범 사례"
    예측 가능한 우선순위 기반 규칙 평가를 위해 Strict 규칙 순서를 사용하세요. Action Order 모드는 규칙이 상호 작용할 때 예상치 못한 결과를 생성할 수 있으므로 사용하지 마세요. 전체 권장 사항은 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)을 참조하세요.

## 스테이트리스 및 스테이트풀 엔진

Network Firewall에는 트래픽이 순서대로 통과하는 두 가지 검사 엔진이 있습니다:

1. **스테이트리스 엔진** - 연결 컨텍스트 없이 패킷 단위로 트래픽을 평가합니다. 3-4계층에서만 작동하며, 먼저 트래픽을 처리합니다.
2. **스테이트풀 엔진(Suricata)** - 전체 연결 추적 및 3-7계층의 애플리케이션 계층 검사를 통해 트래픽을 평가합니다. 스테이트리스 엔진이 전달한 후 트래픽을 처리합니다.

!!! tip "모범 사례"
    스테이트리스 엔진의 기본 작업을 "스테이트풀 규칙 그룹으로 전달"로 구성하고, 모든 필터링은 스테이트풀 엔진에서 수행하세요. 스테이트풀 엔진은 연결 추적, 프로토콜 탐지, 애플리케이션 계층 검사, 로깅 및 거부 작업을 제공하며, 이러한 기능은 스테이트리스 엔진에서는 사용할 수 없습니다. 자세한 규칙 작성 지침은 [고객 관리 규칙](../../customer-managed-rules/docs/index.md)을 참조하세요.

## Network Firewall이 검사하지 않는 것

어떤 트래픽이 Network Firewall을 우회하는지 이해하는 것은 무엇을 검사하는지 이해하는 것만큼 중요합니다. 다음 트래픽 유형은 라우팅 구성에 관계없이 방화벽 엔드포인트에 도달하지 않습니다:

| 트래픽 유형 | Network Firewall을 우회하는 이유 | 대체 제어 |
|---|---|---|
| VPC .2 Resolver에 대한 DNS 쿼리 | DNS 확인은 AmazonProvidedDNS라고도 하는 VPC .2 Resolver에 대한 전용 경로를 사용합니다. 이러한 쿼리는 네트워크 방화벽 엔드포인트를 통과하지 않습니다. 이는 .2 Resolver에만 해당됩니다. Network Firewall은 Route 53 Resolver 인바운드 엔드포인트로 향하는 DNS 트래픽은 검사하고 필터링할 수 있습니다. 이 트래픽은 일반 VPC 라우팅을 따르기 때문입니다. | [Amazon Route 53 Resolver DNS Firewall](https://aws.amazon.com/route53/resolver-dns-firewall/) |
| VPC 피어링 트래픽 | VPC 피어링은 VPC 라우팅 테이블의 로컬 라우트를 따르며, 방화벽 엔드포인트를 통해 라우팅하도록 재정의할 수 없습니다. | 보안 그룹 |
| AWS Global Accelerator 트래픽 | Global Accelerator는 AWS 글로벌 네트워크 엣지를 사용하며 VPC 라우팅 테이블을 우회합니다. | AWS WAF(HTTP용), 보안 그룹 |
| 동일 서브넷 내 트래픽 | 서브넷 내 트래픽은 VPC 라우팅 테이블의 로컬 라우트를 따르며, 방화벽 엔드포인트를 통해 라우팅하도록 재정의할 수 없습니다. | 보안 그룹 |

***핵심 인사이트:*** *DNS는 Network Firewall이 검사하는 데이터 경로와 별도로 인터넷으로의 전용 이그레스 경로입니다. Network Firewall은 DNS 확인 후 실제 연결의 TLS SNI 및 HTTP 호스트 헤더를 여전히 볼 수 있지만(이것이 도메인 필터링이 작동하는 이유입니다), DNS 확인 자체는 Network Firewall에 보이지 않습니다. 즉, DNS 터널링 및 도메인 생성 알고리즘(DGA) 활동은 Network Firewall을 완전히 우회할 수 있습니다. 이 별도의 이그레스 경로를 보호하기 위해 모든 VPC에 DNS Firewall을 배포하세요.*

!!! tip "모범 사례"
    VPC .2 Resolver(AmazonProvidedDNS)를 사용하는 워크로드가 있는 모든 VPC에 Amazon Route 53 Resolver DNS Firewall을 배포하세요. DNS Firewall은 가장 낮은 비용으로 DNS 이그레스 경로를 보호하여 Network Firewall이 볼 수 없는 DNS 기반 유출을 포착합니다. 구성 지침은 [DNS Firewall 모범 사례](../../../dns-firewall/index.md) 가이드를 참조하세요.

## Network Firewall과 보완 서비스

Network Firewall은 심층 방어 네트워크 보안 아키텍처의 한 계층입니다. 다른 제어를 대체하지 않습니다.

### DNS Firewall

Amazon Route 53 Resolver DNS Firewall은 DNS 확인 계층에서 작동하여 연결이 설정되기 전에 금지된 도메인에 대한 쿼리를 차단합니다. Network Firewall은 연결 계층에서 작동하여 DNS 확인 후 트래픽을 검사합니다. 대부분의 사람들이 DNS Firewall을 간과하는 이유는 Network Firewall의 도메인 필터링(TLS SNI 및 HTTP 호스트 헤더를 통한)이 워크로드가 연결할 수 있는 도메인을 제어하는 데 이미 작동하기 때문입니다. DNS Firewall이 여전히 필요한 이유는 DNS가 인터넷으로의 별도의 이그레스 경로이기 때문입니다. DNS Firewall이 없으면, 워크로드는 DNS 터널링을 사용하여 Network Firewall이 볼 수 있는 TCP/TLS 연결을 설정하지 않고 DNS 쿼리만으로 데이터를 유출하거나 명령 및 제어 인프라와 통신할 수 있습니다.

두 서비스를 함께 배포하세요: DNS Firewall은 가장 낮은 비용으로 DNS 이그레스 경로를 보호하고, Network Firewall은 데이터 경로에서 상태 저장 검사를 제공합니다.

### 보안 그룹

보안 그룹은 선택 사항이 아닙니다. VPC의 모든 탄력적 네트워크 인터페이스(ENI)에는 보안 그룹이 연결되어야 하며, 보안 그룹은 인스턴스 수준에서 첫 번째이자 마지막 방어선을 제공합니다. Network Firewall은 프로토콜 인식 검사, IPS 서명, 도메인 기반 필터링, 명시적 거부, 보안 그룹이 수행할 수 없는 다수의 규칙 지원을 추가하여 보안 그룹을 보완합니다. 보안 그룹은 라우팅이 트래픽을 방화벽 엔드포인트를 통해 전달하는지 여부에 관계없이 인스턴스 수준에서 트래픽을 제한하여 Network Firewall을 보완합니다.

### 네트워크 ACL

네트워크 ACL은 서브넷 경계에서 스테이트리스 패킷 필터링을 제공하며, 명시적 거부를 표현할 수 있는 유일한 VPC 네이티브 제어입니다. 이로 인해 대략적이고 안정적인 가드레일에 적합합니다: 알려진 악성 CIDR 범위를 서브넷 경계에서 차단하거나, 보안 그룹이 무엇을 허용하든 절대 넘어서는 안 되는 세그먼테이션 경계를 적용하는 것입니다.

기본 활성 필터링 제어로는 적합하지 않습니다. 스테이트리스이기 때문에, 반환 트래픽을 위한 임시 포트 범위를 포함하여 모든 플로우에 일치하는 인바운드 및 아웃바운드 규칙이 필요합니다. ACL당 규칙 수가 제한되어 있고, 보안 그룹이나 리소스 ID를 참조할 수 없으며, 많은 서브넷과 계정에서 정확성을 유지하는 것은 상당한 운영 부담입니다.

소수의 고가치이고 거의 변경되지 않는 거부 규칙에 네트워크 ACL을 사용하고, 리소스 수준 액세스 제어에는 보안 그룹을, 상태 저장 검사, 도메인 필터링, IPS 커버리지에는 Network Firewall을 사용하세요.

## 주요 개념

### 방화벽 정책

방화벽 정책은 방화벽의 모니터링 및 보호 동작을 정의합니다. 다음을 포함합니다:

* **규칙 그룹** - 스테이트리스 및 스테이트풀 규칙의 정렬된 컬렉션
* **기본 작업** - 어떤 규칙과도 일치하지 않는 트래픽에 대한 처리
* **규칙 순서 모드** - 스테이트풀 엔진이 규칙을 처리하는 방식(Strict 또는 Action Order)
* **변수** - 규칙에서 사용되는 $HOME_NET과 같은 네트워크 변수
* **스트림 예외 정책** - 중간 스트림 트래픽 처리 방식

### 규칙 그룹

[규칙 그룹](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups.html)은 재사용 가능한 규칙 모음입니다. 두 가지 유형이 있습니다:

* **스테이트리스 규칙 그룹** - 스테이트풀 검사 전에 평가되는 패킷 단위 규칙
* **스테이트풀 규칙 그룹** - Suricata가 평가하는 연결 인식 규칙

Network Firewall은 방화벽 정책당 최대 20개의 스테이트리스 규칙 그룹과 20개의 스테이트풀 규칙 그룹을 지원합니다. [고객 관리 규칙](../../customer-managed-rules/docs/index.md)에서 설명하는 이유로 스테이트풀 규칙 그룹만 사용하는 것을 권장합니다. 전체 서비스 제한 목록은 [Network Firewall 할당량](https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html) 페이지를 참조하세요.

### 방화벽 엔드포인트

[방화벽 엔드포인트](https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-components.html)는 특정 서브넷 및 가용 영역에 배포되는 Network Firewall 리소스입니다. 트래픽은 검사를 위해 라우팅 테이블을 통해 방화벽 엔드포인트로 라우팅됩니다.

* 각 엔드포인트는 트래픽 양에 관계없이 시간당 요금이 부과됩니다
* 고가용성을 위해 워크로드가 있는 각 AZ에 엔드포인트를 배포하세요
* 엔드포인트는 전용 서브넷에 배치해야 합니다(방화벽 서브넷에 다른 리소스를 배치하지 마세요)

단계별 배포 지침은 [AWS Network Firewall 시작하기](https://docs.aws.amazon.com/network-firewall/latest/developerguide/getting-started.html)를 참조하세요.

## 제한 사항 및 서비스 할당량

AWS Network Firewall에서 현재 지원하지 않는 Suricata 기능이 있습니다. 규칙을 작성하기 전에 [제한 사항 및 주의 사항](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html) 문서를 확인하세요. 서비스가 지원을 추가함에 따라 목록이 변경됩니다.

전체 할당량 목록은 [AWS Network Firewall 할당량](https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html)을 참조하세요.

## Suricata 리소스

* [Suricata 사용자 가이드](https://docs.suricata.io/en/latest/)
* [Suricata 규칙 형식](https://docs.suricata.io/en/latest/rules/intro.html)
* [Suricata Flow 키워드](https://docs.suricata.io/en/latest/rules/flow-keywords.html)
* [Suricata TLS 키워드](https://docs.suricata.io/en/latest/rules/tls-keywords.html)
* [Suricata HTTP 키워드](https://docs.suricata.io/en/latest/rules/http-keywords.html)
* [Suricata 포럼](https://forum.suricata.io/)

## 다음 읽을 내용

* [배포 아키텍처](../../deployment-architecture/docs/index.md) - 환경에 적합한 배포 모델 선택
* [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md) - 규칙 순서, 기본 작업 및 정책 설정 구성
