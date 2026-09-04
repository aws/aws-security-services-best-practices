# 시작 정책

!!! info "사전 요구 사항"
    이 섹션은 이 가이드의 모든 이전 섹션에 대한 이해를 전제로 합니다. [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md), [고객 관리 규칙](../../customer-managed-rules/docs/index.md), [AWS 관리형 규칙](../../aws-managed-rules/docs/index.md)의 모범 사례를 단일 배포 가능한 템플릿으로 통합합니다.

AWS Network Firewall을 시작하는 것이 가장 어려운 부분입니다. 잘 구성된 정책이 갖춰지면 이후 운영은 간단합니다. 이 페이지는 즉시 배포하고 아무것도 차단하지 않으면서 트래픽 모니터링을 시작할 수 있는 시작 방화벽 정책 템플릿을 제공합니다. 이 가이드에서 다루는 모든 모범 사례를 구현하여 일반적인 잘못된 구성을 방지하고 올바르게 시작하도록 도와줍니다.

이 템플릿은 **모니터 모드**로 방화벽 정책을 배포합니다. 모든 트래픽과 위협 탐지를 차단하지 않고 기록합니다. 목표는 방화벽이 일정 기간 동안 트래픽을 검사하여 어떤 트래픽이 흐르고 있는지 명확한 그림을 가질 수 있도록 하는 것입니다. 트래픽 패턴을 이해한 후, drop 기본 작업을 추가하고 관리형 규칙 그룹에서 alert 전용 재정의를 제거하여 정책을 적용 모드로 전환합니다.

## 템플릿 리포지토리

시작 정책 템플릿은 CloudFormation과 Terraform 모두에서 사용할 수 있습니다:

* **CloudFormation:** [aws-networkfirewall-cfn-templates](https://github.com/aws-samples/aws-networkfirewall-cfn-templates/tree/main/getting_started_policy)
* **Terraform:** [aws-network-firewall-terraform](https://github.com/aws-samples/aws-network-firewall-terraform/tree/main/getting_started_policy)

이 리포지토리에는 지원되는 모든 배포 아키텍처에서 방화벽 자체(VPC, 서브넷, 엔드포인트, 라우팅)를 배포하기 위한 샘플 템플릿도 포함되어 있습니다. 어떤 배포 모델을 사용할지에 대한 지침은 [배포 아키텍처](../../deployment-architecture/docs/index.md)를 참조하세요.

## 템플릿이 배포하는 것

템플릿은 두 가지 리소스를 생성합니다:

1. 모든 권장 설정과 15개의 AWS 관리형 규칙 그룹(모두 alert 모드)으로 구성된 **방화벽 정책**
2. 트래픽 가시성을 위한 모니터링 규칙이 포함된 **사용자 정의 Suricata 규칙 그룹**

이 정책을 기존 또는 새로운 Network Firewall에 연결합니다. 템플릿은 방화벽 자체를 생성하지 않습니다. 배포 아키텍처에 따라 VPC 및 서브넷 결정이 필요하기 때문입니다. 이 정책과 함께 방화벽, VPC, 서브넷, 라우팅을 생성하는 전체 배포 템플릿은 위에 링크된 CloudFormation 및 Terraform 리포지토리를 참조하세요.

## 정책 구성 설명

### 스테이트리스 엔진

스테이트리스 엔진 기본 작업은 모든 트래픽을 스테이트풀 엔진으로 전달(`aws:forward_to_sfe`)하도록 설정됩니다. 스테이트리스 규칙은 구성되지 않습니다. 모든 검사는 스테이트풀 엔진에서 수행됩니다. 이유는 [스테이트리스 규칙을 사용하지 마세요](../../customer-managed-rules/docs/index.md#do-not-use-stateless-rules)를 참조하세요.

### 스테이트풀 엔진 설정

| 설정 | 값 | 이유 |
|---|---|---|
| 규칙 순서 | STRICT_ORDER | 결정론적, 우선순위 기반 평가. [규칙 순서](../../firewall-policy-configuration/docs/index.md#규칙-순서-항상-strict-사용) 참조. |
| 스트림 예외 정책 | REJECT | 중간 스트림 플로우에 TCP RST를 보내 클라이언트가 깔끔하게 재연결하도록 합니다. [스트림 예외 정책](../../firewall-policy-configuration/docs/index.md#스트림-예외-정책) 참조. |
| TCP 유휴 타임아웃 | 350초 | NAT 게이트웨이의 고정 타임아웃에 맞추고, IaC에서 보이도록 명시적으로 설정. 경로에 NAT 게이트웨이가 없고 장기 플로우가 있는 경우 증가시키세요. [TCP 유휴 타임아웃](../../firewall-policy-configuration/docs/index.md#tcp-유휴-타임아웃) 참조. |
| 기본 작업 | Application alert established (server-directed only) | 차단 없이 일치하지 않는 트래픽을 기록합니다. 알림 전에 애플리케이션 계층 데이터(TLS SNI, HTTP 호스트)를 기다립니다. [기본 작업](../../firewall-policy-configuration/docs/index.md#기본-작업) 참조. |

### HOME_NET 변수

HOME_NET은 정책 수준에서 모든 RFC 1918 사설 IP 주소 범위로 설정됩니다: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. 이렇게 하면 향후 추가하는 VPC에 관계없이 방화벽을 통해 흐르는 모든 사설 IP 트래픽이 $HOME_NET을 사용하는 규칙과 올바르게 일치합니다. 전체 설명은 [$HOME_NET 및 $EXTERNAL_NET 변수](../../firewall-policy-configuration/docs/index.md#home-net-및-external-net-변수)를 참조하세요.

### 관리형 규칙 그룹(모두 alert 모드)

모든 관리형 규칙 그룹은 `DROP_TO_ALERT` 재정의로 배포되어 drop/reject 작업을 alert로 변환합니다. 이는 규칙이 트래픽을 차단하지 않고 위협을 탐지하고 기록함을 의미합니다. 규칙이 합법적인 트래픽을 방해하지 않는다고 확신하면, 재정의를 제거하여 차단을 시작합니다.

!!! tip "모범 사례"
    관리형 규칙 그룹의 경우, 이러한 규칙은 휴리스틱이나 행동 패턴이 아닌 확인된 위협 패턴(알려진 악성 도메인, 봇넷 C2 프로토콜, 익스플로잇 페이로드)에 일치하므로 오탐은 드뭅니다. 대부분의 고객은 짧은 모니터링 기간 후 문제 없이 DROP_TO_ALERT 재정의를 제거할 수 있습니다.

#### Active Threat Defense (우선순위 1)

[AttackInfrastructureStrictOrder](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-atd.html)는 맬웨어 스테이징 URL, 봇넷 명령 및 제어 서버, 크립토마이닝 풀을 포함하여 AWS가 추적하는 알려진 악성 인프라와의 통신을 차단합니다. MadPot의 AWS 위협 인텔리전스를 기반으로 합니다. 이것이 가장 중요한 단일 관리형 규칙 그룹입니다.

#### 도메인 및 IP 평판(우선순위 2-5)

이 네 가지 규칙 그룹은 악성 활동과 관련된 것으로 알려진 도메인 및 IP로의 트래픽을 차단합니다. 추가 비용 없이 포함되며 최소한의 용량 풋프린트(각 200)를 가집니다.

| 우선순위 | 규칙 그룹 | 차단 대상 |
|---|---|---|
| 2 | BotNetCommandAndControlDomainsStrictOrder | 알려진 봇넷 C2 도메인 |
| 3 | AbusedLegitBotNetCommandAndControlDomainsStrictOrder | C2에 악용되는 합법적 서비스(파일 공유, 붙여넣기 사이트) |
| 4 | MalwareDomainsStrictOrder | 알려진 맬웨어 배포 도메인 |
| 5 | AbusedLegitMalwareDomainsStrictOrder | 맬웨어 배포에 악용되는 합법적 서비스 |

#### 위협 서명 규칙 그룹(우선순위 6-15)

이 규칙 그룹은 네트워크 트래픽에서 특정 공격 패턴과 프로토콜을 탐지합니다. 선택은 가장 일반적인 Network Firewall 사용 사례에 최적화되어 있습니다: 침해된 인스턴스가 C2와 통신, 페이로드 다운로드, 크립토마이닝 수행 또는 수평 이동을 시도하는 위협 모델인 서버 워크로드(EC2, ECS, EKS) 보호.

| 우선순위 | 규칙 그룹 | 탐지 대상 | 포함 이유 |
|---|---|---|---|
| 6 | ThreatSignaturesBotnetStrictOrder | TCP, UDP 및 기타 프로토콜에서의 봇넷 C2 프로토콜 | 가장 넓은 봇넷 커버리지. 침해된 서버는 많은 프로토콜을 통해 통신합니다. |
| 7 | ThreatSignaturesBotnetWebStrictOrder | HTTP 기반 봇넷 C2 통신 | HTTP는 정상 웹 트래픽과 혼합되므로 가장 일반적인 C2 채널입니다. |
| 8 | ThreatSignaturesMalwareStrictOrder | TCP, UDP, SMTP, ICMP, SMB에서의 맬웨어 및 웜 전파 | 모든 프로토콜에 걸친 광범위한 맬웨어 탐지. |
| 9 | ThreatSignaturesMalwareCoinminingStrictOrder | 크립토마이닝 프로토콜 및 풀 통신 | 크립토마이닝은 서버 워크로드에서 가장 일반적인 침해 후 활동입니다. |
| 10 | ThreatSignaturesExploitsStrictOrder | 직접 익스플로잇(ActiveX, FTP, NetBIOS, RPC, 셸코드, SQL 인젝션, SNMP) | 강력한 동서 커버리지. 내부 시스템 간 수평 익스플로잇 탐지. |
| 11 | ThreatSignaturesIOCStrictOrder | 침해 지표, 공격 응답 서명, 익스플로잇 킷 인프라 | 초기 침해 후 포스트 익스플로잇 활동 탐지. |
| 12 | ThreatSignaturesScannersStrictOrder | 정찰 도구(Nessus, Nikto, 포트 스캐너) | 내부 정찰 탐지. 동서에 핵심(익스플로잇 전 스캐닝 포착). |
| 13 | ThreatSignaturesSuspectStrictOrder | 의심스러운 JA3 핑거프린트, IRC 채팅, 비정상적인 사용자 에이전트 | 정상 서버 트래픽과 일치하지 않는 비정상적인 클라이언트 동작 포착. |
| 14 | ThreatSignaturesEmergingEventsStrictOrder | 활성 캠페인 및 긴급 위협(규칙이 자주 교체됨) | 높은 시의성 가치. 현재 발생 중인 위협을 포착합니다. |
| 15 | ThreatSignaturesDoSStrictOrder | 서비스 거부 패턴 | 낮은 용량 비용(200). 기본 DoS 가시성 제공. |

#### 포함되지 않은 것(및 이유)

방화벽 정책당 상태 저장 규칙의 기본 할당량은 30,000입니다. 이 템플릿은 그 중 29,200을 사용합니다. 다음 규칙 그룹은 기본 제한에 맞지 않습니다:

| 규칙 그룹 | 용량 | 참고 |
|---|---|---|
| ThreatSignaturesBotnetWindowsStrictOrder | 3,400 | Windows 전용 봇넷 탐지. Windows 워크로드를 실행하는 경우 추가하세요. |
| ThreatSignaturesMalwareWebStrictOrder | 3,300 | HTTP/TLS 맬웨어. 웹 전용 서명으로 MalwareStrictOrder를 보완합니다. |
| ThreatSignaturesWebAttacksStrictOrder | 1,400 | 웹 애플리케이션 공격(SQLi, XSS). 인그레스 또는 동서 웹 트래픽에 관련됩니다. |
| ThreatSignaturesPhishingStrictOrder | 4,200 | 자격 증명 피싱. 서버 워크로드보다 최종 사용자 브라우징에 더 관련됩니다. |
| ThreatSignaturesMalwareMobileStrictOrder | 4,000 | 모바일 OS 맬웨어. 모바일 트래픽이 방화벽을 통과하지 않는 한 관련 없습니다. |

ThreatSignaturesFUPStrictOrder도 제외됩니다. 위협 탐지가 아닌 허용 가능한 사용 정책 위반(게임, P2P 트래픽, 부적절한 콘텐츠)을 다루므로, 모든 배포가 가져야 할 기준이 아닌 허용 가능한 사용 적용이 필요한 환경에 적합합니다.

!!! tip "모범 사례"
    이 템플릿을 배포한 직후 [서비스 할당량 증가 요청](https://console.aws.amazon.com/servicequotas/home/services/network-firewall/quotas)을 제출하여 상태 저장 규칙 용량을 50,000으로 올리세요. 두 가지 할당량이 이를 제어합니다: 방화벽 정책당 총 상태 저장 규칙(기본 30,000, 정책이 참조하는 모든 규칙 그룹에 걸쳐) 및 상태 저장 규칙 그룹 용량 최대값(기본 30,000, 단일 규칙 그룹에 대해). 증가는 일반적으로 빠르게 승인되며 추가 관리형 규칙 그룹 및 도메인 허용 목록을 위한 더 큰 사용자 정의 규칙 그룹을 추가할 수 있습니다.

#### 할당량 증가 후 용량 계획

일반적인 질문: "모든 AWS 관리형 규칙을 추가하면 사용자 정의 규칙을 위한 여유가 얼마나 될까요?"

정책당 20개 상태 저장 규칙 그룹 제한이 용량뿐 아니라 바인딩 제약 조건입니다. 50,000 용량이지만 20개 규칙 그룹 슬롯만 있으므로, 관리형 규칙과 사용자 정의 규칙 그룹의 균형을 맞춰야 합니다. 이 템플릿은 20개 슬롯 중 16개를 사용합니다(관리형 15 + 사용자 정의 1), 4개 슬롯이 남습니다.

용량 증가 후 권장 접근 방식:

* 제외된 관리형 규칙 그룹 2-3개 추가(남은 4개 슬롯 중 2-3개 사용)
* 더 높은 용량의 사용자 정의 규칙 그룹(도메인 허용 목록, 환경별 규칙)을 위해 1-2개 슬롯 유지

예를 들어, BotnetWindows(3,400), MalwareWeb(3,300), WebAttacks(1,400)를 추가하면 3개 슬롯과 8,100 용량을 사용하여, 1개의 사용자 정의 규칙 그룹 슬롯과 사용자 정의 규칙에 사용 가능한 약 12,500 용량 단위가 남습니다. 이는 상당한 도메인 허용 목록이나 수백 개의 사용자 정의 Suricata 규칙에 충분합니다.

### 사용자 정의 규칙 그룹(우선순위 100)

사용자 정의 규칙 그룹은 200 용량 단위로 가장 낮은 우선순위(모든 관리형 규칙 후 마지막에 평가)에 배포됩니다. 이렇게 하면 초기 용량을 관리형 규칙에 사용할 수 있습니다. 서비스 할당량 증가가 승인된 후, 도메인 허용 목록 및 기타 사용자 정의 규칙을 위해 더 높은 용량의 추가 사용자 정의 규칙 그룹을 생성하세요.

포함된 사용자 정의 규칙:

**HOME_NET 검증** - 소스와 대상 모두 $HOME_NET과 일치하지 않는 트래픽에 대해 알림을 보냅니다. 이 규칙이 작동하면 HOME_NET 구성이 불완전합니다. [잘못 구성된 $HOME_NET 탐지](../../firewall-policy-configuration/docs/index.md#잘못-구성된-home-net-탐지)를 참조하세요.

**평문 HTTP 탐지** - 네트워크를 떠나는 모든 평문 HTTP 트래픽에 대해 알림을 보냅니다. 서버 워크로드의 모든 아웃바운드 트래픽은 TLS 암호화되어야 합니다. 평문 HTTP는 잘못 구성된 애플리케이션이나 잠재적 데이터 노출을 나타낼 수 있습니다. 기본 작업도 이를 기록하지만, 전용 규칙이 있으면 특별히 검색하고 알림하기 쉽습니다.

**동서 트래픽 모니터링** - 내부 간 트래픽에 대해 알림을 보내는 규칙 세트로, VPC 간 수평 통신 패턴을 발견하는 데 도움이 됩니다. 일반적인 민감한 포트(데이터베이스, SSH, RDP, SMB)에 대한 특정 규칙을 포함하여 어떤 내부 서비스가 서로 통신하는지 볼 수 있습니다. 이 가시성은 동서 액세스 제어 규칙을 구축하기 전에 필수적입니다.

**인바운드 트래픽 모니터링** - 외부 소스에서 네트워크로 시작된 모든 트래픽에 대해 알림을 보냅니다. 이그레스 전용 또는 동서 배포에서 인바운드 인터넷 트래픽은 예상치 못한 것이며 라우팅 잘못된 구성을 나타낼 수 있습니다.

## 적용 모드로 전환

트래픽을 모니터링하고 트래픽 패턴을 이해한 후, 정책을 alert 모드에서 적용 모드로 전환합니다:

### 1단계: 관리형 규칙 그룹에서 DROP_TO_ALERT 재정의 제거

템플릿의 각 관리형 규칙 그룹 참조에서 `Override` 블록을 제거합니다. 이렇게 하면 위협이 탐지될 때 관리형 규칙이 네이티브 작업(drop 또는 reject)을 수행할 수 있습니다. ATD 및 도메인/IP 평판(가장 높은 신뢰도)부터 시작한 다음 위협 서명을 추가하여 점진적으로 수행할 수 있습니다.

### 2단계: drop 기본 작업 추가

기존 alert 작업과 함께 drop 기본 작업을 추가합니다. 다음에서:

* `aws:alert_established_app_layer_to_server`

다음 모두로 변경:

* `aws:drop_established_app_layer_to_server`(일치하지 않는 트래픽 차단)
* `aws:alert_established_app_layer_to_server`(차단되는 것을 기록)

두 작업 모두 유지하세요. alert 작업은 차단된 트래픽이 여전히 기록되도록 합니다. 이것이 없으면 차단된 트래픽이 알림 로그에 나타나지 않습니다. 자세한 내용은 [기본 작업](../../firewall-policy-configuration/docs/index.md#기본-작업)을 참조하세요.

### 3단계: 도메인 허용 목록 규칙 추가

모니터링 기간 동안 관찰한 내용을 기반으로, 워크로드가 합법적으로 도달해야 하는 도메인에 대한 pass 규칙을 추가합니다. 예제는 [도메인 필터링](../../customer-managed-rules/docs/index.md#domain-filtering) 및 [샘플 Suricata 규칙](../../sample-suricata-rules/docs/index.md#allow-rules-and-domain-allowlisting)을 참조하세요.

### 4단계: 동서 모니터링을 액세스 제어로 변환

동서 알림 로그를 검토하여 어떤 내부 플로우가 존재하는지 이해합니다. 모니터링 규칙을 알려진 정상 플로우에 대한 명시적 pass 규칙과 나머지에 대한 drop/reject 규칙으로 변환합니다.

## 용량 요약

| 구성 요소 | 사용된 용량 | 참고 |
|---|---|---|
| AttackInfrastructureStrictOrder | 15,000 | 고정 |
| 도메인/IP 규칙 그룹(4) | 800 | 고정 |
| 위협 서명 그룹(10) | 13,200 | 용량 증가 후 더 추가 가능 |
| 사용자 정의 규칙 그룹 | 200 | 의도적으로 작게 시작 |
| **총합** | **29,200 / 30,000** | |
| 사용된 규칙 그룹 | 16 / 20 | 4개 슬롯 남음 |

## 다음 읽을 내용

* [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md) - 여기서 구성된 각 정책 설정에 대한 심층 분석
* [고객 관리 규칙](../../customer-managed-rules/docs/index.md) - 특정 요구 사항에 맞는 사용자 정의 규칙 작성
* [AWS 관리형 규칙](../../aws-managed-rules/docs/index.md) - 관리형 규칙이 탐지하는 내용 이해
* [로깅 및 모니터링](../../logging-and-monitoring/docs/index.md) - 이 정책이 생성하는 알림 로그 분석
