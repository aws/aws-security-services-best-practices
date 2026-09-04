# 모범 사례 빠른 참조

이 가이드의 가장 영향력 있는 권장 사항을 이유 없이 정리한 것입니다. 각 항목은 그 이유를 설명하는 섹션에 링크되어 있습니다. 처음부터 배포하는 경우, [시작 정책](../../getting-started-policy/docs/index.md)이 대부분의 권장 사항을 CloudFormation 또는 Terraform 템플릿으로 구현합니다.

## 배포 아키텍처

| 권장 사항 | 중요한 이유 | 상세 내용 |
|---|---|---|
| 다중 계정 환경에서는 검사를 중앙 집중화하고, 새로운 배포에는 네이티브 Transit Gateway 연결을 사용하세요 | 하나의 방화벽 엔드포인트 세트와 하나의 정책이 모든 VPC를 처리하여 엔드포인트 비용을 낮추고 정책 관리를 단순화합니다. | [배포 아키텍처](../../deployment-architecture/docs/index.md#transit-gateway-네이티브-연결을-통한-중앙-집중화) |
| 워크로드가 있는 모든 가용 영역에 방화벽 엔드포인트를 배포하고, 각 서브넷을 자체 AZ의 엔드포인트로 라우팅하세요 | 검사를 AZ 로컬로 유지하여 교차 AZ 데이터 전송 요금을 방지하고 각 가용 영역을 독립적으로 유지합니다. | [교차 AZ 데이터 전송 방지](../../cost-considerations/docs/index.md#avoid-cross-az-data-transfer) |
| NAT 게이트웨이를 방화벽과 동일한 네트워크 경로에 배치하세요 | NAT 게이트웨이 시간당 및 데이터 처리 요금이 Network Firewall 요금과 일대일로 면제됩니다. | [NAT 게이트웨이 번들 할인](../../cost-considerations/docs/index.md#nat-gateway-bundled-discount) |
| Amazon S3 및 Amazon DynamoDB에 게이트웨이 VPC 엔드포인트를 사용하세요 | 게이트웨이 엔드포인트는 무료이며 해당 트래픽을 방화벽 데이터 처리에서 제외합니다. | [데이터 처리 비용 절감](../../cost-considerations/docs/index.md#reduce-data-processing-costs) |
| 워크로드가 VPC .2 Resolver를 사용하는 모든 VPC에 Amazon Route 53 Resolver DNS Firewall을 배포하세요 | .2 Resolver에 대한 DNS 확인은 방화벽 엔드포인트가 볼 수 없는 전용 경로를 사용합니다. DNS Firewall이 해당 경로를 보호합니다. | [DNS Firewall](../../prerequisites/docs/index.md#dns-firewall) |
| Network Firewall과 함께 보안 그룹을 리소스 수준 제어로 유지하세요 | 보안 그룹은 트래픽이 어떻게 라우팅되는지에 관계없이 모든 ENI에 적용되므로, 두 제어가 서로를 강화합니다. | [보안 그룹](../../prerequisites/docs/index.md#보안-그룹) |
| 중앙 집중식 배포는 인프라 코드로 관리하고, 방화벽이 많은 계정과 VPC에 분산된 경우 AWS Firewall Manager를 사용하세요 | Firewall Manager의 강점은 계정 및 VPC가 추가될 때 많은 방화벽에 정책을 배포하고 적용하는 것입니다. | [다중 계정 관리](../../deployment-architecture/docs/index.md#aws-firewall-manager를-통한-다중-계정-관리) |

## 방화벽 정책 구성

| 권장 사항 | 중요한 이유 | 상세 내용 |
|---|---|---|
| Strict 규칙 순서를 사용하세요. Action Order를 사용하지 마세요. | Strict 순서는 정의한 순서대로 규칙을 평가하고, 첫 번째 일치가 적용됩니다. Action Order는 작업 유형별로 규칙을 그룹화하므로, 다른 작업 간의 우선순위를 제어할 수 없습니다. | [규칙 순서](../../firewall-policy-configuration/docs/index.md#규칙-순서-항상-strict-사용) |
| 스테이트리스 엔진 기본 작업을 "스테이트풀 규칙 그룹으로 전달"로 설정하고 모든 필터링은 스테이트풀 엔진에서 수행하세요 | 스테이트풀 엔진은 연결 추적, 애플리케이션 계층 검사, 로깅 및 거부 작업을 제공합니다. | [스테이트리스 규칙을 사용하지 마세요](../../customer-managed-rules/docs/index.md#do-not-use-stateless-rules) |
| "Application drop established (server-directed only)" **및** "Application alert established (server-directed only)"를 함께 기본 작업으로 선택하세요 | 애플리케이션 변형은 결정 전에 TLS SNI 또는 HTTP 호스트 헤더를 기다리며, 이것이 도메인 필터링이 의존하는 것입니다. 쌍을 이루는 alert 작업은 drop 작업이 차단하는 것을 기록합니다. | [기본 작업](../../firewall-policy-configuration/docs/index.md#기본-작업) |
| 정책 수준에서 $HOME_NET을 모든 RFC 1918 범위(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)로 설정하고 $HOME_NET 탐지 규칙을 배포하세요 | 기본값은 방화벽 자체의 VPC CIDR만 포함합니다. $HOME_NET이 모든 내부 범위를 포함하면, AWS 관리형 위협 서명을 포함하여 이를 참조하는 규칙이 방화벽을 통해 라우팅되는 모든 VPC의 트래픽과 일치합니다. | [$HOME_NET 및 $EXTERNAL_NET](../../firewall-policy-configuration/docs/index.md#home-net-및-external-net-변수) |
| 스트림 예외 정책을 Reject로 설정하세요 | Reject는 TCP RST를 보내 클라이언트가 재연결하도록 하고, 새 연결은 현재 규칙에 대해 완전히 검사됩니다. | [스트림 예외 정책](../../firewall-policy-configuration/docs/index.md#스트림-예외-정책) |

## 규칙

| 권장 사항 | 중요한 이유 | 상세 내용 |
|---|---|---|
| 사용자 정의 Suricata 규칙을 직접 작성하세요 | 일반 텍스트 규칙은 버전 제어 및 인프라 코드와 함께 작동하고, 규칙 그룹 간에 쉽게 이동하며, 전체 Suricata 기능 세트를 제공합니다. | [사용자 정의 Suricata 규칙 사용](../../customer-managed-rules/docs/index.md#use-custom-suricata-rules) |
| 프로토콜 필드가 `tcp` 또는 `ip`인 모든 상태 저장 규칙에 `flow:` 키워드를 넣으세요 | 이 키워드가 없으면 Suricata가 규칙을 IP 전용으로 분류하고, 플로우의 첫 번째 패킷에서 일치시키며, 플로우 수명 동안 해당 작업을 적용합니다. 이것이 규칙이 순서대로 평가되지 않는 것처럼 보이는 가장 일반적인 이유입니다. | [항상 flow: 키워드 사용](../../customer-managed-rules/docs/index.md#always-use-the-flow-keyword-on-all-tcp-or-ip-protocol-rules) |
| 이그레스에 도메인 허용 목록을 구현하세요: 워크로드에 필요한 도메인을 허용하고 나머지를 차단하세요 | 알려진 안전한 목록을 허용하는 것은 인터넷의 모든 나쁜 대상을 식별하는 것이 불가능한 방식으로 달성 가능하며, 위험 표면을 극적으로 줄입니다. | [도메인 필터링](../../customer-managed-rules/docs/index.md#domain-filtering) |
| 사용자 정의 규칙을 가능한 한 적은 규칙 그룹, 이상적으로는 하나로 통합하고, 성장할 여유를 두고 용량을 설정하세요 | 20개 상태 저장 규칙 그룹 제한은 관리형 규칙 그룹과 공유되며, 규칙 그룹 용량은 그룹 생성 후 고정됩니다. | [적은 규칙 그룹으로 통합](../../customer-managed-rules/docs/index.md#consolidate-into-few-rule-groups) |
| 새 차단 규칙을 먼저 `alert`로 배포한 다음, 실제 트래픽에 대해 검증한 후 `reject` 또는 `drop`으로 전환하세요 | Alert 모드는 규칙이 차단을 시작하기 전에 무엇을 일치시켰을지 보여줍니다. | [이 페이지 사용 방법](../../sample-suricata-rules/docs/index.md#how-to-use-this-page) |

## AWS 관리형 규칙

| 권장 사항 | 중요한 이유 | 상세 내용 |
|---|---|---|
| 모든 방화벽 정책에 Active Threat Defense를 활성화하세요 | 작성하거나 유지할 규칙 없이 Amazon 위협 인텔리전스를 사용하여 알려진 악성 인프라를 높은 신뢰도로 차단합니다. | [Active Threat Defense](../../aws-managed-rules/docs/index.md#active-threat-defense-atd) |
| 모든 정책에 도메인 및 IP 평판 규칙 그룹을 활성화하세요 | 워크로드가 도달할 이유가 없는 대상을 다루며, 추가 비용 없이 작은 용량 풋프린트를 가집니다. | [도메인 및 IP 규칙 그룹](../../aws-managed-rules/docs/index.md#domain-and-ip-rule-groups-free) |
| 세 가지 위협 서명 규칙 그룹으로 시작하세요: Botnet, Malware, Exploits | 가장 넓은 위협 커버리지와 가장 강력한 신호 대 노이즈 비율을 제공하면서 자체 규칙을 위한 규칙 그룹 슬롯을 남겨둡니다. | [배포 시나리오별 규칙 그룹 선택](../../aws-managed-rules/docs/index.md#selecting-rule-groups-by-deployment-scenario) |
| 관리형 규칙 그룹을 먼저 alert 모드로 배포한 다음, Active Threat Defense와 평판 목록부터 시작하여 drop으로 전환하세요 | 서명이 차단을 시작하기 전에 트래픽과 어떻게 일치하는지 보여줍니다. | [Alert 모드 vs drop 모드](../../aws-managed-rules/docs/index.md#deploying-managed-rules-in-alert-mode-vs-drop-mode) |

## 로깅 및 모니터링

| 권장 사항 | 중요한 이유 | 상세 내용 |
|---|---|---|
| 알림 로그와 플로우 로그를 별도의 로그 그룹 또는 S3 접두사에 게시하세요 | 두 로그 유형은 다른 질문에 답하며 분리될 때 쿼리하기 더 쉽습니다. | [로그 대상](../../logging-and-monitoring/docs/index.md#log-destinations) |
| `StreamExceptionPolicyPackets`, `DroppedPackets`, `RejectedPackets`, `TLSErrors`에 CloudWatch 알람을 생성하세요 | 이러한 지표는 트래픽 대칭, 차단 동작 또는 TLS 검사가 변경되었을 때 알려줍니다. | [권장 CloudWatch 알람](../../logging-and-monitoring/docs/index.md#recommended-cloudwatch-alarms) |
| 첫 번째 도메인 허용 목록을 구축하기 전에 Traffic Analysis Mode를 활성화하세요 | 허용 목록을 구축할 수 있는 30일간의 관찰된 HTTP 및 HTTPS 도메인을 제공합니다. | [Traffic Analysis Mode](../../logging-and-monitoring/docs/index.md#traffic-analysis-mode) |
