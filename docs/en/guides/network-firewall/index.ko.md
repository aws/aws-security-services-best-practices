---
title: 소개
---

# AWS Network Firewall 모범 사례

이 가이드는 AWS Network Firewall을 효과적으로 배포하고 운영하기 위한 구체적이고 실질적인 지침을 제공합니다. 보안 전문가, 네트워크 엔지니어 및 솔루션스 아키텍트를 대상으로 작성되었습니다. 어떤 방화벽 접근 방식을 사용할지 평가 중이라면, 먼저 [AWS 네트워크 보안 기본 사항](../firewall-overview/index.md) 가이드를 참조하세요.

## 이 가이드 사용 방법

이 가이드는 기본 개념부터 배포 결정, 규칙 구성, 지속적인 운영까지 순서대로 구성되어 있습니다. 처음 배포하는 경우 사전 요구 사항부터 시작하여 규칙을 구성하기 전에 배포 아키텍처까지 순서대로 읽는 것이 좋습니다. 특정 주제에 대한 지침을 찾고 있다면, 각 페이지는 독립적으로 읽을 수 있도록 작성되어 있습니다.

이유를 읽지 않고 무엇을 해야 하는지만 알고 싶다면, [모범 사례 빠른 참조](./quick-reference/docs/index.md)를 참조하세요. 모든 권장 사항은 그 이유를 설명하는 섹션에 링크되어 있습니다. 가이드 전체에서 실질적인 지침은 녹색 "모범 사례" 상자로 강조 표시되어 있으므로, 해당 부분만 훑어보고 바로 적용할 수 있습니다.

## 가이드 섹션

| 섹션 | 학습 내용 |
|---------|-------------------|
| [사전 요구 사항 및 기본 사항](./prerequisites/docs/index.md) | Suricata 엔진이 트래픽을 처리하는 방식, Network Firewall이 검사하는 것과 검사하지 않는 것, Network Firewall과 DNS Firewall의 관계, 트래픽 대칭 요구 사항 |
| [배포 아키텍처](./deployment-architecture/docs/index.md) | 중앙 집중식 및 분산 배포 모델, 기본 Transit Gateway 통합, 다중 엔드포인트 패턴, AWS Firewall Manager 및 AWS RAM을 사용한 다중 계정 관리 |
| [방화벽 정책 구성](./firewall-policy-configuration/docs/index.md) | 규칙 평가 순서, 기본 작업, 스트림 예외 정책, HOME_NET 변수 구성, TCP 유휴 타임아웃 조정 |
| [고객 관리 규칙](./customer-managed-rules/docs/index.md) | 사용자 정의 Suricata 규칙 작성 모범 사례, `flow:` 키워드 및 Suricata 규칙 유형, 규칙 그룹 용량 계산, 도메인 필터링, 컨테이너 속성 참조, 프로토콜 적용. 사용자 정의 규칙을 작성하기 전에 알아야 할 사항과 숙련된 운영자가 알아야 할 사항을 다룹니다. |
| [샘플 Suricata 규칙](./sample-suricata-rules/docs/index.md) | Network Firewall에서 일반적으로 배포되는 Suricata 규칙과 각 규칙에 대한 설명. 도메인 허용 목록 아키텍처 사용 사례를 위한 시작 규칙 템플릿 포함. 깊은 Suricata 전문 지식 없이도 시작할 수 있도록 도와줍니다. |
| [AWS 관리형 규칙](./aws-managed-rules/docs/index.md) | AWS에서 관리하는 위협 인텔리전스, Active Threat Defense, 도메인 및 IP 평판 목록, URL/도메인 카테고리 필터링, 파트너 관리형 규칙 활용. 모든 규칙을 처음부터 작성할 필요가 없습니다. |
| [TLS 검사](./tls-inspection/docs/index.md) | 인바운드 및 아웃바운드 TLS 복호화 구성, CA 인증서 요구 사항, 범위 구성, TLS 검사가 워크로드에 적합한지 판단하는 데 도움이 되는 지침 |
| [로깅 및 모니터링](./logging-and-monitoring/docs/index.md) | 알림 및 플로우 로그 유형, 로깅 대상, 로그 분석 패턴, CloudWatch 대시보드, 운영 알람 |
| [비용 고려 사항](./cost-considerations/docs/index.md) | 요금 체계, NAT 게이트웨이 번들 요금, 데이터 처리 비용 최적화, GB당 비용 절감 전략 |
| [추가 참고 자료](./additional-references/docs/index.md) | 워크숍, 동영상, 블로그 게시물, 실습 학습을 위한 샘플 코드 |

## AWS Network Firewall이란?

AWS Network Firewall은 Suricata 엔진을 사용하여 3계층에서 7계층까지의 VPC 트래픽을 검사하는 관리형 상태 저장 네트워크 방화벽 서비스입니다. Network Firewall은 리전 서비스로, 워크로드가 실행되는 가용 영역에 방화벽 엔드포인트를 배포하고 라우팅 테이블을 통해 해당 엔드포인트로 트래픽을 라우팅합니다. AWS는 각 방화벽 엔드포인트의 기본 컴퓨팅, 패치, 스케일링 및 가용성을 관리하며, 용량 계획이나 오토 스케일링 구성 없이 엔드포인트당 최대 100Gbps의 처리량을 지원합니다.

Network Firewall은 EC2에서 방화벽 어플라이언스 VM을 실행하고, Gateway Load Balancer로 이를 프론트하며, 인스턴스 가동 시간을 관리하고, 용량 프로비저닝 및 스케일링을 처리하는 운영 오버헤드를 제거합니다. 방화벽 엔드포인트를 배포하고, 규칙을 구성하고, 트래픽을 라우팅하기만 하면 됩니다. 각 가용 영역 내 고가용성 보장을 포함하여 나머지는 AWS가 모두 처리합니다. 보안 및 네트워킹 팀에게 이는 방화벽 인프라 안정성을 유지하는 대신 효과적인 보안 정책 작성에 집중할 수 있음을 의미합니다.

## Network Firewall의 적용 범위

Network Firewall은 **이그레스 트래픽 필터링**에 가장 일반적으로 배포되며, 그 다음은 동서(VPC 간) 검사, 그리고 인그레스 순입니다. 이그레스의 경우, 가장 많이 사용되는 사례는 아웃바운드 트래픽을 알려진 안전한 도메인의 엄격한 허용 목록으로 제한하는 것입니다. 동서 트래픽의 경우, Network Firewall은 Transit Gateway를 통해 라우팅되는 VPC 간 수평 트래픽을 검사합니다. 인그레스의 경우, Network Firewall은 비 HTTP/HTTPS 트래픽(SMTP, 사용자 정의 TCP 또는 데이터베이스 연결과 같은 프로토콜)에 적합합니다. 웹 애플리케이션 인그레스 트래픽은 애플리케이션 계층에서 AWS WAF가 더 적합합니다. 각 트래픽 패턴에 어떤 방화벽 서비스를 사용할지에 대한 자세한 지침은 [AWS 네트워크 보안 기본 사항](../firewall-overview/index.md) 가이드를 참조하세요.

## 주요 기능

Network Firewall을 배포하는 주요 이유입니다. 각 항목은 구성 및 모범 사례를 다루는 가이드 섹션에 링크되어 있습니다.

| 기능 | 설명 | 가이드 섹션 |
|-----------|-------------|---------------|
| 도메인 기반 필터링 | TLS SNI 및 HTTP 호스트 헤더 검사를 사용하여 도메인 이름별로 아웃바운드 트래픽을 허용하거나 거부합니다. SNI 또는 호스트 헤더가 보이는 모든 트래픽에 대해 TLS 복호화 없이 작동하므로, 이그레스 보안의 가장 일반적인 시작점입니다. | [도메인 필터링](./customer-managed-rules/docs/index.md#domain-filtering) |
| 관리형 위협 탐지 | 맬웨어, 익스플로잇, 봇넷, 자격 증명 피싱을 탐지하는 AWS 관리형 위협 서명 규칙 그룹. Active Threat Defense는 AWS 위협 센서의 인텔리전스를 사용하여 알려진 악의적 대상과의 통신을 차단합니다. 파트너 관리형 규칙은 타사 보안 벤더의 추가 위협 인텔리전스를 제공합니다. | [AWS 관리형 규칙](./aws-managed-rules/docs/index.md) |
| URL 및 도메인 카테고리 필터링 | 소셜 네트워킹, 도박, 명령 및 제어, 맬웨어 도메인 등 AWS에서 관리하는 콘텐츠 카테고리별로 트래픽을 차단하거나 허용합니다. | [URL 및 도메인 카테고리 필터링](./sample-suricata-rules/docs/index.md#domain-category-blocking) |
| 프로토콜 탐지 | 포트 번호에 관계없이 애플리케이션 계층 프로토콜을 식별하여, 포트 80에서 HTTP만 실행되도록 적용하거나 비표준 포트에서 SSH를 차단할 수 있습니다. | [고객 관리 규칙](./customer-managed-rules/docs/index.md) |
| 컨테이너 속성 참조 | 정적 IP 목록을 유지하지 않고 방화벽 규칙에서 Amazon ECS 및 Amazon EKS 컨테이너 IP 주소를 동적으로 참조합니다. Network Firewall은 컨테이너 수명 주기 이벤트를 구독하고 Suricata 규칙에서 참조하는 최신 IP 세트를 유지합니다. | [컨테이너 연결](https://docs.aws.amazon.com/network-firewall/latest/developerguide/container-associations.html) |
| 사용자 정의 Suricata 규칙 | IP 평판 목록, GeoIP 필터링, 프로토콜별 매칭을 포함하여 환경에 맞춤화된 Suricata 규칙 언어를 사용하여 상태 저장 검사 규칙을 작성합니다. 이 가이드의 샘플 규칙은 Network Firewall Suricata 구현에서 작동하는 것이 검증 및 확인되었습니다. | [고객 관리 규칙](./customer-managed-rules/docs/index.md) |
| 로깅 및 모니터링 | 방화벽 엔드포인트를 통과하는 모든 트래픽에 대한 상세한 알림 로그 및 플로우 로그. 네트워크 트래픽 패턴 분석을 위해 S3, CloudWatch Logs, Kinesis Data Firehose로의 스트리밍을 지원합니다. | [로깅 및 모니터링](./logging-and-monitoring/docs/index.md) |
| 고가용성 및 스케일링 | AWS가 방화벽 엔드포인트의 가용성, 스케일링 및 패치를 관리합니다. 각 엔드포인트는 용량 계획 없이 최대 100Gbps를 지원합니다. 방화벽 VM 장애, 패치 누락 또는 스케일링 오류로 인한 네트워크 다운타임 위험이 없습니다. | [배포 아키텍처](./deployment-architecture/docs/index.md) |
| JA3/JA4 핑거프린팅 | 트래픽을 복호화하지 않고 암호화 핸드셰이크 핑거프린트로 TLS 클라이언트를 식별하여 필터링하거나 포렌식 로깅에 활용합니다. | [JA3/JA4 해시 로깅](./sample-suricata-rules/docs/index.md#ja3ja4-hash-logging) |
| TLS 검사 | 도메인 수준 필터링을 넘어 더 깊은 콘텐츠 검사를 위해 TLS 트래픽을 복호화, 검사 및 재암호화합니다(예: `github.com`만이 아닌 `github.com/specific-repo`와 같은 URL 경로로 필터링). 일반적으로 이 수준의 가시성이 필요한 워크로드의 하위 집합에 대해 채택됩니다. | [TLS 검사](./tls-inspection/docs/index.md) |

## 관련 가이드

- [AWS Network Firewall 개발자 가이드](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html)
- [AWS 네트워킹 모범 사례 - 보안](https://aws.github.io/aws-networking-best-practices/security/)
- [AWS 네트워크 보안 기본 사항](../firewall-overview/index.md)
