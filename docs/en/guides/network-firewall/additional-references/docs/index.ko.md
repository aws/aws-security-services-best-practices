# 추가 참고 자료

이 페이지는 이 가이드에서 다루는 모범 사례 외에 AWS Network Firewall을 학습하고 구현하기 위한 실습 리소스를 수집합니다: 샘플 코드 리포지토리, 워크숍, 비디오 안내, 블로그 게시물 및 공식 문서 링크.

## 샘플 코드

배포하거나 확장할 작동 코드가 필요하다면 여기서 시작하세요.

* [AWS Network Firewall용 Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator) - Suricata 규칙을 작성, 검증, 관리하기 위한 오픈소스 GUI 애플리케이션. 규칙 충돌 분석, 대량 도메인 가져오기, 관리형 규칙 그룹 필터링, CloudWatch 사용량 분석, 인프라 내보내기(CloudFormation, Terraform, 직접 API)를 포함합니다. 이 가이드 전체에서 참조됩니다.
* [AWS Network Firewall CloudFormation 템플릿](https://github.com/aws-samples/aws-networkfirewall-cfn-templates) - 모든 배포 아키텍처(중앙 집중식, 분산, 결합), 시작 정책, CloudWatch 대시보드를 위한 CloudFormation 템플릿.
* [AWS Network Firewall Terraform 템플릿](https://github.com/aws-samples/aws-network-firewall-terraform) - 위의 CloudFormation 템플릿에 해당하는 Terraform 버전으로, 모든 배포 아키텍처와 시작 정책을 다룹니다.
* [AWS Network Firewall 자동화 예제](https://github.com/aws-samples/aws-network-firewall-automation-examples/tree/main) - 동적 규칙 업데이트, IP 목록 동기화 및 이벤트 기반 규칙 관리를 위한 Lambda 기반 자동화 패턴.

## 워크숍

AWS 워크숍은 샌드박스 AWS 계정에서 서비스를 배포하고 구성하는 과정을 안내하는 실습 랩입니다.

이러한 워크숍을 경험하는 가장 좋은 방법은 [AWS Activation Day 프로그램](https://aws-experience.com/amer/smb/events/series/activation-days)을 통하는 것입니다. Activation Day는 누구에게나 열려 있는 무료 강사 주도 이벤트입니다. AWS 솔루션스 아키텍트가 비용 없이 프로비저닝된 샌드박스 계정으로 라이브 환경에서 워크숍 내용을 안내합니다. AWS 보안, ID 및 거버넌스 서비스를 다루는 예정된 세션은 프로그램 페이지에서 확인하세요.

계정 팀이 있는 AWS 고객이라면, 솔루션스 아키텍트에게 팀을 위한 전용 워크숍 이벤트를 설정하도록 요청할 수도 있습니다. Activation Day와 동일한 워크숍 콘텐츠를 사용하지만 조직을 위해 비공개로 운영됩니다.

자체 환경에 워크숍을 배포하려면, 아래의 오픈소스 코드 리포지토리에 이를 수행하기 위한 인프라 코드가 포함되어 있습니다.

### 워크숍 안내

* [AWS 고급 네트워크 보안: Network Firewall 및 DNS Firewall](https://catalog.workshops.aws/network-security/en-US) - Network Firewall과 DNS Firewall을 함께 다루는 종합 워크숍. Transit Gateway를 사용한 중앙 집중식 배포, Suricata 규칙 작성, 도메인 필터링, 관리형 규칙, 로깅을 안내합니다.
* [AWS Cloud WAN, Network Firewall 및 DNS Firewall로 안전한 네트워크 구축](https://catalog.us-east-1.prod.workshops.aws/workshops/cdef9a06-8156-4669-9e6a-6eb83e4a5adc/en-US) - 위와 동일한 Network Firewall 및 DNS Firewall 내용이지만, 중앙 집중식 네트워킹 허브가 Transit Gateway 대신 Cloud WAN입니다. 트래픽을 방화벽으로 라우팅하기 위한 Cloud WAN 서비스 삽입 개념을 포함합니다.

### 워크숍 소스 코드

* [sample-aws-network-security-workshop](https://github.com/aws-samples/sample-aws-network-security-workshop) - AWS 고급 네트워크 보안 워크숍(Transit Gateway 변형)용 IaC
* [sample-building-secure-global-hybrid-networks-on-aws-workshop](https://github.com/aws-samples/sample-building-secure-global-hybrid-networks-on-aws-workshop) - 안전한 네트워크 구축 워크숍(Cloud WAN 변형)용 IaC

## 비디오

* [소개, 모범 사례 및 사용자 정의 Suricata 규칙](https://www.youtube.com/watch?v=67pVOv3lPlk) - Network Firewall 아키텍처 및 규칙 작성 기본 사항에 대한 광범위한 개요.
* [AWS re:Inforce 2023 - 방화벽과 배치 위치(NIS306)](https://www.youtube.com/watch?v=lTJxWAiQrHM) - Network Firewall, WAF, 보안 그룹 사용 시기를 다루는 배포 아키텍처 결정 프레임워크.
* [대규모 TLS 이그레스 트래픽 복호화, 검사 및 재암호화](https://www.youtube.com/watch?v=S7_hUxWrYmw&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=3&pp=iAQB) - TLS 검사 설정 및 운영 고려 사항.
* [대규모 TLS 트래픽 복호화, 검사 및 재암호화](https://www.youtube.com/watch?v=j2pLuHdAj0A&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=40&pp=iAQB) - 인바운드 및 아웃바운드 시나리오를 포함한 확장된 TLS 검사 안내.
* [AWS Network Firewall Suricata HOME_NET 변수 재정의](https://www.youtube.com/watch?v=ufx8sO5s4BI&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=22&pp=iAQB) - HOME_NET 잘못된 구성 및 수정 방법의 시각적 시연.
* [AWS Network Firewall TCP 트래픽에 대한 reject 작업 지원](https://www.youtube.com/watch?v=_K_2TVNygF4&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=54&pp=iAQB) - Reject 작업 동작 및 drop과의 사용 시기 비교.
* [AWS Network Firewall 태그 기반 리소스 그룹](https://www.youtube.com/watch?v=SDj_tMHN5Zk&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=55&pp=iAQB) - 다중 팀 환경을 위한 태그를 사용한 방화벽 리소스 정리.
* [AWS Network Firewall 콘솔 경험](https://www.youtube.com/watch?v=BYVObzBWnqo&list=PLhr1KZpdzukfJzNDd8eCJH_TGg24ZTwP6&index=1&pp=iAQB) - IaC보다 콘솔을 선호하는 시각적 학습자를 위한 콘솔 안내.

## 블로그

### 아키텍처 및 배포

* [AWS Network Firewall 배포 모델](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall/) - 다이어그램과 함께 중앙 집중식, 분산 및 결합 아키텍처를 다루는 원본 배포 모델 블로그.
* [AWS Network Firewall 배포 모델: Transit Gateway 연결 및 다중 VPC 엔드포인트](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall-transit-gateway-attachment-and-multiple-vpc-endpoints/) - 네이티브 TGW 연결 및 다중 엔드포인트 기능을 다루는 업데이트된 배포 모델.
* [Transit Gateway에 연결된 AWS Network Firewall로 마이그레이션하는 이유와 방법](https://aws.amazon.com/blogs/security/why-and-how-to-migrate-to-a-transit-gateway-attached-aws-network-firewall/) - 검사 VPC에서 네이티브 TGW 연결로의 마이그레이션 가이드.
* [안전한 이그레스 연결을 위한 Network Firewall Proxy 재소개](https://aws.amazon.com/blogs/networking-and-content-delivery/reintroducing-network-firewall-proxy-for-secure-egress-connectivity/) - no-source-preservation 아키텍처를 사용한 Network Firewall의 명시적 프록시 모드.
* [AWS Firewall Manager를 사용하여 AWS Network Firewall을 배포하는 방법](https://aws.amazon.com/blogs/security/how-to-deploy-aws-network-firewall-by-using-aws-firewall-manager/) - Firewall Manager를 사용한 다중 계정 배포 자동화.
* [AWS Cloud WAN의 중앙 집중식 아웃바운드 검사 아키텍처](https://aws.amazon.com/blogs/networking-and-content-delivery/centralized-outbound-inspection-architecture-in-aws-cloud-wan/) - Network Firewall과 함께 Cloud WAN 서비스 삽입.

### 규칙 및 필터링

* [로그 분석에서 규칙 생성까지: AWS Network Firewall이 아웃바운드 트래픽에 대한 도메인 기반 보안을 자동화하는 방법](https://aws.amazon.com/blogs/security/from-log-analysis-to-rule-creation-how-aws-network-firewall-automates-domain-based-security-for-outbound-traffic/) - 자동화된 도메인 검색 및 규칙 생성을 위한 Traffic Analysis Mode.
* [AWS Network Firewall 상태 저장 규칙 그룹의 접두사 목록 소개](https://aws.amazon.com/blogs/networking-and-content-delivery/introducing-prefix-lists-in-aws-network-firewall-stateful-rule-groups/) - 규칙에서 IP 세트 참조로 관리형 접두사 목록 사용.
* [AWS Network Firewall 및 AWS Lambda를 사용하여 비 HTTP/HTTPS 트래픽을 DNS 도메인으로 제어하는 방법](https://aws.amazon.com/blogs/security/how-to-control-non-http-and-non-https-traffic-to-a-dns-domain-with-aws-network-firewall-and-aws-lambda/) - 동적 IP 확인을 사용한 도메인별 비웹 프로토콜 필터링.
* [AWS Network Firewall을 사용하여 Amazon EKS에서 호스팅하는 애플리케이션의 아웃바운드 HTTPS 트래픽 필터링 및 SNI 제공 호스트 이름 수집](https://aws.amazon.com/blogs/security/use-aws-network-firewall-to-filter-outbound-https-traffic-from-applications-hosted-on-amazon-eks/) - EKS 전용 이그레스 필터링 패턴.

### TLS 검사

* [암호화된 트래픽 및 AWS Network Firewall을 위한 TLS 검사 구성](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-traffic-and-aws-network-firewall/) - 단계별 인바운드 TLS 검사 구성.
* [암호화된 이그레스 트래픽 및 AWS Network Firewall을 위한 TLS 검사 구성](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-egress-traffic-and-aws-network-firewall/) - 단계별 아웃바운드 TLS 검사 구성.

### 로깅 및 모니터링

* [AWS Network Firewall 로그 관리를 위한 비용 고려 사항 및 일반적인 옵션](https://aws.amazon.com/blogs/security/cost-considerations-and-common-options-for-aws-network-firewall-log-management/) - 로그 대상 선택, 비용 최적화 및 보존 전략.
* [Amazon OpenSearch Service를 사용하여 AWS Network Firewall 로그를 분석하는 방법(파트 1)](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-analyze-aws-network-firewall-logs-using-amazon-opensearch-service-part-1/) - 로그 분석 및 시각화를 위한 OpenSearch 통합.
* [Amazon OpenSearch Service를 사용하여 AWS Network Firewall 로그를 분석하는 방법(파트 2)](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-analyze-aws-network-firewall-logs-using-amazon-opensearch-service-part-2/) - 고급 OpenSearch 쿼리 및 대시보드 생성.
* [AWS Network Firewall 규칙 히트 카운트 지원](https://aws.amazon.com/blogs/security/aws-network-firewall-now-supports-rule-hit-count/) - 비활성 규칙 찾기, 새 규칙 검증, 활성 제어 증명을 위한 규칙별 트래픽 일치 보고.
* [AWS Network Firewall CloudWatch 대시보드 소개](https://aws.amazon.com/blogs/security/introducing-the-aws-network-firewall-cloudwatch-dashboard/) - 네이티브 모니터링 대시보드 설정 및 사용법.
* [Contributor Insights를 사용한 AWS Network Firewall 분석](https://aws.amazon.com/blogs/mt/use-contributor-insights-to-analyze-aws-network-firewall/) - Top-N 분석을 위한 CloudWatch Contributor Insights.

## AWS 문서

* [AWS Network Firewall 개발자 가이드](https://docs.aws.amazon.com/network-firewall/latest/developerguide/what-is-aws-network-firewall.html) - 전체 서비스 문서.
* [Network Firewall FAQ](https://aws.amazon.com/network-firewall/faqs/) - 일반적인 질문과 답변.
* [Network Firewall 요금](https://aws.amazon.com/network-firewall/pricing/) - 엔드포인트, 처리 및 TLS 검사에 대한 현재 요금.
* [Suricata 규칙 예제](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html) - 공식 AWS Suricata 규칙 예제.
* [규칙 문제 해결](https://docs.aws.amazon.com/network-firewall/latest/developerguide/troubleshooting-rules.html) - 일반적인 규칙 문제 및 해결 방법.
* [상태 저장 규칙 그룹의 평가 순서](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-rule-evaluation-order.html) - Strict 및 Action Order 모드의 작동 방식.
* [규칙 그룹 용량 설정](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-rule-group-capacity.html) - 상태 저장 및 스테이트리스 규칙 그룹 용량 계산 방법.
* [Network Firewall 할당량](https://docs.aws.amazon.com/network-firewall/latest/developerguide/quotas.html) - 조정 가능 및 고정 서비스 제한.
* [스트림 예외 정책](https://docs.aws.amazon.com/network-firewall/latest/developerguide/stream-exception-policy.html) - 중간 스트림 플로우 처리 옵션.
* [TLS 검사 구성](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html) - TLS 복호화 설정 참조.
* [AWS Network Firewall 문제 해결](https://docs.aws.amazon.com/network-firewall/latest/developerguide/troubleshooting.html) - 일반 문제 해결 가이드.

## 관련 가이드

* [AWS 네트워킹 모범 사례 - 보안](https://aws.github.io/aws-networking-best-practices/security/) - 보다 넓은 AWS 네트워킹 보안 지침.
* [AWS 보안 서비스 모범 사례 - AWS 방화벽](../../../firewall-overview/index.md) - AWS 방화벽 서비스(Network Firewall, WAF, 보안 그룹, DNS Firewall) 간 선택.
* [AWS 보안 서비스 모범 사례 - AWS WAF](../../../waf/index.md) - 보완 웹 애플리케이션 방화벽에 대한 모범 사례.
