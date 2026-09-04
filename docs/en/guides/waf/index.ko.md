# AWS WAF 모범 사례
> 2025년 7월부로 AWS WAF는 웹 ACL을 [protection pack](https://aws.amazon.com/blogs/security/introducing-the-new-console-experience-for-aws-waf/)으로 이름을 변경한 새로운 콘솔 경험을 출시했습니다. API, ARN, CLI 명령은 레거시 콘솔과 마찬가지로 여전히 web_acl/webacl이라는 용어를 사용합니다. 이것은 UI 및 문서 변경에 불과하며 두 용어는 호환됩니다. 유일한 차이점은 새 콘솔이 새 UI에서만 사용되는 개념을 도입하고 protection pack만 참조한다는 것입니다.

## 소개

AWS WAF 모범 사례 가이드에 오신 것을 환영합니다. 이 가이드의 목적은 웹 애플리케이션과 API를 보호하기 위해 AWS WAF를 배포, 구성 및 관리하기 위한 구체적인 지침을 제공하는 것입니다. GitHub를 통해 이 지침을 게시하면 서비스 개선 사항과 사용자 커뮤니티의 피드백을 포함한 시의적절한 권장 사항을 빠르게 반복할 수 있습니다. 이 가이드는 단일 리소스에 AWS WAF를 처음 배포하든, AWS Firewall Manager로 관리되는 기존 다중 계정 배포에서 AWS WAF를 최적화하는 방법을 찾든 가치를 제공하도록 설계되었습니다.

## 이 가이드 사용 방법

이 가이드는 일반적인 웹 익스플로잇, 봇 트래픽, 레이어 7 DDoS로부터 웹 애플리케이션과 API를 보호하는 책임이 있는 보안 전문가, 솔루션스 아키텍트, 애플리케이션 팀을 대상으로 합니다. 모범 사례는 더 쉬운 소비를 위해 집중된 섹션으로 구성되어 있습니다. 각 섹션은 간략한 개요로 시작하여 권장 사항 구현에 대한 자세한 지침이 이어지는 해당 모범 사례 세트를 포함합니다. 주제를 특정 순서로 읽을 필요는 없습니다:

* [사전 요구 사항 및 기본 사항](#prerequisites-and-fundamentals) - 새로운 AWS WAF 배포 또는 업데이트를 위한 기본 개념 및 계획
* [AWS 권장 HTTP 아키텍처](#recommended-http-architecture-on-aws) - 최대 WAF 효과를 위해 CloudFront로 HTTP 워크로드 설계
* [운영화](#operationalizing) - 대규모 AWS WAF 관리를 위한 운영 지침
* [AWS 관리형 규칙](#aws-managed-rules) - 기본 및 사용 사례별 Amazon 관리형 규칙 그룹
* [사용자 정의 규칙](#custom-rules) - 애플리케이션별 위협을 위한 사용자 정의 규칙
* [권장 WAF 규칙 순서](#recommended-waf-rule-order) - 최적의 보호 및 비용 효율성을 위한 protection pack의 규칙 배치
* [봇 관리](#bot-management) - Bot Control로 봇 트래픽 감지 및 제어
* [사기 방지](#fraud-prevention) - 사기성 가입 및 로그인 시도 감지
* [CAPTCHA 및 Challenge](#captcha-and-challenge) - 토큰 기반 완화 작업을 효과적으로 사용
* [배포 전략](#deployment-strategy) - 처음으로 WAF를 안전하게 배포하고 관리형 규칙 버전 업데이트
* [WAF 비용](#waf-cost) - AWS WAF 요금, WCU 용량, Shield Advanced 비용 보호 이해
* [로깅 접근 방식](#waf-logging) - AWS WAF 로그의 로그 대상, 필터링, 비용 최적화 구성
* [WAF 로그 쿼리 및 시각화](#monitoring-waf-rules) - 지원되는 대상에서 WAF 로그 쿼리 및 대시보드 구축
* [다른 AWS 서비스와 함께 WAF 사용](#using-waf-with-other-aws-services) - Firewall Manager 및 Shield Advanced와 통합
* [추가 참고 자료](#additional-references) - WAF Classic과의 알려진 차이점을 포함한 보충 주제

## AWS WAF란?

AWS WAF는 보호된 웹 애플리케이션 리소스로 전달되는 HTTP(S) 요청을 모니터링하고 제어할 수 있는 웹 애플리케이션 방화벽입니다. Amazon CloudFront 배포, Amazon API Gateway REST API, Application Load Balancer, AWS AppSync GraphQL API, Amazon Cognito 사용자 풀, AWS App Runner 서비스, AWS Verified Access 인스턴스, AWS Amplify 애플리케이션을 보호할 수 있습니다. AWS WAF를 사용하면 IP 주소, HTTP 헤더, HTTP 본문, URI 문자열, SQL 인젝션, 크로스 사이트 스크립팅과 같은 조건에 따라 웹 요청을 차단, 허용, 카운트하거나 CAPTCHA 및 Challenge 작업을 적용하는 규칙을 생성할 수 있습니다. 자세한 내용은 AWS WAF 개발자 가이드의 [AWS WAF란?](https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html)을 참조하세요.

## AWS WAF 활성화의 이점은?

AWS WAF는 일반적인 공격 패턴을 차단하고 정의한 특정 트래픽 패턴을 필터링하는 보안 규칙을 생성할 수 있도록 하여 애플리케이션에 도달하는 트래픽을 제어할 수 있게 합니다. 주요 이점:

* 직접 규칙을 작성하고 유지할 필요 없이 AWS에서 관리하는 [AWS 관리형 규칙](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups.html)을 사용한 SQL 인젝션 및 크로스 사이트 스크립팅(XSS)과 같은 일반적인 웹 익스플로잇으로부터의 보호.
* IP 주소, HTTP 헤더, 요청 본문, URI 경로, 지리적 출처 등에 따라 요청을 허용, 차단, 카운트 또는 챌린지하는 애플리케이션별 조건을 정의할 수 있는 유연한 [사용자 정의 규칙](https://docs.aws.amazon.com/waf/latest/developerguide/waf-rules.html).
* AWS 관리형 규칙 및 기타 규칙 그룹의 신호를 사용하여 보호 적용 방식을 사용자 정의할 수 있는 [규칙 레이블](https://docs.aws.amazon.com/waf/latest/developerguide/waf-labels.html). 예를 들어, 관리형 규칙을 Count 모드로 전환하고 추가 조건으로 레이블을 사용하여 차단하는 사용자 정의 규칙을 작성하여, 보호를 잃지 않으면서 세분화된 오탐 처리를 가능하게 합니다.
* 개별 클라이언트의 요청 폭주를 자동으로 차단하여 볼류메트릭 공격으로부터 보호하고 DDoS 이벤트의 영향을 줄이는 비율 기반 규칙.
* 머신 러닝 기반 이상 감지를 사용하여 수초 내에 레이어 7 DDoS 공격을 자동으로 감지하고 완화하는 [Anti-DDoS 관리형 규칙 그룹](https://docs.aws.amazon.com/waf/latest/developerguide/waf-anti-ddos-rg-using.html)(`AWSManagedRulesAntiDDoSRuleSet`)을 통한 애플리케이션 계층 DDoS 보호. 이것은 모든 AWS WAF 고객에게 제공되며, [AWS Shield Advanced](https://docs.aws.amazon.com/waf/latest/developerguide/ddos-advanced-summary.html) 구독자에게는 고급 등급이 포함됩니다.
* 자체 식별 크롤러에서 정교한 자동화 위협까지 봇 트래픽을 감지하고 관리하는 [Bot Control](https://docs.aws.amazon.com/waf/latest/developerguide/waf-bot-control.html)을 통한 봇 관리 기능. AI 봇 및 헤드리스 브라우저와 자동화 프레임워크를 감지하는 Web Bot Authentication(WBA)을 포함합니다.
* 크리덴셜 스터핑, 도난된 자격 증명 사용, 사기성 계정 생성 시도를 감지하고 차단하는 [Account Takeover Prevention(ATP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-atp.html) 및 [Account Creation Fraud Prevention(ACFP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-acfp.html) 관리형 규칙 그룹을 통한 사기 방지.
* 실시간 트래픽 분석에 기반한 지속적인 보안 권장 사항과 함께 구성 복잡성을 줄이는 가이드 설정 및 사전 구성된 protection pack.
* [AWS Firewall Manager](https://docs.aws.amazon.com/waf/latest/developerguide/fms-chapter.html)를 사용한 AWS Organization 전체의 중앙 집중식 WAF 정책 관리.
* CloudWatch Logs Insights, Amazon Athena 또는 Amazon QuickSight로 분석할 수 있는 CloudWatch 지표 및 상세 WAF 로그를 통한 웹 트래픽에 대한 실시간 가시성.
* 선불 약정 없이 사용한 만큼만 지불. 요금은 protection pack 수, 규칙 수, 검사된 요청 수를 기반으로 합니다. 자세한 내용은 [AWS WAF 요금](https://aws.amazon.com/waf/pricing/)을 참조하세요.

## 가이드 섹션

* [사전 요구 사항 및 기본 사항](./prerequisites/docs/index.md)
* [AWS 권장 HTTP 아키텍처](./recommended-http-architecture/docs/index.md)
* [운영화](./operationalizing/docs/index.md)
* [AWS 관리형 규칙](./aws-managed-rules/docs/index.md)
* [사용자 정의 규칙](./custom-rules/docs/index.md)
* [봇 관리](./bot-management/docs/index.md)
* [사기 방지](./fraud-prevention/docs/index.md)
* [권장 WAF 규칙 순서](./recommended-waf-rule-order/docs/index.md)
* [CAPTCHA 및 Challenge](./captcha-and-challenge/docs/index.md)
* [WAF 비용](./waf-cost/docs/index.md)
* [로깅 접근 방식](./waf-logging/docs/index.md)
* [WAF 로그 쿼리 및 시각화](./monitoring-waf-rules/docs/index.md)
* [다른 AWS 서비스와 함께 WAF 사용](./using-waf-with-other-services/docs/index.md)
* [추가 참고 자료](./additional-references/docs/index.md)

## 관련 가이드

* [AWS WAF 사용자 가이드](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html)
* [지능형 위협 완화를 위한 모범 사례](https://docs.aws.amazon.com/waf/latest/developerguide/waf-managed-protections-best-practices.html)
* [CAPTCHA 및 Challenge 작업 사용 모범 사례](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-best-practices.html)
* [AWS WAF 고급 비율 기반 규칙의 이점 알아보기](https://aws.amazon.com/blogs/security/discover-the-benefits-of-aws-waf-advanced-rate-based-rules/)
* [AWS WAF에 의해 비율 제한된 IP 주소의 차단 기간을 구성하는 방법](https://aws.amazon.com/blogs/networking-and-content-delivery/configure-block-duration-for-ips-rate-limited-by-aws-waf/)
