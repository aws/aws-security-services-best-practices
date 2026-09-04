# TLS 검사

!!! info "사전 요구 사항"
    이 섹션은 [고객 관리 규칙](../../customer-managed-rules/docs/index.md) 및 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)에 대한 이해를 전제로 합니다. 특히 도메인 필터링 및 스트림 예외 정책 섹션을 먼저 검토하세요.

AWS Network Firewall의 [TLS 검사](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html)는 [AWS Certificate Manager(ACM)](https://docs.aws.amazon.com/acm/latest/userguide/acm-overview.html)에서 관리하는 인증서를 사용하여 TLS 트래픽을 복호화, 검사 및 재암호화하며, 인바운드 검사(서버에 대한 클라이언트 연결 종료)와 아웃바운드 검사(클라이언트에서 외부 서버로의 연결 포워드 프록시) 모두를 지원합니다. 대부분의 Network Firewall 배포에서는 TLS SNI를 통한 도메인 필터링이 이그레스 필터링에 충분한 가시성을 제공하므로 TLS 검사가 필요하지 않습니다. TLS 검사는 암호화된 트래픽의 콘텐츠 수준 검사, 내장 SNI 검증 또는 HTTPS에 대한 URL 수준(도메인 수준이 아닌) 필터링이 필요할 때 올바른 선택입니다.

## TLS 검사 사용 시기

TLS 검사는 비용(고급 검사 요금 체계), 운영 복잡성(인증서 관리, 클라이언트 신뢰 저장소 배포), 그리고 구성 가능한 방화벽 TCP 유휴 타임아웃과 다른 SSL 프록시의 고정 유휴 타임아웃을 추가합니다. 활성화하기 전에 이러한 트레이드오프를 평가하세요.

TLS 검사가 적합한 경우:

* TLS SNI 도메인 이름 외에 암호화된 트래픽의 **콘텐츠**(HTTP 헤더, 전체 URL, 요청 본문)를 검사해야 하는 경우
* TLS SNI 조작에 대한 내장 보호가 필요한 경우(방화벽이 SNI와 서버 인증서의 일치를 자동으로 검증)
* 규정 준수 요구 사항에 따라 암호화된 트래픽 검사가 필수인 경우
* 복호화가 필요한 `aws_url_category`를 사용하여 HTTPS 트래픽에 대한 URL 경로 수준 필터링이 필요한 경우

TLS 검사가 필요하지 않은 경우:

* TLS SNI를 통한 도메인 필터링이 보안 요구 사항에 충분한 경우(가장 일반적인 경우)
* 워크로드가 TLS 가로채기로 중단되는 인증서 피닝을 사용하는 경우
* 다중 엔드포인트 기능을 사용하는 경우(VPC 엔드포인트 연결에서는 TLS 검사가 지원되지 않음)

## 인바운드 TLS 검사

[인바운드 TLS 검사](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html#tls-inspection-inbound)는 VPC 내 서버로 향하는 트래픽을 복호화하고 검사합니다. ACM에서 각 도메인에 대한 서버 인증서를 가져오거나 발급하고, 복호화할 트래픽을 지정하는 범위 구성을 정의하면, Network Firewall이 클라이언트 TLS 연결을 종료하고, 복호화된 트래픽을 검사한 다음 백엔드로 재암호화합니다.

단계별 안내는 블로그 게시물 [암호화된 트래픽 및 AWS Network Firewall을 위한 TLS 검사 구성](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-traffic-and-aws-network-firewall/)을 참조하세요.

!!! warning "인바운드 TLS 검사는 일반적으로 웹 애플리케이션에 적합하지 않습니다"
    공개 웹 애플리케이션의 경우, ALB 오리진 앞에 CloudFront + AWS WAF가 권장 아키텍처입니다. AWS WAF는 보호된 리소스(CloudFront 배포, ALB, API Gateway)에 직접 연결되며, 수동 TLS 인증서 관리나 범위 구성을 구성할 필요 없이 목적에 맞는 레이어 7 웹 애플리케이션 보호를 제공합니다. Network Firewall은 Shield Advanced 비용 보호에 해당하지 않습니다. Network Firewall에서 인바운드 TLS 검사의 주요 사용 사례는 Network Load Balancer(NLB)로 향하는 트래픽에 대해 백엔드에 도달하기 전에 심층 패킷 검사가 필요하고 WAF를 사용할 수 없는 경우입니다.

### 인바운드 범위 구성

!!! tip "모범 사례"
    인바운드 TLS 검사 범위 문을 소스/대상 CIDR 및 포트와 함께 가능한 한 구체적으로 작성하세요. Network Firewall은 범위 구성과 일치하는 비 TLS 트래픽을 차단합니다(예: 범위에 포트 80이 포함된 경우 포트 80의 일반 HTTP가 차단됨). Client Hello에 SNI가 포함되지 않은 경우 또는 SNI가 서버 인증서와 일치하지 않는 경우에도 TLS 트래픽이 차단됩니다.

!!! danger "일반적인 잘못된 구성"
    광범위한 TLS 검사 구성(모든 소스, 모든 대상, 모든 포트)을 사용하면 예상치 못한 차단이 발생합니다. 범위와 일치하는 비 TLS 트래픽은 방화벽이 TLS로 식별할 수 없으므로 차단됩니다. SNI가 없는 TLS 연결도 차단됩니다. 검사하려는 서버의 특정 대상 CIDR 및 포트(일반적으로 443)로 구성 범위를 지정하세요.

### 인바운드 인증서 요구 사항

인바운드 검사의 경우, Network Firewall은 [Mozilla 포함 CA 인증서 목록](https://wiki.mozilla.org/CA/Included_Certificates)에 있는 인증 기관에서 발급한 인증서를 지원합니다. AWS Private CA를 사용하여 Network Firewall의 인바운드 검사용 인증서를 생성할 수도 있지만, 이 경우 클라이언트의 신뢰 저장소에 프라이빗 CA가 있어야 합니다.

백엔드 서버 인증서(ALB 또는 NLB의)도 Mozilla 목록의 공개 CA에서 서명해야 합니다. 백엔드에서 프라이빗 CA 인증서를 사용하면, 클라이언트 측 인증서가 올바르게 작동하더라도 Network Firewall이 TLS 로그에 "Certificate verification failed"와 함께 거부합니다.

## 아웃바운드 TLS 검사

[아웃바운드 TLS 검사](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-configurations.html#tls-inspection-outbound)는 VPC 내 클라이언트에서 외부 서버로의 트래픽을 복호화하고 검사합니다. Network Firewall은 TLS 포워드 프록시로 작동하여, 각 대상 서버에 대해 CA로 서명된 서버 인증서를 동적으로 생성합니다.

단계별 안내는 블로그 게시물 [암호화된 이그레스 트래픽 및 AWS Network Firewall을 위한 TLS 검사 구성](https://aws.amazon.com/blogs/security/tls-inspection-configuration-for-encrypted-egress-traffic-and-aws-network-firewall/)을 참조하세요.

### CA 인증서 요구 사항

인증 기관(CA) 인증서를 ACM에 가져와야 합니다. 이 CA의 개인 키는 SSL 프록시가 서버 인증서를 즉석에서 동적으로 서명하는 데 사용됩니다. CA 인증서는 다음 요구 사항을 충족해야 합니다:

* X509v3 "Basic Constraints" 확장에 `CA:TRUE`가 있고, critical로 표시
* X509v3 "Key Usage" 확장에 `keyCertSign`이 설정되고, critical로 표시

이 요구 사항이 충족되지 않으면 다음 오류가 발생합니다: *"CertificateAuthorityArn is invalid because it references a certificate authority that doesn't comply with RFC 5280 basic constraints."* CA 인증서에 Basic Constraints 및 Key Usage 확장이 필요한 값과 함께 포함되어 있는지 확인하세요.

!!! danger "일반적인 잘못된 구성"
    아웃바운드 TLS 검사에 공개 CA(DigiCert, GoDaddy 등)를 사용할 수 없습니다. SSL 프록시가 인증서를 동적으로 서명하려면 CA 개인 키가 필요합니다. 공개 CA는 CA 개인 키를 절대 제공하지 않습니다. 자체 프라이빗 CA(OpenSSL, Microsoft AD CS, AWS Private CA 등)를 생성하고, CA 인증서와 개인 키를 ACM에 가져온 다음, 클라이언트 신뢰 저장소에 CA 인증서를 배포해야 합니다.

### 클라이언트에 CA 인증서 설치

클라이언트가 동적으로 생성된 인증서를 신뢰하려면, 신뢰할 수 있는 루트 인증서 저장소에 CA 인증서를 추가해야 합니다:

* **Amazon Linux** - `/etc/pki/ca-trust/source/anchors/`에 복사하고 `update-ca-trust` 실행
* **Ubuntu** - `/usr/local/share/ca-certificates/`에 복사하고 `update-ca-certificates` 실행
* **Windows** - 신뢰할 수 있는 루트 인증 기관 저장소에 가져오기

### 인증서 폐기 확인

아웃바운드 TLS 검사에서 인증서 폐기 확인을 활성화할 수 있습니다. Network Firewall은 클라이언트를 대신하여 OCSP 및 CRL을 사용하여 서버 인증서의 폐기 상태를 확인합니다. 폐기되거나 만료된 인증서는 거부되고 TLS 로그에 기록됩니다.

## SNI 조작 보호

TLS 검사가 활성화되면(어느 방향이든), Network Firewall은 Client Hello의 SNI가 서버가 제시하는 인증서와 일치하는지 자동으로 검증합니다. 불일치는 차단되고 TLS 오류 로그 항목을 생성합니다. 이는 규칙 구성 없이 클라이언트 측 SNI 스푸핑에 대한 내장 보호를 제공합니다.

## TLS 검사를 사용한 규칙 작성

복호화 후, 트래픽은 평문 HTTP(또는 HTTP/2)로 스테이트풀 엔진에 도착합니다. 규칙 작성 시 주요 고려 사항:

* `tls.sni` 키워드 규칙은 SSL 프록시가 Client Hello에서 SNI를 캡처하여 Suricata에 메타데이터로 전달하므로, 범위 내 트래픽에 대해 여전히 작동합니다
* HTTP/1.1과 HTTP/2는 별도의 규칙이 필요합니다. Suricata의 HTTP/2 오버로딩 기능은 Network Firewall에서 [명시적으로 지원되지 않습니다](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-limitations-caveats.html)
* TLS 검사가 활성화된 상태에서 기본 차단 규칙을 작성할 때, `app-layer-protocol:!http2` 또는 별도의 `drop http2` 규칙을 사용하여 HTTP/2 트래픽을 고려하세요

## TLS 검사 유휴 타임아웃

SSL 프록시에는 구성 가능한 방화벽 TCP 유휴 타임아웃과 독립적인 고정 유휴 타임아웃이 있습니다:

* 새 연결(완전히 설정되지 않은 연결)의 경우 약 5초
* 유휴 상태가 된 설정된 연결의 경우 약 120초

이러한 값은 조정할 수 없습니다. 프록시-서버 연결에서 백엔드 작업이 120초 이상의 유휴 시간을 소요하는 경우(예: 장시간 실행되는 데이터베이스 쿼리), 클라이언트 측 연결이 TCP 킵얼라이브로 활성 상태를 유지하더라도 프록시가 서버 측 연결을 닫을 수 있습니다. 클라이언트 킵얼라이브는 프록시-서버 구간으로 전달되지 않습니다.

## 세션 홀딩

[세션 홀딩](https://docs.aws.amazon.com/network-firewall/latest/developerguide/session-holding-tls.html)은 아웃바운드 TLS 검사 중 TCP 설정 패킷이 대상 서버에 도달하는 시점을 제어합니다. 활성화되면, 방화벽은 Client Hello에서 SNI를 추출할 때까지 클라이언트 측 패킷을 보류한 다음, 다운스트림 연결을 시작하기 전에 TLS.SNI 기반 규칙을 평가합니다.

세션 홀딩 없이는 방화벽이 SNI를 사용할 수 있기 전에 대상 서버와 전체 TCP 연결을 즉시 설정합니다. 거부 규칙이 최종적으로 연결을 차단하더라도, 대상 서버는 이미 TCP SYN을 수신하고 핸드셰이크를 완료했습니다. 세션 홀딩이 활성화되면, SNI가 거부 규칙과 일치하는 경우 연결이 방화벽에서 차단되고 대상으로 패킷이 전송되지 않습니다.

세션 홀딩은 "Application drop established (bidirectional)" 및 "Application drop established (server-directed only)" 기본 작업과 호환되지 않습니다. "Application drop established (server-directed only)"가 [이 가이드가 권장하는 기본 작업](../../firewall-policy-configuration/docs/index.md#default-actions)이므로, 세션 홀딩을 활성화하면 이를 변경해야 합니다. 대신 "Drop all" 또는 [사용자 정의 기본 차단 규칙](../../sample-suricata-rules/docs/index.md#custom-default-block-rules)을 사용하고, "Drop all"의 경우 TCP 핸드셰이크를 위한 명시적 pass 규칙이 필요하다는 점에 유의하세요.

## 주요 고려 사항

* TLS 버전 1.1, 1.2, 1.3이 지원됩니다
* Network Firewall은 특정 클라이언트 암호 모음 목록만 지원합니다
* 다중 엔드포인트(VPC 엔드포인트 연결) 기능을 사용하는 방화벽에서는 TLS 검사가 **지원되지 않습니다**
* TLS 검사에는 자체 요금 체계가 있습니다(고급 검사 엔드포인트 + 트래픽 처리). [비용 고려 사항](../../cost-considerations/docs/index.md) 및 [Network Firewall 요금](https://aws.amazon.com/network-firewall/pricing/)을 참조하세요
* TLS 검사 범위 내 트래픽은 방화벽 로그 이벤트에 `"tls_inspected": true`가 표시됩니다

전체 고려 사항 및 제한 사항 목록은 [TLS 검사 고려 사항](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-considerations.html) 및 [인증서 요구 사항](https://docs.aws.amazon.com/network-firewall/latest/developerguide/tls-inspection-certificate-requirements.html)을 참조하세요.

## 다음 읽을 내용

* [고객 관리 규칙](../../customer-managed-rules/docs/index.md) - TLS 복호화 없이 작동하는 도메인 필터링 접근 방식
* [로깅 및 모니터링](../../logging-and-monitoring/docs/index.md) - TLS 검사 로깅 및 오류 분석
* [비용 고려 사항](../../cost-considerations/docs/index.md) - TLS 검사 요금 영향
