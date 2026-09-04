# 샘플 Suricata 규칙

!!! info "사전 요구 사항"
    이 섹션은 [고객 관리 규칙](../../customer-managed-rules/docs/index.md)에 대한 이해를 전제로 합니다. `flow:to_server`, 규칙 유형, 도메인 필터링 패턴과 같은 기본 개념을 먼저 검토하세요.

AWS Network Firewall은 상태 저장 검사에 Suricata 규칙 구문을 사용하며, 이 페이지는 도메인 카테고리 차단, 직접 IP 연결 차단, GeoIP 필터링, 포트/프로토콜 적용, 도메인 허용 목록을 포함한 가장 일반적인 필터링 시나리오를 다루는 사용 사례별 개별 규칙 예제를 제공합니다. 각 규칙은 무엇을 하는지, 왜 필요한지, 언제 사용하거나 건너뛸지를 포함합니다.

Network Firewall을 처음 시작하고 이러한 모범 사례를 구현하는 완전한 배포 준비 정책이 필요하다면 [시작 정책](../../getting-started-policy/docs/index.md) 페이지를 참조하세요. 15개의 관리형 규칙 그룹과 권장 정책 설정이 포함된 배포 가능한 CloudFormation 및 Terraform 템플릿이 포함되어 있습니다.

이 페이지는 가장 널리 사용되는 차단 규칙을 먼저 배치하고, 그다음 가시성을 위한 알림 규칙, 허용 목록 패턴, 마지막으로 하단에 사용자 정의 기본 차단 규칙과 같은 고급 옵션 순으로 구성되어 있습니다.

## 이 페이지 사용 방법

아래 규칙을 탐색하고 환경에 적용되는 규칙을 식별하세요. 대부분의 고객은 도메인 카테고리 차단, 직접 IP 연결 차단, 포트/프로토콜 적용 규칙을 시작점으로 원할 것입니다. 필요한 규칙을 복사하고, `msg:` 필드와 SID를 명명 규칙에 맞게 조정한 다음, 적용 전에 검증하기 위해 먼저 alert 전용 모드(`reject`/`drop`을 `alert`로 변경)로 배포하세요.

이 페이지 하단의 [전체 규칙 템플릿](#전체-규칙-템플릿)은 이러한 규칙이 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)에서 권장하는 "Application drop established (server-directed only)" 기본 작업을 사용하여 단일 규칙셋에 어떻게 맞는지 보여줍니다.

!!! note "이 샘플의 flow:to_server에 대해"
    이 페이지의 모든 규칙은 일관성을 위해 애플리케이션 계층 규칙을 포함하여 `flow:to_server`를 포함합니다. `tcp`, `udp` 또는 `ip` 프로토콜 규칙에서 이 키워드는 실제 작업을 합니다: Suricata가 규칙을 IP 전용으로 처리하고 플로우의 첫 번째 패킷에서 작동하는 것을 방지합니다. 프로토콜 필드가 애플리케이션 계층 프로토콜(`tls`, `http`, `ssh`)이거나 애플리케이션 계층 버퍼(`tls.sni`, `http.host`)를 매칭하는 규칙에서는 무해하지만 필수는 아닙니다. [어떤 규칙에 flow: 키워드가 필요한가](../../customer-managed-rules/docs/index.md#어떤-규칙에-flow-키워드가-필요한가)를 참조하세요.

---

## 차단 규칙

이 규칙들은 트래픽을 적극적으로 차단하거나 거부합니다. 고객이 Network Firewall에서 배포하는 가장 일반적이고 유용한 사용자 정의 규칙입니다.

### 도메인 카테고리 차단

이 기능에 대한 공식 문서는 [URL 및 도메인 필터링](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-url-filtering.html)을 참조하세요.

```
reject tls $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_domain_category:Command and Control; ja4.hash; content:"_"; flow:to_server; sid:202602061;)
reject tls $HOME_NET any -> any any (msg:"Category:Malicious"; aws_domain_category:Malicious; ja4.hash; content:"_"; flow:to_server; sid:202602063;)
reject tls $HOME_NET any -> any any (msg:"Category:Malware"; aws_domain_category:Malware; ja4.hash; content:"_"; flow:to_server; sid:202602064;)
reject tls $HOME_NET any -> any any (msg:"Category:Phishing"; aws_domain_category:Phishing; ja4.hash; content:"_"; flow:to_server; sid:202602065;)
reject tls $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_domain_category:Proxy Avoidance; ja4.hash; content:"_"; flow:to_server; sid:202602066;)
reject tls $HOME_NET any -> any any (msg:"Category:Spam"; aws_domain_category:Spam; ja4.hash; content:"_"; flow:to_server; sid:202602067;)
reject http $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_url_category:Command and Control; flow:to_server; sid:202602068;)
reject http $HOME_NET any -> any any (msg:"Category:Malicious"; aws_url_category:Malicious; flow:to_server; sid:2026020610;)
reject http $HOME_NET any -> any any (msg:"Category:Malware"; aws_url_category:Malware; flow:to_server; sid:2026020611;)
reject http $HOME_NET any -> any any (msg:"Category:Phishing"; aws_url_category:Phishing; flow:to_server; sid:2026020612;)
reject http $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_url_category:Proxy Avoidance; flow:to_server; sid:2026020613;)
reject http $HOME_NET any -> any any (msg:"Category:Spam"; aws_url_category:Spam; flow:to_server; sid:2026020614;)
```

**하는 일:** AWS가 명령 및 제어, 악성, 맬웨어, 피싱, 프록시 우회 또는 스팸으로 분류한 도메인에 대한 트래픽을 차단합니다. TLS 트래픽(SNI 필드 검사)에는 `aws_domain_category`를, HTTP 트래픽(호스트 헤더 및 URL 경로 검사)에는 `aws_url_category`를 사용합니다.

**필요한 이유:** AWS가 카테고리 데이터베이스를 자동으로 유지 관리하고 업데이트합니다. 이러한 카테고리는 대부분의 환경에서 합법적인 비즈니스 용도가 없는 도메인을 나타냅니다. 자체 위협 인텔리전스 피드를 유지하지 않고도 광범위한 보호를 제공합니다.

**건너뛸 시기:** 거의 없습니다. 환경에서 잘못 분류될 수 있는 합법적인 VPN 또는 프록시 서비스를 사용하는 경우 "Proxy Avoidance" 카테고리에 대해 `reject` 대신 `alert`로 시작할 수 있습니다.

### 직접 IP 연결 통신 차단

```
reject http $HOME_NET any -> any any (http.host; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"HTTP direct to IP via http host header"; flow:to_server; sid:202501026;)
reject tls $HOME_NET any -> any any (tls.sni; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"TLS direct to IP via TLS SNI"; flow:to_server; sid:202501027;)
reject tls $HOME_NET any -> any any (ja4.hash; content:"_"; startswith; content:!"d"; offset:3; depth:1; msg:"JA4 No SNI Reject"; flow:to_server; sid:1297713;)
```

**하는 일:** 대상이 도메인 이름이 아닌 IP 주소로 지정된 HTTP 및 TLS 연결을 차단합니다. 세 번째 규칙은 SNI 필드가 전혀 없는 TLS 연결(JA4 핑거프린트 특성을 통해 감지)을 차단합니다.

**필요한 이유:** 합법적인 애플리케이션 트래픽은 거의 항상 도메인 이름을 사용합니다. 직접 IP 연결은 명령 및 제어 통신, 데이터 유출 도구, 잘못 구성된 애플리케이션의 일반적인 지표입니다. 이러한 연결을 차단하면 트래픽이 DNS 확인(DNS Firewall도 검사할 수 있는)과 도메인 허용 목록을 통과하도록 강제합니다.

**건너뛸 시기:** 워크로드가 합법적으로 IP 주소에 직접 연결하는 경우(일부 레거시 프로토콜, IP 엔드포인트에 대한 헬스 체크, IP 기반 풀에 대한 NTP). 해당 IP에 대한 특정 pass 규칙을 이 reject 규칙 위에 추가하세요.

### GeoIP 차단

```
drop ip $HOME_NET any -> any any (msg:"Egress traffic to blocked geo"; geoip:dst,XX; metadata:geo XX; flow:to_server; sid:202501028;)
drop ip any any -> $HOME_NET any (msg:"Ingress traffic from blocked geo"; geoip:src,XX; metadata:geo XX; flow:to_server; sid:202501029;)
```

**하는 일:** 지정된 국가 코드에 지리적으로 위치한 IP 주소로 향하는(또는 발신되는) 모든 트래픽을 차단합니다. `XX`를 정책에 해당하는 [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) 국가 코드로 교체하세요.

**필요한 이유:** 워크로드가 특정 지역의 IP 주소와 통신할 합법적인 비즈니스 이유가 없는 경우, IP 수준에서 차단하면 광범위한 안전망을 제공합니다. GeoIP 차단은 도메인 기반 필터링을 우회할 수 있는 트래픽(직접 IP 연결, 비 HTTP/TLS 프로토콜)을 포착합니다.

`!`(NOT) 연산자를 사용하여 로직을 반전시키고 특정 국가로의 트래픽만 허용할 수도 있습니다:

```
drop ip $HOME_NET any -> any any (msg:"Egress to non-approved geo"; geoip:dst,!US,!CA; flow:to_server; sid:202501030;)
```

이것은 미국과 캐나다를 제외한 모든 국가로의 이그레스 트래픽을 차단합니다.

**건너뛸 시기:** 워크로드가 많은 국가에 접속 지점이 있는 글로벌 CDN 인프라 또는 클라우드 프로바이더를 사용하는 서비스와 통신하는 경우. GeoIP 데이터베이스는 100% 정확하지 않으므로 오탐이 가능합니다. 검증을 위해 처음에는 `drop` 대신 `alert`를 사용하세요.

### QUIC 트래픽 차단

```
drop quic $HOME_NET any -> any any (msg:"QUIC traffic blocked"; flow:to_server; sid:3898932;)
```

**하는 일:** 모든 아웃바운드 QUIC(HTTP/3) 트래픽을 차단합니다.

**필요한 이유:** QUIC은 UDP 포트 443에서 실행되며 거의 모든 연결 메타데이터를 암호화하여 검사가 어렵습니다. 대부분의 브라우저와 애플리케이션은 QUIC을 사용할 수 없을 때 Network Firewall이 정상적으로 검사할 수 있는 TCP를 통한 TLS로 폴백합니다. QUIC을 차단하면 트래픽이 검사 가능한 채널을 통과하도록 강제합니다.

**건너뛸 시기:** 워크로드가 성능을 위해 특별히 QUIC이 필요하고(비디오 스트리밍, 실시간 통신) 해당 플로우에 대한 다른 제어가 있는 경우. 광범위하게 QUIC을 차단하고 필요한 워크로드에 대한 특정 pass 규칙을 추가하는 것을 고려하세요.

### 고위험 TLD 차단

```
reject tls $HOME_NET any -> any any (tls.sni; content:".xyz"; nocase; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501040;)
reject http $HOME_NET any -> any any (http.host; content:".xyz"; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501041;)
reject tls $HOME_NET any -> any any (tls.sni; content:".top"; nocase; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501044;)
reject http $HOME_NET any -> any any (http.host; content:".top"; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501045;)
reject tls $HOME_NET any -> any any (tls.sni; content:".buzz"; nocase; endswith; msg:"High risk TLD .buzz blocked"; flow:to_server; sid:202501046;)
reject http $HOME_NET any -> any any (http.host; content:".buzz"; endswith; msg:"High risk TLD .buzz blocked"; flow:to_server; sid:202501047;)
```

**하는 일:** 원치 않는 활동과 불균형적으로 높은 연관률을 가진 일반 TLD(.xyz, .top, .buzz)로 끝나는 도메인에 대한 트래픽을 차단합니다.

**필요한 이유:** 이러한 TLD는 합법적인 엔터프라이즈 소프트웨어 종속성에서 거의 사용되지 않습니다. 이를 차단하면 도메인 허용 목록 및 카테고리 필터링과 함께 낮은 오탐률의 안전망을 제공합니다.

**건너뛸 시기:** 워크로드가 이러한 TLD의 서비스와 합법적으로 통신하는 경우. 일부 합법적인 서비스가 새로운 일반 TLD를 사용합니다. 먼저 alert 전용 모드로 검증하세요.

### 포트/프로토콜 적용

```
reject tcp $HOME_NET any -> any 443 (msg:"Egress Port TCP/443 but not TLS"; app-layer-protocol:!tls; flow:to_server; sid:202501030;)
reject tls $HOME_NET any -> any !443 (msg:"Egress TLS but not port TCP/443"; flow:to_server; sid:202501031;)
reject tcp $HOME_NET any -> any 80 (msg:"Egress Port TCP/80 but not HTTP"; app-layer-protocol:!http; flow:to_server; sid:202501032;)
reject http $HOME_NET any -> any !80 (msg:"Egress HTTP but not port TCP/80"; flow:to_server; sid:202501033;)
reject tcp $HOME_NET any -> any 22 (msg:"Egress Port TCP/22 but not SSH"; app-layer-protocol:!ssh; flow:to_server; sid:202501060;)
reject ssh $HOME_NET any -> any !22 (msg:"Egress SSH but not port TCP/22"; flow:to_server; sid:202501061;)
```

**하는 일:** 프로토콜이 예상 포트에서만 실행되도록 적용합니다. TLS는 포트 443을 사용하고 포트 443은 TLS를 전달해야 합니다. HTTP는 포트 80을 사용하고 포트 80은 HTTP를 전달해야 합니다. SSH는 포트 22를 사용하고 포트 22는 SSH를 전달해야 합니다.

**필요한 이유:** 프로토콜/포트 불일치는 일반적인 회피 기법입니다. 포트 443에서 비 TLS 프로토콜을 실행하면 포트 443이 암호화된 웹 트래픽이라고 가정하는 보안 제어를 우회할 수 있습니다. 이 규칙은 프로토콜 터널링, 잘못 구성된 애플리케이션, 비표준 프로토콜을 사용하여 표준 포트를 통해 데이터를 유출하려는 시도를 포착합니다.

**건너뛸 시기:** 환경에 비표준 포트/프로토콜 조합을 사용하는 합법적인 애플리케이션이 있는 경우(포트 8443의 TLS, 포트 8080의 HTTP). 해당 조합에 대한 특정 pass 규칙을 이 적용 규칙 위에 추가하세요.

---

## 알림 규칙

이 규칙은 트래픽을 차단하지 않고 가시성 및 조사를 위한 로그 항목을 생성합니다. 예상치 못한 통신 패턴을 발견하고, 잘못된 구성을 식별하며, 향후 차단 결정을 위한 컨텍스트를 구축하는 데 사용하세요.

### 고위험 대상 포트에 대한 알림

```
alert ip $HOME_NET any -> any 53 (msg:"Possible DNS Firewall bypass - direct DNS to external resolver"; flow:to_server; sid:202501055;)
alert ip $HOME_NET any -> any 1389 (msg:"Possible Log4j callback"; flow:to_server; sid:202501059;)
alert ip $HOME_NET any -> any [4444,666,3389] (msg:"Egress traffic to high risk port"; flow:to_server; sid:202501058;)
```

**하는 일:** 관련 활동과 일반적으로 연관된 포트로 트래픽이 향할 때 알림을 생성하지만 차단하지는 않습니다: 포트 53(외부 리졸버에 대한 직접 DNS, DNS Firewall 우회), 포트 1389(Log4j 스타일 익스플로잇에 사용되는 LDAP 콜백), 포트 4444/666/3389(일반적인 리버스 셸, 백도어, 원격 데스크톱 포트).

**필요한 이유:** 이 알림은 조사가 필요한 트래픽을 표면화합니다. 외부 리졸버에 대한 포트 53 이그레스는 워크로드가 VPC Resolver(및 DNS Firewall)를 우회하고 있음을 나타내므로 특히 중요합니다. 서버 워크로드에서의 포트 3389(RDP) 이그레스는 거의 합법적이지 않습니다.

**건너뛸 시기:** 환경에서 이러한 포트가 합법적인 트래픽을 전달하지 않아야 한다고 확신하는 경우 `reject` 또는 `drop`으로 변환하세요. 적용 전에 가시성이 필요한 경우 `alert`로 유지하세요.

### AWS 서비스 트래픽에 대한 알림(PrivateLink 후보 식별)

```
alert tls $HOME_NET any -> any any (alert; tls.sni; dotprefix; content:".amazonaws.com"; nocase; endswith; msg:"AWS traffic over NFW - consider VPC endpoint"; flow:to_server; sid:202501070;)
```

**하는 일:** 방화벽을 통해 흐르는 `*.amazonaws.com` 도메인에 대한 모든 TLS 트래픽에 대해 알림을 생성합니다.

**필요한 이유:** Network Firewall을 통과하는 AWS 서비스 엔드포인트(S3, DynamoDB, STS 등)에 대한 트래픽은 일반적으로 VPC 엔드포인트(PrivateLink)를 통해 이동해야 합니다. VPC 엔드포인트는 트래픽을 AWS 네트워크에 유지하고, Network Firewall 데이터 처리 비용을 줄이며, 세분화된 액세스 제어를 위한 VPC 엔드포인트 정책을 활성화합니다. 이 알림 규칙은 방화벽을 통해 워크로드가 접근하는 AWS 서비스를 식별하여 VPC 엔드포인트 설정의 우선순위를 정하는 데 도움이 됩니다.

**건너뛸 시기:** 워크로드가 사용하는 모든 AWS 서비스에 대해 VPC 엔드포인트를 이미 구성한 경우, 이 규칙은 알림을 생성하지 않아야 합니다. 엔드포인트 없이 접근되는 새 서비스를 포착하기 위한 안전망으로 유지할 수 있습니다.

### 의심스러운 TLD에 대한 알림

```
alert tls $HOME_NET any -> any any (tls.sni; pcre:"/^(?!.*\.(com|org|net|io|edu|aws)$).*/i"; msg:"Request to possible suspicious TLD"; flow:to_server; sid:202501065;)
alert http $HOME_NET any -> any any (http.host; pcre:"/^(?!.*\.(com|org|net|io|edu|aws)$).*/i"; msg:"Request to possible suspicious TLD"; flow:to_server; sid:202501066;)
```

**하는 일:** .com, .org, .net, .io, .edu, .aws로 끝나지 않는 모든 도메인에 대한 트래픽에 대해 알림을 생성합니다. 이것은 차단 규칙이 아닌 가시성 규칙입니다.

**필요한 이유:** 대부분의 합법적인 엔터프라이즈 트래픽은 잘 알려진 소수의 TLD로 이동합니다. 비정상적인 TLD로의 트래픽은 차단하지 않더라도 조사할 가치가 있습니다. 이 알림은 예상치 못한 통신 패턴을 발견하고 허용 목록을 구축하는 데 도움이 됩니다.

**건너뛸 시기:** 환경이 많은 다양한 TLD와 합법적으로 통신하는 경우(국제 운영, 국가 TLD의 CDN 프로바이더), 이 규칙은 과도한 알림을 생성합니다. 합법적인 TLD를 포함하도록 PCRE의 제외 목록을 확장하세요.

### $HOME_NET 잘못된 구성 탐지

```
alert ip $HOME_NET any -> any any (noalert; flowbits:set,egress_from_home_net; flow:to_server; sid:8925324;)
alert ip any any -> $HOME_NET any (noalert; flowbits:set,ingress_to_home_net; flow:to_server; sid:8923323;)
alert ip any any -> any any (msg:"$HOME_NET may not be set right! Set it at the firewall policy level."; flowbits:isnotset,ingress_to_home_net; flowbits:isnotset,egress_from_home_net; flowbits:isnotset,home_net_alerted; flowbits:set,home_net_alerted; flow:to_server; sid:8923283;)
```

**하는 일:** 소스와 대상 모두 `$HOME_NET`과 일치하지 않는 방화벽을 통해 흐르는 트래픽을 탐지합니다. 이 규칙이 작동하면 `$HOME_NET` 변수가 방화벽을 통해 트래픽을 라우팅하는 모든 VPC의 CIDR 범위를 포함하지 않는다는 의미입니다.

**필요한 이유:** 잘못 구성된 `$HOME_NET`은 규칙이 예상대로 매칭하지 않는 가장 일반적인 이유 중 하나입니다. 이 탐지 규칙은 보안 격차가 발생하기 전에 문제를 알려줍니다. `home_net_alerted` flowbit는 규칙을 패킷당 하나가 아닌 플로우당 단일 알림으로 제한하여 규칙이 광범위하게 작동하기 시작할 경우 로그 볼륨을 관리 가능하게 유지합니다.

**건너뛸 시기:** 절대로. 이것은 항상 존재해야 하는 안전망 규칙입니다. 이 탐지의 표준 버전이며 [시작 정책](../../getting-started-policy/docs/index.md) 템플릿이 배포하는 것입니다.

---

## 허용 규칙 및 도메인 허용 목록

이 규칙은 명시적으로 트래픽을 허용합니다. 기본 거부 태세에서 도메인 허용 목록은 워크로드가 필요한 인터넷 대상에 도달하도록 허용하는 것입니다.

### 정확한 FQDN 허용

```
pass tls $HOME_NET any -> any any (tls.sni; content:"api.example.com"; startswith; nocase; endswith; flow:to_server; sid:100001;)
pass http $HOME_NET any -> any any (http.host; content:"api.example.com"; startswith; endswith; flow:to_server; sid:100002;)
```

**하는 일:** 기록 없이 정확히 `api.example.com`에 대한 트래픽을 허용합니다. `startswith` + `endswith` 조합은 서브도메인이나 경로 조작이 매칭되지 않도록 합니다.

### 기록과 함께 정확한 FQDN 허용

```
pass tls $HOME_NET any -> any any (alert; tls.sni; content:"api.example.com"; startswith; nocase; endswith; msg:"Allowed api.example.com"; flow:to_server; sid:100003;)
```

**하는 일:** 로그 항목을 생성하면서 `api.example.com`에 대한 트래픽을 허용합니다. pass 규칙의 `alert;` 키워드는 트래픽을 허용하면서 기록하도록 합니다.

**필요한 이유:** 허용된 트래픽을 기록하면 차단되는 것뿐만 아니라 방화벽을 통해 실제로 통신하는 것에 대한 가시성을 얻을 수 있습니다. 이는 용량 계획, 비용 분석 및 보안 모니터링에 필수적입니다.

### 2차 레벨 도메인 및 모든 서브도메인 허용

```
pass tls $HOME_NET any -> any any (tls.sni; dotprefix; content:".example.com"; nocase; endswith; flow:to_server; sid:100004;)
```

**하는 일:** `dotprefix` 키워드를 사용하여 `example.com` 및 모든 서브도메인(*.example.com)에 대한 트래픽을 허용합니다. `dotprefix` 키워드는 콘텐츠 매치에 자동으로 점을 추가하므로 `.example.com`은 `example.com` 자체와 `sub.example.com` 모두를 매칭합니다.

**필요한 이유:** 전체 도메인과 모든 서브도메인을 신뢰하는 경우(AWS 서비스, 자체 조직의 도메인), 와일드카드 매치는 유지해야 하는 규칙 수를 줄입니다.

**건너뛸 시기:** 완전히 제어하지 않는 도메인에 대한 와일드카드 도메인 규칙에 주의하세요. `*.github.com`과 같은 광범위한 규칙은 GitHub에서 호스팅하는 모든 콘텐츠에 대한 트래픽을 허용하며, 이는 의도와 일치하지 않을 수 있습니다.

### 단일 규칙에서 여러 도메인 허용(PCRE)

```
pass tls $HOME_NET any -> any any (tls.sni; pcre:"/(^|\.)(example\.com|example\.net|contoso\.com)$/i"; flow:to_server; sid:100010;)
pass http $HOME_NET any -> any any (http.host; pcre:"/(^|\.)(example\.com|example\.net|contoso\.com)$/i"; flow:to_server; sid:100011;)
```

**하는 일:** 나열된 2차 레벨 도메인 및 해당 서브도메인에 대한 트래픽을 하나의 규칙으로 허용합니다. `(^|\.)` 접두사는 매치를 `dotprefix`처럼 동작하게 하므로 `example.com`과 `api.example.com` 모두를 매칭하지만 `notexample.com`은 매칭하지 않습니다. 후행 `$`는 SNI 또는 호스트 헤더의 끝에 매치를 고정하여 `example.com.attacker.net`과 같은 도메인이 매칭되지 않도록 합니다. `/i` 플래그는 대소문자를 구분하지 않습니다.

**필요한 이유:** 용량. 규칙 그룹의 용량은 생성 시 고정되며 각 Suricata 규칙은 복잡성에 관계없이 정확히 1 용량 단위를 소비하므로, 200개 도메인을 다루는 하나의 PCRE 규칙은 200이 아닌 1 용량 단위를 소비합니다. 이것은 20개 상태 저장 규칙 그룹 제한에서 슬롯을 소비하는 여러 규칙 그룹에 대규모 도메인 허용 목록을 분할하는 것에 대한 권장 대안입니다. [용량 이해 및 계산](../../customer-managed-rules/docs/index.md#용량-이해-및-계산)을 참조하세요.

**알아야 할 트레이드오프:**

* 각 도메인의 점을 이스케이프하세요(`example\.com`, `example.com`이 아님). 이스케이프되지 않은 점은 모든 문자를 매칭합니다.
* PCRE 평가는 `content` 매칭보다 비용이 높으므로, 전체 허용 목록을 하나의 거대한 표현식에 넣는 대신 단일 규칙의 대체 수를 합리적으로 유지하세요.
* 규칙의 모든 도메인이 하나의 SID와 하나의 `msg:`를 공유하므로, 알림 로그와 규칙 히트 카운트는 규칙이 매칭했음을 알려주지만 어떤 도메인이 매칭했는지는 알려주지 않습니다. 로그 이벤트의 `tls.sni` 또는 `http.hostname` 필드를 확인하세요. 함께 속하는 도메인(하나의 애플리케이션, 하나의 벤더)을 그룹화하여 `msg:`가 의미 있게 유지되도록 하세요.
* Suricata 규칙의 최대 길이는 8,192자이며, 이는 하나의 규칙이 보유할 수 있는 도메인 수를 제한합니다.

**건너뛸 시기:** 허용 목록이 개별 `content` 규칙에 편하게 맞을 정도로 작은 경우, 대신 그것을 사용하세요. 도메인당 하나의 규칙이 읽기 쉽고, 풀 리퀘스트에서 검토하기 쉬우며, 도메인당 히트 카운트를 제공합니다.

### 저위험 프로토콜 조용히 허용

```
pass ntp $HOME_NET any -> any 123 (flow:to_server; sid:202501034;)
pass icmp $HOME_NET any -> any any (flow:to_server; sid:202501035;)
```

**하는 일:** 로그 이벤트를 생성하지 않고 NTP(시간 동기화) 및 ICMP(ping, traceroute) 트래픽을 조용히 허용합니다.

**필요한 이유:** NTP 및 ICMP는 보안 가치 없이 로그에 노이즈를 생성하는 대용량, 저위험 프로토콜입니다. 조용히 허용하면 다른 모든 것에 대한 기본 거부 태세를 유지하면서 로그 볼륨과 비용을 줄입니다.

**건너뛸 시기:** NTP를 특정 서버(169.254.169.123의 Amazon Time Sync Service)로 제한하려면 광범위한 pass를 대상 규칙으로 교체하세요. 규정 준수 이유로 ICMP를 완전히 차단하려면 ICMP pass 규칙을 제거하세요.

### 대칭 라우팅 확인(진단)

```
alert tcp any any -> any any (msg:"Routing is symmetric. You can safely remove this test rule."; flow:established; sid:123456;)
```

**하는 일:** `established` 상태에 도달하는 모든 TCP 플로우에 대해 알림을 생성하여, Suricata가 TCP 핸드셰이크의 양방향을 모두 보았음을 확인합니다.

**필요한 이유:** 라우팅 구성이 대칭인지 검증하기 위한 임시 진단 규칙입니다. Network Firewall을 배포하거나 라우팅을 변경한 후, 이 규칙을 추가하고 방화벽 뒤에서 HTTPS 엔드포인트에 curl하세요. `app_proto: "tls"`가 포함된 알림 로그 이벤트가 보이면, 스테이트풀 엔진이 핸드셰이크의 양방향을 모두 보았음을 확인합니다. 확인 후 제거하세요.

---

## 사용자 정의 기본 차단 규칙

이 섹션은 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)에서 설명한 정책 수준 기본 작업의 대안 접근 방식을 다룹니다. 대부분의 배포에서는 정책 수준 기본 작업으로 "Application drop established (server-directed only)"를 사용하는 것을 권장합니다. 아래의 사용자 정의 기본 차단 규칙은 차단된 트래픽의 기록 및 처리 방식에 대한 추가 제어가 필요한 고객을 위한 것입니다.

### 정책 기본 작업 대신 사용자 정의 기본 차단 규칙을 사용할 시기

사용자 정의 기본 차단 규칙은 기본 제공 기본 작업이 제공하지 않는 이점을 제공합니다:

* TLS 트래픽이 차단될 때 JA4 해시 기록
* 로그 메시지에서 이그레스 트래픽과 인그레스 트래픽 구분
* 이그레스 트래픽에 TCP RST(reject)를 보내면서 인그레스 트래픽은 조용히 차단(TCP RST 없음)
* 프로토콜별(TLS, HTTP, TCP, UDP, ICMP) 별도 로그 항목

이러한 기능이 필요하지 않으면, 정책 수준 "Application drop established (server-directed only)" 기본 작업을 사용하고 이 섹션을 완전히 건너뛰세요.

### 사용자 정의 기본 차단 규칙 구현 방법

사용자 정의 기본 차단 규칙을 사용하는 경우, 정책 수준 기본 drop 작업도 선택하지 마세요. 동일한 목적을 수행하며 둘 다 사용하면 중복 로그 항목이 생성됩니다.

### 이그레스 기본 차단 규칙

```
reject tls $HOME_NET any -> any any (msg:"Default Egress HTTPS Reject"; ssl_state:client_hello; ja4.hash; content:"_"; flowbits:set,blocked; flow:to_server; sid:999991;)
alert tls $HOME_NET any -> any any (msg:"PQC"; flowbits:isnotset,blocked; flowbits:set,PQC; noalert; flow:to_server; sid:999993;)
reject http $HOME_NET any -> any any (msg:"Default Egress HTTP Reject"; flowbits:set,blocked; flow:to_server; sid:999992;)
reject tcp $HOME_NET any -> any any (msg:"Default Egress TCP Reject"; flowbits:isnotset,blocked; flowbits:isnotset,PQC; flow:to_server, established; sid:999994;)
drop udp $HOME_NET any -> any any (msg:"Default Egress UDP Drop"; flow:to_server; sid:999995;)
drop icmp $HOME_NET any -> any any (msg:"Default Egress ICMP Drop"; flow:to_server; sid:999996;)
drop ip $HOME_NET any -> any any (msg:"Default Egress All Other IP Drop"; ip_proto:!TCP; ip_proto:!UDP; ip_proto:!ICMP; flow:to_server; sid:999997;)
```

**flowbits 로직 작동 방식:** `ssl_state:client_hello`와 `ja4.hash` 조합은 Client Hello가 수신된 후에만 TLS reject가 작동하도록 합니다. `PQC` flowbit는 Client Hello를 여러 패킷에 걸쳐 분할하는 포스트 양자 TLS 구현을 처리합니다. Client Hello가 아직 완료되지 않은 경우(PQC 분할), 플로우가 PQC로 표시되고 일반 TCP reject가 건너뛰어져 Suricata가 결정을 내리기 전에 전체 Client Hello를 재조립할 시간을 줍니다.

**TCP reject가 `flow:to_server, established`를 사용하는 이유:** `established`는 규칙이 TCP SYN을 매칭할 수 없음을 의미하므로, 3-way 핸드셰이크가 완료되고 Suricata가 일반 TCP reject가 작동하기 전에 애플리케이션 계층 데이터(TLS Client Hello 또는 HTTP 호스트 헤더)를 볼 기회를 얻습니다. `established` 없이는 이 규칙이 도메인 정보가 존재하기 전에 SYN을 거부하여 도메인 기반 필터링이 중단됩니다.

### 인그레스 기본 차단 규칙

```
drop tls any any -> $HOME_NET any (msg:"Default Ingress HTTPS Drop"; ssl_state:client_hello; ja4.hash; content:"_"; flowbits:set,blocked; flow:to_server; sid:999999;)
alert tls any any -> $HOME_NET any (msg:"PQC"; flowbits:isnotset,blocked; flowbits:set,PQC; noalert; flow:to_server; sid:9999910;)
drop http any any -> $HOME_NET any (msg:"Default Ingress HTTP Drop"; flowbits:set,blocked; flow:to_server; sid:9999911;)
drop tcp any any -> $HOME_NET any (msg:"Default Ingress TCP Drop"; flowbits:isnotset,blocked; flowbits:isnotset,PQC; flow:to_server; sid:9999912;)
drop udp any any -> $HOME_NET any (msg:"Default Ingress UDP Drop"; flow:to_server; sid:9999913;)
drop icmp any any -> $HOME_NET any (msg:"Default Ingress ICMP Drop"; flow:to_server; sid:9999914;)
drop ip any any -> $HOME_NET any (msg:"Default Ingress All Other IP Drop"; ip_proto:!TCP; ip_proto:!UDP; ip_proto:!ICMP; flow:to_server; sid:9999915;)
```

**인그레스에 reject 대신 drop을 사용하는 이유:** 알려지지 않은 외부 소스에 TCP RST를 보내고 싶지 않습니다(호스트가 존재함을 확인하고 정찰에 사용될 수 있음).

**인그레스 규칙을 건너뛸 시기:** 방화벽이 이그레스 트래픽만 검사하는 경우(인그레스가 CloudFront + AWS WAF와 같은 별도 경로를 통과하는 중앙 집중식 배포에서 가장 일반적인 패턴).

### JA3/JA4 해시 로깅

사용자 정의 기본 차단 규칙을 사용하는 경우, 추가 포렌식 가시성을 위해 JA3/JA4 핑거프린트 로깅을 활성화할 수도 있습니다:

```
alert tls $HOME_NET any -> any any (ja3.hash; content:!"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; noalert; flow:to_server; sid:202501024;)
alert tls any any -> $HOME_NET any (ja3s.hash; content:!"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; noalert; flow:to_client; sid:202501025;)
```

**하는 일:** 알림 로그 이벤트를 생성하지 않으면서 모든 TLS 연결에 대해 JA3(클라이언트) 및 JA3S(서버) TLS 핑거프린트 해시 로깅을 활성화합니다. `content:!"xxx..."` 트릭은 Suricata가 모든 TLS 플로우에 대해 해시를 계산하고 기록하도록 강제합니다(실제 해시가 해당 더미 값과 일치하지 않으므로).

**필요한 이유:** JA3/JA4 해시가 알림 로그에 나타나 방화벽을 통해 어떤 TLS 클라이언트와 서버가 통신하는지에 대한 가시성을 제공합니다. 이 데이터는 예상치 못한 클라이언트 소프트웨어를 식별하고 의심스러운 연결을 조사하는 데 유용합니다.

**건너뛸 시기:** 분석이나 필터링에 TLS 핑거프린트 데이터를 사용하지 않고 처리 오버헤드를 최소화하려는 경우.

---

## 전체 규칙 템플릿

다음 템플릿은 이 페이지의 가장 일반적인 규칙을 단일 배포 준비 규칙셋으로 결합합니다. [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)에서 권장하는 "Application drop established (server-directed only)" 및 "Application alert established (server-directed only)" 기본 작업을 사용하므로 사용자 정의 기본 차단 규칙이 필요하지 않습니다.

환경별 도메인 허용 목록 규칙을 하단 근처의 지정된 섹션에 배치하세요.

```
# =============================================================================
# AWS Network Firewall - 샘플 Suricata 규칙 템플릿
# =============================================================================
# 규칙 순서: Strict
# 기본 작업: "Application drop established (server-directed only)"
#            "Application alert established (server-directed only)"
# $HOME_NET: 방화벽 정책 수준에서 모든 RFC 1918 공간(10.0.0.0/8, 172.16.0.0/12,
#            192.168.0.0/16)으로 설정.
# =============================================================================

# --- 도메인 카테고리 차단(TLS) ---
reject tls $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_domain_category:Command and Control; ja4.hash; content:"_"; flow:to_server; sid:202602061;)
reject tls $HOME_NET any -> any any (msg:"Category:Malicious"; aws_domain_category:Malicious; ja4.hash; content:"_"; flow:to_server; sid:202602063;)
reject tls $HOME_NET any -> any any (msg:"Category:Malware"; aws_domain_category:Malware; ja4.hash; content:"_"; flow:to_server; sid:202602064;)
reject tls $HOME_NET any -> any any (msg:"Category:Phishing"; aws_domain_category:Phishing; ja4.hash; content:"_"; flow:to_server; sid:202602065;)
reject tls $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_domain_category:Proxy Avoidance; ja4.hash; content:"_"; flow:to_server; sid:202602066;)
reject tls $HOME_NET any -> any any (msg:"Category:Spam"; aws_domain_category:Spam; ja4.hash; content:"_"; flow:to_server; sid:202602067;)

# --- 도메인 카테고리 차단(HTTP) ---
reject http $HOME_NET any -> any any (msg:"Category:Command and Control"; aws_url_category:Command and Control; flow:to_server; sid:202602068;)
reject http $HOME_NET any -> any any (msg:"Category:Malicious"; aws_url_category:Malicious; flow:to_server; sid:2026020610;)
reject http $HOME_NET any -> any any (msg:"Category:Malware"; aws_url_category:Malware; flow:to_server; sid:2026020611;)
reject http $HOME_NET any -> any any (msg:"Category:Phishing"; aws_url_category:Phishing; flow:to_server; sid:2026020612;)
reject http $HOME_NET any -> any any (msg:"Category:Proxy Avoidance"; aws_url_category:Proxy Avoidance; flow:to_server; sid:2026020613;)
reject http $HOME_NET any -> any any (msg:"Category:Spam"; aws_url_category:Spam; flow:to_server; sid:2026020614;)

# --- 직접 IP 연결 통신 차단 ---
reject http $HOME_NET any -> any any (http.host; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"HTTP direct to IP via http host header"; flow:to_server; sid:202501026;)
reject tls $HOME_NET any -> any any (tls.sni; content:"."; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; msg:"TLS direct to IP via TLS SNI"; flow:to_server; sid:202501027;)
reject tls $HOME_NET any -> any any (ja4.hash; content:"_"; startswith; content:!"d"; offset:3; depth:1; msg:"JA4 No SNI Reject"; flow:to_server; sid:1297713;)

# --- GeoIP 차단(XX를 차단할 국가 코드로 교체) ---
# drop ip $HOME_NET any -> any any (msg:"Egress traffic to blocked geo"; geoip:dst,XX; metadata:geo XX; flow:to_server; sid:202501028;)
# 또는 NOT 연산자를 사용하여 특정 국가만 허용:
# drop ip $HOME_NET any -> any any (msg:"Egress to non-approved geo"; geoip:dst,!US,!CA; flow:to_server; sid:202501029;)

# --- QUIC 차단 ---
drop quic $HOME_NET any -> any any (msg:"QUIC traffic blocked"; flow:to_server; sid:3898932;)

# --- 고위험 TLD 차단 ---
reject tls $HOME_NET any -> any any (tls.sni; content:".xyz"; nocase; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501040;)
reject http $HOME_NET any -> any any (http.host; content:".xyz"; endswith; msg:"High risk TLD .xyz blocked"; flow:to_server; sid:202501041;)
reject tls $HOME_NET any -> any any (tls.sni; content:".top"; nocase; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501044;)
reject http $HOME_NET any -> any any (http.host; content:".top"; endswith; msg:"High risk TLD .top blocked"; flow:to_server; sid:202501045;)

# --- 포트/프로토콜 적용 ---
reject tcp $HOME_NET any -> any 443 (msg:"Egress Port TCP/443 but not TLS"; app-layer-protocol:!tls; flow:to_server; sid:202501030;)
reject tls $HOME_NET any -> any !443 (msg:"Egress TLS but not port TCP/443"; flow:to_server; sid:202501031;)
reject tcp $HOME_NET any -> any 80 (msg:"Egress Port TCP/80 but not HTTP"; app-layer-protocol:!http; flow:to_server; sid:202501032;)
reject http $HOME_NET any -> any !80 (msg:"Egress HTTP but not port TCP/80"; flow:to_server; sid:202501033;)
reject tcp $HOME_NET any -> any 22 (msg:"Egress Port TCP/22 but not SSH"; app-layer-protocol:!ssh; flow:to_server; sid:202501060;)
reject ssh $HOME_NET any -> any !22 (msg:"Egress SSH but not port TCP/22"; flow:to_server; sid:202501061;)

# --- 고위험 포트 알림 ---
alert ip $HOME_NET any -> any 53 (msg:"Possible DNS Firewall bypass - direct DNS to external resolver"; flow:to_server; sid:202501055;)
alert ip $HOME_NET any -> any 1389 (msg:"Possible Log4j callback"; flow:to_server; sid:202501059;)
alert ip $HOME_NET any -> any [4444,666,3389] (msg:"Egress traffic to high risk port"; flow:to_server; sid:202501058;)

# --- AWS 트래픽 알림(PrivateLink 후보 식별) ---
alert tls $HOME_NET any -> any any (alert; tls.sni; dotprefix; content:".amazonaws.com"; nocase; endswith; msg:"AWS traffic over NFW - consider VPC endpoint"; flow:to_server; sid:202501070;)

# --- 저위험 프로토콜 허용 ---
pass ntp $HOME_NET any -> any 123 (flow:to_server; sid:202501034;)
pass icmp $HOME_NET any -> any any (flow:to_server; sid:202501035;)

# --- 여기에 도메인 허용 목록을 추가하세요 ---
# 이 줄 아래에 환경별 pass 규칙을 추가하세요.
# 예:
# pass tls $HOME_NET any -> any any (tls.sni; content:"api.yourapp.com"; startswith; nocase; endswith; flow:to_server; sid:100001;)
# pass tls $HOME_NET any -> any any (tls.sni; dotprefix; content:".yourcompany.com"; nocase; endswith; flow:to_server; sid:100002;)
# 하나의 규칙에 많은 도메인(총 1 용량 단위):
# pass tls $HOME_NET any -> any any (tls.sni; pcre:"/(^|\.)(yourcompany\.com|yourapp\.com)$/i"; flow:to_server; sid:100003;)

# --- $HOME_NET 잘못된 구성 탐지(항상 포함) ---
alert ip $HOME_NET any -> any any (noalert; flowbits:set,egress_from_home_net; flow:to_server; sid:8925324;)
alert ip any any -> $HOME_NET any (noalert; flowbits:set,ingress_to_home_net; flow:to_server; sid:8923323;)
alert ip any any -> any any (msg:"$HOME_NET may not be set right! Set it at the firewall policy level."; flowbits:isnotset,ingress_to_home_net; flowbits:isnotset,egress_from_home_net; flowbits:isnotset,home_net_alerted; flowbits:set,home_net_alerted; flow:to_server; sid:8923283;)
```

## 다음 읽을 내용

* [고객 관리 규칙](../../customer-managed-rules/docs/index.md) - 규칙 작성 개념 및 모범 사례
* [AWS 관리형 규칙](../../aws-managed-rules/docs/index.md) - 사용자 정의 규칙을 보완하는 AWS 관리형 규칙 그룹
* [로깅 및 모니터링](../../logging-and-monitoring/docs/index.md) - 규칙이 수행하는 작업 분석
