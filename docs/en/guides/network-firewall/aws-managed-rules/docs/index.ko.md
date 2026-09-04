# AWS 관리형 규칙

!!! info "사전 요구 사항"
    이 섹션은 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md), 특히 $HOME_NET 및 $EXTERNAL_NET 변수 구성에 대한 이해를 전제로 합니다. 네트워크 변수를 구성하지 않았다면 해당 주제를 먼저 검토하세요.

AWS Network Firewall은 자체 IPS 서명을 작성하고 유지할 필요 없이 기본 위협 탐지를 제공하는 AWS 관리형 규칙 그룹을 제공합니다. 이러한 규칙 그룹은 AWS에서 유지 및 업데이트하며 도메인/IP 평판, 위협 서명 및 활성 위협 인텔리전스를 다룹니다. 이 페이지에서는 어떤 관리형 규칙 그룹을 우선시해야 하는지, 효과적으로 구성하는 방법, 사용자 정의 규칙을 어떻게 보완하는지를 다룹니다.

## Active Threat Defense (ATD)

[Active Threat Defense](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-atd.html)는 [MadPot](https://www.aboutamazon.com/news/aws/amazon-madpot-stops-cybersecurity-crime)의 Amazon 위협 인텔리전스를 사용하여 알려진 악성 인프라와의 통신을 차단하는 관리형 규칙 그룹입니다. AWS는 글로벌 네트워크에서 관찰된 위협을 기반으로 규칙을 지속적으로 업데이트하여 활성 위협 및 클라우드 특정 공격 패턴으로부터 보호합니다.

!!! tip "모범 사례"
    모든 방화벽 정책에 Active Threat Defense를 활성화하세요. AWS 자체 위협 인텔리전스에서 검증된 지표를 사용하여 높은 신뢰도의 위협 차단을 제공합니다. AWS는 관련 위협 활동의 증거가 없으면 자동으로 지표를 제거하여 오탐을 최소화합니다.

### ATD가 보호하는 대상

ATD는 알려진 위협과 관련된 IP 주소, 도메인 이름 및 URL 지표에 대해 트래픽을 매칭합니다. AWS는 관찰된 공격 패턴을 기반으로 이러한 지표를 카테고리별로 그룹화합니다:

* **명령 및 제어** - 악의적 행위자가 침해된 시스템을 원격으로 제어하는 데 사용하는 인프라(IP 및 도메인, 이그레스 방향)
* **맬웨어 스테이징** - 맬웨어 및 공격 도구의 배포를 촉진하는 인프라(URL, 인그레스 및 이그레스)
* **크립토마이닝 풀** - 크립토마이너가 사용하는 인프라(IP 및 도메인, 이그레스 방향)
* **싱크홀** - 악의적 목적으로 사용되던 이전에 악용된 인프라(도메인, 이그레스 방향)
* **대역 외 애플리케이션 보안 테스트** - 주입된 페이로드가 취약점의 존재를 검증하기 위해 아웃바운드 연결을 수행하는 인프라(IP 및 도메인, 이그레스 방향)

지표 유형 및 카테고리에 대한 전체 세부 사항은 [Active Threat Defense 관리형 규칙 그룹 지표 이해](https://docs.aws.amazon.com/network-firewall/latest/developerguide/atd-indicators.html)를 참조하세요.

### ATD와 Amazon GuardDuty

Amazon GuardDuty를 사용하는 경우, ATD는 GuardDuty가 탐지하는 위협을 자동으로 차단하여 보안 태세를 강화합니다. GuardDuty는 의심스러운 활동을 관찰하면 결과를 생성하지만 트래픽을 중지하는 조치를 취하지 않습니다. ATD가 활성화된 Network Firewall은 GuardDuty가 결과를 생성하는 동일한 악성 인프라와의 트래픽을 자동으로 차단하여 탐지를 방지로 전환합니다.

ATD가 사전에 차단할 수 있는 GuardDuty 결과:

* 명령 및 제어 활동(Backdoor:EC2/C&CActivity.B, Backdoor:Runtime/C&CActivity.B)
* 크립토마이닝(CryptoCurrency:EC2/BitcoinTool.B, Impact:EC2/BitcoinDomainRequest.Reputation)
* 트로이 목마 활동(Trojan:EC2/BlackholeTraffic)
* 악성 IP 통신(UnauthorizedAccess:EC2/MaliciousIPCaller.Custom)

전체 목록은 [Amazon GuardDuty에서 Active Threat Defense 지표 작업](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-atd-guardduty-use-case.html)을 참조하세요.

ATD의 작동 방식과 심층 방어 아키텍처에서의 역할에 대한 자세한 내용은 다음을 참조하세요:

* [실시간 맬웨어 방어: AWS Network Firewall Active Threat Defense 활용](https://aws.amazon.com/blogs/security/real-time-malware-defense-leveraging-aws-network-firewall-active-threat-defense/)
* [AWS Network Firewall에서 Amazon 위협 인텔리전스를 사용하여 보안 태세 개선](https://aws.amazon.com/blogs/security/improve-your-security-posture-using-amazon-threat-intelligence-on-aws-network-firewall/)

## 도메인 및 IP 규칙 그룹(무료)

[도메인 및 IP 규칙 그룹](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-domain-list.html)은 낮은 평판이거나 악성 활동과 관련된 것으로 알려진 도메인 및 IP에 대한 HTTP 또는 HTTPS 트래픽을 차단합니다. 표준 Network Firewall 처리 요금 외에 추가 비용 없이 포함됩니다.

사용 가능한 규칙 그룹:

* **BotNetCommandAndControlDomainsStrictOrder** - 알려진 봇넷 C2 도메인
* **AbusedLegitBotNetCommandAndControlDomainsStrictOrder** - 봇넷 C2에 악용되는 합법적 서비스(파일 공유, 붙여넣기 사이트, 터널링 서비스)
* **MalwareDomainsStrictOrder** - 알려진 맬웨어 배포 도메인
* **AbusedLegitMalwareDomainsStrictOrder** - 맬웨어 배포에 악용되는 합법적 서비스

!!! tip "모범 사례"
    모든 방화벽 정책에 도메인 및 IP 평판 규칙 그룹을 활성화하세요. 이는 정상적인 상황에서 워크로드가 통신해서는 안 되는 도메인 및 IP를 나타냅니다. 규칙 작성 없이 최소한의 노력으로 기본 보호를 제공합니다.

## 관리형 위협 서명 규칙 그룹(무료)

[관리형 위협 서명 규칙 그룹](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-managed-rule-groups-threat-signature.html)은 맬웨어, 익스플로잇, 봇넷, 웹 기반 공격, 자격 증명 피싱, 스캐닝 도구 등에 대한 IDS/IPS 커버리지를 제공합니다. 이러한 규칙 그룹의 위협 인텔리전스는 타사 파트너(Proofpoint/Emerging Threats)에서 제공됩니다.

### 배포 태그 이해

위협 서명 규칙 그룹 내의 각 규칙은 규칙이 가장 효과적인 위치를 나타내는 [Proofpoint/ET 서명 메타데이터 시스템](https://community.emergingthreats.net/t/signature-metadata/96)의 "배포 유형"으로 태그됩니다:

* **Perimeter** - 내부 클라이언트와 외부 서버 사이(이그레스 보호). 대부분의 규칙이 경계 배포용으로 태그됩니다.
* **Internal** - 수평 이동 탐지를 위한 동서 트래픽 모니터링.
* **Datacenter** - 외부 클라이언트와 내부/DMZ 서버 사이(인그레스 보호).
* **SSLDecrypt** - 작동하려면 TLS 검사가 필요합니다(복호화된 페이로드 콘텐츠 검사).
* **alert_only** - drop 모드에 배치해서는 안 되는 정보성 규칙.

[방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md#동서-트래픽-검사)에서 다루었듯이, Internal 배포용으로 태그된 규칙은 $HOME_NET이 RFC 1918 범위로 설정되어 있는 한 동서 트래픽을 올바르게 매칭합니다.

### 권장 위협 서명 규칙 그룹

아래 표는 사용 가능한 각 위협 서명 규칙 그룹, 탐지 대상 및 권장 배포 시나리오를 보여줍니다. 규칙 수는 대략적이며 파트너가 규칙 세트를 업데이트함에 따라 변경됩니다.

| 규칙 그룹 | 탐지 대상 | 건너뛸 조건 |
|---|---|---|
| **ThreatSignaturesBotnetStrictOrder** | 알려진 활성 봇넷 및 C2 호스트에서 자동 생성된 서명 | 건너뛰지 마세요. 모든 트래픽에 광범위하게 적용 가능. |
| **ThreatSignaturesMalwareStrictOrder** | TCP, UDP, SMTP, ICMP, SMB 프로토콜에서의 맬웨어 및 웜 전파 | 건너뛰지 마세요. 모든 트래픽에 광범위하게 적용 가능. |
| **ThreatSignaturesExploitsStrictOrder** | ActiveX, FTP, NetBIOS, RPC, 셸코드, SQL 인젝션, SNMP, Telnet, VOIP을 포함한 직접 익스플로잇 | 건너뛰지 마세요. 이그레스 및 동서 모두에 대한 강력한 커버리지. |
| **ThreatSignaturesIOCStrictOrder** | 침해 지표, 공격 응답 서명, 익스플로잇 킷 인프라 | 건너뛰지 마세요. 모든 트래픽에 광범위하게 적용 가능. |
| **ThreatSignaturesEmergingEventsStrictOrder** | 단기 캠페인 및 주목 위협(규칙은 임시적이고 자주 교체됨) | 거의 건너뛰지 마세요. 현재 위협에 대한 높은 시의성. |
| **ThreatSignaturesDoSStrictOrder** | 서비스 거부 패턴(작은 규칙 세트, 제한된 커버리지) | 거의 건너뛰지 마세요. 낮은 용량 비용(200). |
| **ThreatSignaturesBotnetWebStrictOrder** | HTTP 기반 봇넷 통신 패턴 | 방화벽을 통해 HTTP/HTTPS 트래픽이 흐르지 않는 경우 |
| **ThreatSignaturesMalwareWebStrictOrder** | HTTP 및 TLS 프로토콜의 악성 코드 | 방화벽을 통해 HTTP/HTTPS 트래픽이 흐르지 않는 경우 |
| **ThreatSignaturesSuspectStrictOrder** | 의심스러운 JA3 핑거프린트, IRC 채팅 프로토콜, 비정상적인 사용자 에이전트 | 방화벽을 통해 TLS/HTTP 트래픽이 흐르지 않는 경우 |
| **ThreatSignaturesWebAttacksStrictOrder** | 웹 클라이언트, 웹 서버 및 특정 웹 애플리케이션을 대상으로 하는 공격 | 내부에서 웹 서비스가 실행되지 않고 인그레스 검사가 없는 경우 |
| **ThreatSignaturesMalwareCoinminingStrictOrder** | 크립토마이닝 소프트웨어(합법적 및 악성) | 합법적인 크립토마이닝 운영을 하는 경우 |
| **ThreatSignaturesScannersStrictOrder** | Nessus, Nikto, 포트 스캐너와 같은 정찰 및 프로빙 도구 | 이러한 규칙을 트리거하는 합법적인 취약점 스캐너를 운영하는 경우 |
| **ThreatSignaturesPhishingStrictOrder** | 자격 증명 피싱 랜딩 페이지 및 피싱 사이트에 대한 자격 증명 제출 | 방화벽을 통해 최종 사용자 브라우징 트래픽이 흐르지 않는 경우 |
| **ThreatSignaturesBotnetWindowsStrictOrder** | Windows 전용 봇넷 동작 | 환경에 Windows 워크로드가 없는 경우 |
| **ThreatSignaturesFUPStrictOrder** | 정책 위반: 게임, P2P 트래픽, 부적절한 콘텐츠 | 허용 가능한 사용 적용이 필요하지 않은 경우 |
| **ThreatSignaturesMalwareMobileStrictOrder** | 모바일 및 태블릿 운영 체제를 대상으로 하는 맬웨어 | 방화벽을 통해 모바일 기기 트래픽이 흐르지 않는 경우 |

### 배포 시나리오별 규칙 그룹 선택

정책당 20개 상태 저장 규칙 그룹 제한은 선택적이어야 함을 의미합니다. 배포 시나리오에 따른 우선순위 권장 방법:

**기본(모든 배포에 권장):**

가장 넓은 범위의 위협을 가장 높은 신호 대 노이즈 비율로 커버하는 세 가지 규칙 그룹:

* ThreatSignaturesBotnetStrictOrder(포괄적인 봇넷/C2 탐지)
* ThreatSignaturesMalwareStrictOrder(일반 맬웨어 탐지)
* ThreatSignaturesExploitsStrictOrder(익스플로잇 탐지, 강력한 동서 커버리지)

**향상된 이그레스 보호(이그레스 중심 배포에 기본에 추가):**

* ThreatSignaturesBotnetWebStrictOrder(HTTP 봇넷 탐지)
* ThreatSignaturesBotnetWindowsStrictOrder(Windows 봇넷 탐지)
* ThreatSignaturesMalwareWebStrictOrder(웹 기반 맬웨어)
* ThreatSignaturesEmergingEventsStrictOrder(현재 캠페인)
* ThreatSignaturesPhishingStrictOrder(자격 증명 피싱)
* ThreatSignaturesMalwareCoinminingStrictOrder(크립토마이닝)

**향상된 동서 보호(수평 이동 탐지를 위해 기본에 추가):**

* ThreatSignaturesWebAttacksStrictOrder(내부 시스템 간 웹 공격)
* ThreatSignaturesIOCStrictOrder(침해 지표)
* ThreatSignaturesScannersStrictOrder(내부 정찰 탐지)

**향상된 인그레스 보호(인바운드 트래픽을 위해 기본에 추가):**

* ThreatSignaturesWebAttacksStrictOrder(웹 애플리케이션 공격)
* ThreatSignaturesIOCStrictOrder(익스플로잇 킷 탐지)

!!! tip "모범 사례"
    기본 세 가지 규칙 그룹에 ATD 및 도메인/IP 평판 규칙 그룹을 추가하여 시작하세요. 이것으로 가장 일반적인 위협 카테고리에 대한 강력한 커버리지를 얻을 수 있습니다. 특정 배포 시나리오 및 사용 가능한 규칙 그룹 용량에 따라 추가 규칙 그룹을 추가하세요. 추가하는 각 규칙 그룹은 정책당 최대 20개 상태 저장 규칙 그룹에서 하나의 슬롯을 소비합니다. 사용자 정의 규칙 그룹을 위한 충분한 슬롯을 남겨두세요.

### 관리형 규칙을 alert 모드 vs drop 모드로 배포

!!! tip "모범 사례"
    관리형 위협 서명 규칙 그룹을 먼저 alert 모드로 배포하세요. 일정 기간 동안 생성된 알림을 모니터링하여 어떤 규칙이 트래픽에 대해 작동하는지, 일치 항목이 합법적인 애플리케이션 동작을 나타내는지 이해하세요. 규칙이 워크로드를 방해하지 않는다는 확신이 생기면 drop 모드로 전환하세요.

오탐의 위험 프로필은 AWS WAF와 다릅니다. WAF 규칙은 HTTP 요청 구조를 검사하며 합법적인 애플리케이션 트래픽을 실수로 차단할 수 있습니다(예: SQL과 유사한 구문을 포함하는 합법적인 쿼리 매개변수를 차단하는 SQL 인젝션 규칙). Network Firewall 관리형 규칙은 네트워크 계층에서 작동하여 알려진 위협과 관련된 패턴을 탐지합니다. WAF 규칙보다 오탐이 적지만, 특히 합법적인 애플리케이션 트래픽과 겹치는 광범위한 네트워크 패턴이나 프로토콜 동작에 매칭하는 규칙에서 여전히 발생할 수 있습니다.

alert에서 drop으로의 전환은 점진적으로 수행할 수 있습니다. 먼저 ATD 및 도메인/IP 평판 규칙 그룹을 drop 모드로 전환한 다음(가장 높은 신뢰도 지표), 각 위협 서명 그룹을 트래픽에 대해 검증하면서 drop으로 전환하세요.

### $HOME_NET은 관리형 규칙에 중요합니다

이러한 규칙은 `$HOME_NET` 및 `$EXTERNAL_NET` 변수를 사용하여 트래픽 방향성을 결정합니다. 이러한 변수가 올바르게 구성되지 않으면 관리형 규칙이 예상대로 트래픽을 매칭하지 않습니다.

!!! danger "일반적인 잘못된 구성"
    고객들이 관리형 위협 서명 규칙 그룹을 배포하고 작동하는 것을 보지 못한 후, 규칙이 효과적이지 않다고 가정합니다. 가장 일반적인 원인은 $HOME_NET이 워크로드가 실제로 실행되는 스포크 VPC CIDR이 아닌 검사 VPC CIDR(기본값)만 포함하고 있기 때문입니다. 정책 수준에서 $HOME_NET을 모든 RFC 1918 공간(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)으로 설정하세요. 전체 지침은 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)을 참조하세요.

콘솔을 통해 관리형 위협 서명 규칙 그룹 내의 [개별 규칙을 확인](https://docs.aws.amazon.com/network-firewall/latest/developerguide/copying-managed-threat-signature-rules.html)하여 정확히 무엇을 탐지하는지 이해할 수 있습니다.

## 파트너 관리형 규칙 그룹(유료)

[파트너 관리형 규칙 그룹](https://docs.aws.amazon.com/network-firewall/latest/developerguide/aws-marketplace-rule-groups.html)은 타사 보안 벤더의 유료 AWS Marketplace 오퍼링입니다. AWS Resource Access Manager(AWS RAM)를 통해 또는 AWS Marketplace 통합을 통해 Network Firewall 콘솔에서 고객에게 공유됩니다.

파트너 관리형 규칙을 사용하면 알려지고 신뢰할 수 있는 보안 파트너의 위협 인텔리전스를 가져와 해당 파트너의 전용 방화벽 어플라이언스를 배포하지 않고도 Network Firewall에서 직접 실행할 수 있습니다. 무료 AWS 관리형 위협 서명 및 Active Threat Defense를 대체하는 것이 아니라 보완하여, 동일한 방화벽에서 여러 인텔리전스 소스의 심층 방어를 제공합니다.

!!! tip "모범 사례"
    사용 가능한 파트너 중 하나와 이미 관계가 있거나 규정 준수 요구 사항에 특정 위협 인텔리전스 소스가 지정된 경우 파트너 관리형 규칙 그룹을 평가하세요.

## Suricata 규칙 생성기를 사용한 필터링된 관리형 규칙 그룹

AWS 관리형 위협 서명 규칙 그룹에는 다양한 배포 시나리오를 다루는 수천 개의 규칙이 포함되어 있습니다. 많은 배포에서는 이러한 규칙의 하위 집합만 필요합니다. 예를 들어, 내부 VPC 간 동서 트래픽을 검사하는 방화벽은 경계 배포용으로 설계된 인터넷 대면 서명이 필요하지 않습니다.

[AWS Network Firewall용 Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator)에는 AWS 관리형 위협 서명에서 파생된 필터링되고 자동 업데이트되는 규칙 그룹을 생성할 수 있는 관리형 규칙 그룹 생성기가 포함되어 있습니다. 필터 기준(배포 유형, 프로토콜 또는 위협 카테고리와 같은 규칙 메타데이터 필드 기반)을 정의하면, 도구가 일치하는 규칙만 추출하고 AWS가 소스 규칙을 업데이트할 때 자동 동기화와 함께 자체 규칙 그룹으로 배포합니다.

![관리형 규칙 그룹 생성기](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/mrg.png)

### 작동 방식

1. **소스 선택** - 하나 이상의 AWS 관리형 StrictOrder 위협 서명 규칙 그룹을 입력으로 선택
2. **필터 정의** - 메타데이터 기반 필터 조건(예: `signature_deployment equals Internal`)을 구축하여 사용 사례에 관련된 규칙만 추출
3. **빌드** - 도구가 선택된 소스에서 규칙을 가져오고, 필터를 적용하고, SID별로 중복을 제거하고, 선택적으로 테스트 모드(안전한 모니터링을 위해 모든 작업을 `alert`로 변환)를 적용
4. **배포** - 원클릭 배포로 AWS Network Firewall에 필터링된 규칙 그룹과 AWS가 소스 규칙 그룹을 업데이트할 때마다 자동으로 필터를 다시 적용하는 Lambda 함수가 생성

### 자동 동기화

배포 후, 도구는 AWS-Managed-Threat-Signatures SNS 주제를 구독하는 Lambda 함수를 프로비저닝합니다. AWS가 관리형 규칙 그룹에 대한 업데이트를 게시하면, Lambda 함수가 자동으로:

* 소스 규칙 그룹을 다시 가져옴
* 필터 기준 및 중복 제거 로직을 다시 적용
* 최신 필터링된 결과로 규칙 그룹을 업데이트
* 선택적으로 규칙이 변경될 때 이메일 알림 전송

이를 통해 실제로 필요한 서명만으로 AWS 관리형 규칙의 자동 업데이트 이점을 얻을 수 있어, 용량 소비를 줄이고 관련 없는 서명의 오탐을 최소화합니다.

### 예: 동서 검사

`signature_deployment equals Internal` 필터를 사용하면 일반적으로 수천 개의 규칙이 수평 이동 탐지, 내부 정찰 및 동서 위협 패턴을 감지하도록 특별히 설계된 200-300개의 집중된 서명 세트로 줄어들며, 내부 트래픽에서 오탐을 생성할 수 있는 인터넷 대면 규칙이 제외됩니다.

### 주요 이점

* **용량 사용 감소** - 배포 시나리오에 관련된 서명에 대해서만 규칙 용량 소비
* **오탐 감소** - 트래픽 패턴에 적용되지 않는 규칙 카테고리 제외
* **자동 업데이트** - 수동 개입 없이 AWS 위협 인텔리전스로 규칙 최신 유지
* **구성 지속성** - 버전 제어 및 재현성을 위해 `.mrg` 파일에 필터 구성 저장

## 다음 읽을 내용

* [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md) - 관리형 규칙을 위한 $HOME_NET 설정
* [고객 관리 규칙](../../customer-managed-rules/docs/index.md) - 사용자 정의 규칙과 함께 관리형 규칙 사용
* [샘플 Suricata 규칙](../../sample-suricata-rules/docs/index.md) - 도메인 카테고리 필터링 규칙 예제
* [로깅 및 모니터링](../../logging-and-monitoring/docs/index.md) - 관리형 규칙 매칭 모니터링
