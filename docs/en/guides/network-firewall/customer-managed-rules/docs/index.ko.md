# 고객 관리 규칙

!!! info "사전 요구 사항"
    이 섹션은 [사전 요구 사항 및 기본 사항](../../prerequisites/docs/index.md) 및 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md)에 대한 이해를 전제로 합니다. AWS Network Firewall이 처음이라면 해당 주제를 먼저 검토하세요.

고객 관리 상태 저장 규칙은 AWS Network Firewall 검사 기능의 핵심으로, Suricata 엔진을 사용하여 TLS SNI 매칭, HTTP 헤더 검사, 프로토콜 탐지, URL 카테고리 매칭, JA3/JA4 핑거프린팅, GeoIP 필터링을 지원하는 3-7계층의 연결 인식 심층 패킷 검사를 수행합니다.

[샘플 Suricata 규칙](../../sample-suricata-rules/docs/index.md)으로 넘어가기 전에 이 페이지를 읽으세요. 여기서 다루는 개념(특히 `flow:` 키워드, Suricata 규칙 유형, 규칙 그룹 조직)은 샘플 규칙이 왜 그렇게 작성되었는지 이해하는 데 필수적인 맥락입니다.

## 스테이트리스 규칙을 사용하지 마세요

!!! tip "모범 사례"
    스테이트리스 엔진의 기본 작업을 "스테이트풀 규칙 그룹으로 전달"로 설정하고 스테이트리스 규칙을 구성하지 마세요. 모든 필터링은 스테이트풀 엔진에서 수행하세요.

스테이트리스 규칙 엔진은 연결 상태나 트래픽 방향에 관계없이 각 패킷을 독립적으로 검사합니다. VPC 네트워크 ACL과 유사하게 둘 다 스테이트리스 패킷 필터이지만, 스테이트리스 엔진은 훨씬 더 많은 규칙으로 확장되고 TCP 플래그와 같은 패킷 수준 옵션을 노출하며 소스와 대상을 표현하는 방식이 더 유연합니다. 네트워크 ACL과 공유하는 중요한 부분은 연결 컨텍스트가 없다는 것입니다. 또한 Network Firewall이 처리된 트래픽 GB당 요금을 부과하므로 네트워크 ACL보다 비용이 상당히 높습니다. 스테이트리스 엔진은 트래픽을 기록할 수 없어 규칙이 잘못 구성된 경우 문제 해결이 어렵습니다.

!!! danger "일반적인 잘못된 구성"
    스테이트리스 엔진이 선택 사항이라는 것을 인식하지 못하고 광범위한 스테이트리스 pass 규칙(예: 모든 TCP 트래픽에 대한 pass)을 생성합니다. 스테이트리스 엔진이 스테이트풀 엔진보다 먼저 평가하므로, 이 pass 규칙은 스테이트풀 엔진이 보기 전에 일치하는 모든 트래픽을 통과시킵니다. 그러면 스테이트풀 규칙은 작동하지 않으며, 스테이트리스 엔진이 기록하지 않으므로 이유를 알 수 없습니다. 이는 스테이트리스 규칙을 사용하지 않으면 완전히 피할 수 있는 어려운 문제 해결 상황을 만듭니다.

스테이트풀 엔진은 스테이트리스 엔진이 하는 모든 것에 더해 반환 트래픽 처리, 심층 패킷 검사, 로깅 및 거부 작업을 제공합니다. 일부 고객은 스테이트리스 엔진에 대한 합법적인 사용 사례가 있지만 이는 드뭅니다. 대다수의 배포에서 모든 필터링은 스테이트풀 엔진에서 수행되어야 합니다.

## 사용자 정의 Suricata 규칙 사용

Network Firewall은 세 가지 [상태 저장 규칙 형식](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-creating-editing.html)을 지원하지만, 세 가지 모두 내부적으로 Suricata 규칙으로 변환됩니다:

1. **[사용자 정의 Suricata 규칙](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html)**(권장) - 원시 Suricata 규칙 구문을 직접 작성
2. **도메인 목록 규칙** - Suricata 도메인 필터링 규칙을 생성하는 UI 추상화
3. **표준 상태 저장 규칙 빌더** - 폼 입력에서 Suricata 규칙을 생성하는 UI 추상화

도메인 목록 규칙과 표준 상태 저장 규칙 빌더는 Suricata 규칙을 생성하는 인터페이스일 뿐입니다. UI 경험이 지원하는 것으로 제한됩니다. 사용자 정의 Suricata 규칙 문자열 옵션을 사용하면, 콘솔 UI가 아직 노출하지 않을 수 있는 전체 Suricata 기능 범위에 액세스할 수 있으며, 규칙 그룹 용량을 조정해야 하는 경우 텍스트 형식으로 규칙을 쉽게 가져오고 내보낼 수 있습니다.

!!! tip "모범 사례"
    사용자 정의 Suricata 규칙을 직접 작성하세요. 이렇게 하면 규칙 동작, 사용자 정의 로그 메시지, 로그 분석을 위한 사용자 정의 서명 ID(SID), 규칙 그룹 간에 규칙을 쉽게 복사, 붙여넣기, 백업, 이동할 수 있는 기능을 완전히 제어할 수 있습니다.

Suricata 규칙 구문은 처음 사용해본 적이 없다면 처음에는 어려워 보일 수 있습니다. 사용 가능한 리소스(이 가이드의 [샘플 Suricata 규칙](../../sample-suricata-rules/docs/index.md) 페이지, [Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator) 도구, [공식 AWS 문서 예제](https://docs.aws.amazon.com/network-firewall/latest/developerguide/suricata-examples.html))를 활용하면 처음 보이는 것보다 접근하기 쉽습니다. 구문을 초기에 학습하는 데 시간을 투자한 고객들은 시간이 지남에 따라 원시 Suricata 규칙을 읽는 것이 콘솔로 구축된 규칙을 탐색하는 것보다 더 직관적이 된다고 일관되게 보고합니다. 이 페이지의 많은 모범 사례를 자동화하는 오픈소스 도구에 대해서는 아래의 [Suricata 규칙 생성기로 규칙 작성](#suricata-규칙-생성기로-규칙-작성)을 참조하세요. 여기에는 UI에서 생성된 규칙을 Suricata 규칙으로 자동 변환하는 기능이 포함됩니다.

사용자 정의 Suricata 규칙의 중요한 운영상 이점은 이식성입니다. 일반 텍스트이므로 버전 제어에 복사하고, 규칙 그룹 간에 이동하며, 인프라 코드 템플릿에 포함할 수 있습니다. 대부분의 고객은 Suricata 규칙을 git 리포지토리에 저장하고 버전 제어된 풀 리퀘스트를 통해 모든 규칙 및 정책 변경을 관리합니다. 이는 누가 어떤 규칙을 언제 변경했는지에 대한 감사 추적, 알려진 양호한 구성으로 롤백하는 기능, 배포 전 방화벽 정책 변경에 대한 피어 리뷰를 제공합니다. 표준 상태 저장 규칙 빌더를 통해 구축된 규칙은 구조화된 객체로 저장됩니다. IaC(CloudFormation, Terraform, CDK)를 통해 규칙을 관리할 때, 일반 텍스트 Suricata 형식은 템플릿에 자연스럽게 통합됩니다. 콘솔에서 수동으로 규칙을 생성하면, 표준 상태 저장 규칙 빌더의 구조화된 형식은 규칙 그룹 간에 규칙을 마이그레이션하거나 백업을 위해 내보내기가 어렵습니다. 어느 정도 익숙해지면 UI나 IaC 출력에서 콘솔로 구축된 규칙을 구문 분석하려는 것보다 원시 Suricata 규칙을 읽는 것이 놀랍게도 더 직관적입니다.

## 모든 TCP 또는 IP 프로토콜 규칙에 항상 flow: 키워드 사용

!!! tip "모범 사례"
    규칙의 프로토콜 필드(필드 2)가 `tcp` 또는 `ip`인 모든 상태 저장 규칙에 `flow:`를 추가하세요. 이 단일 키워드는 Network Firewall 배포에서 가장 일반적인 규칙 충돌 클래스를 방지합니다. 대부분의 경우 `flow:to_server;`가 가장 적합하지만, `flow:established;` 또는 `flow:to_server, established;`도 좋은 옵션입니다.

### flow: 키워드가 중요한 이유

Suricata가 규칙을 구문 분석할 때, 프로토콜 필드와 존재하는 키워드를 기반으로 [내부 규칙 유형](https://docs.suricata.io/en/latest/rules/rule-types.html)을 할당합니다. 유형은 작업이 단일 패킷에 적용되는지 전체 플로우에 적용되는지를 결정합니다.

프로토콜 필드에 `tcp`, `udp` 또는 `ip`가 있고 `flow:` 키워드가 없는 규칙은 **SIG_TYPE_IPONLY**로 분류됩니다. Suricata는 플로우의 첫 번째 패킷(예: TCP SYN)에서 이를 평가하고, 전체 연결에 대한 작업을 고정한 다음 검사를 중지합니다. 애플리케이션 계층 데이터를 포함한 모든 후속 패킷은 다른 규칙에 대해 평가되지 않고 방화벽의 상태 테이블에 의해 처리됩니다. 이것이 Network Firewall에서 대부분의 규칙 순서 문제의 원인입니다.

`flow:`를 추가하면 규칙이 패킷별로 평가되는 **SIG_TYPE_PKT**로 변환됩니다. 플로우가 계속 검사되고, 애플리케이션 계층 규칙이 여전히 우선순위 순서로 작동할 수 있으며, 방향성에 대한 명시적 제어가 가능합니다.

### 어떤 규칙에 flow: 키워드가 필요한가

프로토콜 필드가 `tcp`, `udp` 또는 `ip`이고 주소와 포트에만 매칭하는 모든 규칙에 `flow:`를 추가하세요. 이 키워드가 없으면 Suricata가 규칙을 SIG_TYPE_IPONLY로 분류하고 애플리케이션 계층 데이터가 있기 전에 첫 번째 패킷에서 작업을 고정합니다.

```
# 올바름: flow:to_server가 이를 SIG_TYPE_PKT로 만듦
pass tcp $HOME_NET any -> any 80 (flow:to_server; sid:22222;)
```

애플리케이션 계층 프로토콜 필드(`tls`, `http`, `ssh`, `dns` 등) 또는 애플리케이션 계층 버퍼 키워드(`tls.sni`, `http.host`)가 있는 규칙은 `flow:`가 필요하지 않습니다. 앱 계층 데이터가 사용 가능할 때까지 매칭할 수 없으므로 초기 SYN에서 트리거되지 않습니다. 이러한 규칙에 `flow:to_server`를 추가하는 것은 무해하며 일관성을 위해 일반적입니다.

!!! danger "일반적인 잘못된 구성"
    고객들이 방화벽이 "규칙을 순서대로 처리하지 않는다"거나 높은 우선순위 규칙이 건너뛰어진다고 보고할 때, 원인은 거의 항상 `flow:`가 없는 규칙이 SYN 패킷에서 매칭하여 애플리케이션 계층 규칙이 검사하기 전에 전체 플로우를 통과시키는 것입니다. 규칙에 `flow:to_server;`를 추가하면 우리가 본 모든 경우에서 이를 수정합니다.

### 예: 애플리케이션 계층 규칙이 작동하지 않는 경우

`flow:to_server` 없이 TCP pass 규칙은 SYN 패킷에서 매칭하고 전체 플로우를 통과시킵니다. 규칙셋에서 더 높은 애플리케이션 계층 규칙은 트래픽을 볼 수 없습니다:

```
# 나쁨 - 사용하지 마세요
# 규칙 1: baddomain.com에 대한 HTTP 트래픽을 차단하려는 의도
reject http $HOME_NET any -> any 80 (http.host; content:"baddomain.com"; sid:1;)

# 규칙 2: 모든 TCP 포트 80을 허용(SIG_TYPE_IPONLY 규칙 - SYN에서 매칭, 검사 중지)
pass tcp $HOME_NET any -> any 80 (sid:2;)
```

이 예에서 규칙 2는 첫 번째 TCP SYN 패킷(HTTP 데이터가 존재하기 전)에서 매칭하고 전체 플로우를 통과시킵니다. 플로우가 이미 허용으로 상태 테이블에 있으므로 규칙 1은 평가되지 않습니다. 고객은 낮은 우선순위 규칙이 우선하기 때문에 strict 규칙 순서가 "작동하지 않는다"고 봅니다.

**수정:**

```
# 올바름
# 규칙 1: baddomain.com에 대한 HTTP 트래픽 차단(변경 없음 - flow: 불필요)
reject http $HOME_NET any -> any 80 (http.host; content:"baddomain.com"; sid:1;)

# 규칙 2: TCP 포트 80 허용(SIG_TYPE_PKT 규칙 - 검사 계속)
pass tcp $HOME_NET any -> any 80 (flow:to_server; sid:2;)
```

규칙 2만 변경됩니다. `flow:to_server`와 함께 규칙 2는 SIG_TYPE_PKT 규칙이 됩니다. Suricata는 플로우를 계속 검사하고, HTTP 요청이 호스트 헤더에 "baddomain.com"과 함께 도착하면 규칙 1이 작동하여 차단합니다.

자세한 내용은 [Network Firewall의 규칙 문제 해결](https://docs.aws.amazon.com/network-firewall/latest/developerguide/troubleshooting-rules.html)을 참조하세요.

### Pass 규칙은 나머지 스트림에 대한 검사를 종료합니다

`flow:`를 추가하면 규칙 순서가 수정되지만, `pass` 작업의 더 근본적인 속성은 변경하지 않습니다: `pass` 규칙이 매칭되면 Suricata는 해당 TCP 스트림의 나머지 검사를 중지합니다. 동일한 연결의 후속 페이로드는 해당 페이로드가 악성이더라도 AWS 관리형 위협 서명을 포함한 다른 규칙에 대해 평가되지 않습니다. 이것은 Network Firewall 제한이 아닌 Suricata의 설계입니다.

실질적인 결과는 광범위하게 범위가 지정된 pass 규칙이 단순히 허용적인 액세스가 아니라 사각지대라는 것입니다. `pass tcp $HOME_NET any -> any 443 (flow:to_server, established; sid:1;)`와 같은 규칙은 모든 HTTPS 대상을 허용하고 해당 연결 모두에서 IPS 검사도 제거합니다.

!!! tip "모범 사례"
    `pass` 규칙의 범위를 사용 사례가 허용하는 만큼 좁게 지정하세요. 포트에 대한 광범위한 `pass tcp` 규칙보다 특정 도메인(`tls.sni`, `http.host`)을 매칭하는 애플리케이션 계층 pass 규칙을 선호하여, 허용 결정이 포트 번호가 아닌 의도한 대상에 연결되도록 하세요. 광범위한 범위를 허용해야 하는 경우, AWS 관리형 위협 서명 규칙 그룹을 pass 규칙보다 높은 우선순위에 배치하여 먼저 평가되도록 하세요.

기본 Suricata 동작에 대해서는 [트래픽 무시: pass 규칙](https://docs.suricata.io/en/latest/performance/ignoring-traffic.html#pass-rules) 및 이 [Suricata 포럼 토론](https://forum.suricata.io/t/do-pass-action-allows-all-payload-going-through-same-tcp-stream/3567)을 참조하세요.

## 적은 규칙 그룹으로 통합

Network Firewall에는 방화벽 정책에 연결할 수 있는 규칙 및 규칙 그룹 수에 대한 제한이 있습니다. 방화벽 정책은 최대 20개의 상태 저장 규칙 그룹을 지원하며, 이 제한은 사용자 정의 규칙 그룹과 AWS 관리형 규칙 그룹 간에 공유됩니다. 총 상태 저장 규칙 용량은 정책이 참조하는 모든 규칙 그룹에 걸쳐 기본 30,000이며, 단일 규칙 그룹은 30,000 용량으로 제한됩니다. 둘 다 [서비스 할당량](https://console.aws.amazon.com/servicequotas/home/services/network-firewall/quotas)을 통해 증가를 요청할 수 있는 기본 할당량입니다. 규칙 그룹에는 조정할 수 없는 Suricata 규칙 문자열에 대한 2MB 최대 크기 제한도 있습니다.

!!! tip "모범 사례"
    가능한 한 적은 사용자 정의 규칙 그룹, 이상적으로는 하나만 사용하세요. 이렇게 하면 연결할 수 있는 AWS 관리형 규칙 그룹 수를 최대화하고(20개 상태 저장 규칙 그룹 제한은 사용자 정의와 관리형 간에 공유됨), 문제 해결을 위해 사용자 정의 규칙셋을 위에서 아래로 읽기가 훨씬 쉬워집니다.

### 용량 이해 및 계산

용량은 규칙 그룹이 수명 동안 보유할 것으로 예상되는 규칙 수입니다. 규칙 그룹이 생성될 때 사전 할당되며 **고정**됩니다. 기존 규칙 그룹의 용량을 늘릴 수 없습니다. 업데이트가 그룹의 용량을 초과하면 API가 거부하며, 더 큰 용량으로 새 규칙 그룹을 생성하고 규칙을 이동해야 합니다.

용량이 소비되는 방식은 규칙 그룹 유형에 따라 다릅니다. 공식 참조는 [AWS Network Firewall에서 규칙 그룹 용량 설정](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-rule-group-capacity.html)을 참조하세요.

**Suricata 호환 IPS 규칙 및 표준 상태 저장 규칙**

각 규칙은 복잡성에 관계없이 정확히 **1 용량 단위**를 소비합니다. 여러 `content` 매치, PCRE 및 다중 flowbits가 있는 규칙도 1입니다. AWS 문서에서 상태 저장 규칙 그룹의 용량을 "수명 동안 보유할 것으로 예상되는 규칙 수"로 추정하라고 말하는 것은: 규칙 수가 용량이며, 규칙 복잡성에 대한 승수가 없다는 의미입니다.

**도메인 목록 규칙 그룹**

첫 번째 도메인은 HTTP의 경우 2 용량, HTTPS의 경우 1, 두 프로토콜이 모두 선택된 경우 3을 소비합니다. 첫 번째 이후의 모든 도메인은 프로토콜당 1 용량을 소비합니다. strict 순서 도메인 목록 규칙 그룹은 자동으로 drop 규칙을 생성하지 않으므로, 방화벽 정책에서 직접 drop established 기본 작업을 구성해야 합니다. [기본 작업](../../firewall-policy-configuration/docs/index.md#기본-작업)을 참조하세요.

예를 들어, 20개 도메인, allow 규칙 작업, HTTP 및 HTTPS 모두 선택된 도메인 목록 규칙 그룹:

```
도메인 1:      3 용량
도메인 2-20:   각 2 용량(프로토콜당 1)

총합 = 3 + (2 x 19) = 41
```

**스테이트리스 규칙 그룹**

스테이트리스 용량은 다르게 계산됩니다: 단일 규칙의 용량은 각 매치 설정의 사양 수의 *곱*입니다. 2개 프로토콜, 3개 소스, 5개 대상을 지정하는 규칙은 2 x 3 x 5 = 30입니다. 위에 링크된 용량 문서에 전체 계산 및 작업 예제가 있습니다.

### 필요한 용량 확인

용량을 수동으로 계산할 필요가 없습니다. 정확한 숫자를 얻는 세 가지 방법이 있습니다:

* **생성 호출 드라이 런.** `DryRun`을 `true`로 설정하여 `CreateRuleGroup`을 호출합니다. Network Firewall은 요청을 평가하고 아무것도 생성하지 않고 규칙 그룹이 소비할 양을 반환합니다. 응답에서 `ConsumedCapacity`를 읽으세요. 이것이 가장 신뢰할 수 있는 방법이며 파이프라인에서 사용할 방법입니다. 드라이 런에 넉넉한 `--capacity` 값을 전달하여 요청이 보고하기 전에 거부되지 않도록 하세요.

    ```
    aws network-firewall create-rule-group \
        --rule-group-name my-rule-group \
        --type STATEFUL \
        --capacity 30000 \
        --rule-group file://rules.json \
        --dry-run \
        --query 'RuleGroupResponse.ConsumedCapacity'
    ```

* **오류 메시지 읽기.** 불충분한 용량으로 규칙 그룹을 생성하려고 하면 오류가 필요한 값을 직접 알려줍니다:

    ```
    An error occurred (InvalidRequestException) when calling the CreateRuleGroup operation:
    StatefulRules capacity exceeded, parameter: [67], context: RulesSource.StatefulRules
    ```

    이 예에서 규칙 세트는 최소 67 용량 단위가 필요합니다.

* **기존 규칙 그룹 설명.** `ConsumedCapacity` 필드는 기존 규칙 그룹의 용량 중 얼마나 사용 중인지 보여줍니다.

    ```
    aws network-firewall describe-rule-group \
        --type STATEFUL \
        --rule-group-name my-rule-group
    ```

!!! tip "모범 사례"
    `DryRun` 생성 호출로 필요한 용량을 결정한 다음, 실제 용량을 그보다 훨씬 높게 설정하세요. 모든 사용자 정의 규칙을 하나의 그룹으로 통합하는 경우, 관리형 규칙 그룹을 고려한 후 남은 것으로 용량을 설정하세요. 사용하지 않는 용량은 비용이 들지 않습니다.

### 성장 계획

시간이 지남에 따라 성장할 수 있는 도메인 허용 목록을 구축하는 경우, 용량 제한뿐만 아니라 2MB 규칙 그룹 바이트 제한도 계획하세요. 실용적인 접근 방식은 각 규칙 그룹을 약 7,500개의 도메인 규칙으로 제한하여 규칙당 주석 및 향후 성장을 위한 여유를 남기는 것입니다.

도메인 목록이 규칙 그룹의 용량에 접근하는 경우, 여러 규칙 그룹에 분할하는 대신 단일 규칙에서 많은 도메인을 매칭하는 PCRE 규칙을 고려하세요. PCRE 규칙 하나는 다루는 도메인 수에 관계없이 1 용량 단위입니다. 패턴과 트레이드오프는 [단일 규칙에서 여러 도메인 허용](../../sample-suricata-rules/docs/index.md#allow-multiple-domains-in-a-single-rule-pcre)을 참조하세요.

### 서명 ID(SID)

모든 Suricata 규칙에는 해당 규칙의 고유한 숫자 식별자인 서명 ID(SID)가 필요합니다. SID는 해당 규칙에 의해 생성된 모든 알림 로그 항목에 포함되어, 주어진 트래픽 플로우에서 어떤 규칙이 작동했는지 식별하는 기본 키가 됩니다. SID는 `sid:` 키워드로 정의됩니다:

```
pass tls $HOME_NET any -> any any (tls.sni; content:"example.com"; flow:to_server; sid:100001;)
```

로그에서 알림을 보면 SID가 어떤 규칙이 매칭했는지 알려줍니다. 알림 로그 이벤트에는 규칙이 속한 규칙 그룹을 식별하는 `aws_metadata.resource_arn` 필드도 포함되어, 두 개의 다른 규칙 그룹에서 재사용된 SID도 로그에서 모호하지 않습니다. 규칙셋에서 규칙을 쉽게 찾을 수 있도록 설명적인 `msg:` 필드와 SID 번호 규칙을 결합하세요. SID와 규칙 그룹 ARN이 함께 사용되어 규칙별 트래픽 매치를 보고하는 방법은 [규칙 히트 카운트](../../logging-and-monitoring/docs/index.md#rule-hit-count)를 참조하세요.

## 도메인 필터링

TLS SNI 및 HTTP 호스트 헤더에 대한 도메인 기반 필터링은 Network Firewall의 가장 일반적이고 효과적인 사용 사례 중 하나입니다. CDN 뒤에 있거나 IP가 자주 변경되는 서비스에 대한 IP 기반 규칙을 관리하지 않고도 워크로드가 통신하는 도메인을 제어할 수 있습니다.

!!! tip "모범 사례"
    이그레스 트래픽에 대한 도메인 허용 목록을 구현하세요: 워크로드에 필요한 도메인만 명시적으로 허용하고 나머지는 기본적으로 차단합니다. 이는 인터넷의 모든 나쁜 대상을 식별하고 차단하려는 것(불가능한 작업)에서 워크로드가 실제로 액세스해야 하는 알려진 안전한 도메인만 허용하고 나머지를 기본적으로 차단하는 보안 모델로 전환하여, 위험 표면을 극적으로 줄이기 때문에 매우 일반적으로 권장하는 구성입니다.

Network Firewall은 두 가지 소스에서 도메인 정보를 검사합니다:

* **TLS SNI** - TLS Client Hello의 Server Name Indication 필드(`tls.sni` 키워드로 매칭)
* **HTTP 호스트 헤더** - 평문 HTTP 요청의 Host 헤더(`http.host` 키워드로 매칭)

도메인 기반 규칙은 규칙 작성 방법에 따라 대상 포트에 관계없이 매칭합니다. 이 가이드의 샘플 규칙은 대상 포트에 `any`를 사용하므로 모든 포트에서 TLS 또는 HTTP 트래픽을 매칭합니다. 도메인 기반 규칙은 기본 연결이 IPv4 또는 IPv6를 사용하는지에 관계없이 작동하며, 이는 듀얼 스택 환경에서 IP 기반 필터링에 비해 상당한 이점입니다.

완전한 도메인 필터링 규칙 예제(정확한 매치, dotprefix를 사용한 와일드카드 서브도메인 매칭, 단일 규칙에서 여러 도메인을 위한 PCRE, HTTP/HTTPS 변형)는 [샘플 Suricata 규칙](../../sample-suricata-rules/docs/index.md#allow-rules-and-domain-allowlisting)을 참조하세요.

### SNI 조작 및 TLS 검사 고려 시기

TLS SNI 필터링은 일반적인 산업 표준이지만 알려진 제한이 있습니다: 클라이언트 시스템이 침해된 경우, 합법적인 도메인을 SNI 필드에 넣으면서 다른(악성) IP 주소에 연결하는 TLS 요청을 작성할 수 있습니다. 실제로 대부분의 고객은 도메인 허용 목록이 이미 공격 표면을 극적으로 줄이므로 이 위험을 수용합니다. 비인가 당사자는 워크로드를 침해할 뿐만 아니라 허용 목록에 어떤 특정 도메인이 있는지도 알아야 합니다.

이 위험을 수용할 수 없는 조직의 경우, [TLS 검사](../../tls-inspection/docs/index.md)(복호화)를 활성화하면 이 우려가 제거됩니다. TLS가 복호화되면 방화벽은 SNI가 서버가 제시하는 인증서와 일치하는지 검증합니다. 불일치는 자동으로 차단됩니다.

## 허용된 트래픽 기록

Suricata의 Pass 규칙은 로그 항목을 생성하지 않고 트래픽을 허용합니다. 차단되는 것뿐만 아니라 허용되는 트래픽에 대한 가시성이 필요한 경우, pass 규칙에서 명시적으로 로깅을 활성화해야 합니다.

!!! tip "모범 사례"
    기록하려는 모든 pass 규칙에 `alert;` 키워드를 추가하세요. 이것이 가장 간단한 접근 방식이며 규칙셋을 간결하게 유지합니다.

```
# alert; 키워드를 통해 로깅이 활성화된 Pass 규칙
pass tls $HOME_NET any -> any any (alert; msg:"allowed *.amazonaws.com"; tls.sni; dotprefix; content:".amazonaws.com"; nocase; endswith; flow:to_server; sid:100001;)
```

`alert;` 키워드는 pass 규칙이 로그 항목을 생성하도록 하며, 로그는 방화벽이 트래픽에 대해 수행한 것을 정확히 반영하는 `verdict.action`이 `pass`로 표시됩니다.

pass 규칙을 기록하는 것은 [규칙 히트 카운트](../../logging-and-monitoring/docs/index.md#rule-hit-count)에서 보이게 하는 것이기도 합니다. 히트 카운터는 규칙 매치가 알림 로그 항목을 생성할 때만 증가하므로, `alert;`가 없는 pass 규칙은 얼마나 많은 트래픽을 허용하든 Top Rule Hits 뷰에 나타나지 않습니다.

## IP 세트 참조

크거나 자주 변경되는 IP 주소 세트를 참조해야 하는 규칙의 경우, 관리형 접두사 목록에 연결된 [IP 세트 참조](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-ip-set-references.html)를 사용하세요. IP 세트 참조는 `@` 접두사를 사용하며 규칙 그룹을 수정하거나 재배포하지 않고 IP 목록을 업데이트할 수 있습니다.

!!! tip "모범 사례"
    대상 주소가 시간이 지남에 따라 변경되는 모든 IP 기반 규칙(파트너 IP, SaaS 프로바이더 범위, 내부 서비스 엔드포인트)에 접두사 목록에 연결된 IP 세트 참조를 사용하세요. 이렇게 하면 규칙 정의가 참조하는 특정 IP에서 분리됩니다.

```
pass tls @partnercidrs any -> $HOME_NET 443 (msg:"Allow partner ingress on TLS/443"; flow:to_server; sid:202608211;)
```

고객 관리 또는 AWS 관리 접두사 목록을 규칙 그룹의 IP 세트 참조와 연결하세요. 접두사 목록이 업데이트되면 방화벽 규칙이 자동으로 새 항목을 반영합니다.

제한:

* 상태 저장 규칙 그룹당 최대 5개의 IP 세트 참조
* 접두사 목록당 최대 1,000개 항목
* 20개 규칙 그룹 x 5개 참조 x 1,000개 항목 = 최대 100,000개 CIDR 지원

[컨테이너 속성 연결](https://docs.aws.amazon.com/network-firewall/latest/developerguide/container-associations.html) 기능도 IP 세트를 사용하여 컨테이너 워크로드 IP를 동적으로 참조하지만, 규칙 그룹당 5개 IP 세트 참조 제한은 컨테이너 연결 IP 세트에는 적용되지 않습니다. 이는 컨테이너 속성 연결과 충돌 걱정 없이 수동으로 관리하는 접두사 목록에 IP 세트 참조를 사용할 수 있음을 의미합니다.

구성 세부 사항은 [규칙 그룹의 IP 세트 참조](https://docs.aws.amazon.com/network-firewall/latest/developerguide/rule-groups-ip-set-references.html)를 참조하세요.

## Suricata 규칙 생성기로 규칙 작성

사용자 정의 Suricata 규칙을 올바르게 작성하려면 적절한 `flow:` 키워드 배치, 고유한 SID, 유효한 프로토콜/작업 조합, 일관된 서식 지정, 리비전 추적 등 많은 세부 사항에 주의해야 합니다. [AWS Network Firewall용 Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator)는 이러한 문제를 자동으로 처리하도록 설계된 오픈소스 GUI 애플리케이션으로, 구문을 올바르게 작성하는 것이 아닌 *무엇을* 필터링할지에 집중할 수 있습니다.

![Suricata 규칙 생성기 인터페이스](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/screenshot.png)

### 도구가 해주는 것

* **자동 `flow:` 키워드** - 규칙을 작성할 때 적절한 경우 도구가 `flow:to_server`를 적용하여, Network Firewall 배포에서 가장 일반적인 규칙 충돌(위에서 설명한 SIG_TYPE_IPONLY vs 애플리케이션 계층 규칙 상호 작용)을 방지
* **실시간 구문 검증** - 지원되는 작업(`pass`, `drop`, `reject`, `alert`), 지원되는 프로토콜, 유효한 네트워크/포트 형식, 올바르게 구조화된 규칙 옵션만 허용. 저장 전에 오류가 표시됩니다.
* **자동 SID 관리** - 새 규칙에 대해 다음 사용 가능한 SID를 제안하고, 규칙 그룹 내 중복 SID를 방지하며, 규칙 재정리 시 대량 SID 번호 재지정 제공
* **자동 리비전 추적** - 규칙 필드가 변경되면 `rev` 키워드가 자동 증가하여 규칙별 내장 버전 기록 제공
* **색상 코드 규칙 테이블** - 규칙이 작업 유형별로 시각적으로 구성됨(pass는 녹색, drop은 빨간색, reject는 보라색, alert는 파란색, 주석은 회색). 대규모 규칙셋을 스캔하고 구조를 한눈에 이해하기 쉽습니다.
* **콘텐츠 키워드 자동 완성** - 규칙 옵션을 구축할 때 프로토콜 인식 Suricata 키워드 제안(`tls.sni`, `http.host`, `ja3.hash`, `aws_domain_category` 등)
* **규칙 충돌 분석** - 배포 전에 규칙셋의 다른 규칙과 섀도우하거나 충돌하는 규칙을 감지하여 보안 우회 및 도달할 수 없는 규칙 식별
* **인프라 내보내기** - 적절한 용량 계산, 변수 매핑, strict 규칙 순서가 자동으로 구성된 AWS Network Firewall, Terraform 또는 CloudFormation으로 규칙을 직접 내보내기

### 규칙 작성 외

이 도구는 이 가이드의 다른 섹션에서 다루는 기능도 제공합니다:

* 도메인 허용 목록 구축을 위한 자동 통합이 포함된 [대량 도메인 가져오기](../../logging-and-monitoring/docs/index.md#convert-domain-reports-to-suricata-rules)
* AWS 관리형 위협 서명에서 필터링되고 자동 업데이트되는 규칙 그룹을 생성하기 위한 [관리형 규칙 그룹 생성기](../../aws-managed-rules/docs/index.md#filtered-managed-rule-groups-with-suricata-rule-generator)
* 프로덕션에서 사용되지 않거나 지나치게 광범위한 규칙을 식별하기 위한 [CloudWatch 규칙 사용량 분석](../../logging-and-monitoring/docs/index.md#rule-usage-analysis-with-suricata-rule-generator)
* 방화벽 데이터 처리 비용이 어디에서 발생하는지 이해하기 위한 [트래픽 비용 분석기](../../cost-considerations/docs/index.md#suricata-규칙-생성기로-트래픽-비용-분석)
* Amazon Bedrock을 사용하여 평문 영어 설명에서 규칙을 생성하는 AI 규칙 어시스턴트
* AWS 콘솔에서 생성된 표준 상태 저장 규칙 그룹을 사용자 정의 Suricata 규칙으로 직접 가져오기

설치 지침, 문서 및 전체 기능 세트는 [Suricata 규칙 생성기 GitHub 리포지토리](https://github.com/aws-samples/sample-suricata-generator)를 참조하세요.

## 다음 읽을 내용

* [샘플 Suricata 규칙](../../sample-suricata-rules/docs/index.md) - 사용 사례별 완전한 규칙 템플릿 및 개별 규칙 예제
* [AWS 관리형 규칙](../../aws-managed-rules/docs/index.md) - 위협 탐지를 위한 AWS 관리형 규칙 그룹
* [로깅 및 모니터링](../../logging-and-monitoring/docs/index.md) - 규칙이 수행하는 작업 분석
