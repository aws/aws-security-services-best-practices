# 로깅 및 모니터링

!!! info "사전 요구 사항"
    이 섹션은 [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md) 및 [고객 관리 규칙](../../customer-managed-rules/docs/index.md)에 대한 이해를 전제로 합니다. 특히 기본 작업, 스트림 예외 정책, `alert;` 키워드를 사용한 pass 규칙 로깅을 먼저 검토하세요.

AWS Network Firewall은 세 가지 [로그 유형](https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging.html)을 게시합니다: 알림, 플로우, TLS. 알림 로그는 규칙이 트래픽과 일치할 때 거의 실시간으로 생성됩니다. 플로우 로그는 연결이 종료된 후에만 게시됩니다. TLS 로그는 TLS 검사가 활성화된 경우 인증서 검증 이벤트를 보고합니다. 알림 로그는 활성 모니터링을 위한 기본 운영 도구이며, 플로우 로그는 사후 트래픽 볼륨 및 연결 상태 분석을 제공합니다. 이 페이지에서는 로그 유형, 대상, 분석 기법, 대시보드, 알림을 다룹니다.

## 로그 유형

### 알림 로그

알림 로그는 트래픽이 알림 생성 작업(DROP, ALERT, REJECT)이 있는 상태 저장 규칙과 일치하거나 pass 규칙에서 `alert;` 키워드를 사용할 때 생성됩니다. 알림 로그가 캡처하는 내용:

* 규칙 일치 정보(서명 ID, 리비전, 메시지, 심각도)
* 판정(최종 수행된 작업: pass, drop, reject, alert)
* 7계층 속성(TLS SNI, HTTP 호스트/URL/메서드/사용자 에이전트, 프로토콜 탐지)
* 전체 5-튜플(소스/대상 IP 및 포트, 프로토콜)
* 플로우 로그와 상관관계를 위한 플로우 ID
* 방향(to_server 또는 to_client)
* 도메인 카테고리 정보(URL/도메인 카테고리 필터링 사용 시)
* `aws_metadata.resource_arn` 필드의 규칙 그룹 ID. 두 개의 다른 규칙 그룹에서 동일한 SID도 모호하지 않습니다.

!!! note "알림 로그 작업 이해"
    알림 로그 이벤트는 두 가지 작업 관련 필드를 보여줍니다. `alert.action` 필드는 **알림 규칙 자체**가 허용했는지 차단했는지를 나타내는 "allowed" 또는 "blocked"를 표시합니다. `verdict.action` 필드는 플로우에 대한 **최종 판정**(pass, drop, reject, alert)을 보여줍니다. 알림 규칙 일치는 플로우가 나중에 규칙이나 기본 작업에 의해 최종적으로 차단되더라도 `alert.action: "allowed"`를 보여줍니다. 항상 `verdict.action`에서 실제 결과를 확인하세요.

### 플로우 로그

플로우 로그는 **플로우가 종료된 후**에만 게시됩니다. 정상 종료(양방향 FIN-ACK 또는 RST) 또는 유휴 타임아웃을 통해 종료됩니다. 캡처하는 내용:

* 방화벽을 통과하는 모든 트래픽에 대한 5-튜플 정보
* 트래픽 볼륨(각 방향의 바이트 및 패킷)
* 플로우 수명 동안 관찰된 TCP 플래그
* 플로우 기간, 시작/종료 타임스탬프
* 감지된 애플리케이션 계층 프로토콜(app_proto)
* 플로우 ID(상관관계를 위해 알림 로그와 공유)

단일 TCP 플로우에 대해 Suricata는 두 개의 플로우 로그 이벤트를 게시합니다: 하나는 클라이언트-서버, 하나는 서버-클라이언트. 둘 다 동일한 `flow_id`를 공유합니다.

!!! note "플로우 로그는 실시간이 아닙니다"
    플로우 로그 이벤트는 플로우가 종료된 후에만 게시됩니다. 활성 연결에 대한 플로우 로그가 보이지 않는 것은 정상입니다. 활성 트래픽에 대한 실시간 가시성은 알림 로그를 사용하세요.

### TLS 로그

TLS 로그는 방화벽에서 [TLS 검사 구성](../../tls-inspection/docs/index.md)이 활성화된 경우에만 생성됩니다. 인증서 검증 오류, 폐기 확인 결과, SNI 불일치 이벤트를 포함한 TLS 검사 관련 이벤트를 보고합니다. TLS 검사를 사용하지 않으면 TLS 로그 이벤트가 표시되지 않습니다.

## 로그 대상

Network Firewall은 세 가지 [대상](https://docs.aws.amazon.com/network-firewall/latest/developerguide/firewall-logging-destinations.html)으로 로그를 보낼 수 있습니다(각 로그 유형에 대해 독립적으로 구성):

| 대상 | 적합한 용도 |
|------------|----------|
| **Amazon CloudWatch Logs** | 실시간 분석, 알림, 빠른 운영 쿼리 |
| **Amazon S3** | 장기 저장, 규정 준수, Athena를 사용한 대규모 분석 |
| **Amazon Data Firehose** | 타사 SIEM 도구(Splunk, Datadog) 또는 OpenSearch로 스트리밍 |

각 로그 유형(알림, 플로우, TLS)은 하나의 대상으로 보낼 수 있습니다. 예를 들어, 알림 로그를 CloudWatch Logs에, 플로우 로그를 S3에 보낼 수 있지만, Network Firewall 구성에서 직접 알림 로그를 CloudWatch와 S3 모두에 보낼 수는 없습니다. 여러 위치에 로그가 필요한 경우, CloudWatch Logs로 보내고 구독 필터를 구성하여 S3 또는 다른 대상으로 복제하세요.

!!! tip "모범 사례"
    방화벽 플로우 및 알림 로그를 **별도의** 로그 그룹 또는 S3 버킷 접두사에 게시하세요. 이렇게 하면 각 로그 유형을 독립적으로 쿼리하고 문제 해결 시 상관관계를 파악하기가 더 쉬워집니다.

### 로그 대상 변경

다른 로그 대상으로 전환하려면, 먼저 로깅을 비활성화한 다음 새 대상으로 다시 활성화해야 합니다. 대상을 제자리에서 변경하려고 하면 오류가 발생합니다. 방화벽을 삭제하기 전에도 로깅을 비활성화해야 합니다.

## 플로우 로그 이해

### 플로우 로그의 TCP 플래그

TCP 플로우에 대한 플로우 로그 이벤트에는 플로우 수명 동안 관찰된 모든 TCP 플래그를 나타내는 16진수 값인 `tcp_flags` 필드가 포함됩니다:

| tcp_flags | 의미 |
|-----------|---------|
| `1b` (SYN+FIN+PSH+ACK) | 정상적으로 완료된 연결(정상 종료) |
| `1f` (SYN+FIN+RST+PSH+ACK) | 종료 중 리셋이 있는 연결 |
| `02` (SYN만) | SYN이 전송되었지만 SYN-ACK가 수신되지 않음(라우팅/SG/NACL 문제 가능) |
| `00` (플래그 없음) | 중간 스트림 플로우일 가능성 |

### 플로우 로그 예제

요청 플로우(클라이언트에서 서버):

```json
{
    "firewall_name": "networkfirewall",
    "availability_zone": "eu-west-1a",
    "event_timestamp": "1755003965",
    "event": {
        "tcp": {
            "tcp_flags": "1b",
            "syn": true,
            "fin": true,
            "psh": true,
            "ack": true
        },
        "app_proto": "http",
        "src_ip": "10.80.1.44",
        "src_port": 59772,
        "netflow": {
            "pkts": 6,
            "bytes": 395,
            "start": "2025-08-12T13:05:03.931841+0000",
            "end": "2025-08-12T13:05:03.942320+0000",
            "age": 0,
            "min_ttl": 126,
            "max_ttl": 126,
            "state": "closed",
            "reason": "timeout",
            "alerted": false
        },
        "event_type": "netflow",
        "flow_id": 2031903400513076,
        "dest_ip": "209.85.203.113",
        "proto": "TCP",
        "dest_port": 80,
        "timestamp": "2025-08-12T13:06:05.059525+0000"
    }
}
```

!!! note "state: closed + reason: timeout"
    클라이언트-서버 플로우에서 `"state": "closed"`와 `"reason": "timeout"`이 함께 보이는 것은 정상입니다. 연결이 정상적으로 종료된 후 Suricata의 내부 플로우 추적 상태가 만료되었음을 의미합니다. TCP 연결 자체가 타임아웃되었다는 의미가 아닙니다.

### 중간 스트림 플로우 식별

`"tcp_flags": "00"`(관찰된 TCP 플래그 없음)인 플로우 로그 이벤트는 일반적으로 중간 스트림 플로우, 즉 방화벽이 연결 설정을 보지 못한 채 수신한 트래픽과 관련됩니다. 이러한 이벤트를 쿼리하고 `StreamExceptionPolicyPackets` CloudWatch 지표의 급증과 상관관계를 파악하여 스트림 예외 정책에 영향을 받는 플로우를 식별할 수 있습니다.

### 플로우 및 알림 로그 상관관계

`flow_id` 필드는 동일한 연결에 대한 플로우 로그와 알림 로그 간에 공유됩니다. 플로우의 전체 그림을 얻으려면:

1. 관심 있는 트래픽의 알림 로그 이벤트 찾기
2. `flow_id` 값 복사
3. 해당 `flow_id`로 플로우 로그 그룹 검색
4. 트래픽 볼륨, TCP 플래그, 타이밍을 보여주는 요청 및 응답 플로우 로그 이벤트 확인

**양** 방향(클라이언트-서버 및 서버-클라이언트)의 플로우 로그 이벤트가 보이면 라우팅이 대칭으로 구성되어 있고 방화벽이 대화의 양쪽을 모두 보고 있음을 확인합니다.

## 알림 로그 이해

알림 로그는 활성 모니터링을 위한 기본 운영 도구입니다. 이를 해석하는 방법과 보이는 것에 따라 어떤 조치를 취해야 하는지 이해하는 것은 Network Firewall을 효과적으로 운영하는 데 필수적입니다.

!!! tip "모범 사례"
    배포 후 처음 2주 동안은 매일 알림 로그를 확인하고, 트래픽 패턴이 확립되면 주간 검토로 전환하세요. 세 가지에 집중하세요: 예상치 못한 차단(합법적인 트래픽이 차단됨), 예상치 못한 허용(차단되어야 할 트래픽이 통과), 관리형 규칙 그룹 일치(탐지된 잠재적 위협).

### 알림 로그에서 찾을 것

**판정 필드:** 플로우의 실제 결과는 항상 `verdict.action`을 확인하세요. `alert.action` 필드는 플로우에 대한 최종 결정이 아니라 규칙 자체가 "허용"했는지 "차단"했는지를 보여주므로 오해의 소지가 있습니다. `alert;` 키워드가 있는 pass 규칙은 `alert.action: "allowed"`와 `verdict.action: "pass"`를 보여주며, 이는 트래픽이 허용되고 기록되었음을 의미합니다.

**서명 ID 및 규칙 그룹:** `alert.signature_id`는 어떤 규칙이 작동했는지, `aws_metadata.resource_arn`은 어떤 규칙 그룹에서 왔는지 알려줍니다. 함께 사용하면 동일한 SID가 두 개 이상의 규칙 그룹에 나타나더라도 규칙을 모호하지 않게 식별합니다. SID 2, 4, 6, 8은 방화벽 정책의 strict 순서 기본 작업에 대한 시스템 생성 서명이며, 이 경우 `resource_arn`은 규칙 그룹 ARN이 아닌 방화벽 정책 ARN입니다. 2000000 이상의 SID는 일반적으로 AWS 관리형 위협 서명 규칙입니다.

**App proto:** `app_proto` 필드는 포트에 관계없이 Suricata가 감지한 애플리케이션 계층 프로토콜을 보여줍니다. 포트 443에서 `app_proto: "ssh"`가 보이면, 이는 포트/프로토콜 적용 규칙이 포착해야 하는 프로토콜 위반입니다.

### 알림 로그 기반 조치

| 보이는 것 | 의미 | 조치 |
|---|---|---|
| 필요한 도메인에 SID 4(기본 작업)로 차단 | 합법적인 트래픽이 기본 거부에 의해 차단됨 | 허용 목록에 해당 도메인에 대한 pass 규칙 추가 |
| 내부 트래픽에 대한 관리형 규칙 그룹의 알림 | 관리형 위협 서명이 워크로드의 트래픽과 일치 | 워크로드 조사. 서명이 진양성인지 또는 애플리케이션에 예상되는 트래픽 패턴인지 확인. |
| 동일 소스 IP에서 많은 대상으로의 반복적 차단 | 워크로드가 광범위한 아웃바운드 통신을 시도 | 잠재적 침해 조사. 워크로드가 스캐닝 또는 C2를 시도하는지 확인. |
| "Command and Control"을 보여주는 `aws_category` 알림 | 워크로드가 C2로 분류된 도메인에 도달하려고 시도 | 높은 우선순위 조사. 워크로드를 식별하고 침해되었는지 확인. |
| `app_proto: "failed"`인 플로우 | Suricata가 애플리케이션 프로토콜을 감지하지 못함 | 트래픽이 비정상적이거나 사용자 정의 프로토콜을 사용할 수 있음. 예상되는지 확인. |

### drop established 기본 작업의 알림 로그

트래픽이 alert established가 활성화된 상태 저장 기본 drop 작업과 일치할 때:

```json
{
    "firewall_name": "use1-fw",
    "availability_zone": "us-east-1b",
    "event_timestamp": "1741966203",
    "event": {
        "app_proto": "http",
        "src_ip": "10.170.22.77",
        "src_port": 57516,
        "event_type": "alert",
        "alert": {
            "severity": 3,
            "signature_id": 4,
            "rev": 0,
            "signature": "aws:alert_established action",
            "action": "blocked",
            "category": ""
        },
        "flow_id": 1262530044160208,
        "dest_ip": "23.218.218.146",
        "proto": "TCP",
        "verdict": {
            "action": "drop"
        },
        "http": {
            "hostname": "ctldl.windowsupdate.com",
            "url": "/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab",
            "http_user_agent": "Microsoft-CryptoAPI/10.0",
            "http_method": "GET",
            "protocol": "HTTP/1.1",
            "length": 0
        },
        "dest_port": 80,
        "timestamp": "2025-03-14T15:30:03.633598+0000",
        "direction": "to_server"
    }
}
```

### pass 규칙(alert; 키워드 사용)의 알림 로그

`alert;` 키워드를 포함하는 pass 규칙에 의해 트래픽이 허용되면, 알림 로그는 방화벽이 트래픽을 허용했음을 정확히 반영하는 `verdict.action`이 "pass"로 표시됩니다:

```json
{
    "firewall_name": "use1-fw",
    "availability_zone": "us-east-1a",
    "event_timestamp": "1752419374",
    "aws_metadata": {
        "resource_arn": "arn:aws:network-firewall:us-east-1:123456789012:stateful-rulegroup/custom-egress-rules"
    },
    "event": {
        "tx_id": 0,
        "app_proto": "tls",
        "src_ip": "10.170.18.47",
        "src_port": 49402,
        "event_type": "alert",
        "alert": {
            "severity": 3,
            "signature_id": 100003,
            "rev": 1,
            "signature": "matching TLS allow-listed FQDNs",
            "action": "allowed",
            "category": ""
        },
        "flow_id": 1734870487617660,
        "dest_ip": "67.220.244.190",
        "proto": "TCP",
        "verdict": {
            "action": "pass"
        },
        "tls": {
            "sni": "ssm.us-east-1.amazonaws.com",
            "version": "UNDETERMINED"
        },
        "dest_port": 443,
        "timestamp": "2025-07-13T15:09:34.606289+0000",
        "direction": "to_server"
    }
}
```

### 도메인 카테고리 알림 로그

URL/도메인 카테고리 필터링을 사용할 때 `aws_category` 필드는 어떤 카테고리가 일치했는지 보여줍니다:

```json
{
    "firewall_name": "use1-fw",
    "availability_zone": "us-east-1a",
    "event_timestamp": "1769632645",
    "event": {
        "aws_category": "[\"Social Networking\"]",
        "app_proto": "tls",
        "src_ip": "10.170.18.98",
        "src_port": 48420,
        "event_type": "alert",
        "alert": {
            "severity": 3,
            "signature_id": 666,
            "rev": 1,
            "signature": "Domain Category Social Networking",
            "action": "blocked",
            "category": ""
        },
        "flow_id": 1438444877819569,
        "dest_ip": "157.240.229.35",
        "proto": "TCP",
        "verdict": {
            "action": "drop"
        },
        "tls": {
            "sni": "www.facebook.com",
            "version": "UNDETERMINED"
        },
        "dest_port": 443,
        "timestamp": "2026-01-28T20:37:25.670695+0000",
        "direction": "to_server"
    }
}
```

## 방화벽 모니터링 대시보드

네이티브 [방화벽 모니터링 대시보드](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-using-dashboard.html)는 주요 트래픽 발생자, 상위 프로토콜, 알림 활동, 트래픽 패턴을 포함한 주요 지표의 내장 뷰를 제공합니다. 사용 가능한 지표는 [상세 모니터링 지표](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-detailed-monitoring-metrics.html) 참조에 문서화되어 있습니다.

!!! tip "모범 사례"
    네이티브 방화벽 모니터링 대시보드를 기본 운영 뷰로 사용하세요. 추가 설정이나 인프라 없이 트래픽 패턴, 상위 트래픽 발생자, 알림 활동에 대한 즉각적인 가시성을 제공합니다.

### 규칙 히트 카운트

[규칙 히트 카운트](https://aws.amazon.com/blogs/security/aws-network-firewall-now-supports-rule-hit-count/)는 사용자 정의 규칙과 AWS 관리형 규칙 그룹 모두에 대해 각 상태 저장 규칙이 트래픽과 얼마나 자주 일치하는지 보고합니다. 이 기능 이전에는 "내 규칙 중 실제로 작동하는 것은?"에 답하려면 수동 로그 분석이 필요했습니다. 이제 대시보드 뷰입니다.

규칙 히트 카운트는 기본적으로 활성화되며 구성이 필요하지 않습니다. 사용하려면 방화벽에 알림 로깅이 구성되어 있어야 하며, 대시보드 위젯을 보려면 상세 모니터링이 활성화되어 있어야 합니다. 콘솔에서 방화벽의 **모니터링 및 관찰 가능성** 탭, **상위 분석** 아래의 **Top Rule Hits** 지표에서 찾을 수 있습니다. 뷰는 히트 카운트, 총 히트 비율, 리소스 ARN, 서명 ID, 규칙의 `msg:` 필드를 설명으로, UTC의 마지막 발생 타임스탬프를 보여줍니다. 카운트는 리전의 모든 가용 영역에 걸쳐 방화벽별로 집계됩니다.

!!! tip "모범 사례"
    매월 Top Rule Hits를 검토하세요. 의미 있는 기간 동안 트래픽과 일치하지 않은 규칙은 제거 후보입니다: 용량을 소비하고, 규칙셋에 노이즈를 추가하며, 종종 strict 순서에서 앞선 규칙이 이를 섀도잉하고 있다는 증거입니다. 반대 방향으로도 사용하여, 새로 배포한 규칙을 `alert`에서 `drop`으로 전환하기 전에 예상한 트래픽과 일치하는지 확인하세요.

!!! danger "일반적인 잘못된 구성"
    히트 카운터는 규칙 일치가 알림 로그 항목을 생성할 때만 증가합니다. 즉, `alert`, `drop`, `reject` 규칙은 카운트되지만, `pass` 규칙은 기본적으로 알림 로그를 생성하지 않으므로 카운트되지 않습니다. `alert;` 키워드가 없는 pass 규칙은 얼마나 많은 트래픽을 허용하든 히트가 0으로 나타나며, 워크로드가 의존하는 규칙을 삭제할 수 있습니다. 카운트하려는 모든 pass 규칙에 `alert;`를 추가하세요. [허용된 트래픽 기록](../../customer-managed-rules/docs/index.md#허용된-트래픽-기록)을 참조하세요.

알아두어야 할 다른 사항:

* 메타데이터는 상세 모니터링 활성화 여부에 관계없이 방화벽 로그에 기록되므로, 원시 로그에서 직접 자체 대시보드나 쿼리를 구축할 수 있습니다.
* 스테이트리스 규칙은 히트 카운트 추적을 지원하지 않습니다.
* 히트를 특정 규칙으로 추적하려면 `alert.signature_id`와 `aws_metadata.resource_arn`의 조합으로 검색하세요. 서명 ID 2, 4, 6, 8은 정책의 strict 순서 기본 작업이며, 이 경우 `resource_arn`은 방화벽 정책 ARN입니다.
* 기능 자체는 무료이지만, 그 뒤의 로그 저장 및 쿼리에는 비용이 듭니다. 로그 그룹에 보존 정책을 설정하세요. [로깅 비용 절감](#로깅-비용-절감)을 참조하세요.
* 규칙 히트 카운트는 Middle East(UAE) 및 Middle East(Bahrain)를 제외한 Network Firewall이 제공되는 모든 리전에서 사용할 수 있습니다.

콘솔 뷰보다 더 깊은 규칙별 분석(규칙 수명별 확인된 미사용 탐지, 지나치게 광범위한 규칙의 파레토 분석, 여러 규칙 파일에 대한 섀도잉 탐지 포함)은 아래의 [Suricata 규칙 생성기를 사용한 규칙 사용량 분석](#suricata-규칙-생성기를-사용한-규칙-사용량-분석)을 참조하세요.

### 모니터링할 주요 CloudWatch 지표

Network Firewall은 방화벽이 활성화되면 자동으로 CloudWatch에 지표를 게시합니다. 방화벽이 배포되고 트래픽을 처리하는 것 외에 추가 구성이 필요하지 않습니다. CloudWatch 콘솔의 **지표 > AWS/NetworkFirewall**에서 이러한 지표를 보거나, 자동으로 시각화하는 [네이티브 방화벽 모니터링 대시보드](https://docs.aws.amazon.com/network-firewall/latest/developerguide/nwfw-using-dashboard.html)를 사용하세요.

* **`ReceivedPackets`(스테이트리스)** - 0이면 트래픽이 방화벽으로 라우팅되지 않습니다. 라우팅을 확인하세요.
* **`ReceivedPackets`(스테이트풀)** - 0이지만 스테이트리스 ReceivedPackets > 0이면, 스테이트리스 엔진이 스테이트풀로 전달하지 않습니다. 스테이트리스 기본 작업을 확인하세요.
* **`StreamExceptionPolicyPackets`** - 스트림 예외 정책에 의해 처리되는 중간 스트림 플로우.
* **`DroppedPackets` / `RejectedPackets`** - 상태 저장 규칙 또는 기본 작업에 의해 차단되거나 거부되는 트래픽.
* **`TLSReceivedPackets` / `TLSPassedPackets` / `TLSDroppedPackets`** - TLS 검사 활동(활성화된 경우).
* **`TLSErrors`** - TLS 검사 오류(서버 인증서와의 SNI 불일치, 지원되지 않는 암호 모음).

사용 가능한 지표 및 차원의 전체 목록은 [Network Firewall CloudWatch 지표](https://docs.aws.amazon.com/network-firewall/latest/developerguide/monitoring-cloudwatch.html)를 참조하세요.

### 권장 CloudWatch 알람

CloudWatch 콘솔(**알람 > 알람 생성 > 지표 선택 > AWS/NetworkFirewall**)에서 또는 인프라 코드(CloudFormation `AWS::CloudWatch::Alarm`, Terraform `aws_cloudwatch_metric_alarm`)를 통해 이러한 알람을 생성하세요. 각 지표는 방화벽이 배포되고 트래픽을 처리하면 Network Firewall에 의해 자동으로 게시됩니다. 알람을 생성할 때 방화벽 이름과 가용 영역을 차원으로 선택하세요.

* **`DroppedPackets` / `RejectedPackets` 급증에 대한 알람** - 차단되거나 거부된 패킷의 갑작스러운 증가는 종종 소비 워크로드가 이그레스 프로필을 변경했음을 나타냅니다(새 종속성, 잘못 구성된 애플리케이션 또는 침해된 리소스). 기준선이 환경에 따라 다르므로 고정 임계값보다 이상 감지 또는 변화율에 대한 알람을 사용하세요.
* **`StreamExceptionPolicyPackets`에 대한 알람** - 지속적인 상승은 비대칭 라우팅으로 인한 중간 스트림 플로우를 나타냅니다. 장애 조치 이벤트 후 짧은 급증이 예상되며 몇 초 내에 해결되어야 합니다. 5분 기간에 걸쳐 0(또는 설정된 기준선) 이상의 지속적 값에 대해 알람을 설정하세요.
* **`TLSErrors`에 대한 알람** - TLS 검사가 활성화된 경우, TLS 오류 수의 증가는 인증서 문제, 지원되지 않는 암호 모음, 검사를 허용하지 않는 애플리케이션을 나타낼 수 있습니다. 기준선 이상의 지속적 증가에 대해 알람을 설정하세요.
* **트래픽 존재에 대한 `ReceivedPackets` 모니터링** - `ReceivedPackets`가 예기치 않게 0으로 떨어지면, 트래픽이 더 이상 방화벽으로 라우팅되지 않을 수 있습니다. 이에 대해 알람을 설정할지는 환경에 따라 다릅니다. 방화벽에 항상 트래픽이 흐르는 경우, 제로 트래픽 알람이 라우팅 잘못된 구성을 감지하는 데 도움이 됩니다. 트래픽이 간헐적이거나 버스트성인 경우 이 알람은 노이즈를 생성합니다.

## Suricata 규칙 생성기를 사용한 규칙 사용량 분석

[AWS Network Firewall용 Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator)에는 방화벽의 알림 로그를 쿼리하여 규칙별 사용량 분석을 제공하는 CloudWatch 규칙 사용량 분석 기능이 포함되어 있습니다. 네이티브 [규칙 히트 카운트](#규칙-히트-카운트) 뷰는 어떤 규칙이 일치했고 얼마나 자주인지를 알려줍니다. 규칙 사용량 분석기는 동일한 기본 데이터를 가져와 규칙 파일과 상관관계를 분석하여 후속 질문에 답합니다: **히트가 0인 규칙을 안전하게 삭제할 수 있는가, 아니면 판단하기엔 너무 새로운가? 어떤 규칙이 트래픽의 불균형적인 비율을 처리하는가? 어떤 규칙이 섀도잉되고 있는가?**

이것은 지속적인 규칙 위생에 유용합니다. 용량을 확보하기 위해 안전하게 제거할 수 있는 규칙을 식별하고, 불균형적인 트래픽을 처리하는 지나치게 광범위한 규칙을 감지하며, 평가 순서에서 앞선 규칙에 의해 섀도잉될 수 있는 규칙을 찾습니다.

### 분석기가 제공하는 것

분석기는 CloudWatch Logs를 쿼리하여 서명 ID(SID)별 히트 카운트를 집계한 다음, 로컬 규칙 파일과 상관관계를 파악하여 다중 탭 분석을 생성합니다:

* **건강 점수** - 활성 대 미사용 규칙의 비율을 기반으로 한 전체 규칙 그룹 건강 점수(0-100), 영향별로 순위가 매겨진 우선순위 권장 사항
* **미사용 규칙 탐지** - 히트가 0인 규칙, 세 가지 신뢰 수준으로 분리:
    * *확인된 미사용* - 14일 이상(구성 가능) 배포되어 일치 없는 규칙(안전하게 제거)
    * *최근 배포* - 14일 미만(구성 가능) 배포되어 일치 없는 규칙(판단하기엔 너무 새로움)
    * *알 수 없는 수명* - 배포 날짜 정보가 없는 규칙(수동 검토 권장)
* **저빈도 규칙** - 분석 기간에 10회 미만 히트가 있는 규칙, 마지막 히트 이후 일수별로 색상 코드 표시. strict 평가 순서에서 앞선 규칙에 의해 섀도잉된 규칙을 나타낼 수 있습니다.
* **규칙 효과(파레토 분석)** - 트래픽의 대부분을 처리하는 규칙을 식별합니다. 총 트래픽의 10-30% 이상을 처리하는 규칙을 잠재적으로 지나치게 광범위한 것으로 표시하고, 더 나은 가시성을 위해 더 구체적인 규칙으로 분할하는 권장 사항을 제시합니다.
* **효율성 등급** - 사용량 등급(Critical, High, Medium, Low, Unused)에 걸친 규칙의 시각적 분포와 건강 벤치마크
* **기록되지 않는 규칙** - `alert` 키워드가 없는 pass 규칙과 CloudWatch를 통해 추적할 수 없는 `noalert`가 있는 규칙을 식별하여 미사용 탐지에서 제외
* **추적되지 않는 SID** - CloudWatch 로그에서 발견되었지만 현재 규칙 파일에는 없는 SID(최근 삭제된 규칙, AWS 기본 정책 작업 또는 분석에 포함되지 않은 다른 규칙 그룹의 규칙)

![CloudWatch 규칙 사용량 분석](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/usage_analysis.png)

### AWS 관리형 규칙 그룹 분석

분석기는 사용자 정의 규칙과 함께 AWS 관리형 위협 서명 규칙 그룹(ThreatSignaturesPhishing, MalwareDomainList, BotNetCommandAndControl 등)도 포함할 수 있습니다. 이를 통해 사용자 정의 규칙 그룹뿐만 아니라 전체 방화벽 정책의 모든 규칙에 대한 완전한 방화벽 가시성을 얻을 수 있습니다.

포함할 관리형 규칙 그룹을 선택한 후, "All Rules" 탭은 소스, 작업, 히트, 일일 히트별로 정렬 가능한 히트 카운트와 함께 모든 규칙(사용자 정의 및 관리형)을 보여줍니다. 이를 통해:

* 어떤 관리형 규칙 그룹이 트래픽에 대해 활성적으로 트리거되는지 확인
* 용량을 절약하기 위해 제거할 수 있는 히트가 0인 관리형 규칙 그룹 식별
* 방화벽 정책이 탐지하는 것의 전체 그림 이해

![모든 규칙 분석](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/all_rules_analysis.png)

### 다중 파일 분석

방화벽 정책이 여러 사용자 정의 규칙 그룹을 사용하는 경우, 분석기는 이를 단일 분석으로 결합할 수 있습니다. 모든 사용자 정의 파일의 모든 규칙은 건강 점수, 미사용 탐지, 효과 순위를 위해 하나의 통합 풀로 처리되며, 각 규칙은 소스 파일에 귀속됩니다.

![추가 로컬 파일 분석](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/additional_local_files.png)

### 카테고리 기반 도메인 분석

규칙이 [카테고리 기반 필터링](../../sample-suricata-rules/docs/index.md#도메인-카테고리-차단)에 `aws_domain_category` 또는 `aws_url_category` 키워드를 사용하는 경우, 분석기는 각 카테고리 규칙을 트리거한 특정 도메인을 보여줍니다. 이를 통해:

* **규정 준수 보고** - "이번 달에 탐지한 모든 Command & Control 도메인을 보여주세요"
* **위협 인텔리전스** - 도메인별 히트 카운트와 함께 카테고리별 공격 패턴 이해
* **정책 검증** - 카테고리 규칙이 예상 트래픽을 포착하는지 확인하고 앞선 규칙에 의해 섀도잉될 수 있는 히트가 0인 카테고리 식별

도메인 테이블은 *직접* 일치(이 카테고리를 대상으로 하는 규칙이 작동)와 *간접* 일치(AWS 데이터베이스에 따라 도메인이 카테고리에 속하지만, strict 평가 순서로 인해 다른 규칙이 먼저 작동)를 구분합니다.

![카테고리 기반 도메인 분석](https://raw.githubusercontent.com/aws-samples/sample-suricata-generator/main/images/category_analysis.png)

### 분석 실행 방법

1. [Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator)에서 규칙 파일 열기
2. **Tools > Analyze Rule Usage**로 이동
3. CloudWatch 로그 그룹 이름, AWS 리전, 시간 범위(7, 30, 60 또는 90일) 구성
4. 선택적으로 추가 로컬 규칙 파일 및/또는 AWS 관리형 규칙 그룹 추가
5. **Analyze** 클릭 - 도구가 CloudWatch Logs Insights를 서버 측에서 쿼리하고 10-60초 내에 결과 반환

분석에는 읽기 전용 CloudWatch Logs 액세스(`logs:StartQuery` 및 `logs:GetQueryResults`)가 필요하며, Network Firewall이 CloudWatch Logs로 알림 로그를 보내도록 구성되어 있어야 합니다.

!!! tip "지속적 최적화를 위해 매월 실행"
    매월 분석을 실행하면 규칙 그룹을 지속적으로 최적화할 수 있습니다: 확인된 미사용 규칙을 제거하여 용량 확보, 지나치게 광범위한 규칙을 개선하여 더 나은 가시성, 새 규칙이 예상대로 트리거되는지 검증.

## CloudWatch Logs Insights 쿼리

이 쿼리는 일반적인 운영 질문에 답하는 데 도움이 됩니다. 쿼리에 따라 알림 또는 플로우 로그 그룹에 대해 실행하세요.

### 트래픽 볼륨별 상위 도메인

**답하는 질문:** 워크로드가 방화벽을 통해 가장 많은 데이터를 보내는 도메인은 무엇인가?

**실행 시기:** 월간 비용 검토, VPC 엔드포인트 후보 식별, 예상치 못한 높은 데이터 처리 요금 조사.

**찾을 것:** VPC 엔드포인트를 통해 이동해야 하는 AWS 서비스 엔드포인트(*.amazonaws.com). 예상치 못한 도메인으로의 대규모 데이터 전송. 불균형적인 대역폭을 소비하는 단일 도메인.

flow_id를 사용하여 플로우 로그(트래픽 볼륨)와 알림 로그(TLS SNI)를 상관관계:

```
fields @timestamp, event.flow_id, event.netflow.bytes, event.tls.sni
| stats sum(event.netflow.bytes) as flowBytes, latest(event.tls.sni) as sni by event.flow_id
| stats sum(flowBytes) as totalBytes, count(*) as flowCount by sni
| sort totalBytes desc
| limit 20
```

### 차단된 트래픽 요약(알림 로그)

**답하는 질문:** 방화벽이 무엇을 차단하고 있으며 얼마나 자주인가?

**실행 시기:** 초기 배포 중 매일(합법적인 트래픽이 차단되는지 확인). 지속적 모니터링을 위해 매주. 규칙 변경 직후.

**찾을 것:** 워크로드에 필요하지만 차단되는 도메인(허용 목록에 추가). 동일 소스에서 동일 대상으로의 반복적 차단(잘못 구성된 애플리케이션). 도메인 정보 없는 차단(직접 IP 트래픽).

```
filter event.verdict.action = "drop" or event.verdict.action = "reject"
| stats count(*) as blockCount by event.alert.signature, event.tls.sni, event.http.hostname
| sort blockCount desc
| limit 25
```

### 규칙 및 규칙 그룹별 규칙 히트 카운트(알림 로그)

**답하는 질문:** 어떤 규칙이 트래픽과 일치하는가, 얼마나 자주, 각각 어떤 규칙 그룹에서 왔는가?

**실행 시기:** 월간 규칙 위생 검토, 콘솔 대시보드 외부에서 히트 카운트 데이터가 필요할 때(사용자 정의 대시보드, 보고서 또는 예약 쿼리용).

**찾을 것:** 결과에서 완전히 없는 규칙(해당 기간에 전혀 일치하지 않음). 총 히트의 불균형적인 비율을 처리하는 규칙(보통 의도한 것보다 광범위함). `alert;` 키워드가 없는 pass 규칙은 여기에 전혀 나타나지 않습니다.

```
stats count(*) as hits, latest(@timestamp) as lastSeen
    by event.alert.signature_id, event.alert.signature, aws_metadata.resource_arn
| sort hits desc
| limit 100
```

### 소스 IP별 상위 트래픽 발생자(플로우 로그)

**답하는 질문:** 어떤 내부 IP 주소가 방화벽을 통해 가장 많은 트래픽을 생성하는가?

**실행 시기:** 높은 데이터 처리 비용을 조사할 때, 방화벽의 가장 무거운 사용자인 워크로드를 식별해야 할 때.

**찾을 것:** 불균형적인 트래픽을 생성하는 단일 IP(잠재적 데이터 유출 또는 잘못된 구성). 방화벽을 통해 라우팅되어서는 안 되는 예상치 못한 소스 IP.

```
stats sum(event.netflow.bytes) as totalBytes, sum(event.netflow.pkts) as totalPkts by event.src_ip
| sort totalBytes desc
| limit 20
```

### 잠재적 중간 스트림 플로우 식별(플로우 로그)

**답하는 질문:** 올바른 핸드셰이크 없이 방화벽에 도달하는 TCP 플로우가 있는가?

**실행 시기:** 배포 후, 라우팅 변경 후, CloudWatch 지표에서 StreamExceptionPolicyPackets가 상승할 때.

**찾을 것:** tcp_flags "00" 플로우의 지속적 볼륨은 비대칭 라우팅(여러 방화벽 인스턴스에 트래픽 분산)을 나타냅니다. 장애 조치 이벤트 후 짧은 급증이 예상되며 빠르게 해결되어야 합니다.

```
filter event.tcp.tcp_flags = "00"
| fields @timestamp, event.src_ip, event.src_port, event.dest_ip, event.dest_port, event.flow_id
| sort @timestamp desc
| limit 50
```

### 설정 실패 플로우(SYN만)

**답하는 질문:** TCP 핸드셰이크를 완료하지 못한 연결 시도가 있는가?

**실행 시기:** 연결 문제를 조사할 때, 워크로드가 외부 서비스에 연결하는 데 타임아웃을 보고할 때.

**찾을 것:** 동일 대상으로의 많은 SYN 전용 플로우는 대상에 도달할 수 없거나, 보안 그룹 또는 NACL이 반환 트래픽을 차단하거나, 방화벽이 SYN을 차단하고 있음을 나타냅니다(동일 대상에 대한 해당 drop 이벤트의 알림 로그를 확인하세요).

```
filter event.tcp.tcp_flags = "02"
| fields @timestamp, event.src_ip, event.dest_ip, event.dest_port, event.netflow.pkts
| sort @timestamp desc
| limit 50
```

## 대규모 로그 쿼리

적절한 쿼리 도구는 로그 대상에 따라 다릅니다:

| 대상 | 쿼리 도구 |
|------------|------------|
| S3 | [Amazon Athena](https://docs.aws.amazon.com/athena/latest/ug/querying-network-firewall-logs.html) |
| CloudWatch Logs | [Logs Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax-examples.html) 및/또는 [Contributor Insights](https://aws.amazon.com/blogs/mt/use-contributor-insights-to-analyze-aws-network-firewall/) |
| Data Firehose | [OpenSearch](https://aws.amazon.com/blogs/networking-and-content-delivery/how-to-analyze-aws-network-firewall-logs-using-amazon-opensearch-service-part-1/) 또는 타사 도구(Splunk, Sumo Logic, Datadog) |

대시보드 및 시각화: CloudWatch Dashboards, Amazon QuickSight 또는 OpenSearch Dashboards.

## 로깅 비용 절감

### noalert 키워드 사용

flowbits를 설정하거나 중간 로직을 수행하지만 로그 이벤트를 생성할 필요가 없는 규칙에 `noalert;`를 추가하세요:

```
# 로그 이벤트를 생성하지 않고 조용히 flowbit 설정
alert tls $HOME_NET any -> any any (ja3.hash; content:"7a15285d4efc355608b304698cd7f9ab"; flowbits:set,ja3_allowed; noalert; sid:11111;)
```

### 추가 비용 전략

* 모든 로그를 수동으로 분석하는 대신 [트래픽 분석 보고서 기능](https://docs.aws.amazon.com/network-firewall/latest/developerguide/reporting.html)을 사용하세요

더 많은 전략은 블로그를 참조하세요: [AWS Network Firewall 로그 관리를 위한 비용 고려 사항 및 일반적인 옵션](https://aws.amazon.com/blogs/security/cost-considerations-and-common-options-for-aws-network-firewall-log-management/).

## Traffic Analysis Mode

[Traffic Analysis Mode](https://aws.amazon.com/blogs/security/from-log-analysis-to-rule-creation-how-aws-network-firewall-automates-domain-based-security-for-outbound-traffic/)는 자동화된 도메인 가시성을 제공하고 관찰된 트래픽 패턴을 기반으로 규칙 생성을 단순화합니다. 방화벽에 대해 활성화하면, 30일 기간 동안 HTTP 및 HTTPS 트래픽을 분석하고 자주 접근하는 도메인을 보여주는 도메인 보고서를 생성합니다.

Traffic Analysis Mode는 초기 도메인 허용 목록을 구축할 때 특히 유용합니다. 활성화하고 30일 동안 트래픽을 관찰한 다음, 보고서를 사용하여 기본 규칙 그룹을 생성하세요. 보고서에서 관찰된 도메인으로 상태 저장 도메인 목록 규칙 그룹을 자동으로 생성하거나, 오프라인 분석을 위해 보고서를 CSV 파일로 다운로드할 수 있습니다.

주요 세부 사항:

* 데이터 수집은 옵트인이며 방화벽 정책 및 로깅 구성과 독립적으로 수행됩니다
* 활성화해도 방화벽 성능에 영향을 미치지 않습니다
* 보고서에는 기능이 활성화된 시점부터 수집된 트래픽 데이터만 포함됩니다(최대 30일)
* 프로토콜당(HTTP 및 HTTPS) 30일마다 하나의 보고서를 실행할 수 있습니다
* 30일 후 기존 보고서는 자동으로 삭제됩니다

### 도메인 보고서를 Suricata 규칙으로 변환

[AWS Network Firewall용 Suricata 규칙 생성기](https://github.com/aws-samples/sample-suricata-generator)에는 Traffic Analysis Mode 도메인 보고서(또는 모든 도메인 목록)를 최적화된 Suricata 규칙으로 변환하는 대량 도메인 가져오기 기능이 포함되어 있습니다. 워크플로우:

1. Traffic Analysis Mode를 활성화하고 30일 동안 데이터를 수집하도록 두기
2. 도메인 보고서를 CSV 파일로 다운로드
3. Suricata 규칙 생성기를 열고 **File > Import Domain List**를 사용하여 도메인 가져오기
4. 작업(허용 목록의 경우 `pass`), HTTP 및 TLS 프로토콜 모두 활성화, 도메인 통합 활성화 구성
5. 생성된 규칙을 검토하고 허용하지 않으려는 도메인 제거
6. 규칙 그룹을 AWS Network Firewall로 내보내기

이 도구는 관련 서브도메인을 와일드카드 규칙으로 자동 통합하여 규칙 수와 용량 사용을 줄입니다. 예를 들어, `example.com`의 세 서브도메인은 세 개의 별도 규칙이 아닌 하나의 `*.example.com` 와일드카드 규칙이 됩니다.

## 다음 읽을 내용

* [비용 고려 사항](../../cost-considerations/docs/index.md) - 로그 관리 비용 최적화
* [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md) - 스트림 예외 정책 및 로깅에 미치는 영향
