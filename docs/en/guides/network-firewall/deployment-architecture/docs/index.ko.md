# 배포 아키텍처

!!! info "사전 요구 사항"
    이 섹션은 [사전 요구 사항 및 기본 사항](../../prerequisites/docs/index.md)에 대한 이해를 전제로 합니다. AWS Network Firewall 개념이 처음이라면 해당 주제를 먼저 검토하세요.

AWS Network Firewall은 중앙 집중식, 분산 및 결합 배포 모델을 지원하며, 다중 계정 환경에서는 엔드포인트 비용을 최소화하고 정책 관리를 단순화하기 때문에 중앙 집중식 검사가 권장되는 시작점입니다. 올바른 아키텍처를 선택하면 비용, 확장성, 영향 범위 및 운영 복잡성에 영향을 미칩니다.

이러한 모델을 구현하는 샘플 CloudFormation 및 Terraform 템플릿은 [aws-networkfirewall-cfn-templates](https://github.com/aws-samples/aws-networkfirewall-cfn-templates) 및 [aws-network-firewall-terraform](https://github.com/aws-samples/aws-network-firewall-terraform) 리포지토리를 참조하세요.

## 중앙 집중식 배포 모델

중앙 집중식 배포는 여러 스포크 VPC의 트래픽이 단일 방화벽 엔드포인트 세트를 통해 라우팅되는 허브 위치에 Network Firewall을 배치합니다. 이것이 다중 계정 환경에서 가장 일반적이고 권장되는 패턴입니다.

### Transit Gateway 네이티브 연결을 통한 중앙 집중화

AWS Network Firewall은 방화벽을 Transit Gateway에 네트워크 기능 연결로 직접 연결하는 [Transit Gateway와의 네이티브 통합](https://aws.amazon.com/about-aws/whats-new/2025/07/aws-network-firewall-native-transit-gateway-support/)을 지원하여 전용 검사 VPC를 생성하고 관리할 필요가 없습니다. 이것이 신규 배포에 권장되는 중앙 집중식 모델입니다.

이 기능을 사용한 아키텍처 패턴에 대한 자세한 안내는 [Deployment models for AWS Network Firewall: Transit Gateway attachment and multiple VPC endpoints](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall-transit-gateway-attachment-and-multiple-vpc-endpoints/)를 참조하세요.

방화벽 생성 시 Transit Gateway를 지정하면(VPC 불필요) AWS가 방화벽 엔드포인트, 서브넷 및 Transit Gateway 연결을 포함하는 내부 VPC를 생성하고 관리합니다. Transit Gateway 어플라이언스 모드가 자동으로 활성화되어 수동 구성 없이 대칭 라우팅을 제공합니다. Transit Gateway 라우팅 테이블에 정적 라우트를 구성하여 트래픽을 방화벽 연결을 통해 전달합니다.

이 모델은 동서(VPC 간) 검사, 중앙 집중식 인터넷 이그레스(NAT 게이트웨이 및 인터넷 게이트웨이가 있는 별도의 이그레스 VPC 필요), 단일 방화벽을 통한 이그레스 및 동서 결합을 지원합니다.

[Transit Gateway 유연 비용 할당](https://docs.aws.amazon.com/vpc/latest/tgw/metering-policy.html)을 지원하여 중앙 집중식 방화벽을 통해 보내는 트래픽에 대해 계정 소유자에게 비용을 청구할 수 있습니다. 이 비용 할당 기능은 Transit Gateway에 연결된 방화벽에서만 사용할 수 있습니다.

![Transit Gateway에 연결된 Network Firewall과 중앙 집중식 이그레스 VPC](../../../../images/network-firewall/tgw-attached-firewall.png)

기존 검사 VPC에서 네이티브 TGW 연결로의 마이그레이션 지침은 [Why and how to migrate to a Transit Gateway-attached AWS Network Firewall](https://aws.amazon.com/blogs/security/why-and-how-to-migrate-to-a-transit-gateway-attached-aws-network-firewall/)을 참조하세요.

### 검사 VPC를 통한 중앙 집중화

이것은 Transit Gateway 네이티브 연결 이전에 존재했던 원래 중앙 집중식 모델입니다. Network Firewall은 Transit Gateway에 연결된 고객 관리 검사 VPC에 배포됩니다. VPC, 서브넷, 방화벽 엔드포인트 및 라우팅 테이블을 직접 생성하고 관리합니다.

!!! tip "모범 사례"
    새로운 중앙 집중식 배포의 경우, 고객 관리 검사 VPC보다 [네이티브 Transit Gateway 연결](#transit-gateway-네이티브-연결을-통한-중앙-집중화)을 선택하세요. 아래에 나열된 특정 요구 사항이 있는 경우에만 검사 VPC를 선택하세요. 이미 검사 VPC를 운영 중이고 해당 요구 사항이 적용되지 않는 경우, [마이그레이션 블로그](https://aws.amazon.com/blogs/security/why-and-how-to-migrate-to-a-transit-gateway-attached-aws-network-firewall/)를 참조하세요.

**검사 VPC를 사용할 때 포기해야 하는 것:**

* **Network Firewall 요금에 대한 유연 비용 할당.** Transit Gateway 미터링 정책은 방화벽이 Transit Gateway에 네이티브로 연결된 경우에만 트래픽을 생성한 계정에 Network Firewall 데이터 처리 비용을 청구할 수 있습니다. 검사 VPC를 사용하면 Transit Gateway 데이터 처리 요금은 할당할 수 있지만 Network Firewall 요금은 할당할 수 없습니다. 많은 중앙 보안 팀에게 이는 비용 청구 모델과 전체 비용을 흡수하는 것의 차이입니다.
* **AWS가 대신 관리해주는 인프라.** VPC, 각 AZ의 방화벽 서브넷, 검사 VPC 라우팅 테이블, Transit Gateway 연결, 트래픽을 안팎으로 전달하는 라우팅 테이블 연결 및 전파를 직접 소유합니다. 네이티브 연결을 사용하면 AWS가 서비스 관리 VPC에서 이 모든 것을 프로비저닝하고 관리합니다.
* **자동 어플라이언스 모드.** 네이티브 연결은 Transit Gateway 어플라이언스 모드를 자동으로 활성화합니다. 검사 VPC에서는 직접 활성화해야 하며, 이를 잊으면 검사를 조용히 저하시키는 비대칭 라우팅의 일반적인 원인이 됩니다.

**검사 VPC가 여전히 올바른 선택인 경우:**

* 네이티브 연결에서 사용하는 서비스 관리 VPC에서는 사용할 수 없는 방화벽 엔드포인트 ENI에 대한 PrivateLink 엔드포인트 메트릭 및 VPC 플로우 로그에 대한 액세스가 필요한 경우
* 중앙 집중식 인그레스 검사가 필요한 경우(검사 VPC 내 인터넷 게이트웨이와 로드 밸런서 사이에 방화벽을 배치)
* 네이티브 Network Firewall 연결이 현재 지원하지 않는 Transit Gateway 암호화가 필요한 경우
* 네이티브 통합에서 지원하지 않는 특수 라우팅이 필요한 경우

검사 VPC 연결에서 대칭 라우팅을 보장하려면 [TGW 어플라이언스 모드](https://docs.aws.amazon.com/network-firewall/latest/developerguide/vpc-config.html)를 활성화하세요. 이를 활성화하지 않으면, 반환 트래픽이 다른 AZ의 엔드포인트에 도착하여 올바른 트래픽 평가를 방해할 수 있습니다.

![전용 검사 VPC와 별도의 이그레스 VPC에 배치된 Network Firewall](../../../../images/network-firewall/inspection-vpc-tgw.png)

방화벽과 동일한 검사 VPC에 NAT 게이트웨이를 배치하여 검사와 이그레스를 단일 VPC로 결합할 수도 있습니다:

![동일한 중앙 집중식 검사 VPC에 배치된 Network Firewall과 NAT 게이트웨이](../../../../images/network-firewall/centralized-inspection-vpc-tgw-natgw.png)

### Cloud WAN 및 서비스 삽입을 통한 중앙 집중화

[AWS Cloud WAN](https://aws.amazon.com/cloud-wan/)은 Transit Gateway 대신 라우팅 허브로 사용할 수 있습니다. 이 모델에서는 Network Firewall이 검사 VPC에 배포되고 Cloud WAN의 [서비스 삽입](https://docs.aws.amazon.com/network-manager/latest/cloudwan/cloudwan-policy-service-insertion.html) 기능이 트래픽을 방화벽을 통해 전달합니다.

**사용 시기:**

* 이미 Cloud WAN을 글로벌 네트워크 백본으로 사용하는 조직
* Cloud WAN의 글로벌 라우팅 기능(다중 리전 네트워크 세그먼테이션, 동적 라우팅 정책)이 필요한 경우

![Cloud WAN 서비스 삽입을 사용한 중앙 집중식 Network Firewall 검사](../../../../images/network-firewall/centralized-cloud-wan.png)

이 패턴에 대한 자세한 안내는 [Centralized outbound inspection architecture in AWS Cloud WAN](https://aws.amazon.com/blogs/networking-and-content-delivery/centralized-outbound-inspection-architecture-in-aws-cloud-wan/)을 참조하세요.

## 분산 배포 모델

분산 배포는 검사가 필요한 VPC에 직접 방화벽 엔드포인트를 배치하여 트래픽을 로컬로 유지하고 Transit Gateway 또는 Cloud WAN 데이터 처리 요금을 방지합니다.

### 전용 방화벽 엔드포인트를 사용한 분산 배포

Network Firewall은 검사가 필요한 각 개별 VPC에 배포되며, 각 VPC는 자체 방화벽 및 방화벽 정책을 갖습니다.

**사용 시기:**

* 단일 계정 또는 소수 계정 환경
* 특정 워크로드가 독립적인 장애 도메인과 함께 전용 검사가 필요한 경우
* 높은 처리량 워크로드에 대한 Transit Gateway 데이터 처리 요금이 추가 방화벽 엔드포인트 비용을 초과하는 경우
* 워크로드가 중앙 집중식 정책을 공유할 수 없는 고유한 방화벽 정책이 필요한 경우

각 VPC에는 자체 방화벽 엔드포인트(고가용성을 위해 AZ당 하나)가 필요하며, 다중 VPC 환경에서는 총 엔드포인트 시간당 비용이 높아집니다. 계정 간 정책 적용을 위해 [AWS Firewall Manager](https://docs.aws.amazon.com/firewall-manager/latest/userguide/what-is-fms.html)를 통해 중앙에서 관리할 수 있습니다.

![VPC별 전용 방화벽 엔드포인트를 사용한 분산 배포](../../../../images/network-firewall/distributed-deployment.png)

!!! warning "대규모 환경에서의 비용"
    많은 VPC가 있는 다중 계정 환경에서는 전용 방화벽을 사용한 분산 배포가 비용이 많이 듭니다. 예를 들어, 3개 AZ에 걸친 10개 VPC는 30개 엔드포인트와 10개의 별도 방화벽이 필요하며, 이는 3개 엔드포인트(AZ당 하나)만 필요한 중앙 집중식 모델과 비교됩니다. 현재 엔드포인트당 요금은 [Network Firewall 요금](https://aws.amazon.com/network-firewall/pricing/) 페이지를 참조하세요.

### 다중 VPC 엔드포인트 연결을 사용한 분산 배포

[다중 VPC 엔드포인트 연결](https://aws.amazon.com/about-aws/whats-new/2025/05/aws-network-firewall-multiple-vpc-endpoints/) 기능은 AZ당 최대 50개의 보조 엔드포인트가 단일 기본 방화벽을 공유할 수 있도록 하여 분산 모델의 비용 및 관리 문제를 해결합니다. 이는 중앙 집중식 관리(하나의 방화벽, 하나의 정책, 하나의 규칙 세트)와 함께 분산 엔드포인트(각 스포크 VPC에서의 AZ 로컬 검사)를 제공합니다.

이 기능을 사용한 아키텍처 패턴에 대한 자세한 안내는 [Deployment models for AWS Network Firewall: Transit Gateway attachment and multiple VPC endpoints](https://aws.amazon.com/blogs/networking-and-content-delivery/deployment-models-for-aws-network-firewall-transit-gateway-attachment-and-multiple-vpc-endpoints/)를 참조하세요.

기본 방화벽은 하나의 계정/VPC에서 생성되고, 보조 엔드포인트는 다른 VPC(동일 계정 또는 AWS RAM을 통한 교차 계정)에 연결됩니다. 모든 엔드포인트는 동일한 방화벽 정책 및 규칙 그룹을 공유합니다. 보조 엔드포인트는 할인된 시간당 요금이 부과됩니다.

![단일 방화벽을 공유하는 다중 VPC 엔드포인트 연결을 사용한 분산 배포](../../../../images/network-firewall/multi-endpoint.png)

**이그레스 아키텍처 제약 조건:**

다중 엔드포인트 지원은 각 계정이 자체 인터넷 이그레스 인프라(NAT 게이트웨이 + 인터넷 게이트웨이)를 유지하는 **분산 이그레스** 아키텍처를 위해 설계되었습니다. 공유 방화벽은 중앙 집중식 검사 및 정책 적용을 제공하지만, 이그레스 인프라는 계정별로 유지됩니다.

* **지원됨:** 스포크 VPC > 방화벽 엔드포인트(보조) > NAT 게이트웨이(스포크 계정) > 인터넷 게이트웨이(스포크 계정)
* **지원되지 않음:** 스포크 VPC > 방화벽 엔드포인트(보조) > NAT 게이트웨이(허브 계정) > 인터넷 게이트웨이(허브 계정)

**주요 제한 사항:**

* VPC 엔드포인트 연결이 있는 방화벽에서는 TLS 검사가 지원되지 않습니다
* 동서 검사는 동일 AZ 내 트래픽으로 제한됩니다
* 모든 엔드포인트(기본 + 보조)는 AZ당 결합된 처리량 용량을 공유합니다
* 보조 엔드포인트는 기본 방화벽이 이미 엔드포인트를 보유한 AZ에만 배포할 수 있습니다

## 결합 배포 모델

결합 모델은 동서 및 이그레스 트래픽을 위한 중앙 집중식 방화벽을 실행하면서 인터넷 인그레스 검사를 위해 특정 VPC에 별도의 방화벽을 배포합니다. 이전 배포 모델 가이드에서 대부분의 트래픽에 대한 중앙 집중식 비용 효율성과 필요한 곳에서의 전용 검사를 얻는 방법으로 나타납니다.

!!! tip "모범 사례"
    결합 배포 모델을 시작점으로 권장하지 않습니다. 두 가지 배포 모델을 나란히 실행하면 두 세트의 엔드포인트 비용, 두 세트의 라우팅을 고려해야 하며, 서로 일관성을 유지해야 하는 방화벽 정책이 필요합니다. 또한 Network Firewall 요금에 대한 유연 비용 할당 손실을 포함한 [고객 관리 검사 VPC의 제한 사항](#검사-vpc를-통한-중앙-집중화)을 상속합니다.

결합 모델을 사용하기 전에, 이를 유도하는 요구 사항을 다른 방식으로 충족할 수 있는지 확인하세요:

* **웹 애플리케이션 인그레스.** 오리진 앞에 AWS WAF가 있는 Amazon CloudFront가 HTTP 및 HTTPS 인그레스에 권장되는 아키텍처이며, 인그레스 경로에 방화벽이 전혀 필요하지 않습니다. [인그레스 패턴](../../../firewall-overview/ingress-patterns/docs/index.md)을 참조하세요.
* **비 HTTP 인그레스 검사.** 중앙 집중식 인그레스 검사는 [고객 관리 검사 VPC](#검사-vpc를-통한-중앙-집중화)가 여전히 적합한 경우 중 하나이며, 단일 중앙 집중식 방화벽에서 인그레스와 이그레스를 모두 처리할 수 있습니다.
* **자체 정책 또는 장애 도메인이 필요한 워크로드.** [다중 VPC 엔드포인트 연결](#다중-vpc-엔드포인트-연결을-사용한-분산-배포)은 하나의 방화벽과 하나의 정책을 유지하면서 개별 VPC에 AZ 로컬 엔드포인트를 제공하며, 이는 대부분의 사람들이 결합 모델로 달성하려는 것을 다룹니다.

두 가지 이상의 배포 모델을 실행하게 되는 경우, 고유한 방화벽 정책의 수를 가능한 한 적게 유지하고 동일한 인프라 코드 리포지토리에서 관리하여 서로 달라지지 않도록 하세요.

## AWS Network Firewall Proxy

!!! note "프리뷰"
    AWS Network Firewall Proxy는 현재 프리뷰 단계입니다. 정식 출시 전에 기능 및 동작이 변경될 수 있습니다.

[AWS Network Firewall Proxy](https://aws.amazon.com/blogs/networking-and-content-delivery/reintroducing-network-firewall-proxy-for-secure-egress-connectivity/)는 Network Firewall에 직접 내장된 명시적 프록시 기능입니다. 라우팅을 통해 투명하게 트래픽을 가로채는 기본 배포 모드 대신, Network Firewall Proxy는 클라이언트가 명시적으로 프록시 엔드포인트를 구성해야 합니다. 초기 프리뷰와의 주요 차이점은 프록시가 이제 별도의 제품이 아닌 Network Firewall 자체의 기능이라는 것입니다. 즉, 투명 방화벽과 명시적 프록시 사용 사례 모두에 동일한 방화벽 정책, 동일한 규칙 그룹 및 동일한 관리 플레인을 사용합니다.

### 작동 방식

Network Firewall Proxy는 `no-source-preservation`이라는 새로운 배포 모드를 사용합니다. 이 모드에서 방화벽은 NAT 게이트웨이에 연결됩니다. 트래픽은 클라이언트에서 방화벽 엔드포인트로 흐르며, 방화벽이 트래픽을 검사하고 필터링한 다음, 연결된 NAT 게이트웨이의 IP 주소를 사용하여 클라이언트를 대신하여 업스트림 대상과 통신합니다.

![Network Firewall 기본 source-preservation 배포 모드](../../../../images/network-firewall/nfw-proxy-source-preservation.png)

*기본 Network Firewall 배포(source-preservation): 라우트 대상으로서의 방화벽*

`no-source-preservation` 모드에서 클라이언트는 워크로드가 방화벽의 FQDN(방화벽 생성 후 제공됨)으로 트래픽을 보내도록 구성합니다. 호스트 이름은 로컬 VPC 엔드포인트로 확인되므로 프록시 트래픽에 대한 라우팅 테이블 변경이 필요하지 않습니다. Linux에서는 일반적으로 환경 변수를 사용합니다:

```
export https_proxy="https://<nfw_hostname>:<port>"
export http_proxy="https://<nfw_hostname>:<port>"
```

### 프록시가 지원하는 기능

프록시가 Network Firewall에 직접 통합되어 있으므로 Network Firewall의 전체 기능 세트를 지원합니다:

* 스테이트풀 및 스테이트리스 규칙 엔진(모든 Suricata 규칙이 그대로 작동)
* AWS 관리형 규칙 그룹(위협 서명, ATD, 도메인/IP 평판)
* TLS 검사
* URL 및 도메인 카테고리 필터링
* 지리적 IP 필터링
* 컨테이너 속성 기반 규칙
* 로깅 및 모니터링(CONNECT에서의 요청 도메인과 같은 추가 프록시별 필드 포함)

### Network Firewall Proxy 사용 시기

* 이미 명시적 프록시 구성을 사용하는 환경(기업 환경, 프록시 환경 변수가 있는 컨테이너화된 워크로드)
* 겹치는 CIDR이 있는 네트워크에서 이그레스를 중앙 집중화해야 하는 경우(`no-source-preservation` 모드가 이를 기본적으로 처리)
* 별도의 구성을 유지하지 않고 투명하게 검사되는 트래픽과 명시적으로 프록시된 트래픽 모두에 동일한 보안 정책을 적용하려는 경우

### 아키텍처 패턴

`no-source-preservation` 방화벽은 로컬 VPC, 원격 VPC 또는 온프레미스 소스에서의 프록시 트래픽을 보호할 수 있습니다. 워크로드가 Network Firewall 엔드포인트에 연결할 수 있는 한 프록시 기능을 사용할 수 있습니다. 트래픽은 엔드포인트를 통해서만 방화벽에 도달할 수 있으며, NAT 게이트웨이로 직접 트래픽을 라우팅하면 Network Firewall 정책이 적용되지 않습니다.

자세한 설정 지침 및 아키텍처 패턴은 [Reintroducing Network Firewall Proxy for Secure Egress Connectivity](https://aws.amazon.com/blogs/networking-and-content-delivery/reintroducing-network-firewall-proxy-for-secure-egress-connectivity/) 및 [Network Firewall Proxy 문서](https://docs.aws.amazon.com/network-firewall/latest/developerguide/network-firewall-proxy-developer-guide.html)를 참조하세요.

## AWS Firewall Manager를 통한 다중 계정 관리

[AWS Firewall Manager](https://docs.aws.amazon.com/firewall-manager/latest/userguide/what-is-fms.html)는 여러 계정에 걸친 Network Firewall의 중앙 집중식 정책 관리를 제공합니다. 새 계정 및 VPC에 방화벽 엔드포인트와 정책을 자동으로 배포하고 규정 준수를 모니터링합니다.

Firewall Manager는 많은 VPC와 계정에 걸쳐 별도의 방화벽을 배포하고 관리해야 하는 **분산 배포 모델**에서 가장 유용합니다. 중앙 집중식 배포의 경우, 이미 하나의 계정에서 단일 방화벽을 관리하고 있으므로 Firewall Manager가 추가하는 가치가 제한적입니다. 대부분의 중앙 집중식 배포 고객은 Git 리포지토리의 인프라 코드(CloudFormation, Terraform, CDK)를 통해 방화벽 정책을 관리하며, 이미 중앙 집중화된 리소스 위에 추가 추상화 계층으로 Firewall Manager를 추가하는 것에서 큰 이점을 보지 못합니다.

**Firewall Manager 사용 시기:**

* 많은 계정에 걸쳐 많은 VPC에 방화벽이 있는 분산 배포가 있는 경우
* 새 VPC/계정이 생성될 때 방화벽 엔드포인트의 자동 배포가 필요한 경우
* 분산 방화벽에 대한 규정 준수 모니터링 및 정책 드리프트의 자동 수정이 필요한 경우

**직접 관리(IaC) 사용 시기:**

* 보안 계정에서 관리되는 하나의 방화벽(또는 소수)으로 중앙 집중식 배포가 있는 경우
* 팀이 이미 인프라 코드를 관리하고 Git 기반 변경 제어를 선호하는 경우

## AWS RAM을 통한 리소스 공유

[AWS Resource Access Manager(AWS RAM)](https://docs.aws.amazon.com/network-firewall/latest/developerguide/sharing.html)는 여러 Network Firewall 배포 패턴에서 계정 간 리소스를 공유하는 데 사용됩니다.

### 중앙 집중식 배포 패턴

중앙 계정의 보안 팀이 방화벽을 소유하고 운영합니다. AWS RAM은 Transit Gateway를 공유하여 스포크 계정이 연결을 생성하고 검사 경로로 트래픽을 라우팅할 수 있도록 합니다. 방화벽 정책, 규칙 그룹 및 방화벽 자체는 중앙 계정에 남아 있으며 공유되지 않습니다. 스포크 계정은 Transit Gateway를 통해 트래픽을 라우팅하기만 하면 됩니다. 중앙 보안 팀은 변경 제어가 있는 Git 리포지토리에서 IaC를 통해 방화벽 정책을 관리합니다.

### 분산 배포 패턴

보안 팀이 방화벽 정책과 규칙 그룹을 중앙에서 생성한 다음 스포크 계정에 공유하여 각 계정이 공유된 정책을 참조하는 자체 방화벽을 생성할 수 있도록 합니다. 이는 **중앙 집중식 제어 플레인**(정책이 한 번 중앙에서 정의됨)과 **분산 데이터 플레인**(방화벽 엔드포인트가 각 스포크 VPC에 로컬로 배포됨)을 적용합니다. 중앙 계정은 소유권을 유지하고 공유 리소스를 업데이트할 수 있습니다. 변경 사항은 모든 소비자에게 자동으로 전파됩니다.

### 다중 엔드포인트 패턴

기본 방화벽 소유자가 AWS RAM을 통해 **방화벽**을 공유하여 스포크 계정이 보조 VPC 엔드포인트 연결을 생성할 수 있도록 합니다. 스포크 계정은 자체 VPC에 공유 방화벽으로 트래픽을 라우팅하는 엔드포인트를 생성합니다. 방화벽 소유자는 정책 및 규칙 그룹에 대한 완전한 제어를 유지합니다.

## 다음 읽을 내용

* [방화벽 정책 구성](../../firewall-policy-configuration/docs/index.md) - 방화벽 정책 설정 구성
* [비용 고려 사항](../../cost-considerations/docs/index.md) - Network Firewall 비용 이해 및 최적화
* [고객 관리 규칙](../../customer-managed-rules/docs/index.md) - 방화벽 정책을 위한 규칙 작성
