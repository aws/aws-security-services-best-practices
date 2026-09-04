# 다른 AWS 서비스와 함께 AWS WAF 사용

!!! warning "향후 콘텐츠 업데이트 진행 중"
    이 섹션은 현재 업데이트 중입니다. 아래 내용은 불완전하거나, 곧 포함될 예정인 내용의 예상 개요를 제시합니다. 곧 다시 방문하거나 그동안 AWS WAF 공개 문서를 참조하세요.

## AWS Firewall Manager (FMS)

[Firewall Manager에서 WAF 정책](https://docs.aws.amazon.com/waf/latest/developerguide/waf-policies.html)을 생성할 수 있습니다. protection pack의 상단과 하단에 배치할 규칙 그룹을 지정합니다. AWS Organization에서 리소스 범위를 정의하면, FMS가 각 멤버 계정에 protection pack을 생성하고 범위 내 리소스에 연결합니다. FMS 관리 protection pack은 멤버 계정에서 사용자 정의할 수 있지만, 상단 및 하단 규칙 그룹은 수정할 수 없습니다.

### FMS AWS WAF 보안 정책에 포함할 규칙 결정

AWS WAF용 FMS 보안 정책은 일반적으로 중앙 보안 팀이 관리합니다. 이 팀은 조직 전체에 걸쳐 기본 규칙을 적용할 책임이 있습니다. 고유한 기준선이 필요한 조직의 일부가 있을 수 있으며, 따라서 고유한 정책이 필요합니다.

FMS 관리 protection pack은 멤버 계정에서 사용자 정의해야 할 수 있습니다. 관리형 규칙이 해결해야 할 오탐을 유발하거나, 기준선으로 완화되지 않는 애플리케이션별 위협이 있을 수 있습니다. FMS 정책에 애플리케이션별 변경을 하기보다는 protection pack을 업데이트하는 것이 좋습니다. 일반적으로 소수의 리소스에 각각 적용되는 많은 FMS 정책보다, 광범위한 리소스에 적용되는 소수의 FMS 정책을 갖는 것이 일반적입니다.

### CloudFormation을 사용한 FMS 관리 protection pack 업데이트

[AWS WAF V2 리소스](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/AWS_WAFv2.html)는 CloudFormation 템플릿을 사용하여 완전히 정의할 수 있습니다. Firewall Manager를 사용하여 protection pack을 관리할 때 몇 가지 고려 사항이 있습니다.

CloudFormation을 사용하여 AWS WAF용 [Firewall Manager 정책](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fms-policy.html)을 정의할 수 있습니다. 정책에는 FMS가 생성하는 protection pack의 상단과 하단에 원하는 AWS WAF 규칙의 정의가 포함됩니다. CloudFormation(또는 다른 [인프라 코드](https://docs.aws.amazon.com/whitepapers/latest/introduction-devops-aws/infrastructure-as-code.html) 도구)을 사용할 때 몇 가지 영향이 있습니다.

CloudFormation 템플릿 형식은 [AWS::WAFev2::WebACL](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-webacl.html)과 [AWS::FMS::Policy](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-fms-policy.html) 간에 동일하지 않습니다. 기존 AWS WAF protection pack을 Firewall Manager 정책의 기반으로 사용하려면, AWS WAF 콘솔에서 protection pack을 JSON으로 다운로드하거나 [GetWebACL](https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACL.html) API를 사용해야 합니다. 이 JSON을 사용하여 FMS 정책 리소스의 [SecurityServicePolicyData](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-fms-policy-securityservicepolicydata.html) 요소를 구성합니다. 간단한 경우에는 FMS 콘솔에서 수동으로 AWS WAF 규칙을 다시 생성하는 것이 더 쉬울 수 있습니다.

멤버 계정은 AWS 콘솔, CLI 또는 SDK를 사용하여 FMS가 생성한 protection pack을 사용자 정의할 수 있습니다. 그러나 FMS 관리 protection pack에 사용자 정의 규칙을 추가하는 표준 CloudFormation 템플릿을 생성할 수 없습니다. AWS WAF 규칙은 AWS::WAFev2::WebACL 리소스 내에 정의됩니다. protection pack이 이미 존재하므로 CloudFormation 템플릿에서 정의할 수 없습니다. 현재 이를 해결하는 두 가지 옵션이 있습니다.

1. FMS 관리 protection pack을 CloudFormation 스택에 [가져온](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import.html) 다음, 사용자 정의 규칙으로 스택을 업데이트합니다.
2. [AWS::WAFv2::RuleGroup](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-wafv2-rulegroup.html)에서 사용자 정의 규칙을 정의한 다음, FMS 관리 protection pack을 발견하고 규칙 그룹을 참조하는 규칙을 생성하는 코드가 있는 Lambda 기반 [사용자 정의 리소스](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-custom-resources.html)를 사용합니다.

### FMS 관리 규칙 그룹으로 인한 오탐 처리

대규모 조직에서는 FMS 관리 protection pack에 하나 이상의 멤버 계정에 오탐을 유발하는 규칙이 포함되는 것이 드문 일이 아닙니다. 여러 FMS 정책을 사용하여 이러한 상황을 처리할 수 있습니다.

1. 오탐 처리를 허용하기 위해 문제가 되는 규칙을 *Count* 모드로 설정한 *예외 정책*. 이 정책의 범위는 특정 태그가 있는 리소스만 포함합니다. 멤버 계정은 오탐을 적절히 처리하는 규칙을 추가할 책임이 있습니다.
2. 모든 관리형 규칙이 *Block* 모드인 *기본 정책*. 이 정책은 오탐에 대해 걱정하지 않는 리소스를 보호하는 데 사용됩니다. 이 정책의 범위는 예외 정책에서 사용하는 태그가 있는 리소스를 제외합니다.

오탐을 처리하는 데 사용되는 레이블 기반 예외 패턴(관리형 규칙을 Count 모드로 설정한 다음, 추가 조건과 함께 레이블을 매칭하여 Block하는 사용자 정의 규칙 작성)에 대한 자세한 지침은 [예외 생성](../../operationalizing/docs/index.md#creating-exceptions)을 참조하세요.

## Amazon GuardDuty

Amazon GuardDuty가 생성한 결과를 기반으로 AWS WAF 규칙 생성을 자동화할 수 있습니다. 블로그 [Amazon GuardDuty 및 AWS WAF v2를 사용하여 의심스러운 호스트를 자동으로 차단하는 방법](https://aws.amazon.com/blogs/security/how-to-use-amazon-guardduty-and-aws-waf-v2-to-automatically-block-suspicious-hosts/)을 참조하세요.

## AWS Shield Advanced

AWS Shield Advanced는 [Anti-DDoS 관리형 규칙 그룹](https://docs.aws.amazon.com/waf/latest/developerguide/waf-anti-ddos-rg-using.html)(`AWSManagedRulesAntiDDoSRuleSet`)을 통해 애플리케이션 계층(레이어 7) DDoS 보호를 제공합니다. 이 관리형 규칙 그룹은 머신 러닝 기반 이상 감지를 사용하여 수초 내에 애플리케이션 계층 DDoS 공격을 자동으로 감지하고 완화합니다. Anti-DDoS AMR은 모든 AWS WAF 고객에게 제공되며, Shield Advanced 구독자에게는 [고급 등급](https://docs.aws.amazon.com/waf/latest/developerguide/waf-anti-ddos-advanced.html)이 포함됩니다(Shield Advanced로 보호되는 WAF 리소스에 대해 월간 최대 500억 요청).

[Firewall Manager의 AWS Shield 정책](https://docs.aws.amazon.com/waf/latest/developerguide/shield-policies.html)을 사용하여 조직 전체에 Shield Advanced 보호를 자동으로 구성할 수 있습니다.

## AWS Transfer Family

AWS Transfer Family는 파일 전송 프로토콜을 관리하는 서비스입니다. 블로그 [AWS Web Application Firewall 및 Amazon API Gateway로 AWS Transfer Family 보호](https://aws.amazon.com/blogs/storage/securing-aws-transfer-family-with-aws-web-application-firewall-and-amazon-api-gateway/)를 참조하세요.
