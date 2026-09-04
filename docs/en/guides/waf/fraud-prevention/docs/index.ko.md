# 사기 방지

AWS WAF Fraud Control은 인증 및 계정 생성 엔드포인트를 자격 증명 기반 공격으로부터 보호하는 두 가지 관리형 규칙 그룹을 제공합니다. 두 규칙 그룹 모두 기본 WAF 요금 외에 요청당 요금이 있으며, 보호하는 로그인/가입 시도에 대해서만 트리거(및 비용 발생)되도록 구성이 필요합니다. Fraud Control은 Amazon Cognito 사용자 풀에서는 사용할 수 없습니다.

두 규칙 그룹 모두 토큰 기반 클라이언트 검증을 위한 [AWS WAF 애플리케이션 통합](https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-integration.html)과 함께 가장 잘 작동합니다. 애플리케이션 통합 SDK는 Fraud Control 규칙에 추가 신호를 제공하는 토큰을 생성합니다. SDK 없이도 Fraud Control은 작동하지만 탐지 기능이 감소합니다. 애플리케이션 통합에 대한 자세한 내용은 [CAPTCHA 및 Challenge](../../captcha-and-challenge/docs/index.md)를 참조하세요. 로그인 및 가입 요청은 POST이며, 세션 및 클라이언트 핑거프린트 기반 규칙이 전체 탐지 기능을 제공하려면 이미 WAF 토큰을 포함해야 합니다.

## Account Takeover Prevention (ATP)

[Account Takeover Prevention(ATP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-atp.html) 규칙 그룹(`AWSManagedRulesATPRuleSet`)은 애플리케이션의 로그인 엔드포인트에 대한 자격 증명 기반 공격을 감지하고 차단하기 위해 로그인 시도를 검사합니다.

**하는 일**

- 다크 웹에서 새로운 유출된 자격 증명이 발견될 때마다 정기적으로 업데이트되는 도난된 자격 증명 데이터베이스와 사용자 이름 및 비밀번호 조합을 확인합니다.
- IP 주소 및 클라이언트 세션별로 로그인 시도 데이터를 집계하여 너무 많은 의심스러운 로그인 요청을 보내는 클라이언트를 감지하고 차단합니다.
- CloudFront 배포의 경우, 로그인 시도에 대한 애플리케이션의 응답을 검사하여 성공률과 실패율을 추적합니다. 이를 통해 ATP는 로그인 실패가 너무 많은 클라이언트 세션 또는 IP 주소를 일시적으로 차단할 수 있습니다.

**보호 대상**

- 크리덴셜 스터핑 - 침해 데이터베이스에서 도난된 사용자 이름/비밀번호 쌍의 자동화된 재생.
- 비밀번호 스프레이 - 잠금 임계값을 피하기 위해 많은 계정에 걸쳐 소수의 일반적인 비밀번호를 시도.
- 무차별 대입 공격 - 단일 계정 또는 소수의 계정에 대한 대량 로그인 시도.
- 자격 증명 테스트 - 도난된 자격 증명이 다른 곳에서 판매하거나 사용하기 전에 여전히 활성 상태인지 확인.
- 사용자 이름/이메일 열거 - 오류 응답이나 타이밍의 차이를 관찰하여 유효한 계정을 발견하기 위해 로그인 엔드포인트를 체계적으로 탐색.

**구성**

ATP는 로그인 엔드포인트 경로와 사용자 이름 및 비밀번호를 포함하는 요청 필드를 지정해야 합니다. ATP는 이 엔드포인트와 일치하는 요청만 평가하며, 모든 트래픽을 검사하지 않습니다. 이 내장 범위 지정은 별도의 범위 축소 문이 필요 없음을 의미하지만, 추가 세분화를 위해 추가할 수 있습니다.

**고려 사항**

- 응답 검사(로그인 성공/실패율 추적)는 ATP가 CloudFront 배포와 연결된 경우에만 사용할 수 있습니다.
- ATP는 로그인 엔드포인트의 정확한 요청 형식, 즉 HTTP 메서드, 경로, 요청 본문에서 사용자 이름과 비밀번호가 나타나는 위치를 알아야 합니다. 로그인 엔드포인트가 여러 형식(예: JSON 및 폼 인코딩)을 허용하는 경우 둘 다 구성해야 할 수 있습니다.

## Account Creation Fraud Prevention (ACFP)

[Account Creation Fraud Prevention(ACFP)](https://docs.aws.amazon.com/waf/latest/developerguide/waf-acfp.html) 규칙 그룹(`AWSManagedRulesACFPRuleSet`)은 사기성 가입을 감지하고 차단하기 위해 계정 생성 시도를 검사합니다.

**하는 일**

- 가입 요청을 비정상적인 활동에 대해 모니터링하고 요청 식별자, 행동 분석, 머신 러닝을 사용하여 의심스러운 요청을 자동으로 차단합니다.
- 알려진 침해된 자격 증명으로 계정이 생성되는 것을 방지하기 위해 도난된 자격 증명 데이터베이스와 사용자 이름 및 비밀번호 조합을 확인합니다.
- 이메일 주소에 사용되는 도메인을 평가하고 사기성 계정 생성과 관련된 패턴에 대해 전화번호 및 주소 필드를 모니터링합니다.
- CloudFront 배포의 경우, 계정 생성 시도에 대한 애플리케이션의 응답을 검사하여 성공률과 실패율을 추적하여 실패한 시도가 너무 많은 세션 또는 IP를 일시적으로 차단합니다.

**보호 대상**

- 가짜 계정 생성 - 스팸, 악용 또는 재판매를 위한 계정의 자동화된 대량 등록.
- 프로모션 및 추천 악용 - 가입 보너스, 무료 평가판 또는 추천 프로그램을 악용하기 위한 일회용 계정 생성.
- 자격 증명 세탁 - 합법적으로 보이는 신원을 확립하기 위해 알려진 침해된 자격 증명으로 계정 등록.
- 다운스트림 사기 준비 - 나중에 결제 사기, 피싱 또는 소셜 엔지니어링에 사용될 계정 생성.
- 볼류메트릭 악용 - 많은 계정에 걸쳐 동일한 전화번호, 이메일 주소 또는 기타 신원 속성을 재사용하는 대량 가입.

**구성**

ATP와 마찬가지로 ACFP는 등록 엔드포인트 경로와 계정 생성 데이터(이메일, 비밀번호, 전화번호, 주소)를 포함하는 요청 필드를 지정해야 합니다. ACFP는 이 엔드포인트와 일치하는 요청만 평가합니다.

**고려 사항**

- 응답 검사는 ACFP가 CloudFront 배포와 연결된 경우에만 사용할 수 있습니다.

## 관련 리소스

- [AWS WAF Fraud Control 문서](https://docs.aws.amazon.com/waf/latest/developerguide/waf-fraud-control.html)
- [ATP 규칙 그룹 참조](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-atp.html)
- [ACFP 규칙 그룹 참조](https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-acfp.html)
- [AWS WAF 애플리케이션 통합 SDK](https://docs.aws.amazon.com/waf/latest/developerguide/waf-application-integration.html)
- [CAPTCHA 및 Challenge](../../captcha-and-challenge/docs/index.md) - Fraud Control 탐지를 향상시키는 토큰 기반 완화 작업
- [권장 WAF 규칙 순서](../../recommended-waf-rule-order/docs/index.md) - 규칙 평가 순서에서 Fraud Control의 위치
