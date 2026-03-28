# DNS Firewall ベストプラクティス

## 概要

Amazon Route 53 Resolver DNS Firewall は、VPC からのアウトバウンド DNS クエリを制御およびフィルタリングできるマネージドファイアウォールサービスです。既知の悪意のあるドメインへの DNS クエリや、DNS プロトコルを使用したデータ漏洩の試みをブロックすることで、ワークロードを DNS ベースの脅威から保護します。


## Amazon Route 53 Resolver DNS Firewall を有効にするメリット

Amazon Route 53 Resolver DNS Firewall を有効にすることで、以下の主要なメリットが得られます:


* **セキュリティの強化**: マルウェア、フィッシング、コマンドアンドコントロール攻撃など、DNS ベースの脅威から VPC を保護します。
* **運用負荷の軽減**: AWS が自動的に更新するマネージドドメインリストを活用することで、セキュリティチームの負担を軽減します。
* **カスタマイズ可能な保護**: 特定のセキュリティ要件に対応するため、または既知の脅威をブロックするために、カスタムドメインリストを作成・管理できます。
* **高度な脅威検出**: DNS Firewall Advanced ルールグループを活用して、DNS トンネリングやデータ漏洩などの高度な DNS 攻撃から保護します。
* **一元管理**: AWS Firewall Manager と組み合わせることで、複数のアカウントや VPC にわたって DNS Firewall ルールを容易にデプロイ・管理できます。
* **コストの最適化**: DNS レイヤーで悪意のあるトラフィックをフィルタリングすることで、Network Firewall などの後続のセキュリティコントロールにおける不要なデータ処理コストを削減します。
* **シームレスな統合**: 既存の AWS サービスや現在のセキュリティアーキテクチャと容易に統合できます。
* **スケーラビリティ**: 追加のインフラストラクチャ管理を必要とせず、DNS トラフィックに応じて自動的にスケールします。

Route 53 Resolver DNS Firewall を導入することで、組織のセキュリティ体制を大幅に強化し、AWS リソースを DNS ベースの脅威から保護できます。

## ベストプラクティス

### AWS マネージドドメインリストによる多層防御の実装

* AWS マネージドドメインリストを最初の防御ラインとして活用してください。
* これらのリストは AWS セキュリティによって自動的に更新されます。

[参考: AWS マネージドドメインリストのドキュメント](https://docs.aws.amazon.com/ja_jp/Route53/latest/DeveloperGuide/resolver-dns-firewall-managed-domain-lists.html)


### DNS Firewall Advanced ルールグループの活用

* DNS Firewall Advanced ルールグループを実装して、以下の脅威から保護してください:
    * DNS トンネリング
    * ドメイン生成アルゴリズム（DGA）

[参考: DNS Firewall Advanced の機能](https://docs.aws.amazon.com/ja_jp/Route53/latest/DeveloperGuide/firewall-advanced.html)


### AWS Firewall Manager による一元管理

* AWS Firewall Manager を使用して、以下を実現してください:
    * 組織全体で DNS Firewall ルールを一貫してデプロイ
    * 新しい VPC の作成時に自動的に保護を適用
    * アカウント間でルールを一元管理

[Firewall Manager のドキュメント](https://docs.aws.amazon.com/ja_jp/waf/latest/developerguide/getting-started-fms-dns-firewall.html)


### DNS クエリログの有効化と設定

* 以下の目的で DNS クエリログを有効にしてください:
    * セキュリティ調査と脅威ハンティング
    * トラフィックパターンの分析
    * Amazon CloudWatch Logs または S3 へのログ出力の設定
    * 適切なログ保持ポリシーの設定

[参考: DNS クエリログの設定](https://docs.aws.amazon.com/ja_jp/Route53/latest/DeveloperGuide/firewall-resolver-query-logs-configuring.html)


### 悪意のあるトラフィックをソースに近い場所でブロック

* DNS Firewall を早期フィルタリングメカニズムとして使用してください。
* Network Firewall に到達する前に、DNS レイヤーで悪意のあるトラフィックをブロックします。
* 不要なデータ処理コストを削減できます。
* 他のセキュリティコントロールと組み合わせて実装してください。

## 実装ガイダンス

### 初期セットアップ

1. DNS Firewall ルールグループを作成します。
2. AWS マネージドドメインリストと DNS Firewall Advanced ルールを関連付けます。
3. 必要に応じてカスタムドメインリストを設定します。
4. 適切なアクション（ALLOW、ALERT、BLOCK）を指定したカスタムルールを作成します。
5. ルールグループを VPC に関連付けます。

[参考: 開始方法ガイド](https://docs.aws.amazon.com/ja_jp/Route53/latest/DeveloperGuide/resolver-dns-firewall-getting-started.html)


## モニタリングとメンテナンス

* DNS クエリログの定期的なレビュー
* ルール設定の確認と調整
* ルールの有効性の検証



## 推奨ルールグループ設定

* 推奨される DNS Firewall ルールグループの設定については、こちらのリンクを参照してください: [推奨ルールグループ設定](https://github.com/aws-samples/amazon-route-53-resolver-dns-firewall-automation-examples/blob/main/sample-rule-group/template.yaml)

## その他のリソース

* [DNS Firewall の概要](https://docs.aws.amazon.com/ja_jp/Route53/latest/DeveloperGuide/resolver-dns-firewall-overview.html)
* [許可リスト自動生成ソリューション](https://github.com/aws-samples/amazon-route-53-resolver-dns-firewall-automation-examples/tree/main/AllowListGenerator)
* [AWS セキュリティブログ - Amazon Route 53 Resolver DNS Firewall による高度な DNS 脅威からの保護](https://aws.amazon.com/blogs/security/protect-against-advanced-dns-threats-with-amazon-route-53-resolver-dns-firewall/)
* [ドメインリスト管理のドキュメント](https://docs.aws.amazon.com/ja_jp/Route53/latest/DeveloperGuide/resolver-dns-firewall-managed-domain-lists.html)
