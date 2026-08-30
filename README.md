# phishfinder

偽サイト・なりすましドメインの候補を自分で生成し、DNS・RDAP・TLSなどの情報から怪しさをランキングする実験用ツールです。

通常の実行はDockerの1コマンドで済むようにしています。`PYTHONPATH` の指定やローカルPython環境の準備は不要です。

## いちばん簡単な実行方法

Docker Desktopを起動した状態で、リポジトリ直下から実行します。

```powershell
docker compose run --rm --build phishfinder
```

この1コマンドで、次の処理をまとめて実行します。

1. `data/seeds.txt` を読み込む
2. 各seedから類似ドメイン候補を生成する
3. DNSで実在する候補だけを残す
4. Domain Riskを算出する
5. `reports/domain_report.json` にレポートを保存する

小さく動作確認する場合:

```powershell
docker compose run --rm --build phishfinder --seed-limit 1 --variant-limit 5
```

テストもDocker内で実行できます。

```powershell
docker compose run --rm --build phishfinder test
```

レポートはホスト側の `reports/` に保存されます。seedはホスト側の `data/seeds.txt` を読みます。

## 設定ファイル

通常はコマンドオプションではなく、`config.json` を編集して設定します。

```json
{
  "seeds_path": "data/seeds.txt",
  "seed_limit": 3,
  "variant_limit": 50,
  "dns_details": false,
  "rdap": false,
  "tls": false,
  "progress": true,
  "output_format": "json",
  "output_path": "reports/domain_report.json",
  "screenshots": {
    "enabled": false,
    "limit": 20,
    "output_dir": "reports/screenshots",
    "timeout_seconds": 8,
    "javascript_enabled": false
  }
}
```

デフォルトでは、1つのseedにつき最大50個の亜種ドメインを作ります。`seed_limit` が3なので、通常実行では最大150候補をDNS確認します。

すべてのseedを使いたい場合は、`seed_limit` を `null` にします。すべての亜種を使いたい場合は、`variant_limit` を `null` にします。ただし時間が大きく増えます。

スクリーンショットを取得したい場合は、`screenshots.enabled` を `true` にします。デフォルトでは無効です。

```json
{
  "screenshots": {
    "enabled": true,
    "limit": 20,
    "output_dir": "reports/screenshots",
    "timeout_seconds": 8,
    "javascript_enabled": false
  }
}
```

スクリーンショットはDomain Risk上位から最大 `limit` 件だけ取得します。private IP、localhost、リンクローカル、予約済みIPに解決された候補は除外します。クリック、ログイン、フォーム送信は行いません。

保存先はseedごとに分かれます。

```text
reports/screenshots/
  ntt.com/
    seed/
      ntt.com.png
    candidates/
      1ntt.com.png
```

スクリーンショット取得を小さく試すためのサンプル設定もあります。

```powershell
docker compose run --rm --build phishfinder --config data/screenshot_config.example.json
```

## よく使うコマンド

一時的に設定を上書きしたい場合だけ、コマンドオプションを使えます。

RDAP登録日とTLS証明書情報も含める場合:

```powershell
docker compose run --rm --build phishfinder --rdap --tls
```

MX/NSレコードも含める場合:

```powershell
docker compose run --rm --build phishfinder --dns-details
```

JSONではなくCSVで保存する場合:

```powershell
docker compose run --rm --build phishfinder --format csv --output reports/domain_report.csv
```

調査量を増やす場合。最初は小さく試し、慣れてから増やします。

```powershell
docker compose run --rm --build phishfinder --seed-limit 10 --variant-limit 1000 --rdap --tls
```

進捗バーを表示しない場合:

```powershell
docker compose run --rm --build phishfinder --no-progress
```

## seedの使い方

`data/seeds.txt` には、調査対象となる正規ドメインを1行ずつ保存します。デフォルトでは、日本企業・日本サービス中心のseedを入れています。特にNTTグループは厚めに入れています。

公開ランキングからseedを保存することもできます。データ元は研究用途でよく使われるTrancoです。

```powershell
docker compose run --rm --build phishfinder import-seeds --limit 100 --output data/tranco_seeds.txt
```

注意: `--output data/seeds.txt` を指定すると、現在の日本企業seedを上書きします。

Tranco公式サイトでは、最新の標準リストを取得できることが案内されています。
https://tranco-list.eu/

追加の候補として、手動で選んだ日本企業中心の候補も用意しています。

```powershell
docker compose run --rm --build phishfinder --seeds data/recommended_seeds.txt --seed-limit 3 --variant-limit 100
```

## ヒット数の見方

`--seed-limit 1 --variant-limit 5` の場合、「1つのseedから5個の候補を作り、そのうち何件がDNSで実在したか」を表示します。

例:

```text
[scan] ntt.com: 5 件の候補をDNS確認中...
[scan] ntt.com: 5 件中 2 件が実在しました。
合計: seed 1 件、候補 5 件、実在候補 2 件
```

人気ドメインや短いドメインでは、よくあるtypoやキーワード付きドメインがすでに登録済みのことがあります。そのため、少数サンプルではヒット率が高く見える場合があります。発表では `--variant-limit 1000` 以上で全体の割合を見る方が自然です。

## 遅いときの理由

通常実行ではA/AAAAのDNS確認だけを行います。`--dns-details` を付けると、実在した候補ごとにMXとNSも確認するため遅くなります。

`--rdap` と `--tls` もネットワーク確認が増えるため、最初は小さい件数で試してください。

## ファイル構成

- `Dockerfile`: Dockerイメージ定義
- `docker-compose.yml`: 1コマンド実行用の設定
- `run.py`: コンテナ内で動く一括実行スクリプト
- `data/seeds.txt`: 調査対象の正規ドメイン一覧。1行1ドメイン
- `reports/domain_report.json`: デフォルトの出力先
- `reports/review.csv`: 人間が分類するためのレビューCSV
- `reports/screenshots/`: スクリーンショット保存先
- `src/phishfinder/`: 実装
- `tests/`: テスト

## 現在できること

- 類似ドメイン候補の生成
- A/AAAAレコードによる実在確認
- `nslookup` によるMX/NSレコード取得
- RDAPによる登録日の取得
- TLS証明書の取得
- HTTPステータス、ページタイトル、HTML本文の一部取得
- ログインフォーム検出
- ブランド名検出
- Domain Riskの採点
- Content Riskの採点
- JSON/CSVレポート出力
- `tqdm` による進捗バー表示
- Dockerによる実行環境の分離
- Playwrightによるスクリーンショット取得。デフォルトは無効

## 人間レビューCSV

通常実行すると、メインレポートとは別に `reports/review.csv` も出力します。

```powershell
docker compose run --rm --build phishfinder
```

レビューCSVには、次のような列が入ります。

```text
rank, seed_domain, domain, domain_risk, content_risk, http_status, http_title, has_login_form, screenshot_path, human_label, label_choices, memo
```

`human_label` は最初は `未確認` です。確認後に、次のような分類へ手で書き換えます。

```text
確認対象
無関係
パーキング
ブランド意識あり
フィッシング疑い
```

## Dockerを使わずに動かす場合

ローカルPythonで動かす場合だけ、仮想環境を作ります。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python run.py
```

## TDDでの進め方

機能を増やすときは、次の順で進めます。

1. `tests/` に失敗するテストを書く
2. `src/phishfinder/` に最小実装を追加する
3. `docker compose run --rm --build phishfinder test` を実行する
4. `run.py` とREADMEを更新する

## 安全面

Dockerでは、ローカルPython環境や普段使いブラウザから処理を分離できます。HTTPメタデータ取得とスクリーンショット取得もコンテナ内で実行します。

スクリーンショット取得はデフォルトでは無効です。有効にした場合も、上位候補だけに限定します。コンテナは低権限ユーザーで実行し、設定用の `config.json`、seed用の `data/`、出力用の `reports/` だけをマウントします。

ログイン試行、フォーム送信、脆弱性スキャン、管理画面探索は行いません。
