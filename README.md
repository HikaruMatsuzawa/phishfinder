# phishfinder

偽サイト・なりすましドメインの候補を生成し、DNS、RDAP、TLS、HTTP、スクリーンショットから怪しさをランキングする実験用ツールです。

## 実行方法

Docker Desktopを起動し、リポジトリ直下で次の1コマンドを実行します。

```powershell
docker compose run --rm --build phishfinder
```

通常利用で打つコマンドはこれだけです。調査対象数、スクリーンショット、RDAP、TLSなどは `config.json` を編集して変更します。

## 何が実行されるか

1. `data/seeds.txt` から正規ドメインを読む
2. seedごとに類似ドメイン候補を生成する
3. DNSで実在する候補だけを残す
4. 必要に応じてRDAP、TLS、HTTP、スクリーンショットを取得する
5. Domain RiskとContent Riskを算出する
6. `reports/domain_report.json` と `reports/review.csv` を出力する

実行中は標準出力に、現在の設定、seedごとの進捗、ヒット件数、保存先、上位候補のサマリーが表示されます。

## 設定

設定は `config.json` にまとめています。コメント付きで書いてあるので、基本的にはこのファイルだけ見れば調整できます。

よく変える項目:

- `seed_limit`: 使うseed数。`null` にすると `data/seeds.txt` の全seedを使います。
- `variant_limit`: 1 seedあたりの候補数。`null` にすると生成した全候補を調べます。
- `rdap`: 登録日を取得するか。
- `tls`: TLS証明書を取得するか。
- `http.enabled`: HTTPステータス、タイトル、HTML、ログインフォーム、ブランド名を確認するか。
- `screenshots.enabled`: スクリーンショットを取得するか。初期値は `true` です。
- `screenshots.javascript_enabled`: スクリーンショット撮影時にJavaScriptを有効にするか。

`seed_limit` と `variant_limit` を両方 `null` にすると調査量が大きくなります。最初は小さい値で確認してから増やしてください。

## 類似ドメイン生成

候補生成では、次の変換を組み合わせます。

- 文字削除、文字追加、連続文字化、隣接文字の入れ替え
- `o -> 0`、`l -> 1`、`s -> 5` のような見た目の置換
- キーボードで近い文字への置換
- `login`、`secure`、`id`、`pay`、`mypage`、`support` などの単語追加
- `ntt-east.co.jp` から `ntteast.co.jp` のようなハイフン除去
- `.com`、`.jp`、`.co.jp`、`.ne.jp`、`.site`、`.online` などへのTLD変更
- キリル文字などを使ったIDNホモグラフ

`.co.jp` や `.ne.jp` は1つのサフィックスとして扱います。たとえば `ntt-east.co.jp` は `ntt-east` と `co.jp` に分けて変換します。

## スクリーンショット

デフォルトでは、スクリーンショットも取得します。不要な場合は `config.json` の `screenshots.enabled` を `false` にします。

```json
"screenshots": {
  "enabled": true,
  "limit": 3,
  "output_dir": "reports/screenshots",
  "timeout_seconds": 8,
  "javascript_enabled": true,
  "include_seed": true
}
```

JavaScriptはONにできます。むしろ発表で使うスクリーンショットは、JavaScriptをONにした方が実サイトに近い見た目になりやすいです。

安全面では、普段のブラウザではなくDocker内のPlaywrightで撮影します。クリック、ログイン、フォーム送信、ダウンロード許可は行いません。private IP、localhost、リンクローカル、予約済みIPに解決される候補は除外します。

保存先はseedごとに分かれます。

```text
reports/screenshots/
  ntt.com/
    seed/
      ntt.com.png
    candidates/
      1ntt.com.png
```

さらに小さい確認用設定は `data/smoke_config.json` にあります。

```powershell
docker compose run --rm --build phishfinder --config data/smoke_config.json
```

## 出力

主な出力先:

- `reports/domain_report.json`: 機械的に見るための詳細レポート
- `reports/review.csv`: 人間が確認して分類するためのCSV
- `reports/screenshots/`: seedと候補のスクリーンショット

`reports/review.csv` には次の列が入ります。

```text
rank, seed_domain, domain, domain_risk, content_risk, http_status, http_title, has_login_form, screenshot_path, human_label, label_choices, memo
```

`human_label` は最初は `未確認` です。確認後に次のような分類へ書き換えます。

```text
確認対象 / 無関係 / パーキング / ブランド意識あり / フィッシング疑い
```

## seed

`data/seeds.txt` は1行1ドメインです。初期状態では日本企業とNTTグループを中心に入れています。

公開ランキングからseedを作る機能もありますが、通常の実験では `data/seeds.txt` を編集するだけで十分です。

## テスト

変更後はDocker内でテストします。

```powershell
docker compose run --rm --build phishfinder test
```

## 安全面

このツールは調査候補の発見と観察だけを行います。ログイン試行、フォーム送信、脆弱性スキャン、管理画面探索は行いません。

Dockerを使うことで、ローカルPython環境や普段使いブラウザから処理を分離します。ただし未知サイトへHTTPアクセスする以上、リスクはゼロではありません。大きな調査を行う前に、`seed_limit`、`variant_limit`、`screenshots.limit` を小さくして挙動を確認してください。
