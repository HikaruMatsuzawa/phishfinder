# phishfinder

偽サイト・なりすましドメインを調べるための実験用リポジトリです。

このリポジトリには、用途の違う2つの処理があります。

## 1. なりすましドメイン探索

`data/seeds.txt` に書いた正規ドメインから、typo、似た文字、`login` や `secure` などを含む候補を生成し、DNSで実在確認します。

```powershell
docker compose run --rm --build phishfinder
```

設定は `config.json` を編集します。

主な出力先:

- `reports/domain_report.json`
- `reports/review.csv`
- `reports/screenshots/`

## 2. 公開フィッシングURLの観察

公開フィッシングDBに掲載されているURLを、Docker内のブラウザで開いてスクリーンショットを保存します。

発表で「実際の偽サイトはどんな見た目なのか」を確認する用途はこちらです。

```powershell
docker compose run --rm --build phishing_observer
```

設定は `phishing_capture/config.json` を編集します。

主な出力先:

- `reports/phishing_observation/<実行日時>/screenshots/`
- `reports/phishing_observation/<実行日時>/references/`
- `reports/phishing_observation/<実行日時>/review.csv`
- `reports/phishing_observation/<実行日時>/observation_report.json`

`review.csv` には、実際にアクセスできてスクリーンショットも取れた候補だけを残します。URL、公開DB上の標的ブランド、verified/online、最終URL、HTTPステータス、ページタイトル、フォーム数、パスワード入力欄の有無、検出したブランド語、スクリーンショットパスが入ります。

404、503、タイムアウトなどは `rejected.csv` に分けます。

## ドコモ系だけを探す

`phishing_capture/config.json` の `target_terms` を次のようにすると、URLまたは公開DB上の標的ブランドに指定語を含むものだけを観察します。部分文字列ではなく、URLのラベルやパスの単語として一致するものを拾います。

```json
"target_terms": ["docomo", "daccount", "ahamo", "nttdocomo"]
```

空配列 `[]` に戻すと、公開フィード内のURLを上から順に観察します。

ドコモ系を狙う場合、初期設定ではPhishTankを使います。PhishTankの `online-valid.csv` は、verifiedかつonlineのURLを配布しており、`target` 列に標的ブランドが入る場合があります。

## 「本物はどっち？」用の比較画像

`phishing_capture/config.json` の `reference_sites` に正規サイトを指定すると、偽サイト候補とは別に正規サイトのスクリーンショットも保存します。

```json
"reference_sites": {
  "docomo": "https://www.docomo.ne.jp/",
  "daccount": "https://id.smt.docomo.ne.jp/",
  "ahamo": "https://ahamo.com/"
}
```

保存先は `reports/phishing_observation/<実行日時>/references/` です。発表では、`references/` の正規画像と `screenshots/` の候補画像を並べると、「どちらが本物でしょう？」という見せ方ができます。

## スクショを早く撮りすぎない工夫

観察処理では、ページを開いた直後にすぐ撮るのではなく、次を待ってから撮影します。

- DOM読み込み完了
- 追加待機時間 `wait_after_load_ms`
- 通信の落ち着き `wait_until_network_idle`
- bodyテキストの安定 `wait_for_stable_body_ms`

真っ白なページや読み込み途中の画面が多い場合は、`timeout_seconds` と `wait_after_load_ms` を少し増やしてください。

## 手動でURLを追加する

公開フィードとは別に観察したいURLがある場合は、`phishing_capture/manual_urls.txt` に1行ずつ書きます。

```text
https://example.invalid/login
```

`#` で始まる行は無視されます。

## 安全上の方針

このリポジトリでは、普段使いのブラウザではなくDocker内のPlaywrightでページを開きます。

観察処理では次の操作は行いません。

- ログイン
- フォーム送信
- クリックによる探索
- ファイルのダウンロード許可
- カメラ、マイク、位置情報などの権限許可
- private IP、localhost、link-localなどへのアクセス

スクリーンショットを実際の見た目に近づけるため、`phishing_capture/config.json` の初期設定ではJavaScriptをONにしています。リスクをさらに下げたい場合は、`javascript_enabled` を `false` にしてください。

発表資料に載せるときは、URLを `example[.]com` のように無効化し、QRコードや入力先URLが見える場合はぼかしてください。

## テスト

変更後の確認はDocker内で実行します。

```powershell
docker compose run --rm --build phishfinder test
```
