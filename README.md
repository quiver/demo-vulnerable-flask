# Flask脆弱性教材

Flaskで作った、脆弱性学習用の小さなWebアプリです。ローカル環境または隔離された演習環境だけで実行してください。

`app.py` を静的スキャンするだけで根拠が見える脆弱性を3項目に絞っています。各項目は `app.py` の行番号と直接対応するため、検出ツールの検証にも使えます。

認証や管理機能は持たない構成です。ブラウザから直接、公開ページの動線だけで全脆弱性を再現できます。

## 実行方法

```bash
uv run flask --app app run
```

ブラウザで `http://127.0.0.1:5000` を開きます。

## 含まれる脆弱性

事前に `uv run flask --app app run` で起動し、`http://127.0.0.1:5000` をブラウザで開いてください。

### 1. SQLインジェクション

検索画面で、検索キーワード `q` をそのまま `LIKE` 句に連結しています。

```python
sql = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
```

`UNION SELECT` などのSQL構文を含む入力で、本来取得できないテーブルの情報まで取り出せます。

検出シグネチャは「f文字列 / `%` 連結で組み立てたSQLを `conn.execute()` に渡している」です。

#### 再現手順

1. 検索画面を開く http://127.0.0.1:5000/search
2. キーワードに「`' UNION SELECT 1, name, price FROM products --`」を入力
3. 「実行されたSQL」行に組み立てられたクエリが表示される
4. 検索結果にUNIONで結合された行が現れ、テーブル内容が引き出せていることを確認できる

`q` の値を変えれば任意のSELECT文を実行できます。`sqlite_master` を狙えばスキーマ自体も取り出せます。

### 2. クロスサイトスクリプティング

検出シグネチャは「ユーザー入力 (request.form / request.args / DBの読出し結果) を `render_template_string` の `| safe` 配下にエスケープせず埋め込んでいる」で共通です。

#### 2-1. Stored XSS: `/product/<id>` のコメント

商品ページで、DBから読み出したコメント本文をHTMLエスケープせずに埋め込んでいます。

```python
f"<section class='card'><p>{comment['body']}</p></section>"
```

投稿はDBに残るため、商品ページを開いた他の利用者のブラウザ上でスクリプトが実行され続けます。

再現手順

1. 商品ページを開く `http://127.0.0.1:5000/product/1`
2. 「コメント」欄に以下を投稿する

   ```html
   <script>alert('xss-' + document.cookie)</script>
   ```

3. ページがリロードされた瞬間にアラートが表示される
4. 別ブラウザ (またはシークレットウィンドウ) で同じURLを開くと、別の閲覧者にもアラートが発火する。投稿はDBに残るため、`vulnshop.db` を削除するまで影響が続く

#### 2-2. Reflected XSS: `/search` のキーワード反映

検索画面 の `<input name="q" value="{keyword}">` と `app.py:142` の `実行されたSQL: <code>{sql}</code>` は、`request.args["q"]` を未エスケープでHTMLへ反映しています。検索リンクを踏ませる形での攻撃が可能です。

再現手順

1. 検索画面を開く http://127.0.0.1:5000/search
2. キーワードに「`<img src=x onerror=alert(1)>`」を入力
3. スクリプトが実行されます。

### 3. パストラバーサル

検出シグネチャは「ユーザー入力を `Path` (または文字列) と結合してファイルI/Oに渡している」で共通です。

#### 3-1. アップロード経由の書き込み (`/upload`)

アップロード画面で、フォームから受け取ったファイル名 (`filename` フィールド、未指定なら multipart の元ファイル名) をそのまま保存先パスに使っています。

```python
name = override or uploaded.filename
save_path = UPLOAD_DIR / name
```

`filename` フィールドに `../` を含めると `uploads/` の外へ書き込めます。`werkzeug.utils.secure_filename` などのサニタイズが使われていないことが静的に確認できます。

再現手順

1. アップロード画面を開く `http://127.0.0.1:5000/upload`
2. 任意のローカルファイルを「ファイル」に選び、「ファイル名」に `../pwned.txt` と入力して「アップロード」を押す
3. レスポンスの「保存先:」に表示されるパスが `uploads/` の外 (リポジトリ直下) になっていることを確認
4. `ls` でリポジトリ直下に `pwned.txt` が作られていることを確認

curl でも同じことが可能です。

```bash
echo hacked > /tmp/pwned.txt
curl -i -F "file=@/tmp/pwned.txt" -F "filename=../pwned.txt" \
  http://127.0.0.1:5000/upload
```

「ファイル名」に `../app.py` など重要ファイル名を入れると既存ファイル上書きの危険が即座にわかります (実検証では退避してから試してください)。

#### 3-2. ダウンロード経由の読み取り (`/download`)

ダウンロード機能で、クエリパラメータ `filename` を検証せず `UPLOAD_DIR` と結合して `send_file` に渡しています。

```python
return send_file(UPLOAD_DIR / filename)
```

`filename` に `../` を含めることで `uploads/` 外のファイルを読み取れます。基底ディレクトリ内であることを確認するチェック (`Path.resolve()` + 範囲確認など) が一切ありません。

再現手順

1. ブラウザで `http://127.0.0.1:5000/download?filename=../app.py` を開く
2. `app.py` のソースコードがそのままダウンロード/表示される

curl の場合

```bash
curl -s 'http://127.0.0.1:5000/download?filename=../app.py' | head
```

## 注意

このコードは、あえて安全でない実装にしています。インターネットに公開したり、実サービスの土台に使ったりしないでください。

## 参考リンク

- Flask Documentation: https://flask.palletsprojects.com/
