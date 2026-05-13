import os
import sqlite3
from pathlib import Path

from flask import Flask, render_template_string, request, send_file, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vulnshop.db"
UPLOAD_DIR = BASE_DIR / "uploads"

app = Flask(__name__)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    UPLOAD_DIR.mkdir(exist_ok=True)
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                body TEXT NOT NULL
            );
            """
        )
        if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
            conn.executemany(
                "INSERT INTO products (name, price) VALUES (?, ?)",
                [
                    ("マグカップ", 1200),
                    ("パーカー", 4800),
                    ("ステッカー", 500),
                ],
            )


def page(title: str, body: str) -> str:
    return render_template_string(
        """
        <!doctype html>
        <html lang="ja">
        <head>
          <meta charset="utf-8">
          <title>{{ title }} - VulnShop</title>
          <style>
            body { font-family: system-ui, sans-serif; line-height: 1.6; max-width: 960px; margin: 32px auto; padding: 0 16px; }
            nav a { margin-right: 12px; }
            input, textarea { display: block; width: 100%; max-width: 520px; margin: 6px 0 12px; padding: 8px; }
            button { padding: 8px 12px; }
            .card { border: 1px solid #ddd; border-radius: 8px; padding: 16px; margin: 12px 0; }
            .hint { background: #fff7d6; border: 1px solid #e6d27a; border-radius: 8px; padding: 12px; }
            code { background: #f2f2f2; padding: 2px 4px; }
          </style>
        </head>
        <body>
          <nav>
            <a href="{{ url_for('index') }}">ホーム</a>
            <a href="{{ url_for('search') }}">商品検索</a>
            <a href="{{ url_for('upload') }}">アップロード</a>
          </nav>
          <h1>{{ title }}</h1>
          {{ body | safe }}
        </body>
        </html>
        """,
        title=title,
        body=body,
    )


@app.route("/")
def index() -> str:
    with get_db() as conn:
        products = conn.execute("SELECT * FROM products ORDER BY id").fetchall()
    cards = "".join(
        f"""
        <section class="card">
          <h2>{product["name"]}</h2>
          <p>{product["price"]} 円</p>
          <a href="{url_for("product", product_id=product["id"])}">詳細を見る</a>
        </section>
        """
        for product in products
    )
    return page(
        "VulnShop",
        f"""
        <div class="hint">
          <p>このアプリは脆弱性学習用です。ローカル環境や隔離された演習環境だけで実行してください。</p>
          <p>下記のページで、それぞれの脆弱性を体験できます。</p>
          <ul>
            <li><a href="{url_for("search")}">商品検索</a> — SQLインジェクションと反射型XSS</li>
            <li><a href="{url_for("product", product_id=1)}">商品詳細 (例: /product/1)</a> — 保存型XSS (コメント欄)</li>
            <li><a href="{url_for("upload")}">アップロード</a> — パストラバーサル (書き込み)、<code>/download</code> で読み取り</li>
          </ul>
        </div>
        {cards}
        """,
    )


@app.route("/search")
def search() -> str:
    keyword = request.args.get("q", "")
    results: list[sqlite3.Row] = []
    sql = "SELECT * FROM products"
    if keyword:
        # Intentionally vulnerable: SQL injection.
        sql = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    with get_db() as conn:
        results = conn.execute(sql).fetchall()

    items = "".join(
        f"<li><a href='{url_for('product', product_id=row['id'])}'>{row['name']}</a> - {row['price']} 円</li>"
        for row in results
    )
    return page(
        "商品検索",
        f"""
        <div class="hint">
          <p>このページではSQLインジェクションと反射型XSSを試せます。</p>
          <p><b>SQLインジェクション:</b> 「キーワード」に以下を入れて検索してみましょう。「実行されたSQL」行と検索結果に余分なテーブル内容が現れます。</p>
          <pre><code>' UNION SELECT 1, name, price FROM products -- </code></pre>
        </div>
        <form>
          <label>キーワード <input name="q" value="{keyword}"></label>
          <button>検索</button>
        </form>
        <p>実行されたSQL: <code>{sql}</code></p>
        <ul>{items}</ul>
        """,
    )


@app.route("/product/<int:product_id>", methods=["GET", "POST"])
def product(product_id: int) -> str:
    if request.method == "POST":
        body = request.form.get("body", "")
        with get_db() as conn:
            conn.execute(
                "INSERT INTO comments (product_id, body) VALUES (?, ?)",
                (product_id, body),
            )

    with get_db() as conn:
        item = conn.execute(
            "SELECT * FROM products WHERE id = ?", (product_id,)
        ).fetchone()
        comments = conn.execute(
            "SELECT * FROM comments WHERE product_id = ? ORDER BY id DESC",
            (product_id,),
        ).fetchall()
    if not item:
        return page("見つかりません", "<p>商品が見つかりません。</p>")

    rendered_comments = "".join(
        # Intentionally vulnerable: stored XSS because comment body is not escaped.
        f"<section class='card'><p>{comment['body']}</p></section>"
        for comment in comments
    )
    return page(
        item["name"],
        f"""
        <p>{item["price"]} 円</p>
        <h2>コメント</h2>
        <div class="hint">
          <p>このページでは保存型XSSを試せます。「コメント」欄に以下をコピーして投稿してみましょう。投稿直後、また再訪したときにもアラートが発火します。</p>
          <pre><code>テスト&lt;script&gt;alert('hello world')&lt;/script&gt;</code></pre>
        </div>
        <form method="post">
          <label>コメント <textarea name="body"></textarea></label>
          <button>投稿</button>
        </form>
        {rendered_comments}
        """,
    )


@app.route("/upload", methods=["GET", "POST"])
def upload() -> str:
    message = ""
    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded and uploaded.filename:
            # Intentionally vulnerable: path traversal by trusting user-supplied filename.
            override = request.form.get("filename", "").strip()
            name = override or uploaded.filename
            save_path = UPLOAD_DIR / name
            uploaded.save(save_path)
            message = f"<p>保存先: <code>{save_path}</code></p>"

    files = "".join(
        f"<li><a href='{url_for('download', filename=name)}'>{name}</a></li>"
        for name in os.listdir(UPLOAD_DIR)
    )
    return page(
        "アップロード",
        f"""
        <div class="hint">
          <p>このページではパストラバーサルを試せます。</p>
          <p><b>書き込み:</b> 任意のファイルを選び、「ファイル名」に以下を入れてアップロードしてください。<code>uploads/</code> の外 (リポジトリ直下) にファイルが作られます。</p>
          <pre><code>../pwned.txt</code></pre>
          <p><b>読み取り:</b> ブラウザで以下を開くと、<code>uploads/</code> 外のファイルを読み取れます。</p>
          <pre><code>http://127.0.0.1:5000/download?filename=../app.py</code></pre>
        </div>
        {message}
        <form method="post" enctype="multipart/form-data">
          <label>ファイル <input name="file" type="file"></label>
          <label>ファイル名 (空欄なら元のファイル名) <input name="filename" placeholder="../pwned.txt"></label>
          <button>アップロード</button>
        </form>
        <ul>{files}</ul>
        """,
    )


@app.route("/download")
def download() -> str:
    filename = request.args.get("filename", "")
    # Intentionally vulnerable: arbitrary file read by joining unchecked user input.
    return send_file(UPLOAD_DIR / filename)


init_db()
