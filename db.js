const sqlite3 = require("sqlite3").verbose();

// SQLiteのデータベースファイルに接続（存在しない場合は作成）
const db = new sqlite3.Database("./users.db", (err) => {
  if (err) {
    return console.error(err.message);
  }
  console.log("Connected to the SQLite database.");
});

// ユーザー用のテーブルを作成
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);
});

module.exports = db;
