const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bodyParser = require("body-parser");
const session = require("express-session");
const bcrypt = require("bcrypt");
const db = require("./db"); // SQLite データベースのインポート

const app = express();
const saltRounds = 10; // bcryptでのハッシュ化の強度

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// PassportのLocalStrategyでログイン認証
passport.use(
  new LocalStrategy(function (username, password, done) {
    // データベースからユーザーを取得
    db.get(
      "SELECT * FROM users WHERE username = ?",
      [username],
      (err, user) => {
        if (err) {
          return done(err);
        }
        if (!user) {
          return done(null, false, { message: "ユーザーが見つかりません" });
        }
        // パスワードが正しいかチェック
        bcrypt.compare(password, user.password, (err, result) => {
          if (err) {
            return done(err);
          }
          if (result) {
            return done(null, user); // パスワードが一致すればログイン成功
          } else {
            return done(null, false, { message: "パスワードが間違っています" });
          }
        });
      }
    );
  })
);

// ユーザー情報をセッションに保存
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

// セッションからユーザー情報を復元
passport.deserializeUser(function (id, done) {
  db.get("SELECT * FROM users WHERE id = ?", [id], (err, user) => {
    if (err) {
      return done(err);
    }
    done(null, user);
  });
});

// ユーザー登録ページ
app.get("/register", (req, res) => {
  res.render("register");
});

// ユーザー登録処理
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  // パスワードをハッシュ化して保存
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      return res.send("エラーが発生しました");
    }
    // データベースにユーザー情報を保存
    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hash],
      (err) => {
        if (err) {
          return res.send("ユーザー登録に失敗しました: " + err.message);
        }
        res.redirect("/login");
      }
    );
  });
});

// ログインページ
app.get("/login", (req, res) => {
  res.render("login");
});

// ログイン処理
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login",
    successRedirect: "/profile",
  })
);

// 認証済みか確認するミドルウェア
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

// プロフィールページ（認証済みユーザーのみアクセス可能）
app.get("/profile", isAuthenticated, (req, res) => {
  res.render("profile", { user: req.user });
});

// ログアウトページ
app.get("/logout", (req, res) => {
  res.render("logout");
});

// サーバー起動
app.listen(3000, () => {
  console.log("Server is running on http://localhost:3000");
});
