const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const app = express();
const cors = require('cors');

app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.USER_DATABASE_URL,
});

const projectpool = new Pool({
  connectionString: process.env.PROJECT_DATABASE_URL,
});

// テーブル作成クエリを定義
const createTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  );
`;

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Authorizationヘッダーからトークンを取得

  if (!token) {
    return res.status(401).json({ error: 'トークンが見つかりません' });
  }

  jwt.verify(token, 'ZeiParasecret', (err, user) => {
    if (err) {
      console.error('JWT検証エラー:', err.message);
      return res.status(403).json({ error: 'トークンが無効です' });
    }
    req.user = user; // トークンが有効な場合、ユーザーデータをリクエストに保存
    next(); // 次の処理へ進む
  });
};

const interval = setInterval(function() {
  console.log("サーバーは稼働中");
}, 10000);

/*
pool.query(createTableQuery)
  .then(() => console.log('Users table created successfully'))
  .catch(err => console.error('Error creating users table:', err));
*/

app.use(express.json()); // リクエストのボディをJSONとしてパース

app.get('/', (req, res) => {
    res.send('正常に稼働しています');
});

app.get('/user/:username', async (req, res) => {
  const username = req.params.username;
  console.log('${username} のリクエストを受け付けました');

  try {
    // ユーザー情報をPostgreSQLから取得
    const result = await pool.query('SELECT username, profile FROM users WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    // ユーザー情報を返す
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

// ユーザー登録エンドポイント
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // 必須項目の検証
  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  }

  const client = await pool.connect();
  
  try {
    // ユーザー名がすでに存在するかをチェック
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      return res.status(400).json({ error: 'そのユーザー名はすでに存在しています' });
    }

    // パスワードのハッシュ化
    const hashedPassword = await bcrypt.hash(password, 10);

    // ユーザーをデータベースに追加
    await client.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );

    // 成功レスポンス
    res.status(201).json({ message: 'ユーザー登録が完了しました' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

app.get('/auth/check', authenticateToken, (req, res) => {
  res.json({ isAuthenticated: true, user: req.user });
});

app.post('creatproject', async (req, res) => {
  const { user, title, content } = req.body;
  let d = new Date();
  let date = `${d.getFullYear()}/${d.getMonth()}/${d.getDay()}`
  const client = await projectpool.connect();
  await client.query(
      'INSERT INTO users (user, content, date, title) VALUES ($1, $2, $3, $4)',
      [user, content, date, title]
    );
});

// ログインエンドポイント
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // 必須項目の検証
  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  }

  const client = await pool.connect();
  
  try {
    // ユーザー名が存在するかを確認
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'ユーザー名またはパスワードが間違っています' });
    }

    const user = result.rows[0];

    // パスワードが一致するか確認
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: 'ユーザー名またはパスワードが間違っています' });
    }

    // JWTの発行
    const token = jwt.sign({ userId: user.id, username:username }, 'ZeiParasecret', { expiresIn: '7d' }); // 7日間有効


    // トークンを返す
    res.json({ message: 'ログイン成功', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

// サーバー起動
const PORT = process.env.PORT || 3000; // 環境変数 PORT を優先
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
