const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg'); // PostgreSQLを使う場合
const app = express();
const cors = require('cors');
app.use(cors()); // 全てのリクエストを許可
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const createTableQuery = `
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
  );
`;

pool.query(createTableQuery)
  .then(() => console.log('Users table created successfully'))
  .catch(err => console.error('Error creating users table:', err));


app.use(express.json()); // リクエストのボディをJSONとしてパース

app.get('/', (req, res) => {
    res.send('正常に稼働しています');
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

app.get('/token/check', authenticateToken, (req, res) => {
  res.json({ isAuthenticated: true });
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
    const token = jwt.sign({ userId: user.id }, 'ZeiParasecret', { expiresIn: '7d' }); // 7日間有効


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
